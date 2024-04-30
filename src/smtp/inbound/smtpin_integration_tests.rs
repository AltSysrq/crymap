//-
// Copyright (c) 2024, Jason Lingle
//
// This file is part of Crymap.
//
// Crymap is free software: you can  redistribute it and/or modify it under the
// terms of  the GNU General Public  License as published by  the Free Software
// Foundation, either version  3 of the License, or (at  your option) any later
// version.
//
// Crymap is distributed  in the hope that  it will be useful,  but WITHOUT ANY
// WARRANTY; without  even the implied  warranty of MERCHANTABILITY  or FITNESS
// FOR  A PARTICULAR  PURPOSE.  See the  GNU General  Public  License for  more
// details.
//
// You should have received a copy of the GNU General Public License along with
// Crymap. If not, see <http://www.gnu.org/licenses/>.

use std::borrow::Cow;
use std::cell::RefCell;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, Mutex, Weak};

use chrono::prelude::*;
use lazy_static::lazy_static;
use rayon::prelude::*;
use tempfile::TempDir;

use super::integration_test_common::*;
use crate::{
    account::{model::Uid, v2::Account},
    crypt::master_key::MasterKey,
    mime::dkim,
    support::{
        append_limit::APPEND_SIZE_LIMIT,
        async_io::ServerIo,
        dns,
        error::Error,
        log_prefix::LogPrefix,
        system_config::{self, SmtpConfig, SystemConfig},
    },
};

// Similar to the IMAP integration tests, we share a system directory between
// the tests since accounts are expensive to set up, and the sharing works as
// long as the tests are run concurrently.
//
// The test system has three user accounts: dib, gäz, and zim. Two extras,
// "gir1" and "gir2", are created initially but are destroyed by one of the
// tests.
lazy_static! {
    static ref SYSTEM_DIR: Mutex<Weak<Setup>> = Mutex::new(Weak::new());
    static ref DKIM_KEY: openssl::pkey::PKey<openssl::pkey::Private> =
        openssl::pkey::PKey::generate_ed25519().unwrap();
}

struct Setup {
    system_dir: TempDir,
    master_key: Arc<MasterKey>,
}

fn set_up() -> Arc<Setup> {
    crate::init_test_log();

    let mut lock = SYSTEM_DIR.lock().unwrap();

    if let Some(setup) = lock.upgrade() {
        return setup;
    }

    let setup = Arc::new(set_up_new_root());
    *lock = Arc::downgrade(&setup);
    setup
}

fn set_up_new_root() -> Setup {
    let system_dir = TempDir::new().unwrap();
    let master_key = Arc::new(MasterKey::new());

    vec!["dib", "gäz", "zim", "gir1", "gir2"]
        .into_par_iter()
        .for_each(|user_name| {
            let user_dir = system_dir.path().join(user_name);
            fs::create_dir(&user_dir).unwrap();

            let mut account = Account::new(
                LogPrefix::new("initial-setup".to_owned()),
                user_dir,
                Arc::clone(&master_key),
            )
            .unwrap();
            account.provision(b"hunter2").unwrap();
        });

    Setup {
        system_dir,
        master_key,
    }
}

impl Setup {
    fn connect(&self, cxn_name: &'static str, live_dns: bool) -> SmtpClient {
        let (server_io, client_io) = UnixStream::pair().unwrap();
        // We don't want the server thread to hold on to the TempDir since the
        // test process can exit before the last server thread notices the EOF
        // and terminates.
        let data_root: PathBuf = self.system_dir.path().to_owned();

        std::thread::spawn(move || {
            run_server(data_root, cxn_name, server_io, live_dns)
        });

        SmtpClient::new(cxn_name, client_io)
    }
}

#[tokio::main(flavor = "current_thread")]
async fn run_server(
    data_root: PathBuf,
    cxn_name: &'static str,
    server_io: UnixStream,
    live_dns: bool,
) {
    // DNS setup: earth.com has no configuration. mars.com has full DMARC which
    // accepts our client IP. venus.com has full DMARC which rejects our client
    // IP, but has DKIM set up with the same key.
    let mut dns_cache = dns::Cache::default();
    dns_cache.txt.push((
        Rc::new(dns::Name::from_ascii("mars.com").unwrap()),
        dns::Entry::Ok(vec!["v=spf1 ip4:192.0.2.3 -all".to_owned().into()]),
    ));
    dns_cache.txt.push((
        Rc::new(dns::Name::from_ascii("selector._domainkey.mars.com").unwrap()),
        dns::Entry::Ok(vec![format!(
            "k=ed25519;p={}",
            base64::encode(&DKIM_KEY.raw_public_key().unwrap()),
        )
        .into()]),
    ));
    dns_cache.txt.push((
        Rc::new(dns::Name::from_ascii("_dmarc.mars.com").unwrap()),
        dns::Entry::Ok(vec!["v=DMARC1; p=reject".to_owned().into()]),
    ));
    dns_cache.txt.push((
        Rc::new(dns::Name::from_ascii("venus.com").unwrap()),
        dns::Entry::Ok(vec!["v=spf1 -all".to_owned().into()]),
    ));
    dns_cache.txt.push((
        Rc::new(
            dns::Name::from_ascii("selector._domainkey.venus.com").unwrap(),
        ),
        dns::Entry::Ok(vec![format!(
            "k=ed25519;p={}",
            base64::encode(&DKIM_KEY.raw_public_key().unwrap()),
        )
        .into()]),
    ));
    dns_cache.txt.push((
        Rc::new(dns::Name::from_ascii("_dmarc.venus.com").unwrap()),
        dns::Entry::Ok(vec!["v=DMARC1; p=reject".to_owned().into()]),
    ));

    let system_config = SystemConfig {
        smtp: SmtpConfig {
            domains: std::iter::once((
                system_config::DomainName(
                    dns::Name::from_ascii("irk.com").unwrap(),
                ),
                system_config::SmtpDomain::default(),
            ))
            .collect(),
            reject_dmarc_failures: true,
            ..SmtpConfig::default()
        },
        ..SystemConfig::default()
    };

    let dns_resolver = if live_dns {
        Some(Rc::new(
            hickory_resolver::AsyncResolver::tokio_from_system_conf().unwrap(),
        ))
    } else {
        None
    };

    let server_io = ServerIo::new_owned_socket(server_io).unwrap();
    let local = tokio::task::LocalSet::new();
    let result = local
        .run_until(super::serve_smtpin(
            server_io,
            dns_resolver,
            Rc::new(RefCell::new(dns_cache)),
            Arc::new(system_config),
            LogPrefix::new(cxn_name.to_owned()),
            ssl_acceptor(),
            data_root,
            "mx.irk.com".to_owned(),
            "192.0.2.3".parse().unwrap(),
        ))
        .await;

    match result {
        Ok(()) => (),
        Err(crate::support::error::Error::Io(e))
            if io::ErrorKind::UnexpectedEof == e.kind()
                || Some(nix::libc::EPIPE) == e.raw_os_error() =>
        {
            ()
        },
        Err(e) => panic!("Unexpected server error: {e} {e:?}"),
    }
}

/// Fetch the email which contains the given string.
fn fetch_email(setup: &Setup, account_name: &str, key: &str) -> Option<String> {
    let mut account = Account::new(
        LogPrefix::new("verify".to_owned()),
        setup.system_dir.path().join(account_name),
        Arc::clone(&setup.master_key),
    )
    .unwrap();

    let (mut mailbox, _) = account.select("INBOX", false, None).unwrap();
    for _ in 0..5 {
        // Messages are always delivered one at a time, so we can just do
        // linear probing until we hit a non-existent UID.
        for uid in 1.. {
            let mut r = match account.open_message_by_uid(&mailbox, Uid::u(uid))
            {
                Ok((_, r)) => r,
                Err(Error::NxMessage)
                | Err(Error::UnaddressableMessage)
                | Err(Error::ExpungedMessage) => break,
                Err(e) => panic!("Unexpected error: {}", e),
            };

            let mut data = Vec::new();
            r.read_to_end(&mut data).unwrap();

            let string = String::from_utf8(data).unwrap();
            if string.contains(key) {
                return Some(string);
            }
        }

        // An unrelated thread may be processing the delivery we're looking for
        // right now as part of its own `select()`, so give that time to
        // happen. We retry several times since it can actually take a while
        // under very high load.
        std::thread::sleep(std::time::Duration::from_millis(250));
        account.poll(&mut mailbox).unwrap();
    }

    None
}

#[test]
fn helo() {
    let setup = set_up();
    let mut cxn = setup.connect("helo", false);

    let mut responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(
        responses[0].starts_with("220 mx.irk.com"),
        "Unexpected greeting: {}",
        responses[0],
    );

    cxn.write_line("HELO mail.earth.com\r\n");
    responses = cxn.read_responses();
    // Non-extended HELO yields not extensions, just the basic status code.
    assert_eq!(1, responses.len());
    assert!(
        responses[0].starts_with("250 mx.irk.com"),
        "Unexpected greeting: {}",
        responses[0],
    );

    cxn.write_line("QUIT\r\n");
    responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(
        responses[0].starts_with("221 2.0.0"),
        "Unexpected goodbye: {}",
        responses[0]
    );
}

#[test]
fn ehlo() {
    let setup = set_up();
    let mut cxn = setup.connect("ehlo", false);

    let mut responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(
        responses[0].starts_with("220 mx.irk.com"),
        "Unexpected greeting: {}",
        responses[0],
    );

    cxn.write_line("EHLO mail.earth.com\r\n");
    responses = cxn.read_responses();
    assert!(responses.len() > 1);
    assert!(
        responses[0].starts_with("250-mx.irk.com"),
        "Unexpected greeting: {}",
        responses[0],
    );
    assert!(responses.iter().any(|r| r.contains("STARTTLS")));
    assert!(responses.iter().any(|r| r.contains("PIPELINING")));
    assert!(responses.iter().any(|r| r.contains("BINARYMIME")));
    assert!(!responses.iter().any(|r| r.contains("AUTH")));

    cxn.write_line("QUIT\r\n");
    responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(
        responses[0].starts_with("221 2.0.0"),
        "Unexpected goodbye: {}",
        responses[0]
    );
}

#[test]
fn misc_commands() {
    let setup = set_up();
    let mut cxn = setup.connect("misc_commands", false);
    cxn.skip_pleasantries("HELO mail.earth.com");

    cxn.write_line("HELP ME\r\n");
    let responses = cxn.read_responses();
    assert!(responses.last().unwrap().starts_with("214 2.0.0"));

    cxn.simple_command("VRFY <gäz@localhost>", "252 2.7.0");
    cxn.simple_command("EXPN <list@localhost>", "550 5.3.3");
    cxn.simple_command("NOOP", "250 2.0.0");
}

#[test]
fn wrong_greeting() {
    let setup = set_up();
    let mut cxn = setup.connect("wrong_greeting", false);

    cxn.read_responses();
    cxn.simple_command("LHLO mail.earth.com", "500 5.5.5");
}

#[test]
fn relay_explicitly_rejected() {
    let setup = set_up();
    let mut cxn = setup.connect("relay_explicitly_rejected", false);
    cxn.skip_pleasantries("HELO mail.earth.com");
    cxn.simple_command("MAIL FROM:<human@earth.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<martian@mars.com>", "551 ");
}

#[test]
fn bad_recipient() {
    let setup = set_up();
    let mut cxn = setup.connect("bad_recipient", false);
    cxn.skip_pleasantries("HELO mail.earth.com");
    cxn.simple_command("MAIL FROM:<human@earth.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<nobody@irk.com>", "550 5.1.1");
    cxn.simple_command("RCPT TO:<..@irk.com>", "550 5.1.1");
    cxn.simple_command("RCPT TO:<dib>", "550 5.1.3");
    cxn.simple_command("RCPT TO:<dib@//>", "550 5.1.3");
}

#[test]
fn too_many_recipients() {
    let setup = set_up();
    let mut cxn = setup.connect("too_many_recipients", false);
    cxn.skip_pleasantries("HELO mail.earth.com");
    cxn.simple_command("MAIL FROM:<human@earth.com>", "250 2.0.0");
    for i in 0..100 {
        cxn.write_line(&format!("RCPT TO:<zim+{i}@irk.com>\r\n"));
        let responses = cxn.read_responses();
        assert_eq!(1, responses.len());
        if responses[0].starts_with("452 5.5.3") {
            return;
        }

        assert!(responses[0].starts_with("250 2.1.5"));
    }

    panic!("never got 'too many recipients' response");
}

#[test]
fn too_many_ineffectual_commands() {
    let setup = set_up();
    let mut cxn = setup.connect("too_many_recipients", false);
    cxn.skip_pleasantries("HELO mail.earth.com");

    for _ in 0..100 {
        cxn.write_line("NOOP\r\n");
        let responses = cxn.read_responses();
        assert_eq!(1, responses.len());
        if responses[0].starts_with("221 ") {
            return;
        }
    }

    panic!("never disconnected");
}

#[test]
fn minimal_mail_delivery() {
    let setup = set_up();
    let mut cxn = setup.connect("minimal_mail_delivery", false);
    cxn.skip_pleasantries("HELO 192.0.2.3");
    cxn.simple_command("MAIL FROM:<>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<zim@irk.com>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");
    cxn.write_line(
        "From: someone@earth.com\r\n\
         Subject: Foo\r\n\
         \r\n\
         minimal_mail_delivery\r\n\
         .\r\n",
    );

    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("250 2.0.0"));

    let delivered =
        fetch_email(&setup, "zim", "minimal_mail_delivery").unwrap();
    println!("delivered:\n{delivered}");
    // We don't get an SPF header because none of the possible inputs were
    // actually domains.
    assert!(delivered.contains("spf=none"));
    assert!(!delivered.contains("Received-SPF"));
}

#[test]
fn slow_mail_delivery() {
    fn delay() {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    let setup = set_up();
    let mut cxn = setup.connect("slow_mail_delivery", false);
    cxn.skip_pleasantries("HELO 192.0.2.3");
    cxn.simple_command("MAIL FROM:<>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<zim@irk.com>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");
    cxn.write_raw(b"From: ");
    delay();
    cxn.write_raw(b"someone@earth.com\r");
    delay();
    cxn.write_raw(b"\nSubject: Foo");
    delay();
    cxn.write_raw(b"\r");
    delay();
    cxn.write_raw(b"\n");
    delay();
    cxn.write_raw(b"\r");
    delay();
    cxn.write_raw(b"\n");
    cxn.write_raw(b"slow_mail_delivery\r\n.\r\n");

    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("250 2.0.0"));

    let delivered =
        fetch_email(&setup, "zim", "minimal_mail_delivery").unwrap();
    println!("delivered:\n{delivered}");
}

#[test]
fn multi_mail_delivery() {
    let setup = set_up();
    let mut cxn = setup.connect("multi_mail_delivery", false);
    cxn.skip_pleasantries("HELO mail.earth.com");
    cxn.simple_command("MAIL FROM:<human@earth.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<dib@irk.com>", "250 2.1.5");
    cxn.simple_command("RCPT TO:<zim@irk.com>", "250 2.1.5");
    cxn.simple_command("RCPT TO:<gäz@irk.com>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");
    cxn.write_line(
        "From: human@earth.com\r\n\
         Subject: Foo\r\n\
         \r\n\
         multi_mail_delivery\r\n\
         .\r\n",
    );

    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("250 2.0.0"));

    let delivered = fetch_email(&setup, "dib", "multi_mail_delivery").unwrap();
    println!("delivered:\n{delivered}");
    assert!(delivered.contains("spf=temperror"));
    assert!(delivered.contains("envelope-from=\"earth.com\""));

    assert!(fetch_email(&setup, "zim", "multi_mail_delivery").is_some());
    assert!(fetch_email(&setup, "gäz", "multi_mail_delivery").is_some());
}

#[test]
fn huge_headers_via_data() {
    let setup = set_up();
    let mut cxn = setup.connect("huge_headers_via_data", false);
    cxn.skip_pleasantries("HELO mail.earth.com");
    cxn.simple_command("MAIL FROM:<human@earth.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<zim@irk.com>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");
    cxn.write_line("From: human@earth.com\r\n");
    let chunk =
        "All headers and no play makes Jack a dull message\r\n".repeat(1024);
    for _ in 0..64 {
        cxn.write_raw(chunk.as_bytes());
    }
    cxn.write_line("\r\n\r\n huge_headers_via_data\r\n.\r\n");

    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("554 5.3.4"));

    assert!(fetch_email(&setup, "zim", "huge_headers_via_data").is_none());
}

#[test]
fn endless_headers_via_bdat() {
    let setup = set_up();
    let mut cxn = setup.connect("endless_headers_via_data", false);
    cxn.skip_pleasantries("HELO mail.earth.com");
    cxn.simple_command("MAIL FROM:<human@earth.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<zim@irk.com>", "250 2.1.5");
    let chunk =
        "All headers and no play makes Jack a dull message\r\n".repeat(1024);
    let mut rejected = false;
    for _ in 0..64 {
        cxn.write_line(&format!("BDAT {}\r\n", chunk.len()));
        cxn.write_raw(chunk.as_bytes());

        let responses = cxn.read_responses();
        assert_eq!(1, responses.len());
        if responses[0].starts_with("554 5.3.4") {
            rejected = true;
            break;
        }

        assert!(responses[0].starts_with("250 2.0.0"));
    }

    assert!(rejected);

    // Ensure the state machine isn't broken
    cxn.simple_command("MAIL FROM:<human@earth.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<zim@irk.com>", "250 2.1.5");
}

#[test]
fn bodiless_message() {
    let setup = set_up();
    let mut cxn = setup.connect("bodiless_message", false);
    cxn.skip_pleasantries("HELO mail.earth.com");
    cxn.simple_command("MAIL FROM:<human@earth.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<zim@irk.com>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");
    cxn.write_line(
        "From: human@earth.com\r\n\
         Subject: bodiless_message\r\n\
         .\r\n",
    );

    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("554 5.6.0"));

    assert!(fetch_email(&setup, "zim", "bodiless_message").is_none());
}

#[test]
fn oversized_message_via_data() {
    let setup = set_up();
    let mut cxn = setup.connect("oversized_message_via_data", false);
    cxn.skip_pleasantries("HELO mail.earth.com");
    cxn.simple_command("MAIL FROM:<human@earth.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<zim@irk.com>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");
    cxn.write_line(
        "From: human@earth.com\r\n\
         Subject: oversized_message_via_data\r\n\
         \r\n",
    );

    let megabyte = vec![b'x'; 1024 * 1024];
    for _ in 0..APPEND_SIZE_LIMIT as usize * 2 / megabyte.len() {
        cxn.write_raw(&megabyte);
    }
    cxn.write_line("\r\n.\r\n");

    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("554 5.2.3"));

    assert!(fetch_email(&setup, "zim", "oversized_message_via_data").is_none());
}

#[test]
fn oversized_message_via_small_bdats() {
    let setup = set_up();
    let mut cxn = setup.connect("oversized_message_via_small_bdats", false);
    cxn.skip_pleasantries("HELO mail.earth.com");
    cxn.simple_command("MAIL FROM:<human@earth.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<zim@irk.com>", "250 2.1.5");

    let header = "From: human@earth.com\r\n\
         Subject: oversized_message_via_small_bdats\r\n\
         \r\n";
    cxn.simple_command(
        &format!("BDAT {}\r\n{header}", header.len() + 2),
        "250 2.0.0",
    );

    let mut rejected = false;
    let megabyte = vec![b'x'; 1024 * 1024];
    for _ in 0..APPEND_SIZE_LIMIT as usize * 2 / megabyte.len() {
        cxn.write_line(&format!("BDAT {}\r\n", megabyte.len()));
        cxn.write_raw(&megabyte);

        let responses = cxn.read_responses();
        assert_eq!(1, responses.len());
        if responses[0].starts_with("554 5.2.3") {
            rejected = true;
            break;
        }

        assert!(responses[0].starts_with("250 2.0.0"));
    }

    assert!(rejected);

    assert!(
        fetch_email(&setup, "zim", "oversized_message_via_small_bdats")
            .is_none()
    );

    // Ensure the state machine isn't broken
    cxn.simple_command("MAIL FROM:<human@earth.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<zim@irk.com>", "250 2.1.5");
}

#[test]
fn oversized_message_via_huge_bdat() {
    let setup = set_up();
    let mut cxn = setup.connect("oversized_message_via_huge_bdat", false);
    cxn.skip_pleasantries("HELO mail.earth.com");
    cxn.simple_command("MAIL FROM:<human@earth.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<zim@irk.com>", "250 2.1.5");

    let header = "From: human@earth.com\r\n\
         Subject: oversized_message_via_huge_bdat\r\n\
         \r\n";
    cxn.simple_command(
        &format!("BDAT {}\r\n{header}", header.len() + 2),
        "250 2.0.0",
    );

    let megabyte = vec![b'x'; 1024 * 1024];
    let n = APPEND_SIZE_LIMIT as usize * 2 / megabyte.len();
    cxn.write_line(&format!("BDAT {} LAST\r\n", megabyte.len() * n));
    for _ in 0..n {
        cxn.write_raw(&megabyte);
    }

    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("554 5.2.3"));

    assert!(
        fetch_email(&setup, "zim", "oversized_message_via_huge_bdat").is_none()
    );

    // Ensure the state machine isn't broken
    cxn.simple_command("MAIL FROM:<human@earth.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<zim@irk.com>", "250 2.1.5");
}

#[test]
fn no_from_header() {
    let setup = set_up();
    let mut cxn = setup.connect("no_from_header", false);
    cxn.skip_pleasantries("HELO mail.earth.com");
    cxn.simple_command("MAIL FROM:<human@earth.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<zim@irk.com>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");
    cxn.write_line(
        "Subject: no_from_header\r\n\
         \r\n\
         From: human@earth.com\r\n\
         \r\n\
         no_from_header\r\n\
         .\r\n",
    );

    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("554 5.6.0"));

    assert!(fetch_email(&setup, "zim", "no_from_header").is_none());
}

#[test]
fn two_from_headers() {
    let setup = set_up();
    let mut cxn = setup.connect("two_from_headers", false);
    cxn.skip_pleasantries("HELO mail.earth.com");
    cxn.simple_command("MAIL FROM:<human@earth.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<zim@irk.com>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");
    cxn.write_line(
        "Subject: no_from_header\r\n\
         From: human@earth.com\r\n\
         From: human@mars.com\r\n\
         \r\n\
         two_from_headers\r\n\
         .\r\n",
    );

    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("554 5.6.0"));

    assert!(fetch_email(&setup, "zim", "two_from_headers").is_none());
}

#[test]
fn bad_from_header() {
    let setup = set_up();
    let mut cxn = setup.connect("bad_from_header", false);
    cxn.skip_pleasantries("HELO mail.earth.com");
    cxn.simple_command("MAIL FROM:<human@earth.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<zim@irk.com>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");
    cxn.write_line(
        "Subject: no_from_header\r\n\
         From: bad\r\n\
         \r\n\
         bad_from_header\r\n\
         .\r\n",
    );

    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("554 5.6.0"));

    assert!(fetch_email(&setup, "zim", "bad_from_header").is_none());
}

#[test]
fn dmarc_accept_small() {
    let setup = set_up();
    let mut cxn = setup.connect("dmarc_accept_small", false);
    cxn.skip_pleasantries("HELO mail.mars.com");
    cxn.simple_command("MAIL FROM:<martian@mars.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<zim@irk.com>", "250 2.1.5");

    let unsigned_message_header = "From: martian@mars.com\r\n\
         Subject: Valid message\r\n";
    let unsigned_message_body = "dmarc_accept_small\r\n";

    let keys = vec![("selector".to_owned(), DKIM_KEY.clone())];
    let mut signer = dkim::Signer::new(
        &keys,
        &dkim::Signer::default_template(Utc::now(), Cow::Borrowed("mars.com")),
    );
    signer.write_all(unsigned_message_body.as_bytes()).unwrap();
    let signature = signer.finish(unsigned_message_header.as_bytes());

    cxn.simple_command("DATA", "354 ");
    cxn.write_line(&signature);
    cxn.write_line(unsigned_message_header);
    cxn.write_line("\r\n");
    cxn.write_line(unsigned_message_body);
    cxn.write_line(".\r\n");

    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("250 2.0.0"));

    let delivered = fetch_email(&setup, "zim", "dmarc_accept_small").unwrap();
    println!("delivered:\n{delivered}");
    assert!(delivered.contains("spf=pass"));
    assert!(delivered.contains("dkim=pass"));
    assert!(delivered.contains("dmarc=pass"));
}

#[test]
fn dmarc_accept_large_body() {
    let setup = set_up();
    let mut cxn = setup.connect("dmarc_accept_large_body", false);
    cxn.skip_pleasantries("HELO mail.mars.com");
    cxn.simple_command("MAIL FROM:<martian@mars.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<zim@irk.com>", "250 2.1.5");

    let unsigned_message_header = "From: martian@mars.com\r\n\
         Subject: Valid message\r\n";
    let unsigned_message_body = "dmarc_accept_large_body\r\n".repeat(65536);

    let keys = vec![("selector".to_owned(), DKIM_KEY.clone())];
    let mut signer = dkim::Signer::new(
        &keys,
        &dkim::Signer::default_template(Utc::now(), Cow::Borrowed("mars.com")),
    );
    signer.write_all(unsigned_message_body.as_bytes()).unwrap();
    let signature = signer.finish(unsigned_message_header.as_bytes());

    cxn.simple_command("DATA", "354 ");
    cxn.write_line(&signature);
    cxn.write_line(unsigned_message_header);
    cxn.write_line("\r\n");
    cxn.write_raw(unsigned_message_body.as_bytes());
    cxn.write_line(".\r\n");

    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("250 2.0.0"));

    let delivered =
        fetch_email(&setup, "zim", "dmarc_accept_large_body").unwrap();
    println!("delivered:\n{delivered}");
    assert!(delivered.contains("spf=pass"));
    assert!(delivered.contains("dkim=pass"));
    assert!(delivered.contains("dmarc=pass"));
}

#[test]
fn dmarc_reject_corrupted_body() {
    let setup = set_up();
    let mut cxn = setup.connect("dmarc_reject_corrupted_body", false);
    cxn.skip_pleasantries("HELO mail.mars.com");
    cxn.simple_command("MAIL FROM:<martian@mars.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<zim@irk.com>", "250 2.1.5");

    let unsigned_message_header = "From: martian@mars.com\r\n\
         Subject: Valid message\r\n";
    let unsigned_message_body = "dmarc_accept\r\n";

    let keys = vec![("selector".to_owned(), DKIM_KEY.clone())];
    let mut signer = dkim::Signer::new(
        &keys,
        &dkim::Signer::default_template(Utc::now(), Cow::Borrowed("mars.com")),
    );
    signer.write_all(unsigned_message_body.as_bytes()).unwrap();
    let signature = signer.finish(unsigned_message_header.as_bytes());

    cxn.simple_command("DATA", "354 ");
    cxn.write_line(&signature);
    cxn.write_line(unsigned_message_header);
    cxn.write_line("\r\n");
    cxn.write_line("dmarc_reject_corrupted_body\r\n");
    cxn.write_line(".\r\n");

    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("554 5.7.1"));

    assert!(fetch_email(&setup, "zim", "dmarc_reject_corrupted_body").is_none());
}

#[test]
fn dmarc_reject_wrong_spf_domain() {
    let setup = set_up();
    let mut cxn = setup.connect("dmarc_reject_wrong_spf_domain", false);
    cxn.skip_pleasantries("HELO mail.mars.com");
    cxn.simple_command("MAIL FROM:<martian@earth.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<zim@irk.com>", "250 2.1.5");

    let unsigned_message_header = "From: martian@mars.com\r\n\
         Subject: Valid message\r\n";
    let unsigned_message_body = "dmarc_reject_wrong_spf_domain\r\n";

    let keys = vec![("selector".to_owned(), DKIM_KEY.clone())];
    let mut signer = dkim::Signer::new(
        &keys,
        &dkim::Signer::default_template(Utc::now(), Cow::Borrowed("mars.com")),
    );
    signer.write_all(unsigned_message_body.as_bytes()).unwrap();
    let signature = signer.finish(unsigned_message_header.as_bytes());

    cxn.simple_command("DATA", "354 ");
    cxn.write_line(&signature);
    cxn.write_line(unsigned_message_header);
    cxn.write_line("\r\n");
    cxn.write_line(unsigned_message_body);
    cxn.write_line(".\r\n");

    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("554 5.7.1"));

    assert!(
        fetch_email(&setup, "zim", "dmarc_reject_wrong_spf_domain").is_none()
    );
}

#[test]
fn dmarc_reject_spf_failure() {
    let setup = set_up();
    let mut cxn = setup.connect("dmarc_reject_spf_failure", false);
    cxn.skip_pleasantries("HELO mail.venus.com");
    cxn.simple_command("MAIL FROM:<martian@venus.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<zim@irk.com>", "250 2.1.5");

    let unsigned_message_header = "From: martian@venus.com\r\n\
         Subject: Valid message\r\n";
    let unsigned_message_body = "dmarc_reject_spf_failure\r\n";

    let keys = vec![("selector".to_owned(), DKIM_KEY.clone())];
    let mut signer = dkim::Signer::new(
        &keys,
        &dkim::Signer::default_template(Utc::now(), Cow::Borrowed("venus.com")),
    );
    signer.write_all(unsigned_message_body.as_bytes()).unwrap();
    let signature = signer.finish(unsigned_message_header.as_bytes());

    cxn.simple_command("DATA", "354 ");
    cxn.write_line(&signature);
    cxn.write_line(unsigned_message_header);
    cxn.write_line("\r\n");
    cxn.write_line(unsigned_message_body);
    cxn.write_line(".\r\n");

    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("554 5.7.1"));

    assert!(fetch_email(&setup, "zim", "dmarc_reject_spf_failure").is_none());
}

#[test]
fn delivery_total_failure() {
    let setup = set_up();
    let mut cxn = setup.connect("delivery_total_failure", false);
    cxn.skip_pleasantries("HELO mail.earth.com");
    cxn.simple_command("MAIL FROM:<human@earth.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<gir1@irk.com>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");

    // Now, between verifying gir@localhost above and actually receiving the
    // content, something comes along and removes the gir1 account.
    fs::remove_dir_all(setup.system_dir.path().join("gir1")).unwrap();

    cxn.write_line(
        "From: human@earth.com\r\n\
         \r\n\
         delivery_total_failure\r\n\
         .\r\n",
    );

    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("450 "));
}

#[test]
fn delivery_partial_failure() {
    let setup = set_up();
    let mut cxn = setup.connect("delivery_total_failure", false);
    cxn.skip_pleasantries("HELO mail.earth.com");
    cxn.simple_command("MAIL FROM:<human@earth.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<gir2@irk.com>", "250 2.1.5");
    cxn.simple_command("RCPT TO:<gäz@irk.com>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");

    // Now, between verifying gir@localhost above and actually receiving the
    // content, something comes along and removes the gir2 account.
    fs::remove_dir_all(setup.system_dir.path().join("gir2")).unwrap();

    cxn.write_line(
        "From: human@earth.com\r\n\
         \r\n\
         delivery_partial_failure\r\n\
         .\r\n",
    );

    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    // Since one of the messages succeeded, the whole request "succeeds".
    assert!(responses[0].starts_with("250 2.0.0 "));
    assert!(fetch_email(&setup, "gäz", "delivery_partial_failure").is_some());
}

#[test]
fn out_of_order_commands() {
    let setup = set_up();
    let mut cxn = setup.connect("out_of_order_commands", false);
    cxn.read_responses(); // Skip greeting

    // Things that shouldn't work before HELO
    cxn.simple_command("MAIL FROM:<>", "503 5.5.1");
    cxn.simple_command("RCPT TO:<dib@irk.com>", "503 5.5.1");
    cxn.simple_command("DATA", "503 5.5.1");
    // 5 = "foo\r\n".len()
    cxn.simple_command("BDAT 5\r\nfoo", "503 5.5.1");

    cxn.write_line("HELO mail.earth.com\r\n");
    let responses = cxn.read_responses();
    assert!(responses.last().unwrap().starts_with("250 "));

    // HELO not allowed after HELO
    cxn.simple_command("HELO mail.earth.com", "503 5.5.1");
    cxn.simple_command("EHLO mail.earth.com", "503 5.5.1");

    // Things that shouldn't work before MAIL FROM
    cxn.simple_command("RCPT TO:<dib@irk.com>", "503 5.5.1");
    cxn.simple_command("DATA", "503 5.5.1");
    cxn.simple_command("BDAT 5\r\nfoo", "503 5.5.1");

    cxn.simple_command("MAIL FROM:<>", "250 2.0.0");
    cxn.simple_command("MAIL FROM:<>", "503 5.5.1");

    // DATA and BDAT don't work without recipients
    cxn.simple_command("DATA", "503 5.5.1");
    cxn.simple_command("BDAT 5\r\nfoo", "503 5.5.1");

    // Finish up and send an email to ensure that the data we sent through BDAT
    // didn't stay in the buffer.
    let ooo_email = "From: human@earth.com\r\nSubject: Out of order\r\n\r\n";
    // If any BDAT chunks were improperly saved, they manifest as a prefix on
    // the email we're sending now
    let unexpected_email = format!("foo\r\n{}", ooo_email);

    cxn.simple_command("RCPT TO:<dib@irk.com>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");
    cxn.write_line(&format!("{}.\r\n", ooo_email));
    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("250 2.0.0"));

    assert!(fetch_email(&setup, "dib", &ooo_email).is_some());
    assert!(fetch_email(&setup, "dib", &unexpected_email).is_none());

    cxn.simple_command("MAIL FROM:<>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<dib@irk.com>", "250 2.1.5");
    cxn.simple_command("BDAT 5\r\nfoo", "250 2.0.0");
    // Things not allowed after BDAT
    cxn.simple_command("RCPT TO:<gäz@irk.com>", "503 5.5.1");
    cxn.simple_command("DATA", "503 5.5.1");

    // RSET resets everything
    cxn.simple_command("RSET", "250 2.0.0");
    cxn.simple_command("MAIL FROM:<>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<dib@irk.com>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");
    cxn.write_line(&format!("{}.\r\n", ooo_email));
    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("250 2.0.0"));

    // Ensure the BDAT above wasn't saved.
    assert!(!fetch_email(&setup, "dib", &unexpected_email).is_some());
}

#[test]
fn start_tls() {
    let setup = set_up();
    let mut cxn = setup.connect("start_tls", false);
    cxn.skip_pleasantries("HELO 192.0.2.3");
    cxn.simple_command("STARTTLS", "220 2.0.0");
    cxn.start_tls();

    // Sleep briefly to ensure the async code has a chance to observe a stall.
    std::thread::sleep(std::time::Duration::from_millis(100));
    cxn.simple_command("HELO 192.0.2.3", "250 ");
    cxn.simple_command("MAIL FROM:<>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<zim@irk.com>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");
    cxn.write_line(
        "From: someone@earth.com\r\n\
         Subject: Foo\r\n\
         \r\n\
         starttls_mail_delivery\r\n\
         .\r\n",
    );

    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("250 2.0.0"));

    let delivered =
        fetch_email(&setup, "zim", "starttls_mail_delivery").unwrap();
    println!("delivered:\n{delivered}");
    assert!(delivered.contains("ESMTPS"));
}

#[test]
#[cfg(feature = "live-network-tests")]
fn live_test() {
    let setup = set_up();
    let mut cxn = setup.connect("live_test", true);
    // In the test build, smtpin.spftest.lin.gl is special-cased to be an
    // organisational domain.
    //
    // This domain has DMARC configured and an SPF record that only allows
    // 192.0.2.3. There's a DKIM entry for `selector`, but it's deliberately
    // invalid so that no real key is needed here.
    cxn.skip_pleasantries("HELO smtpin.spftest.lin.gl");
    cxn.simple_command("MAIL FROM:<foo@smtpin.spftest.lin.gl>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<zim@irk.com>", "250 2.1.5");

    let unsigned_message_header = "From: foo@smtpin.spftest.lin.gl\r\n\
         Subject: Live test\r\n";
    let unsigned_message_body = "live_test\r\n";

    let keys = vec![("selector".to_owned(), DKIM_KEY.clone())];
    let mut signer = dkim::Signer::new(
        &keys,
        &dkim::Signer::default_template(
            Utc::now(),
            Cow::Borrowed("smtpin.spftest.lin.gl"),
        ),
    );
    signer.write_all(unsigned_message_body.as_bytes()).unwrap();
    let signature = signer.finish(unsigned_message_header.as_bytes());

    cxn.simple_command("DATA", "354 ");

    cxn.write_line(&signature);
    cxn.write_line(unsigned_message_header);
    cxn.write_line("\r\n");
    cxn.write_line(unsigned_message_body);
    cxn.write_line(".\r\n");

    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("250 2.0.0"));

    let delivered = fetch_email(&setup, "zim", "live_test").unwrap();
    println!("delivered:\n{delivered}");
    assert!(delivered.contains("spf=pass"));
    assert!(delivered.contains("dkim=permerror"));
    assert!(delivered.contains("dmarc=permerror"));
}
