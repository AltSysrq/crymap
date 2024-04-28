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

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Weak};

use chrono::prelude::*;
use lazy_static::lazy_static;
use rayon::prelude::*;
use tempfile::TempDir;

use super::integration_test_common::*;
use crate::{
    account::v2::{Account, SmtpTransfer, SpooledMessageId},
    crypt::master_key::MasterKey,
    mime::dkim,
    support::{
        append_limit::APPEND_SIZE_LIMIT,
        async_io::ServerIo,
        dns,
        log_prefix::LogPrefix,
        system_config::{self, SmtpConfig, SystemConfig},
    },
};

// Similar to the IMAP integration tests, we share a system directory between
// the tests since accounts are expensive to set up, and the sharing works as
// long as the tests are run concurrently.
//
// The test system has three user accounts: dib, gäz, and zim. gaz is aliased
// to gäz.
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

    vec!["dib", "gäz", "zim"]
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
    nix::unistd::symlinkat(
        &system_dir.path().join("gäz"),
        None,
        &system_dir.path().join("gaz"),
    )
    .unwrap();

    Setup {
        system_dir,
        master_key,
    }
}

impl Setup {
    fn connect(&self, cxn_name: &'static str) -> SmtpClient {
        self.connect2(cxn_name).0
    }

    fn connect2(
        &self,
        cxn_name: &'static str,
    ) -> (SmtpClient, Arc<Mutex<Vec<SpooledMessageId>>>) {
        let (server_io, client_io) = UnixStream::pair().unwrap();
        // We don't want the server thread to hold on to the TempDir since the
        // test process can exit before the last server thread notices the EOF
        // and terminates.
        let data_root: PathBuf = self.system_dir.path().to_owned();
        let spool_rx = Arc::new(Mutex::new(Vec::<SpooledMessageId>::new()));

        let spool_tx = Arc::clone(&spool_rx);
        std::thread::spawn(move || {
            run_server(data_root, cxn_name, server_io, Arc::clone(&spool_tx))
        });

        (SmtpClient::new(cxn_name, client_io), spool_rx)
    }
}

#[tokio::main(flavor = "current_thread")]
async fn run_server(
    data_root: PathBuf,
    cxn_name: &'static str,
    server_io: UnixStream,
    spool_tx: Arc<Mutex<Vec<SpooledMessageId>>>,
) {
    let system_config = SystemConfig {
        smtp: SmtpConfig {
            domains: [
                (
                    system_config::DomainName(
                        dns::Name::from_ascii("earth.com").unwrap(),
                    ),
                    system_config::SmtpDomain {
                        dkim: std::iter::once((
                            "ed".to_owned(),
                            system_config::DkimKey(DKIM_KEY.clone()),
                        ))
                        .collect(),
                    },
                ),
                // mars.com is used for testing very large messages. Since it
                // does not have DKIM, it can process data much faster in debug
                // builds.
                (
                    system_config::DomainName(
                        dns::Name::from_ascii("mars.com").unwrap(),
                    ),
                    system_config::SmtpDomain::default(),
                ),
            ]
            .into_iter()
            .collect(),
            ..SmtpConfig::default()
        },
        ..SystemConfig::default()
    };

    let server_io = ServerIo::new_owned_socket(server_io).unwrap();
    let local = tokio::task::LocalSet::new();
    let result = local
        .run_until(super::serve_smtpsub(
            server_io,
            Arc::new(system_config),
            LogPrefix::new(cxn_name.to_owned()),
            Some(ssl_acceptor()),
            data_root,
            "mx.earth.com".to_owned(),
            Box::new(move |_, id| spool_tx.lock().unwrap().push(id)),
        ))
        .await;

    match result {
        Ok(()) => (),
        Err(crate::support::error::Error::Io(e))
            if io::ErrorKind::UnexpectedEof == e.kind()
                || io::ErrorKind::Other == e.kind()
                || Some(nix::libc::EPIPE) == e.raw_os_error() =>
        {
            ()
        },
        Err(e) => panic!("Unexpected server error: {e} {e:?}"),
    }
}

#[test]
fn helo() {
    let setup = set_up();
    let mut cxn = setup.connect("helo");

    let mut responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(
        responses[0].starts_with("220 mx.earth.com"),
        "Unexpected greeting: {}",
        responses[0],
    );

    cxn.write_line("HELO localhost\r\n");
    responses = cxn.read_responses();
    // Non-extended HELO yields not extensions, just the basic status code.
    assert_eq!(1, responses.len());
    assert!(
        responses[0].starts_with("250 mx.earth.com"),
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
    let mut cxn = setup.connect("ehlo");

    let mut responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(
        responses[0].starts_with("220 mx.earth.com"),
        "Unexpected greeting: {}",
        responses[0],
    );

    cxn.write_line("EHLO mail.irk.com\r\n");
    responses = cxn.read_responses();
    assert!(responses.len() > 1);
    assert!(
        responses[0].starts_with("250-mx.earth.com"),
        "Unexpected greeting: {}",
        responses[0],
    );
    assert!(responses.iter().any(|r| r.contains("STARTTLS")));
    assert!(responses.iter().any(|r| r.contains("PIPELINING")));
    assert!(!responses.iter().any(|r| r.contains("BINARYMIME")));
    assert!(!responses.iter().any(|r| r.contains("AUTH")));

    cxn.simple_command("STARTTLS", "220 2.0.0");
    cxn.start_tls();

    // Sleep briefly to ensure the async code has a chance to observe a stall.
    std::thread::sleep(std::time::Duration::from_millis(100));
    responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(
        responses[0].starts_with("220 mx.earth.com"),
        "Unexpected greeting: {}",
        responses[0],
    );

    cxn.write_line("EHLO mail.irk.com\r\n");
    responses = cxn.read_responses();
    assert!(responses.len() > 1);
    assert!(
        responses[0].starts_with("250-mx.earth.com"),
        "Unexpected greeting: {}",
        responses[0],
    );
    assert!(!responses.iter().any(|r| r.contains("STARTTLS")));
    assert!(responses.iter().any(|r| r.contains("PIPELINING")));
    assert!(!responses.iter().any(|r| r.contains("BINARYMIME")));
    assert!(responses.iter().any(|r| r.contains("AUTH PLAIN")));

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
    let mut cxn = setup.connect("misc_commands");
    cxn.skip_pleasantries("HELO localhost");

    cxn.write_line("HELP ME\r\n");
    let responses = cxn.read_responses();
    assert!(responses.last().unwrap().starts_with("214 2.0.0"));

    cxn.simple_command("VRFY <gäz@localhost>", "252 2.7.0");
    cxn.simple_command("EXPN <list@localhost>", "550 5.3.3");
    cxn.simple_command("NOOP", "250 2.0.0");
}

#[test]
fn out_of_order_commands() {
    let setup = set_up();
    let mut cxn = setup.connect("out_of_order_commands");
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

    cxn.simple_command("MAIL FROM:<>", "530 5.7.1");

    cxn.simple_command("AUTH PLAIN emltAHppbQBodW50ZXIy", "538 5.7.11");
    cxn.simple_command("STARTTLS", "220");
    cxn.start_tls();
    cxn.skip_pleasantries("HELO localhost");
    cxn.simple_command("AUTH PLAIN emltAHppbQBodW50ZXIy", "235");

    cxn.simple_command("MAIL FROM:<>", "250 2.0.0");
    cxn.simple_command("MAIL FROM:<>", "503 5.5.1");
}

#[test]
fn wrong_greeting() {
    let setup = set_up();
    let mut cxn = setup.connect("wrong_greeting");

    cxn.read_responses();
    cxn.simple_command("LHLO mail.irk.com", "500 5.5.5");
}

#[test]
fn auth_rejected_on_cleartext() {
    let setup = set_up();
    let mut cxn = setup.connect("auth_rejected_on_cleartext");
    cxn.skip_pleasantries("HELO localhost");
    cxn.simple_command("AUTH PLAIN", "538 5.7.11");
    cxn.simple_command("AUTH PLAIN =", "538 5.7.11");
    cxn.simple_command("AUTH PLAIN emltAHppbQBodW50ZXIy", "538 5.7.11");
}

#[test]
fn inline_auth_success() {
    let setup = set_up();
    let mut cxn = setup.connect("inline_auth_success");
    cxn.skip_pleasantries_with_tls("HELO localhost");
    // zim\0zim\0hunter2
    cxn.simple_command("AUTH PLAIN emltAHppbQBodW50ZXIy", "235 2.7.0");
    cxn.simple_command("AUTH PLAIN emltAHppbQBodW50ZXIy", "503 ");
}

#[test]
fn out_of_line_auth_success() {
    let setup = set_up();
    let mut cxn = setup.connect("out_of_line_auth_success");
    cxn.skip_pleasantries_with_tls("HELO localhost");
    cxn.simple_command("AUTH PlAiN =", "334 ");
    // zim\0zim\0hunter2
    cxn.simple_command("emltAHppbQBodW50ZXIy", "235 2.7.0");

    let mut cxn = setup.connect("out_of_line_auth_success");
    cxn.skip_pleasantries_with_tls("HELO localhost");
    cxn.simple_command("AUTH plain", "334 ");
    // zim\0zim\0hunter2
    cxn.simple_command("emltAHppbQBodW50ZXIy", "235 2.7.0");
}

#[test]
fn bad_auth_method() {
    let setup = set_up();
    let mut cxn = setup.connect("bad_auth_method");
    cxn.skip_pleasantries_with_tls("HELO localhost");
    cxn.simple_command("AUTH NTLM =", "504 5.5.4");
}

#[test]
fn cancel_out_of_line_auth() {
    let setup = set_up();
    let mut cxn = setup.connect("out_of_line_auth_success");
    cxn.skip_pleasantries_with_tls("HELO localhost");
    cxn.simple_command("AUTH PLAIN", "334 ");
    cxn.simple_command("*", "501 ");
    cxn.simple_command("NOOP", "250 ");
}

#[test]
fn auth_with_implicit_authorise_id() {
    let setup = set_up();
    let mut cxn = setup.connect("auth_with_implicit_authorise_id");
    cxn.skip_pleasantries_with_tls("HELO localhost");
    // \0zim\0hunter2
    cxn.simple_command("AUTH PLAIN AHppbQBodW50ZXIy", "235 2.7.0");
}

#[test]
fn invalid_auth() {
    let setup = set_up();
    let mut cxn = setup.connect("invalid_auth");
    cxn.skip_pleasantries_with_tls("HELO localhost");
    // \0zim\0hunter3
    cxn.simple_command("AUTH PLAIN AHppbQBodW50ZXIz", "535 5.7.8");
    // \0../etc/passwd\0hunter2
    cxn.simple_command(
        "AUTH PLAIN AC4uL2V0Yy9wYXNzd2QAaHVudGVyMg==",
        "535 5.7.8",
    );
    // dib\0zim\0hunter2
    cxn.simple_command("AUTH PLAIN ZGliAHppbQBodW50ZXIy", "535 5.7.8");
    cxn.simple_command("AUTH PLAIN AAAA", "500 5.5.2");
    cxn.simple_command("AUTH PLAIN", "334 ");
    cxn.simple_command("invalidbase64!", "500 5.5.2");
    cxn.simple_command("AUTH PLAIN", "334 ");
    let mut overlong = "long".repeat(32768 / 4 + 1);
    overlong.push_str("\r\n");
    cxn.write_raw(overlong.as_bytes());
    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("500 5.5.6"));
}

fn check_message(
    setup: &Setup,
    username: &str,
    id: SpooledMessageId,
    transfer: SmtpTransfer,
    mail_from: &str,
    destinations: &[&str],
    contains_data: &str,
) {
    let mut account = Account::new(
        LogPrefix::new("verify".to_owned()),
        setup.system_dir.path().join(username),
        Arc::clone(&setup.master_key),
    )
    .unwrap();
    let mut message = account.open_spooled_message(id).unwrap();
    assert_eq!(transfer, message.transfer);
    assert_eq!(mail_from, message.mail_from);
    assert_eq!(destinations.len(), message.destinations.len());
    assert!(destinations
        .iter()
        .all(|&lhs| message.destinations.iter().any(|rhs| lhs == rhs)),);

    let mut data = Vec::<u8>::new();
    message.data.read_to_end(&mut data).unwrap();
    assert_eq!(data.len(), message.size as usize);
    assert!(data
        .windows(contains_data.len())
        .any(|w| w == contains_data.as_bytes()));

    let end_of_headers = memchr::memmem::find(&data, b"\r\n\r\n").unwrap() + 4;
    let mut dkim_verifier = dkim::Verifier::new(&data[..end_of_headers]);
    dkim_verifier.write_all(&data[end_of_headers..]).unwrap();
    let dkim_venv = dkim::VerificationEnvironment {
        now: Utc::now(),
        txt_records: vec![dkim::TxtRecordEntry {
            selector: "ed".to_owned(),
            sdid: "earth.com".to_owned(),
            txt: Ok(format!(
                "k=ed25519;p={}",
                base64::encode(&DKIM_KEY.raw_public_key().unwrap())
            )
            .into()),
        }],
    };
    let dkim_results = dkim_verifier.finish(&dkim_venv).collect::<Vec<_>>();
    assert_eq!(1, dkim_results.len());
    assert_eq!(None, dkim_results[0].error);
}

#[test]
fn simple_message_spooling() {
    let email = "\
From: Zim <zim@earth.com>\r
To: tallest@irk.com\r
Subject: Invasion status\r
\r
simple_message_spooling\r
";

    let setup = set_up();
    let (mut cxn, spool_rx) = setup.connect2("simple_message_spooling");
    cxn.quick_log_in("HELO localhost", "zim", "hunter2");
    cxn.simple_command("MAIL FROM:<zim@earth.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<tallest@irk.com>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");
    cxn.write_line(&format!("{email}.\r\n"));

    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("250 2.0.0"));

    check_message(
        &setup,
        "zim",
        spool_rx.lock().unwrap()[0],
        SmtpTransfer::SevenBit,
        "zim@earth.com",
        &["tallest@irk.com"],
        "simple_message_spooling",
    );
}

#[test]
fn long_message_valid_dkim() {
    let mut email = "\
From: zim@earth.com\r
To: tallest@irk.com\r
Subject: Very long message\r
\r
Ensures that the DKIM signature is produced correctly even if the message does\r
not end up entirely in the initial header buffer, and that the message is\r
detected as binary even though the binary bit is at the very end..\r
"
    .to_owned();
    for _ in 0..10000 {
        email.push_str("long_message_valid_dkim\r\n");
    }
    email.push_str("\x00\r\n");

    let setup = set_up();
    let (mut cxn, spool_rx) = setup.connect2("long_message_valid_dkim");
    cxn.quick_log_in("HELO localhost", "zim", "hunter2");
    cxn.simple_command("MAIL FROM:<zim@earth.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<tallest@irk.com>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");
    cxn.write_line(&format!("{email}.\r\n"));

    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("250 2.0.0"));

    check_message(
        &setup,
        "zim",
        spool_rx.lock().unwrap()[0],
        SmtpTransfer::Binary,
        "zim@earth.com",
        &["tallest@irk.com"],
        "long_message_valid_dkim",
    );
}

#[test]
fn implicit_return_path_from_from_header() {
    let email = "\
From: zim+implicit_return_path_from_from_header@earth.com
To: tallest@irk.com
Subject: Implicit return path

The message is sent with no return path, so one is inferred from the From
header.
";

    let setup = set_up();
    let (mut cxn, spool_rx) =
        setup.connect2("implicit_return_path_from_from_header");
    cxn.quick_log_in("HELO localhost", "zim", "hunter2");
    cxn.simple_command("MAIL FROM:<>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<tallest@irk.com>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");
    cxn.write_line(&format!("{email}.\r\n"));

    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("250 2.0.0"));

    check_message(
        &setup,
        "zim",
        spool_rx.lock().unwrap()[0],
        SmtpTransfer::SevenBit,
        "zim+implicit_return_path_from_from_header@earth.com",
        &["tallest@irk.com"],
        "Return-Path: <zim+implicit_return_path_from_from_header@earth.com>",
    );
}

#[test]
fn huge_headers_via_data() {
    let setup = set_up();
    let (mut cxn, spool_rx) = setup.connect2("huge_headers_via_data");
    cxn.quick_log_in("HELO localhost", "zim", "hunter2");
    cxn.simple_command("MAIL FROM:<zim@earth.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<tallest@irk.com>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");
    cxn.write_line("From: zim@earth.com\r\n");
    let chunk =
        "All headers and no play makes Jack a dull message\r\n".repeat(1024);
    for _ in 0..64 {
        cxn.write_raw(chunk.as_bytes());
    }
    cxn.write_line("\r\n\r\n huge_headers_via_data\r\n.\r\n");

    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("554 5.3.4"));

    assert!(spool_rx.lock().unwrap().is_empty());
}

#[test]
fn endless_headers_via_bdat() {
    let setup = set_up();
    let mut cxn = setup.connect("endless_headers_via_data");
    cxn.quick_log_in("HELO localhost", "zim", "hunter2");
    cxn.simple_command("MAIL FROM:<zim@earth.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<tallest@irk.com>", "250 2.1.5");
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
    cxn.simple_command("MAIL FROM:<zim@earth.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<tallest@irk.com>", "250 2.1.5");
}

#[test]
fn bodiless_message() {
    let setup = set_up();
    let (mut cxn, spool_rx) = setup.connect2("bodiless_message");
    cxn.quick_log_in("HELO localhost", "zim", "hunter2");
    cxn.simple_command("MAIL FROM:<zim@earth.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<tallest@irk.com>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");
    cxn.write_line(
        "From: zim@earth.com\r\n\
         Subject: bodiless_message\r\n\
         .\r\n",
    );

    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("554 5.6.0"));

    assert!(spool_rx.lock().unwrap().is_empty());
}

#[test]
fn oversized_message_via_data() {
    let setup = set_up();
    let (mut cxn, spool_rx) = setup.connect2("oversized_message_via_data");
    cxn.quick_log_in("HELO localhost", "zim", "hunter2");
    cxn.simple_command("MAIL FROM:<zim@mars.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<tallest@irk.com>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");
    cxn.write_line(
        "From: zim@mars.com\r\n\
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

    assert!(spool_rx.lock().unwrap().is_empty());
}

#[test]
fn oversized_message_via_small_bdats() {
    let setup = set_up();
    let (mut cxn, spool_rx) =
        setup.connect2("oversized_message_via_small_bdats");
    cxn.quick_log_in("HELO localhost", "zim", "hunter2");
    cxn.simple_command("MAIL FROM:<zim@mars.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<tallest@irk.com>", "250 2.1.5");

    let header = "From: zim@mars.com\r\n\
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

    assert!(spool_rx.lock().unwrap().is_empty());

    // Ensure the state machine isn't broken
    cxn.simple_command("MAIL FROM:<zim@earth.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<tallest@irk.com>", "250 2.1.5");
}

#[test]
fn oversized_message_via_huge_bdat() {
    let setup = set_up();
    let (mut cxn, spool_rx) = setup.connect2("oversized_message_via_huge_bdat");
    cxn.quick_log_in("HELO localhost", "zim", "hunter2");
    cxn.simple_command("MAIL FROM:<zim@mars.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<tallest@irk.com>", "250 2.1.5");

    let header = "From: zim@mars.com\r\n\
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

    assert!(spool_rx.lock().unwrap().is_empty());

    // Ensure the state machine isn't broken
    cxn.simple_command("MAIL FROM:<zim@earth.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<tallest@irk.com>", "250 2.1.5");
}

#[test]
fn no_from_header() {
    let setup = set_up();
    let (mut cxn, spool_rx) = setup.connect2("no_from_header");
    cxn.quick_log_in("HELO localhost", "zim", "hunter2");
    cxn.simple_command("MAIL FROM:<zim@earth.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<tallest@irk.com>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");
    cxn.write_line(
        "Subject: no_from_header\r\n\
         \r\n\
         From: zim@earth.com\r\n\
         \r\n\
         no_from_header\r\n\
         .\r\n",
    );

    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("554 5.6.0"));

    assert!(spool_rx.lock().unwrap().is_empty());
}

#[test]
fn two_from_headers() {
    let setup = set_up();
    let (mut cxn, spool_rx) = setup.connect2("two_from_headers");
    cxn.quick_log_in("HELO localhost", "zim", "hunter2");
    cxn.simple_command("MAIL FROM:<zim@earth.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<tallest@irk.com>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");
    cxn.write_line(
        "Subject: no_from_header\r\n\
         From: zim@earth.com\r\n\
         From: zim@mars.com\r\n\
         \r\n\
         two_from_headers\r\n\
         .\r\n",
    );

    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("554 5.6.0"));

    assert!(spool_rx.lock().unwrap().is_empty());
}

#[test]
fn bad_from_header() {
    let setup = set_up();
    let (mut cxn, spool_rx) = setup.connect2("bad_from_header");
    cxn.quick_log_in("HELO localhost", "zim", "hunter2");
    cxn.simple_command("MAIL FROM:<zim@earth.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<tallest@irk.com>", "250 2.1.5");
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

    assert!(spool_rx.lock().unwrap().is_empty());
}

#[test]
fn return_path_wrong_domain() {
    let setup = set_up();
    let mut cxn = setup.connect("return_path_wrong_domain");
    cxn.quick_log_in("HELO localhost", "zim", "hunter2");
    cxn.simple_command("MAIL FROM:<zim@irk.com>", "551 5.7.1");
}

#[test]
fn return_path_wrong_user() {
    let setup = set_up();
    let mut cxn = setup.connect("return_path_wrong_user");
    cxn.quick_log_in("HELO localhost", "zim", "hunter2");
    cxn.simple_command("MAIL FROM:<dib@earth.com>", "550 5.7.1");
}

#[test]
fn from_header_wrong_domain() {
    let setup = set_up();
    let (mut cxn, spool_rx) = setup.connect2("from_header_wrong_domain");
    cxn.quick_log_in("HELO localhost", "zim", "hunter2");
    cxn.simple_command("MAIL FROM:<zim@earth.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<tallest@irk.com>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");
    cxn.write_line(
        "Subject: from_header_wrong_domain
From: zim@irk.com

from_header_wrong_domain
.\r\n
",
    );

    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("551 5.7.1"));

    assert!(spool_rx.lock().unwrap().is_empty());
}

#[test]
fn from_header_wrong_user() {
    let setup = set_up();
    let (mut cxn, spool_rx) = setup.connect2("from_header_wrong_user");
    cxn.quick_log_in("HELO localhost", "zim", "hunter2");
    cxn.simple_command("MAIL FROM:<zim@earth.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<tallest@irk.com>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");
    cxn.write_line(
        "Subject: from_header_wrong_user
From: dib@earth.com

from_header_wrong_user
.\r\n
",
    );

    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("550 5.7.1"));

    assert!(spool_rx.lock().unwrap().is_empty());
}

#[test]
fn auth_gaz_send_gäz() {
    let email = "Subject: Gaz/Gäz
From: <gäz@earth.com>

auth_gaz_send_gäz
";

    let setup = set_up();
    let (mut cxn, spool_rx) = setup.connect2("auth_gaz_send_gäz");
    cxn.quick_log_in("HELO localhost", "gaz", "hunter2");
    cxn.simple_command("MAIL FROM:<gäz@earth.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<tallest@irk.com>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");
    cxn.write_line(&format!("{email}.\r\n"));

    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("250 2.0.0"));

    check_message(
        &setup,
        "gaz",
        spool_rx.lock().unwrap()[0],
        SmtpTransfer::EightBit,
        "gäz@earth.com",
        &["tallest@irk.com"],
        "auth_gaz_send_gäz",
    );
}

#[test]
fn auth_gäz_send_gaz() {
    let email = "Subject: Gäz/Gaz
From: <gaz@earth.com>

auth_gäz_send_gaz
";

    let setup = set_up();
    let (mut cxn, spool_rx) = setup.connect2("auth_gäz_send_gaz");
    cxn.quick_log_in("HELO localhost", "gäz", "hunter2");
    cxn.simple_command("MAIL FROM:<gaz@earth.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<tallest@irk.com>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");
    cxn.write_line(&format!("{email}.\r\n"));

    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("250 2.0.0"));

    check_message(
        &setup,
        "gaz",
        spool_rx.lock().unwrap()[0],
        SmtpTransfer::EightBit,
        "gaz@earth.com",
        &["tallest@irk.com"],
        "auth_gäz_send_gaz",
    );
}

#[test]
fn bad_recipient() {
    let setup = set_up();
    let mut cxn = setup.connect("bad_recipient");
    cxn.quick_log_in("HELO localhost", "zim", "hunter2");
    cxn.simple_command("MAIL FROM:<zim@earth.com>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<dib>", "550 5.1.3");
    cxn.simple_command("RCPT TO:<dib@//>", "550 5.1.3");
}

#[test]
fn too_many_recipients() {
    let setup = set_up();
    let mut cxn = setup.connect("too_many_recipients");
    cxn.quick_log_in("HELO localhost", "zim", "hunter2");
    cxn.simple_command("MAIL FROM:<zim@earth.com>", "250 2.0.0");
    for i in 0..100 {
        cxn.write_line(&format!("RCPT TO:<tallest+{i}@irk.com>\r\n"));
        let responses = cxn.read_responses();
        assert_eq!(1, responses.len());
        if responses[0].starts_with("452 5.5.3") {
            return;
        }

        assert!(responses[0].starts_with("250 2.1.5"));
    }

    panic!("never got 'too many recipients' response");
}
