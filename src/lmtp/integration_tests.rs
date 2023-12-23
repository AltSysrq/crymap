//-
// Copyright (c) 2020, 2023, Jason Lingle
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
use std::io::{self, BufRead, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Weak};

use lazy_static::lazy_static;
use openssl::{
    pkey,
    ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode},
    x509,
};
use rayon::prelude::*;
use tempfile::TempDir;

use super::server::*;
use crate::account::model::Uid;
use crate::account::v2::Account;
use crate::crypt::master_key::MasterKey;
use crate::support::{
    append_limit::APPEND_SIZE_LIMIT, async_io::ServerIo, error::Error,
    log_prefix::LogPrefix, system_config::SystemConfig,
};

// Similar to the IMAP integration tests, we share a system directory between
// the tests since accounts are expensive to set up, and the sharing works as
// long as the tests are run concurrently.
//
// The test system has three user accounts: dib, gäz, and zim. One extra,
// "gir", is created initially but is destroyed by one of the tests.
lazy_static! {
    static ref SYSTEM_DIR: Mutex<Weak<Setup>> = Mutex::new(Weak::new());
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

    vec!["dib", "gäz", "zim", "gir"]
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

lazy_static! {
    static ref CERTIFICATE_PRIVATE_KEY: pkey::PKey<pkey::Private> =
        pkey::PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap())
            .unwrap();
    static ref CERTIFICATE: x509::X509 = {
        let mut builder = x509::X509Builder::new().unwrap();
        builder.set_pubkey(&CERTIFICATE_PRIVATE_KEY).unwrap();
        builder
            .sign(
                &CERTIFICATE_PRIVATE_KEY,
                openssl::hash::MessageDigest::sha256(),
            )
            .unwrap();
        builder.set_version(2).unwrap();
        builder
            .set_not_before(&openssl::asn1::Asn1Time::from_unix(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&openssl::asn1::Asn1Time::days_from_now(2).unwrap())
            .unwrap();
        builder.build()
    };
}

impl Setup {
    fn connect(&self, cxn_name: &'static str) -> impl Read + Write {
        let (server_io, client_io) = UnixStream::pair().unwrap();
        // We don't want the server thread to hold on to the TempDir since the
        // test process can exit before the last server thread notices the EOF
        // and terminates.
        let data_root: PathBuf = self.system_dir.path().to_owned();

        std::thread::spawn(move || run_server(data_root, cxn_name, server_io));

        client_io
    }
}

#[tokio::main(flavor = "current_thread")]
async fn run_server(data_root: PathBuf, cxn_name: &str, server_io: UnixStream) {
    let server_io = ServerIo::new_owned_socket(server_io).unwrap();
    let mut ssl_acceptor =
        SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
    ssl_acceptor
        .set_private_key(&CERTIFICATE_PRIVATE_KEY)
        .unwrap();
    ssl_acceptor.set_certificate(&CERTIFICATE).unwrap();

    let ssl_acceptor = ssl_acceptor.build();

    let mut server = Server::new(
        server_io,
        Arc::new(SystemConfig::default()),
        LogPrefix::new(cxn_name.to_owned()),
        ssl_acceptor,
        data_root,
        "localhost".to_owned(),
        cxn_name.to_owned(),
    );

    match server.run().await {
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

/// Read responses from `r` up to and including the final response.
///
/// This creates a `BufReader` over `r` and will lose any data which was
/// buffered after the last read line. This should be fine since we don't do
/// pipelining here.
fn read_responses(r: &mut impl Read) -> Vec<String> {
    let mut ret = Vec::<String>::new();
    let mut r = io::BufReader::new(r);

    loop {
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        println!("Read response: {:?}", line);

        if line.is_empty() {
            panic!("Unexpected EOF");
        }

        let last = " " == &line[3..4];
        ret.push(line);

        if last {
            break;
        }
    }

    ret
}

fn skip_pleasantries(cxn: &mut (impl Read + Write), name: &str) {
    read_responses(cxn);
    writeln!(cxn, "LHLO {}\r", name).unwrap();
    read_responses(cxn);
}

/// Send a command which is expected to have one response with the given
/// prefix.
fn simple_command(cxn: &mut (impl Read + Write), command: &str, prefix: &str) {
    writeln!(cxn, "{}\r", command).unwrap();
    let responses = read_responses(cxn);
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with(prefix));
}

/// Return whether the given account received the specified email.
fn received_email(setup: &Setup, account_name: &str, email: &str) -> bool {
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

            if data.ends_with(email.as_bytes()) {
                return true;
            }
        }

        // An unrelated thread may be processing the delivery we're looking for
        // right now as part of its own `select()`, so give that time to
        // happen. We retry several times since it can actually take a while
        // under very high load.
        std::thread::sleep(std::time::Duration::from_millis(250));
        account.poll(&mut mailbox).unwrap();
    }

    false
}

#[test]
fn first_contact() {
    let setup = set_up();
    let mut cxn = setup.connect("first_contact");

    let responses = read_responses(&mut cxn);
    assert_eq!(1, responses.len());
    assert!(
        responses[0].starts_with("220 localhost"),
        "Unexpected greeting: {}",
        responses[0]
    );

    writeln!(cxn, "QUIT\r").unwrap();

    let responses = read_responses(&mut cxn);
    assert_eq!(1, responses.len());
    assert!(
        responses[0].starts_with("221 2.0.0"),
        "Unexpected goodbye: {}",
        responses[0]
    );
}

#[test]
fn test_lhlo() {
    let setup = set_up();
    let mut cxn = setup.connect("test_lhlo");

    read_responses(&mut cxn);

    writeln!(cxn, "LHLO test_lhlo\r").unwrap();

    let responses = read_responses(&mut cxn);
    assert!(responses[0].starts_with("250-localhost "));
    assert!(responses.contains(&"250-STARTTLS\r\n".to_owned()));
    assert!(responses.last().unwrap().starts_with("250 "));
}

#[test]
fn misc_commands() {
    let setup = set_up();
    let mut cxn = setup.connect("misc_commands");
    skip_pleasantries(&mut cxn, "misc_commands");

    writeln!(cxn, "HELP ME\r").unwrap();
    let responses = read_responses(&mut cxn);
    assert!(responses.last().unwrap().starts_with("214 2.0.0"));

    simple_command(&mut cxn, "VRFY <gäz@localhost>", "252 2.7.0");
    simple_command(&mut cxn, "EXPN <list@localhost>", "550 5.3.3");
    simple_command(&mut cxn, "NOOP", "250 2.0.0");
}

#[test]
fn data_delivery() {
    let setup = set_up();
    let mut cxn = setup.connect("data_delivery");
    skip_pleasantries(&mut cxn, "data_delivery");

    let email_a = "Subject: Email A\r\n\r\nContent A\r\n";
    simple_command(&mut cxn, "MAIL FROM:<tallest@irk>", "250 2.0.0");
    simple_command(&mut cxn, "RCPT TO:<dib@localhost>", "250 2.1.5");
    simple_command(&mut cxn, "RCPT TO:<gäz@localhost>", "250 2.1.5");
    simple_command(&mut cxn, "DATA", "354 ");

    writeln!(cxn, "{}.\r", email_a).unwrap();
    let responses = read_responses(&mut cxn);
    assert_eq!(2, responses.len());
    assert!(responses[0].starts_with("250-2.0.0"));
    assert!(responses[1].starts_with("250 2.0.0"));

    let email_b = "Subject: Email B\r\n\r\nContent B\r\n";
    simple_command(&mut cxn, "MAIL FROM:<>", "250 2.0.0");
    simple_command(&mut cxn, "RCPT TO:<zim@localhost>", "250 2.1.5");
    simple_command(&mut cxn, "DATA", "354 ");

    writeln!(cxn, "{}.\r", email_b).unwrap();
    let responses = read_responses(&mut cxn);
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("250 2.0.0"));

    assert!(received_email(&setup, "dib", email_a));
    assert!(!received_email(&setup, "dib", email_b));
    assert!(received_email(&setup, "gäz", email_a));
    assert!(!received_email(&setup, "gäz", email_b));
    assert!(!received_email(&setup, "zim", email_a));
    assert!(received_email(&setup, "zim", email_b));
}

#[test]
fn bdat_delivery() {
    let setup = set_up();
    let mut cxn = setup.connect("bdat_delivery");
    skip_pleasantries(&mut cxn, "bdat_delivery");

    // Must preserve bare line endings, not do anything with leading ., and
    // must tolerate unterminated final line.
    let email_binary = "Subject: Binary email\r\n\r\n\r\r\n\n\r\n.\r\n.a\r\nx";
    simple_command(&mut cxn, "MAIL FROM:<> BODY=BINARYMIME", "250 2.0.0");
    simple_command(&mut cxn, "RCPT TO:<dib@localhost>", "250 2.1.5");
    let mut count_sent = 0;
    for chunk in email_binary.as_bytes().chunks(8) {
        count_sent += chunk.len();
        writeln!(
            cxn,
            "BDAT {}{}\r",
            chunk.len(),
            if count_sent == email_binary.len() {
                " LAST"
            } else {
                ""
            }
        )
        .unwrap();
        cxn.write_all(chunk).unwrap();

        let responses = read_responses(&mut cxn);
        assert_eq!(1, responses.len());
        assert!(responses[0].starts_with("250 2.0.0"));
    }

    assert!(received_email(&setup, "dib", email_binary));

    // Send another email to ensure the state machine isn't broken
    let email_followup = "Subject: Followup Email\r\n\r\nbinary followup\r\n";
    simple_command(&mut cxn, "MAIL FROM:<>", "250 2.0.0");
    simple_command(&mut cxn, "RCPT TO:<gäz@localhost>", "250 2.1.5");
    simple_command(&mut cxn, "DATA", "354 ");
    writeln!(cxn, "{}.\r", email_followup).unwrap();
    let responses = read_responses(&mut cxn);
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("250 2.0.0"));

    assert!(!received_email(&setup, "dib", email_followup));
    assert!(received_email(&setup, "gäz", email_followup));
}

// This specifically tests that spilled buffers are reset properly when
// delivering to multiple accounts.
#[test]
fn large_delivery() {
    let setup = set_up();
    let mut cxn = setup.connect("large_delivery");
    skip_pleasantries(&mut cxn, "large_delivery");

    let large_content =
        format!("Subject: Large\r\n\r\n{}\r\n", "x".repeat(1024 * 1024));

    simple_command(&mut cxn, "MAIL FROM:<tallest@irk>", "250 2.0.0");
    simple_command(&mut cxn, "RCPT TO:<dib@localhost>", "250 2.1.5");
    simple_command(&mut cxn, "RCPT TO:<gäz@localhost>", "250 2.1.5");
    simple_command(&mut cxn, "DATA", "354 ");

    writeln!(cxn, "{}.\r", large_content).unwrap();
    let responses = read_responses(&mut cxn);
    assert_eq!(2, responses.len());
    assert!(responses[0].starts_with("250-2.0.0"));
    assert!(responses[1].starts_with("250 2.0.0"));

    assert!(received_email(&setup, "dib", &large_content));
    assert!(received_email(&setup, "gäz", &large_content));
}

#[test]
fn huge_message_rejected() {
    let setup = set_up();
    let mut cxn = setup.connect("huge_delivery");
    skip_pleasantries(&mut cxn, "huge_delivery");

    let large_content = format!(
        "Subject: Oversize\r\n\r\n{}\r\n",
        "x".repeat(APPEND_SIZE_LIMIT as usize)
    );

    simple_command(&mut cxn, "MAIL FROM:<tallest@irk>", "250 2.0.0");
    simple_command(&mut cxn, "RCPT TO:<dib@localhost>", "250 2.1.5");
    simple_command(&mut cxn, "RCPT TO:<gäz@localhost>", "250 2.1.5");
    simple_command(&mut cxn, "DATA", "354 ");

    writeln!(cxn, "{}.\r", large_content).unwrap();
    let responses = read_responses(&mut cxn);
    assert_eq!(2, responses.len());
    assert!(responses[0].starts_with("552-5.2.3"));
    assert!(responses[1].starts_with("552 5.2.3"));

    assert!(!received_email(&setup, "dib", &large_content));
    assert!(!received_email(&setup, "gäz", &large_content));
}

#[test]
fn huge_mail_from_size_rejected() {
    let setup = set_up();
    let mut cxn = setup.connect("huge_mail_from");
    skip_pleasantries(&mut cxn, "huge_mail_from");

    simple_command(&mut cxn, "MAIL FROM:<> SIZE=1222333444", "552 5.2.3");
}

#[test]
fn failed_delivery() {
    let setup = set_up();
    let mut cxn = setup.connect("failed_delivery");
    skip_pleasantries(&mut cxn, "failed_delivery");

    let failed_email = "Subject: Failed to deliver to gir\r\n\r\ngir\r\n";

    simple_command(&mut cxn, "MAIL FROM:<tallest@irk>", "250 2.0.0");
    simple_command(&mut cxn, "RCPT TO:<gir@localhost>", "250 2.1.5");
    simple_command(&mut cxn, "RCPT TO:<zim@localhost>", "250 2.1.5");
    simple_command(&mut cxn, "DATA", "354 ");

    // Now, between verifying gir@localhost above and actually receiving the
    // content, something comes along and removes the gir account.
    fs::remove_dir_all(setup.system_dir.path().join("gir")).unwrap();

    writeln!(cxn, "{}.\r", failed_email).unwrap();
    let responses = read_responses(&mut cxn);
    // We still get both responses; the first one indicates failure
    assert_eq!(2, responses.len());
    assert!(responses[0].starts_with("450-"));
    assert!(responses[1].starts_with("250 2.0.0"));

    // The email was still delivered to zim, though
    assert!(received_email(&setup, "zim", failed_email));
}

#[test]
fn failed_rcpt_to() {
    let setup = set_up();
    let mut cxn = setup.connect("failed_rcpt_to");
    skip_pleasantries(&mut cxn, "failed_rcpt_to");

    simple_command(&mut cxn, "MAIL FROM:<>", "250 2.0.0");
    simple_command(&mut cxn, "RCPT TO:<nobody@localhost>", "550 5.1.1");
    simple_command(&mut cxn, "RCPT TO:<..@localhost>", "550 5.1.1");
}

#[test]
fn out_of_order_commands() {
    let setup = set_up();
    let mut cxn = setup.connect("out_of_order_commands");
    read_responses(&mut cxn); // Skip greeting

    // Things that shouldn't work before LHLO
    simple_command(&mut cxn, "MAIL FROM:<>", "503 5.5.1");
    simple_command(&mut cxn, "RCPT TO:<dib@localhost>", "503 5.5.1");
    simple_command(&mut cxn, "DATA", "503 5.5.1");
    // 5 = "foo\r\n".len()
    simple_command(&mut cxn, "BDAT 5\r\nfoo", "503 5.5.1");

    writeln!(cxn, "LHLO out_of_order_commands\r").unwrap();
    let responses = read_responses(&mut cxn);
    assert!(responses.last().unwrap().starts_with("250 "));

    // LHLO not allowed after LHLO
    simple_command(&mut cxn, "LHLO out_of_order_commands", "503 5.5.1");

    // Things that shouldn't work before MAIL FROM
    simple_command(&mut cxn, "RCPT TO:<dib@localhost>", "503 5.5.1");
    simple_command(&mut cxn, "DATA", "503 5.5.1");
    simple_command(&mut cxn, "BDAT 5\r\nfoo", "503 5.5.1");

    simple_command(&mut cxn, "MAIL FROM:<>", "250 2.0.0");
    simple_command(&mut cxn, "MAIL FROM:<>", "503 5.5.1");

    // DATA and BDAT don't work without recipients
    simple_command(&mut cxn, "DATA", "503 5.5.1");
    simple_command(&mut cxn, "BDAT 5\r\nfoo", "503 5.5.1");

    // Finish up and send an email to ensure that the data we sent through BDAT
    // didn't stay in the buffer.
    let ooo_email = "Subject: Out of order\r\n\r\n";
    // If any BDAT chunks were improperly saved, they manifest as a prefix on
    // the email we're sending now
    let unexpected_email = format!("foo\r\n{}", ooo_email);

    simple_command(&mut cxn, "RCPT TO:<dib@localhost>", "250 2.1.5");
    simple_command(&mut cxn, "DATA", "354 ");
    writeln!(cxn, "{}.\r", ooo_email).unwrap();
    let responses = read_responses(&mut cxn);
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("250 2.0.0"));

    assert!(received_email(&setup, "dib", ooo_email));
    assert!(!received_email(&setup, "dib", &unexpected_email));

    simple_command(&mut cxn, "MAIL FROM:<>", "250 2.0.0");
    simple_command(&mut cxn, "RCPT TO:<dib@localhost>", "250 2.1.5");
    simple_command(&mut cxn, "BDAT 5\r\nfoo", "250 2.0.0");
    // Things not allowed after BDAT
    simple_command(&mut cxn, "RCPT TO:<gäz@localhost>", "503 5.5.1");
    simple_command(&mut cxn, "DATA", "503 5.5.1");

    // RSET resets everything
    simple_command(&mut cxn, "RSET", "250 2.0.0");
    simple_command(&mut cxn, "MAIL FROM:<>", "250 2.0.0");
    simple_command(&mut cxn, "RCPT TO:<dib@localhost>", "250 2.1.5");
    simple_command(&mut cxn, "DATA", "354 ");
    writeln!(cxn, "{}.\r", ooo_email).unwrap();
    let responses = read_responses(&mut cxn);
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("250 2.0.0"));

    // Ensure the BDAT above wasn't saved.
    assert!(!received_email(&setup, "dib", &unexpected_email));
}

#[test]
fn start_tls() {
    let setup = set_up();
    let mut cxn = setup.connect("starttls");
    skip_pleasantries(&mut cxn, "starttls");

    simple_command(&mut cxn, "STARTTLS", "220 2.0.0");

    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_verify(SslVerifyMode::NONE);

    let mut cxn = connector
        .build()
        .connect("localhost", cxn)
        .map_err(|_| "SSL handshake failed")
        .unwrap();
    // Sleep briefly to ensure the async code has a chance to observe a stall.
    std::thread::sleep(std::time::Duration::from_millis(100));
    skip_pleasantries(&mut cxn, "starttls");

    let tls_email = "Subject: TLS\r\n\r\nThis message was sent over TLS.\r\n";
    simple_command(&mut cxn, "MAIL FROM:<>", "250 2.0.0");
    simple_command(&mut cxn, "RCPT TO:<dib@localhost>", "250 2.1.5");
    simple_command(&mut cxn, "DATA", "354 ");
    writeln!(cxn, "{}.\r", tls_email).unwrap();
    let responses = read_responses(&mut cxn);
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("250 2.0.0"));

    assert!(received_email(&setup, "dib", tls_email));
}
