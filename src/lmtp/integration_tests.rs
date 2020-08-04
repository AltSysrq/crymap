//-
// Copyright (c) 2020, Jason Lingle
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
    ssl::{SslAcceptor, SslMethod},
    x509,
};
use rayon::prelude::*;
use tempfile::TempDir;

use super::server::*;
use crate::account::account::Account;
use crate::account::model::Uid;
use crate::crypt::master_key::MasterKey;
use crate::support::error::Error;
use crate::support::rcio::RcIo;
use crate::support::system_config::SystemConfig;

// Similar to the IMAP integration tests, we share a system directory between
// the tests since accounts are expensive to set up, and the sharing works as
// long as the tests are run concurrently.
//
// The test system has three user accounts: dib, gäz, and zim. One extra,
// "gir", is created initially but is destroyed by one of the tests.
lazy_static! {
    static ref SYSTEM_DIR: Mutex<Weak<TempDir>> = Mutex::new(Weak::new());
}

#[derive(Clone, Debug)]
struct Setup {
    system_dir: Arc<TempDir>,
}

fn set_up() -> Setup {
    crate::init_test_log();

    let mut lock = SYSTEM_DIR.lock().unwrap();

    if let Some(system_dir) = lock.upgrade() {
        return Setup { system_dir };
    }

    let setup = set_up_new_root();
    *lock = Arc::downgrade(&setup.system_dir);
    setup
}

fn set_up_new_root() -> Setup {
    let system_dir = Arc::new(TempDir::new().unwrap());

    vec!["dib", "gäz", "zim", "gir"]
        .into_par_iter()
        .for_each(|user_name| {
            let user_dir = system_dir.path().join(user_name);
            fs::create_dir(&user_dir).unwrap();

            let account = Account::new(
                "initial-setup".to_owned(),
                user_dir,
                Some(Arc::new(MasterKey::new())),
            );
            account.provision(b"hunter2").unwrap();
        });

    Setup { system_dir }
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
                openssl::hash::MessageDigest::sha3_256(),
            )
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

        std::thread::spawn(move || {
            let server_io = RcIo::wrap(server_io);
            let mut ssl_acceptor =
                SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
                    .unwrap();
            ssl_acceptor
                .set_private_key(&CERTIFICATE_PRIVATE_KEY)
                .unwrap();
            ssl_acceptor.set_certificate(&CERTIFICATE).unwrap();

            let ssl_acceptor = ssl_acceptor.build();

            let mut server = Server::new(
                Box::new(io::BufReader::new(server_io.clone())),
                Box::new(server_io),
                Arc::new(SystemConfig::default()),
                cxn_name.to_owned(),
                ssl_acceptor,
                data_root,
                "localhost".to_owned(),
                cxn_name.to_owned(),
            );

            match server.run() {
                Ok(()) => (),
                Err(crate::support::error::Error::Io(e))
                    if io::ErrorKind::UnexpectedEof == e.kind()
                        || Some(nix::libc::EPIPE) == e.raw_os_error() =>
                {
                    ()
                }
                Err(e) => panic!("Unexpected server error: {}", e),
            }
        });

        client_io
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
    let account = Account::new(
        "verify".to_owned(),
        setup.system_dir.path().join(account_name),
        None,
    );
    let config = account.load_config().unwrap();
    let master_key =
        MasterKey::from_config(&config.master_key, b"hunter2").unwrap();

    let account = Account::new(
        "verify".to_owned(),
        setup.system_dir.path().join(account_name),
        Some(Arc::new(master_key)),
    );

    let mailbox = account.mailbox("INBOX", true).unwrap();
    // Messages are always delivered one at a time, so we can just do linear
    // probing until we hit a non-existent UID.
    for uid in 1.. {
        let mut r = match mailbox.open_message(Uid::u(uid)) {
            Ok((_, r)) => r,
            Err(Error::NxMessage)
            | Err(Error::UnaddressableMessage)
            | Err(Error::ExpungedMessage) => return false,
            Err(e) => panic!("Unexpected error: {}", e),
        };

        let mut data = Vec::new();
        r.read_to_end(&mut data).unwrap();

        if data.ends_with(email.as_bytes()) {
            return true;
        }
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
