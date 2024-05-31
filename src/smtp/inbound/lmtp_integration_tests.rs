//-
// Copyright (c) 2020, 2023, 2024, Jason Lingle
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
use std::io::{self, Read};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Weak};

use lazy_static::lazy_static;
use rayon::prelude::*;
use tempfile::TempDir;

use super::integration_test_common::*;
use crate::{
    account::{model::Uid, v2::Account},
    crypt::master_key::MasterKey,
    support::{
        append_limit::APPEND_SIZE_LIMIT, async_io::ServerIo, error::Error,
        log_prefix::LogPrefix, system_config::SystemConfig,
    },
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

impl Setup {
    fn connect(&self, cxn_name: &'static str) -> SmtpClient {
        let (server_io, client_io) = UnixStream::pair().unwrap();
        // We don't want the server thread to hold on to the TempDir since the
        // test process can exit before the last server thread notices the EOF
        // and terminates.
        let data_root: PathBuf = self.system_dir.path().to_owned();

        std::thread::spawn(move || run_server(data_root, cxn_name, server_io));

        SmtpClient::new(cxn_name, client_io)
    }
}

#[tokio::main(flavor = "current_thread")]
async fn run_server(data_root: PathBuf, cxn_name: &str, server_io: UnixStream) {
    let server_io = ServerIo::new_owned_socket(server_io).unwrap();
    let result = super::serve_lmtp(
        server_io,
        Arc::new(SystemConfig::default()),
        LogPrefix::new(cxn_name.to_owned()),
        ssl_acceptor(),
        data_root,
        "localhost".to_owned(),
        cxn_name.to_owned(),
    )
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

    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(
        responses[0].starts_with("220 localhost"),
        "Unexpected greeting: {}",
        responses[0]
    );

    cxn.write_line("QUIT\r\n");

    let responses = cxn.read_responses();
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

    cxn.read_responses();

    cxn.write_line("LHLO test_lhlo\r\n");

    let responses = cxn.read_responses();
    assert!(responses[0].starts_with("250-localhost "));
    assert!(responses.contains(&"250-STARTTLS\r\n".to_owned()));
    assert!(responses.last().unwrap().starts_with("250 "));
}

#[test]
fn misc_commands() {
    let setup = set_up();
    let mut cxn = setup.connect("misc_commands");
    cxn.skip_pleasantries("LHLO misc_commands");

    cxn.write_line("HELP ME\r\n");
    let responses = cxn.read_responses();
    assert!(responses.last().unwrap().starts_with("214 2.0.0"));

    cxn.simple_command("VRFY <gäz@localhost>", "252 2.7.0");
    cxn.simple_command("EXPN <list@localhost>", "550 5.3.3");
    cxn.simple_command("NOOP", "250 2.0.0");
}

#[test]
fn data_delivery() {
    let setup = set_up();
    let mut cxn = setup.connect("data_delivery");
    cxn.skip_pleasantries("LHLO data_delivery");

    let email_a = "Subject: Email A\r\n\r\nContent A\r\n";
    cxn.simple_command("MAIL FROM:<tallest@irk>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<dib@localhost>", "250 2.1.5");
    cxn.simple_command("RCPT TO:<gäz@localhost>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");

    cxn.write_line(&format!("{}.\r\n", email_a));
    let responses = cxn.read_responses();
    assert_eq!(2, responses.len());
    assert!(responses[0].starts_with("250-2.0.0"));
    assert!(responses[1].starts_with("250 2.0.0"));

    let email_b = "Subject: Email B\r\n\r\nContent B\r\n";
    cxn.simple_command("MAIL FROM:<>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<zim@localhost>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");

    cxn.write_line(&format!("{}.\r\n", email_b));
    let responses = cxn.read_responses();
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
fn data_delivery_from_unix_client() {
    let setup = set_up();
    let mut cxn = setup.connect("unix_unix_data_delivery");
    cxn.skip_pleasantries("LHLO unix_unix_data_delivery");

    let email_a = "Subject: Unix email from Unix client\r\n\r\nContent A\r\n";
    cxn.unix_simple_command("MAIL FROM:<tallest@irk>", "250 2.0.0");
    cxn.unix_simple_command("RCPT TO:<dib@localhost>", "250 2.1.5");
    cxn.unix_simple_command("DATA", "354 ");
    cxn.write_line(&format!("{}.\n", &email_a.replace("\r\n", "\n")));
    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());

    let email_b = "Subject: DOS email from UNIX client\r\n\r\nContent B\r\n";
    cxn.unix_simple_command("MAIL FROM:<tallest@irk>", "250 2.0.0");
    cxn.unix_simple_command("RCPT TO:<dib@localhost>", "250 2.1.5");
    cxn.unix_simple_command("DATA", "354 ");
    cxn.write_line(&format!("{}.\n", &email_b));
    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());

    assert!(received_email(&setup, "dib", email_a));
    assert!(received_email(&setup, "dib", email_b));
}

#[test]
fn unix_data_delivery_from_dos_client() {
    let setup = set_up();
    let mut cxn = setup.connect("unix_dos_data_delivery");
    cxn.skip_pleasantries("LHLO unix_dos_data_delivery");

    let email_a = "Subject: Unix message from DOS client\r\n\r\nContent A\r\n";
    cxn.simple_command("MAIL FROM:<tallest@irk>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<dib@localhost>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");

    cxn.write_line(&format!("{}.\r\n", &email_a.replace("\r\n", "\n")));
    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());

    assert!(received_email(&setup, "dib", email_a));
}

#[test]
fn bdat_delivery() {
    let setup = set_up();
    let mut cxn = setup.connect("bdat_delivery");
    cxn.skip_pleasantries("LHLO bdat_delivery");

    // Must preserve bare line endings, not do anything with leading ., and
    // must tolerate unterminated final line.
    let email_binary = "Subject: Binary email\r\n\r\n\r\r\n\n\r\n.\r\n.a\r\nx";
    cxn.simple_command("MAIL FROM:<> BODY=BINARYMIME", "250 2.0.0");
    cxn.simple_command("RCPT TO:<dib@localhost>", "250 2.1.5");
    let mut count_sent = 0;
    for chunk in email_binary.as_bytes().chunks(8) {
        count_sent += chunk.len();
        cxn.write_line(&format!(
            "BDAT {}{}\r\n",
            chunk.len(),
            if count_sent == email_binary.len() {
                " LAST"
            } else {
                ""
            }
        ));
        cxn.write_raw(chunk);

        let responses = cxn.read_responses();
        assert_eq!(1, responses.len());
        assert!(responses[0].starts_with("250 2.0.0"));
    }

    assert!(received_email(&setup, "dib", email_binary));

    // Send another email to ensure the state machine isn't broken
    let email_followup = "Subject: Followup Email\r\n\r\nbinary followup\r\n";
    cxn.simple_command("MAIL FROM:<>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<gäz@localhost>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");
    cxn.write_line(&format!("{}.\r\n", email_followup));
    let responses = cxn.read_responses();
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
    cxn.skip_pleasantries("LHLO large_delivery");

    let large_content =
        format!("Subject: Large\r\n\r\n{}\r\n", "x".repeat(1024 * 1024));

    cxn.simple_command("MAIL FROM:<tallest@irk>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<dib@localhost>", "250 2.1.5");
    cxn.simple_command("RCPT TO:<gäz@localhost>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");

    cxn.write_line(&format!("{}.\r\n", large_content));
    let responses = cxn.read_responses();
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
    cxn.skip_pleasantries("LHLO huge_delivery");

    let large_content = format!(
        "Subject: Oversize\r\n\r\n{}\r\n",
        "x".repeat(APPEND_SIZE_LIMIT as usize)
    );

    cxn.simple_command("MAIL FROM:<tallest@irk>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<dib@localhost>", "250 2.1.5");
    cxn.simple_command("RCPT TO:<gäz@localhost>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");

    cxn.write_line(&format!("{}.\r\n", large_content));
    let responses = cxn.read_responses();
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
    cxn.skip_pleasantries("LHLO huge_mail_from");

    cxn.simple_command("MAIL FROM:<> SIZE=1222333444", "552 5.2.3");
}

#[test]
fn failed_delivery() {
    let setup = set_up();
    let mut cxn = setup.connect("failed_delivery");
    cxn.skip_pleasantries("LHLO failed_delivery");

    let failed_email = "Subject: Failed to deliver to gir\r\n\r\ngir\r\n";

    cxn.simple_command("MAIL FROM:<tallest@irk>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<gir@localhost>", "250 2.1.5");
    cxn.simple_command("RCPT TO:<zim@localhost>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");

    // Now, between verifying gir@localhost above and actually receiving the
    // content, something comes along and removes the gir account.
    fs::remove_dir_all(setup.system_dir.path().join("gir")).unwrap();

    cxn.write_line(&format!("{}.\r\n", failed_email));
    let responses = cxn.read_responses();
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
    cxn.skip_pleasantries("LHLO failed_rcpt_to");

    cxn.simple_command("MAIL FROM:<>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<nobody@localhost>", "550 5.1.1");
    cxn.simple_command("RCPT TO:<..@localhost>", "550 5.1.1");
}

#[test]
fn out_of_order_commands() {
    let setup = set_up();
    let mut cxn = setup.connect("out_of_order_commands");
    cxn.read_responses(); // Skip greeting

    // Things that shouldn't work before LHLO
    cxn.simple_command("MAIL FROM:<>", "503 5.5.1");
    cxn.simple_command("RCPT TO:<dib@localhost>", "503 5.5.1");
    cxn.simple_command("DATA", "503 5.5.1");
    // 5 = "foo\r\n".len()
    cxn.simple_command("BDAT 5\r\nfoo", "503 5.5.1");

    cxn.write_line("LHLO out_of_order_commands\r\n");
    let responses = cxn.read_responses();
    assert!(responses.last().unwrap().starts_with("250 "));

    // LHLO not allowed after LHLO
    cxn.simple_command("LHLO out_of_order_commands", "503 5.5.1");

    // Things that shouldn't work before MAIL FROM
    cxn.simple_command("RCPT TO:<dib@localhost>", "503 5.5.1");
    cxn.simple_command("DATA", "503 5.5.1");
    cxn.simple_command("BDAT 5\r\nfoo", "503 5.5.1");

    cxn.simple_command("MAIL FROM:<>", "250 2.0.0");
    cxn.simple_command("MAIL FROM:<>", "503 5.5.1");

    // DATA and BDAT don't work without recipients
    cxn.simple_command("DATA", "503 5.5.1");
    cxn.simple_command("BDAT 5\r\nfoo", "503 5.5.1");

    // Finish up and send an email to ensure that the data we sent through BDAT
    // didn't stay in the buffer.
    let ooo_email = "Subject: Out of order\r\n\r\n";
    // If any BDAT chunks were improperly saved, they manifest as a prefix on
    // the email we're sending now
    let unexpected_email = format!("foo\r\n{}", ooo_email);

    cxn.simple_command("RCPT TO:<dib@localhost>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");
    cxn.write_line(&format!("{}.\r\n", ooo_email));
    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("250 2.0.0"));

    assert!(received_email(&setup, "dib", ooo_email));
    assert!(!received_email(&setup, "dib", &unexpected_email));

    cxn.simple_command("MAIL FROM:<>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<dib@localhost>", "250 2.1.5");
    cxn.simple_command("BDAT 5\r\nfoo", "250 2.0.0");
    // Things not allowed after BDAT
    cxn.simple_command("RCPT TO:<gäz@localhost>", "503 5.5.1");
    cxn.simple_command("DATA", "503 5.5.1");

    // RSET resets everything
    cxn.simple_command("RSET", "250 2.0.0");
    cxn.simple_command("MAIL FROM:<>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<dib@localhost>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");
    cxn.write_line(&format!("{}.\r\n", ooo_email));
    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("250 2.0.0"));

    // Ensure the BDAT above wasn't saved.
    assert!(!received_email(&setup, "dib", &unexpected_email));
}

#[test]
fn start_tls() {
    let setup = set_up();
    let mut cxn = setup.connect("starttls");
    cxn.skip_pleasantries("LHLO starttls");

    cxn.simple_command("STARTTLS", "220 2.0.0");
    cxn.start_tls();

    // Sleep briefly to ensure the async code has a chance to observe a stall.
    std::thread::sleep(std::time::Duration::from_millis(100));
    cxn.write_line("LHLO starttls\r\n");
    let responses = cxn.read_responses();
    assert!(responses.last().unwrap().starts_with("250 "));

    let tls_email = "Subject: TLS\r\n\r\nThis message was sent over TLS.\r\n";
    cxn.simple_command("MAIL FROM:<>", "250 2.0.0");
    cxn.simple_command("RCPT TO:<dib@localhost>", "250 2.1.5");
    cxn.simple_command("DATA", "354 ");
    cxn.write_line(&format!("{}.\r\n", tls_email));
    let responses = cxn.read_responses();
    assert_eq!(1, responses.len());
    assert!(responses[0].starts_with("250 2.0.0"));

    assert!(received_email(&setup, "dib", tls_email));
}
