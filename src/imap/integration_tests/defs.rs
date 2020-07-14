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

use std::borrow::Cow;
use std::fs;
use std::io;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Weak};

use lazy_static::lazy_static;
use regex::bytes::Regex;
use tempfile::TempDir;

use crate::account::account::Account;
use crate::crypt::master_key::MasterKey;
use crate::imap::client::Client;
use crate::imap::command_processor::CommandProcessor;
use crate::imap::server::Server;
use crate::support::system_config::*;
use crate::test_data::*;

pub(super) use crate::imap::syntax as s;

lazy_static! {
    static ref SYSTEM_DIR: Mutex<Weak<TempDir>> = Mutex::new(Weak::new());
}

#[derive(Clone, Debug)]
pub struct Setup {
    system_dir: Arc<TempDir>,
}

pub fn set_up() -> Setup {
    crate::init_test_log();

    let mut lock = SYSTEM_DIR.lock().unwrap();

    if let Some(system_dir) = lock.upgrade() {
        return Setup { system_dir };
    }

    let system_dir = Arc::new(TempDir::new().unwrap());
    let user_dir = system_dir.path().join("azure");
    fs::create_dir(&user_dir).unwrap();

    let account = Account::new(
        "initial-setup".to_owned(),
        user_dir,
        Some(Arc::new(MasterKey::new())),
    );
    account.provision(b"hunter2").unwrap();

    *lock = Arc::downgrade(&system_dir);

    Setup { system_dir }
}

pub type PipeClient =
    Client<io::BufReader<os_pipe::PipeReader>, os_pipe::PipeWriter>;

impl Setup {
    pub fn connect(&self, name: &'static str) -> PipeClient {
        let (server_in, client_out) = os_pipe::pipe().unwrap();
        let (client_in, server_out) = os_pipe::pipe().unwrap();
        // We don't want the server thread to hold on to the TempDir since the
        // test process can exit before the last server thread notices the EOF
        // and terminates.
        let data_root: PathBuf = self.system_dir.path().to_owned();

        std::thread::spawn(move || {
            let processor = CommandProcessor::new(
                name.to_owned(),
                Arc::new(SystemConfig {
                    security: SecurityConfig::default(),
                    tls: TlsConfig {
                        private_key: PathBuf::new(),
                        certificate_chain: PathBuf::new(),
                    },
                }),
                data_root,
            );
            let mut server = Server::new(
                io::BufReader::new(server_in),
                io::BufWriter::new(server_out),
                processor,
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

        Client::new(io::BufReader::new(client_in), client_out, Some(name))
    }
}

pub fn receive_line_like(client: &mut PipeClient, pat: &str) {
    let mut buf = Vec::new();
    client.read_logical_line(&mut buf).unwrap();
    assert!(
        Regex::new(pat).unwrap().is_match(&buf),
        "Expected\n\
         match: {:?}\n\
         Got:   {:?}\n",
        pat,
        String::from_utf8_lossy(&buf)
    );
}

pub fn skip_greeting(client: &mut PipeClient) {
    let mut buf = Vec::new();
    client.read_one_response(&mut buf).unwrap();
}

pub fn quick_log_in(client: &mut PipeClient) {
    let mut buf = Vec::new();
    client.read_one_response(&mut buf).unwrap();
    buf.clear();

    let responses = client
        .command(
            s::Command::LogIn(s::LogInCommand {
                userid: Cow::Borrowed("azure"),
                password: Cow::Borrowed("hunter2"),
            }),
            &mut buf,
        )
        .unwrap();

    assert_eq!(1, responses.len());
}

pub fn quick_create(client: &mut PipeClient, mailbox: &str) {
    ok_command!(
        client,
        s::Command::Create(s::CreateCommand {
            mailbox: Cow::Borrowed(mailbox),
        })
    );
}

pub fn quick_append_enron(
    client: &mut PipeClient,
    mailbox: &str,
    num_messages: usize,
) {
    for &message in &ENRON_SMALL_MULTIPARTS[..num_messages] {
        client
            .start_append(
                mailbox,
                s::AppendFragment {
                    flags: None,
                    internal_date: None,
                    _marker: PhantomData,
                },
                message,
            )
            .unwrap();

        let mut buffer = Vec::new();
        let mut responses = client.finish_append(&mut buffer).unwrap();
        assert_tagged_ok(responses.pop().unwrap());
    }
}

pub fn quick_select(client: &mut PipeClient, mailbox: &str) {
    ok_command!(
        client,
        s::Command::Select(s::SelectCommand {
            mailbox: Cow::Borrowed(mailbox),
        })
    );
}

pub fn assert_tagged_ok(r: s::ResponseLine<'_>) {
    assert_matches!(
        s::ResponseLine {
            tag: Some(_),
            response: s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::Ok,
                code: None,
                quip: _,
            }),
        }, r);
}

pub fn assert_tagged_ok_any(r: s::ResponseLine<'_>) {
    assert_matches!(
        s::ResponseLine {
            tag: Some(_),
            response: s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::Ok,
                code: _,
                quip: _,
            }),
        }, r);
}

pub fn assert_tagged_no(r: s::ResponseLine<'_>) {
    assert_matches!(
        s::ResponseLine {
            tag: Some(_),
            response: s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::No,
                code: None,
                quip: _,
            }),
        }, r);
}

pub fn c(s: &'static str) -> s::Command<'static> {
    match s::Command::parse(s.as_bytes()) {
        Ok((b"", command)) => command,
        _ => panic!("Bad command: {}", s),
    }
}
