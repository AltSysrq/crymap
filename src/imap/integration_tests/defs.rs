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

use std::borrow::Cow;
use std::fs;
use std::io;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Weak};

use chrono::prelude::*;
use lazy_static::lazy_static;
use regex::bytes::Regex;
use tempfile::TempDir;

use crate::test_data::*;
use crate::{
    account::{model::Flag, v2::Account},
    crypt::master_key::MasterKey,
    imap::{
        client::Client, command_processor::CommandProcessor,
        literal_source::LiteralSource, mailbox_name::MailboxName,
    },
    support::{
        async_io::ServerIo, chronox::*, error::Error, log_prefix::LogPrefix,
        system_config::*,
    },
};

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

    let setup = set_up_new_root();
    *lock = Arc::downgrade(&setup.system_dir);
    setup
}

pub fn set_up_new_root() -> Setup {
    let system_dir = Arc::new(TempDir::new().unwrap());
    let user_dir = system_dir.path().join("azure");
    fs::create_dir(&user_dir).unwrap();

    let mut account = Account::new(
        LogPrefix::new("initial-setup".to_owned()),
        user_dir,
        Arc::new(MasterKey::new()),
    )
    .unwrap();
    account.provision(b"hunter2").unwrap();

    Setup { system_dir }
}

pub type PipeClient = Client<io::BufReader<UnixStream>, UnixStream>;

impl Setup {
    pub fn connect(&self, name: &'static str) -> PipeClient {
        // These streams are really bidirectional, but it's simpler to keep
        // them separate.
        let (server_in, client_out) = UnixStream::pair().unwrap();
        let (client_in, server_out) = UnixStream::pair().unwrap();
        // We don't want the server thread to hold on to the TempDir since the
        // test process can exit before the last server thread notices the EOF
        // and terminates.
        let data_root: PathBuf = self.system_dir.path().to_owned();

        std::thread::spawn(move || {
            run_imap_server(name, data_root, server_in, server_out);
        });

        Client::new(io::BufReader::new(client_in), client_out, Some(name))
    }
}

#[tokio::main(flavor = "current_thread")]
async fn run_imap_server(
    name: &'static str,
    data_root: PathBuf,
    server_in: UnixStream,
    server_out: UnixStream,
) {
    let processor = CommandProcessor::new(
        LogPrefix::new(name.to_owned()),
        Arc::new(SystemConfig {
            smtp: SmtpConfig {
                host_name: "mx.example.com".to_owned(),
                ..Default::default()
            },
            ..Default::default()
        }),
        data_root,
        None,
    );
    let io = ServerIo::new_owned_pair(server_in, server_out).unwrap();
    crate::imap::server::run(io, processor).await;
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

    // Disable flags responses by default to prevent test cross-talk.
    ok_command!(client, s::Command::Simple(s::SimpleCommand::XCryFlagsOff));
}

pub fn quick_create(client: &mut PipeClient, mailbox: &str) {
    ok_command!(
        client,
        s::Command::Create(s::CreateCommand {
            mailbox: MailboxName::of_wire(Cow::Borrowed(mailbox)),
            special_use: None,
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
            .start_append(mailbox, s::AppendFragment::default(), message)
            .unwrap();

        let mut buffer = Vec::new();
        let mut responses = client.finish_append(&mut buffer).unwrap();
        assert_tagged_ok_any(responses.pop().unwrap());
    }
}

pub fn quick_select(client: &mut PipeClient, mailbox: &str) {
    ok_command!(
        client,
        s::Command::Select(s::SelectCommand {
            mailbox: MailboxName::of_wire(Cow::Borrowed(mailbox)),
            modifiers: None,
        })
    );
}

/// Causes the client to EXAMINE a particular mailbox which is shared among a
/// number of read-only tests.
///
/// The content of the mailbox is similar to the `account::mailbox::search`
/// unit tests:
/// - UID 1 is the CHRISTMAS_TREE test message
/// - UID 2 is the TORTURE_TEST test message
/// - UIDs 3 through 22 are the ENRON_SMALL_MULTIPARTS messages
/// - UIDs 8 through 22 are \Recent
/// - UID 1 is \Answered
/// - UID 2 is \Deleted
/// - UID 3 is \Draft
/// - UID 4 is \Flagged
/// - UID 5 is \Seen
/// - UID 6 has been expunged
/// - UID 7 is $Important
/// - UID 22 is \Seen (so that there is a \Seen \Recent message)
///
/// The INTERNALDATE of each message is midnight UTC on 2020-01-$uid.
pub fn examine_shared(client: &mut PipeClient) {
    lazy_static! {
        static ref MUTEX: Mutex<()> = Mutex::new(());
    }

    const MBOX: &str = "shared";

    let _lock = MUTEX.lock().unwrap();

    command!(mut responses = client, c("EXAMINE shared"));
    unpack_cond_response! {
        (Some(_), cond, _, _) = responses.pop().unwrap() => {
            if s::RespCondType::Ok == cond {
                return;
            }
        }
    };

    quick_create(client, MBOX);
    quick_select(client, MBOX);

    fn internal_date_for_uid(uid: u32) -> Option<DateTime<FixedOffset>> {
        Some(FixedOffset::zero().ymd_hmsx(2020, 1, uid, 0, 0, 0))
    }

    macro_rules! append {
        ($uid:expr, $flags:expr, $message:expr) => {{
            client
                .start_append(
                    MBOX,
                    s::AppendFragment {
                        flags: $flags,
                        internal_date: internal_date_for_uid($uid),
                        ..s::AppendFragment::default()
                    },
                    $message,
                )
                .unwrap();
            let mut buffer = Vec::new();
            let mut responses = client.finish_append(&mut buffer).unwrap();
            assert_tagged_ok_any(responses.pop().unwrap());
        }};
    }

    append!(1, Some(vec![Flag::Answered]), CHRISTMAS_TREE);
    append!(2, Some(vec![Flag::Deleted]), TORTURE_TEST);
    append!(3, Some(vec![Flag::Draft]), ENRON_SMALL_MULTIPARTS[0]);
    append!(4, Some(vec![Flag::Flagged]), ENRON_SMALL_MULTIPARTS[1]);
    append!(5, Some(vec![Flag::Seen]), ENRON_SMALL_MULTIPARTS[2]);
    append!(6, None, ENRON_SMALL_MULTIPARTS[3]);
    ok_command!(client, c("XVANQUISH 6"));
    append!(
        7,
        Some(vec![Flag::Keyword("$Important".to_owned())]),
        ENRON_SMALL_MULTIPARTS[4]
    );

    // Switch to EXAMINE so the remainder of the messages are \Recent for
    // future sessions
    ok_command!(client, c("EXAMINE shared"));

    for i in 5u32..20 {
        append!(
            i + 3,
            if 19 == i {
                Some(vec![Flag::Seen])
            } else {
                None
            },
            ENRON_SMALL_MULTIPARTS[i as usize]
        );
    }
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
        },
        r
    );
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
        },
        r
    );
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
        },
        r
    );
}

pub fn assert_error_response(
    response: s::ResponseLine<'_>,
    expected_code: Option<s::RespTextCode<'_>>,
    error: Error,
) {
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, code, Some(quip)) = response => {
            assert_eq!(expected_code, code);
            assert_eq!(error.to_string(), quip);
        }
    };
}

pub fn c(s: &'static str) -> s::Command<'static> {
    cb(s)
}

pub fn cb<'a>(s: &'a str) -> s::Command<'a> {
    match s::Command::parse(s.as_bytes()) {
        Ok((b"", command)) => command,
        _ => panic!("Bad command: {}", s),
    }
}

pub fn r(s: &'static str) -> s::Response<'static> {
    match s::Response::parse(s.as_bytes()) {
        Ok((b"", response)) => response,
        _ => panic!("Bad response: {}", s),
    }
}

pub fn test_require_capability(client_name: &'static str, capability: &str) {
    let setup = set_up();
    let mut client = setup.connect(client_name);

    let mut buffer = Vec::new();
    let response = client.read_one_response(&mut buffer).unwrap();
    unpack_cond_response! {
        (None, s::RespCondType::Ok, Some(s::RespTextCode::Capability(caps)), _)
            = response
        => {
            assert!(caps.capabilities.contains(&Cow::Borrowed(capability)));
        }
    }
}

pub fn list_results_to_str(lines: Vec<s::ResponseLine<'_>>) -> String {
    let mut ret = String::new();
    for line in lines {
        match line {
            s::ResponseLine {
                tag: None,
                response: s::Response::List(mut ml),
            } => {
                ml.flags.sort();
                ret.push_str(&ml.name.raw);
                for flag in ml.flags {
                    ret.push(' ');
                    ret.push_str(&flag);
                }

                if let Some(child_info) = ml.child_info {
                    ret.push_str(" CHILDINFO");
                    for info in child_info {
                        ret.push(' ');
                        ret.push_str(&info);
                    }
                }

                ret.push('\n');
            },

            line => panic!("Unexpected response line: {:?}", line),
        }
    }

    ret
}

pub fn lsub_results_to_str(lines: Vec<s::ResponseLine<'_>>) -> String {
    let mut ret = String::new();
    for line in lines {
        match line {
            s::ResponseLine {
                tag: None,
                response:
                    s::Response::Lsub(s::MailboxList {
                        mut flags, name, ..
                    }),
            } => {
                flags.sort();
                ret.push_str(&name.raw);
                for flag in flags {
                    ret.push(' ');
                    ret.push_str(&flag);
                }
                ret.push('\n');
            },

            line => panic!("Unexpected response line: {:?}", line),
        }
    }

    ret
}

pub fn assert_bad_command(
    client: &mut PipeClient,
    code: Option<s::RespTextCode<'_>>,
    command: &str,
) {
    command!(mut responses = client, cb(command));
    unpack_cond_response! {
        (Some(_), s::RespCondType::Bad, c, _) = responses.pop().unwrap() => {
            assert_eq!(code, c);
        }
    };
}

pub fn assert_literal_like(
    start: &[u8],
    end: &[u8],
    len: u64,
    binary: bool,
    mut lit: LiteralSource,
) {
    if 0 != len {
        assert_eq!(len, lit.len);
    }
    assert_eq!(binary, lit.binary);

    let mut data = Vec::<u8>::new();
    lit.data.read_to_end(&mut data).unwrap();
    if 0 != len {
        assert_eq!(len as usize, data.len());
    }
    assert_eq!(lit.len as usize, data.len());
    assert!(
        data.starts_with(start),
        "Data didn't have expected prefix; got:\n{}",
        String::from_utf8_lossy(&data)
    );
    assert!(
        data.ends_with(end),
        "Data didn't have expected end; got:\n{}",
        String::from_utf8_lossy(&data)
    );
}
