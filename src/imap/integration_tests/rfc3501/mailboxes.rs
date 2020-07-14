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

use super::super::defs::*;
use crate::support::error::Error;

fn list_results_to_str(lines: Vec<s::ResponseLine<'_>>) -> String {
    let mut ret = String::new();
    for line in lines {
        match line {
            s::ResponseLine {
                tag: None,
                response: s::Response::List(s::MailboxList { flags, name }),
            } => {
                ret.push_str(&name);
                for flag in flags {
                    ret.push(' ');
                    ret.push_str(&flag);
                }
                ret.push('\n');
            }

            line => panic!("Unexpected response line: {:?}", line),
        }
    }

    ret
}

fn lsub_results_to_str(lines: Vec<s::ResponseLine<'_>>) -> String {
    let mut ret = String::new();
    for line in lines {
        match line {
            s::ResponseLine {
                tag: None,
                response: s::Response::Lsub(s::MailboxList { flags, name }),
            } => {
                ret.push_str(&name);
                for flag in flags {
                    ret.push(' ');
                    ret.push_str(&flag);
                }
                ret.push('\n');
            }

            line => panic!("Unexpected response line: {:?}", line),
        }
    }

    ret
}

#[test]
fn mailbox_management() {
    let setup = set_up();
    let mut client = setup.connect("3501mbmm");
    quick_log_in(&mut client);

    ok_command!(client, c("CREATE 3501mbmm/noselect/foo"));
    ok_command!(client, c("CREATE 3501mbmm/parent/bar"));

    command!(mut responses = client,
             c("LIST \"\" 3501mbmm/*"));
    assert_tagged_ok(responses.pop().unwrap());

    assert_eq!(
        "3501mbmm/noselect\n\
         3501mbmm/noselect/foo\n\
         3501mbmm/parent\n\
         3501mbmm/parent/bar\n",
        list_results_to_str(responses)
    );

    ok_command!(client, c("DELETE 3501mbmm/noselect"));

    command!(responses = client, c("DELETE 3501mbmm/noselect"));
    assert_eq!(1, responses.len());
    assert_tagged_no(responses.into_iter().next().unwrap());

    ok_command!(
        client,
        c("RENAME 3501mbmm/noselect/foo 3501mbmm/parent/foo")
    );

    command!(mut responses = client,
             c("LIST 3501mbmm/ *"));
    assert_tagged_ok(responses.pop().unwrap());

    assert_eq!(
        "3501mbmm/noselect \\Noselect\n\
         3501mbmm/parent\n\
         3501mbmm/parent/bar\n\
         3501mbmm/parent/foo\n",
        list_results_to_str(responses)
    );

    ok_command!(client, c("DELETE 3501mbmm/noselect"));

    command!(mut responses = client,
             c("LIST 3501mbmm/ *"));
    assert_tagged_ok(responses.pop().unwrap());
    assert_eq!(
        "3501mbmm/parent\n\
         3501mbmm/parent/bar\n\
         3501mbmm/parent/foo\n",
        list_results_to_str(responses)
    );
}

#[test]
fn subscription_management() {
    let setup = set_up();
    let mut client = setup.connect("3501mbsm");
    quick_log_in(&mut client);

    ok_command!(client, c("SUBSCRIBE 3501mbsm/parent/foo"));
    ok_command!(client, c("SUBSCRIBE 3501mbsm/parent/bar"));
    ok_command!(client, c("SUBSCRIBE 3501mbsm/parent"));
    ok_command!(client, c("CREATE 3501mbsm/other"));

    command!(mut responses = client,
             c("LSUB \"\" 3501mbsm/*"));
    assert_tagged_ok(responses.pop().unwrap());
    assert_eq!(
        "3501mbsm/parent\n\
         3501mbsm/parent/bar\n\
         3501mbsm/parent/foo\n",
        lsub_results_to_str(responses)
    );

    command!(mut responses = client,
             c("LSUB \"\" 3501mbsm/%"));
    assert_tagged_ok(responses.pop().unwrap());
    assert_eq!("3501mbsm/parent\n", lsub_results_to_str(responses));

    ok_command!(client, c("UNSUBSCRIBE 3501mbsm/parent"));

    command!(mut responses = client,
             c("LSUB \"\" 3501mbsm/*"));
    assert_tagged_ok(responses.pop().unwrap());
    assert_eq!(
        "3501mbsm/parent/bar\n\
         3501mbsm/parent/foo\n",
        lsub_results_to_str(responses)
    );

    command!(mut responses = client,
             c("LSUB \"\" 3501mbsm/%"));
    assert_tagged_ok(responses.pop().unwrap());
    assert_eq!(
        "3501mbsm/parent \\Noselect\n",
        lsub_results_to_str(responses)
    );
}

#[test]
fn error_cases() {
    let setup = set_up();
    let mut client = setup.connect("3501mbec");
    quick_log_in(&mut client);

    command!([response] = client, c("CREATE INBOX"));
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::MailboxExists.to_string(), quip);
        }
    };

    command!([response] = client, c("CREATE INBOX/child"));
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::BadOperationOnInbox.to_string(), quip);
        }
    };

    command!([response] = client, c("CREATE Archive"));
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::MailboxExists.to_string(), quip);
        }
    };

    command!([response] = client, c("CREATE \"\""));
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::UnsafeName.to_string(), quip);
        }
    };

    command!([response] = client, c("CREATE ../foo"));
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::UnsafeName.to_string(), quip);
        }
    };

    command!([response] = client, c("DELETE INBOX"));
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::BadOperationOnInbox.to_string(), quip);
        }
    };

    command!([response] = client, c("DELETE 3501mbec"));
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::NxMailbox.to_string(), quip);
        }
    };

    command!([response] = client, c("DELETE \"\""));
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::NxMailbox.to_string(), quip);
        }
    };

    command!([response] = client, c("DELETE ../foo"));
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::UnsafeName.to_string(), quip);
        }
    };

    command!([response] = client, c("RENAME INBOX Archive"));
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::MailboxExists.to_string(), quip);
        }
    };

    command!([response] = client, c("RENAME Archive INBOX"));
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::MailboxExists.to_string(), quip);
        }
    };

    command!([response] = client, c("RENAME Archive Archive"));
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::RenameToSelf.to_string(), quip);
        }
    };

    command!([response] = client, c("RENAME Archive Archive/child"));
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::RenameIntoSelf.to_string(), quip);
        }
    };

    command!([response] = client, c("RENAME Archive INBOX/child"));
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::BadOperationOnInbox.to_string(), quip);
        }
    };

    command!([response] = client, c("RENAME Archive \"\""));
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::UnsafeName.to_string(), quip);
        }
    };

    command!([response] = client, c("RENAME Archive ../foo"));
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::UnsafeName.to_string(), quip);
        }
    };

    command!([response] = client, c("RENAME \"\" bar"));
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::NxMailbox.to_string(), quip);
        }
    };

    command!([response] = client, c("RENAME ../foo bar"));
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::UnsafeName.to_string(), quip);
        }
    };
}
