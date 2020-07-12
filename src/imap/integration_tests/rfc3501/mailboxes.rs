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

    ok_command!(
        client,
        s::Command::Create(s::CreateCommand {
            mailbox: Cow::Borrowed("3501mbmm/noselect/foo"),
        })
    );
    ok_command!(
        client,
        s::Command::Create(s::CreateCommand {
            mailbox: Cow::Borrowed("3501mbmm/parent/bar"),
        })
    );

    command!(mut responses = client, s::Command::List(s::ListCommand {
        reference: Cow::Borrowed(""),
        pattern: Cow::Borrowed("3501mbmm/*"),
    }));
    assert_tagged_ok(responses.pop().unwrap());

    assert_eq!(
        "3501mbmm/noselect\n\
         3501mbmm/noselect/foo\n\
         3501mbmm/parent\n\
         3501mbmm/parent/bar\n",
        list_results_to_str(responses)
    );

    ok_command!(
        client,
        s::Command::Delete(s::DeleteCommand {
            mailbox: Cow::Borrowed("3501mbmm/noselect"),
        })
    );

    command!(
        responses = client,
        s::Command::Delete(s::DeleteCommand {
            mailbox: Cow::Borrowed("3501mbmm/noselect"),
        })
    );
    assert_eq!(1, responses.len());
    assert_tagged_no(responses.into_iter().next().unwrap());

    ok_command!(
        client,
        s::Command::Rename(s::RenameCommand {
            src: Cow::Borrowed("3501mbmm/noselect/foo"),
            dst: Cow::Borrowed("3501mbmm/parent/foo"),
        })
    );

    command!(mut responses = client, s::Command::List(s::ListCommand {
        reference: Cow::Borrowed("3501mbmm/"),
        pattern: Cow::Borrowed("*"),
    }));
    assert_tagged_ok(responses.pop().unwrap());

    assert_eq!(
        "3501mbmm/noselect \\Noselect\n\
         3501mbmm/parent\n\
         3501mbmm/parent/bar\n\
         3501mbmm/parent/foo\n",
        list_results_to_str(responses)
    );

    ok_command!(
        client,
        s::Command::Delete(s::DeleteCommand {
            mailbox: Cow::Borrowed("3501mbmm/noselect"),
        })
    );

    command!(mut responses = client, s::Command::List(s::ListCommand {
        reference: Cow::Borrowed("3501mbmm/"),
        pattern: Cow::Borrowed("*"),
    }));
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

    ok_command!(
        client,
        s::Command::Subscribe(s::SubscribeCommand {
            mailbox: Cow::Borrowed("3501mbsm/parent/foo"),
        })
    );
    ok_command!(
        client,
        s::Command::Subscribe(s::SubscribeCommand {
            mailbox: Cow::Borrowed("3501mbsm/parent/bar"),
        })
    );
    ok_command!(
        client,
        s::Command::Subscribe(s::SubscribeCommand {
            mailbox: Cow::Borrowed("3501mbsm/parent"),
        })
    );
    ok_command!(
        client,
        s::Command::Create(s::CreateCommand {
            mailbox: Cow::Borrowed("3501mbsm/other"),
        })
    );

    command!(mut responses = client, s::Command::Lsub(s::LsubCommand {
        reference: Cow::Borrowed(""),
        pattern: Cow::Borrowed("3501mbsm/*"),
    }));
    assert_tagged_ok(responses.pop().unwrap());
    assert_eq!(
        "3501mbsm/parent\n\
         3501mbsm/parent/bar\n\
         3501mbsm/parent/foo\n",
        lsub_results_to_str(responses)
    );

    command!(mut responses = client, s::Command::Lsub(s::LsubCommand {
        reference: Cow::Borrowed(""),
        pattern: Cow::Borrowed("3501mbsm/%"),
    }));
    assert_tagged_ok(responses.pop().unwrap());
    assert_eq!("3501mbsm/parent\n", lsub_results_to_str(responses));

    ok_command!(
        client,
        s::Command::Unsubscribe(s::UnsubscribeCommand {
            mailbox: Cow::Borrowed("3501mbsm/parent"),
        })
    );

    command!(mut responses = client, s::Command::Lsub(s::LsubCommand {
        reference: Cow::Borrowed(""),
        pattern: Cow::Borrowed("3501mbsm/*"),
    }));
    assert_tagged_ok(responses.pop().unwrap());
    assert_eq!(
        "3501mbsm/parent/bar\n\
         3501mbsm/parent/foo\n",
        lsub_results_to_str(responses)
    );

    command!(mut responses = client, s::Command::Lsub(s::LsubCommand {
        reference: Cow::Borrowed(""),
        pattern: Cow::Borrowed("3501mbsm/%"),
    }));
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

    command!(
        [response] = client,
        s::Command::Create(s::CreateCommand {
            mailbox: Cow::Borrowed("INBOX"),
        })
    );
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::MailboxExists.to_string(), quip);
        }
    };

    command!(
        [response] = client,
        s::Command::Create(s::CreateCommand {
            mailbox: Cow::Borrowed("INBOX/child"),
        })
    );
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::BadOperationOnInbox.to_string(), quip);
        }
    };

    command!(
        [response] = client,
        s::Command::Create(s::CreateCommand {
            mailbox: Cow::Borrowed("Archive"),
        })
    );
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::MailboxExists.to_string(), quip);
        }
    };

    command!(
        [response] = client,
        s::Command::Create(s::CreateCommand {
            mailbox: Cow::Borrowed(""),
        })
    );
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::UnsafeName.to_string(), quip);
        }
    };

    command!(
        [response] = client,
        s::Command::Create(s::CreateCommand {
            mailbox: Cow::Borrowed("../foo"),
        })
    );
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::UnsafeName.to_string(), quip);
        }
    };

    command!(
        [response] = client,
        s::Command::Delete(s::DeleteCommand {
            mailbox: Cow::Borrowed("INBOX"),
        })
    );
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::BadOperationOnInbox.to_string(), quip);
        }
    };

    command!(
        [response] = client,
        s::Command::Delete(s::DeleteCommand {
            mailbox: Cow::Borrowed("3501mbec"),
        })
    );
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::NxMailbox.to_string(), quip);
        }
    };

    command!(
        [response] = client,
        s::Command::Delete(s::DeleteCommand {
            mailbox: Cow::Borrowed(""),
        })
    );
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::NxMailbox.to_string(), quip);
        }
    };

    command!(
        [response] = client,
        s::Command::Delete(s::DeleteCommand {
            mailbox: Cow::Borrowed("../foo"),
        })
    );
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::UnsafeName.to_string(), quip);
        }
    };

    command!(
        [response] = client,
        s::Command::Rename(s::RenameCommand {
            src: Cow::Borrowed("INBOX"),
            dst: Cow::Borrowed("Archive"),
        })
    );
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::MailboxExists.to_string(), quip);
        }
    };

    command!(
        [response] = client,
        s::Command::Rename(s::RenameCommand {
            src: Cow::Borrowed("Archive"),
            dst: Cow::Borrowed("INBOX"),
        })
    );
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::MailboxExists.to_string(), quip);
        }
    };

    command!(
        [response] = client,
        s::Command::Rename(s::RenameCommand {
            src: Cow::Borrowed("Archive"),
            dst: Cow::Borrowed("Archive"),
        })
    );
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::RenameToSelf.to_string(), quip);
        }
    };

    command!(
        [response] = client,
        s::Command::Rename(s::RenameCommand {
            src: Cow::Borrowed("Archive"),
            dst: Cow::Borrowed("Archive/child"),
        })
    );
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::RenameIntoSelf.to_string(), quip);
        }
    };

    command!(
        [response] = client,
        s::Command::Rename(s::RenameCommand {
            src: Cow::Borrowed("Archive"),
            dst: Cow::Borrowed("INBOX/child"),
        })
    );
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::BadOperationOnInbox.to_string(), quip);
        }
    };

    command!(
        [response] = client,
        s::Command::Rename(s::RenameCommand {
            src: Cow::Borrowed("Archive"),
            dst: Cow::Borrowed(""),
        })
    );
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::UnsafeName.to_string(), quip);
        }
    };

    command!(
        [response] = client,
        s::Command::Rename(s::RenameCommand {
            src: Cow::Borrowed("Archive"),
            dst: Cow::Borrowed("../foo"),
        })
    );
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::UnsafeName.to_string(), quip);
        }
    };

    command!(
        [response] = client,
        s::Command::Rename(s::RenameCommand {
            src: Cow::Borrowed(""),
            dst: Cow::Borrowed("bar"),
        })
    );
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::NxMailbox.to_string(), quip);
        }
    };

    command!(
        [response] = client,
        s::Command::Rename(s::RenameCommand {
            src: Cow::Borrowed("../foo"),
            dst: Cow::Borrowed("bar"),
        })
    );
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, None, Some(quip)) = response => {
            assert_eq!(Error::UnsafeName.to_string(), quip);
        }
    };
}
