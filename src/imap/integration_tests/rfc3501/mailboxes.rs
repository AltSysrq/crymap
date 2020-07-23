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

#[test]
fn mailbox_management() {
    let setup = set_up();
    let mut client = setup.connect("3501mbmm");
    quick_log_in(&mut client);

    ok_command!(client, c("CREATE 3501mbmm/noselect/foo"));
    ok_command!(client, c("CREATE 3501mbmm/parent/bar/"));

    command!(mut responses = client,
             c("LIST \"\" 3501mbmm/*"));
    assert_tagged_ok(responses.pop().unwrap());

    // \HasChildren and \HasNoChildren are from the RFC 3348 CHILDREN
    // extension, which adds these implicitly.
    assert_eq!(
        "3501mbmm/noselect \\HasChildren\n\
         3501mbmm/noselect/foo \\HasNoChildren\n\
         3501mbmm/parent \\HasChildren\n\
         3501mbmm/parent/bar \\HasNoChildren\n",
        list_results_to_str(responses)
    );

    ok_command!(client, c("DELETE 3501mbmm/noselect"));

    command!(responses = client, c("DELETE 3501mbmm/noselect"));
    assert_eq!(1, responses.len());
    assert_error_response(
        responses.into_iter().next().unwrap(),
        Some(s::RespTextCode::InUse(())),
        Error::MailboxHasInferiors,
    );

    ok_command!(
        client,
        c("RENAME 3501mbmm/noselect/foo 3501mbmm/parent/foo")
    );

    command!(mut responses = client,
             c("LIST 3501mbmm/ *"));
    assert_tagged_ok(responses.pop().unwrap());

    assert_eq!(
        "3501mbmm/noselect \\HasNoChildren \\Noselect\n\
         3501mbmm/parent \\HasChildren\n\
         3501mbmm/parent/bar \\HasNoChildren\n\
         3501mbmm/parent/foo \\HasNoChildren\n",
        list_results_to_str(responses)
    );

    ok_command!(client, c("DELETE 3501mbmm/noselect"));

    command!(mut responses = client,
             c("LIST 3501mbmm/ *"));
    assert_tagged_ok(responses.pop().unwrap());
    assert_eq!(
        "3501mbmm/parent \\HasChildren\n\
         3501mbmm/parent/bar \\HasNoChildren\n\
         3501mbmm/parent/foo \\HasNoChildren\n",
        list_results_to_str(responses)
    );

    command!(mut responses = client,
             c("LIST \"\" \"\""));
    assert_tagged_ok(responses.pop().unwrap());
    assert_eq!(" \\Noselect\n", list_results_to_str(responses));
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
    assert_error_response(
        response,
        Some(s::RespTextCode::AlreadyExists(())),
        Error::MailboxExists,
    );

    command!([response] = client, c("CREATE INBOX/child"));
    assert_error_response(
        response,
        Some(s::RespTextCode::Cannot(())),
        Error::BadOperationOnInbox,
    );

    command!([response] = client, c("CREATE Archive"));
    assert_error_response(
        response,
        Some(s::RespTextCode::AlreadyExists(())),
        Error::MailboxExists,
    );

    command!([response] = client, c("CREATE \"\""));
    assert_error_response(
        response,
        Some(s::RespTextCode::Cannot(())),
        Error::UnsafeName,
    );

    command!([response] = client, c("CREATE ../foo"));
    assert_error_response(
        response,
        Some(s::RespTextCode::Cannot(())),
        Error::UnsafeName,
    );

    command!([response] = client, c("DELETE INBOX"));
    assert_error_response(
        response,
        Some(s::RespTextCode::Cannot(())),
        Error::BadOperationOnInbox,
    );

    command!([response] = client, c("DELETE 3501mbec"));
    assert_error_response(
        response,
        Some(s::RespTextCode::Nonexistent(())),
        Error::NxMailbox,
    );

    command!([response] = client, c("DELETE \"\""));
    assert_error_response(
        response,
        Some(s::RespTextCode::Nonexistent(())),
        Error::NxMailbox,
    );

    command!([response] = client, c("DELETE ../foo"));
    assert_error_response(
        response,
        Some(s::RespTextCode::Cannot(())),
        Error::UnsafeName,
    );

    command!([response] = client, c("RENAME INBOX Archive"));
    assert_error_response(
        response,
        Some(s::RespTextCode::AlreadyExists(())),
        Error::MailboxExists,
    );

    command!([response] = client, c("RENAME Archive INBOX"));
    assert_error_response(
        response,
        Some(s::RespTextCode::AlreadyExists(())),
        Error::MailboxExists,
    );

    command!([response] = client, c("RENAME Archive Archive"));
    assert_error_response(
        response,
        Some(s::RespTextCode::AlreadyExists(())),
        Error::RenameToSelf,
    );

    command!([response] = client, c("RENAME Archive Archive/child"));
    assert_error_response(
        response,
        Some(s::RespTextCode::Cannot(())),
        Error::RenameIntoSelf,
    );

    command!([response] = client, c("RENAME Archive INBOX/child"));
    assert_error_response(
        response,
        Some(s::RespTextCode::Cannot(())),
        Error::BadOperationOnInbox,
    );

    command!([response] = client, c("RENAME Archive \"\""));
    assert_error_response(
        response,
        Some(s::RespTextCode::Cannot(())),
        Error::UnsafeName,
    );

    command!([response] = client, c("RENAME Archive ../foo"));
    assert_error_response(
        response,
        Some(s::RespTextCode::Cannot(())),
        Error::UnsafeName,
    );

    command!([response] = client, c("RENAME \"\" bar"));
    assert_error_response(
        response,
        Some(s::RespTextCode::Nonexistent(())),
        Error::NxMailbox,
    );

    command!([response] = client, c("RENAME ../foo bar"));
    assert_error_response(
        response,
        Some(s::RespTextCode::Cannot(())),
        Error::UnsafeName,
    );
}

#[test]
fn delete_mailbox_in_use() {
    let setup = set_up();
    let mut client = setup.connect("3501mbdi");
    quick_log_in(&mut client);
    quick_create(&mut client, "3501mbdi");
    quick_append_enron(&mut client, "3501mbdi", 1);
    quick_select(&mut client, "3501mbdi");

    let mut client2 = setup.connect("3501mbdi");
    quick_log_in(&mut client2);

    // client2 deletes the mailbox while client still has it selected
    ok_command!(client2, c("DELETE 3501mbdi"));

    // client takes an action that causes it to notice that.
    // We use XVANQUISH here because it won't produce any intermediate
    // responses.
    client.write_raw(b"X XVANQUISH 1\r\n").unwrap();
    let mut buffer = Vec::new();
    let response = client.read_one_response(&mut buffer).unwrap();

    unpack_cond_response! {
        (None, s::RespCondType::Bye, None, _) = response
    };
}
