//-
// Copyright (c) 2020, 2021, 2023, Jason Lingle
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
use crate::account::model::Flag;
use crate::support::error::Error;

#[test]
fn flag_crud() {
    let setup = set_up();
    let mut client = setup.connect("3501flfc");
    quick_log_in(&mut client);
    quick_create(&mut client, "3501flfc");
    quick_append_enron(&mut client, "3501flfc", 3);
    quick_select(&mut client, "3501flfc");

    ok_command!(client, c("XVANQUISH 2"));

    command!(mut responses = client, c("STORE 2 +FLAGS (\\Seen \\Deleted)"));
    assert_eq!(2, responses.len());
    assert_tagged_ok(responses.pop().unwrap());
    assert_eq!(
        &r("2 FETCH (UID 3 FLAGS (\\Recent \\Seen \\Deleted))"),
        &responses[0].response
    );

    command!(mut responses = client, c("UID STORE 3 -FLAGS (\\Deleted)"));
    assert_eq!(2, responses.len());
    assert_tagged_ok(responses.pop().unwrap());
    assert_eq!(
        &r("2 FETCH (UID 3 FLAGS (\\Recent \\Seen))"),
        &responses[0].response
    );

    ok_command!(client, c("XCRY FLAGS ON"));
    command!(mut responses = client, c("STORE 2 FLAGS (3501flfc)"));
    assert_eq!(3, responses.len());
    assert_tagged_ok(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Flags(ref flags) in responses => {
            assert!(flags.contains(&Flag::Keyword("3501flfc".to_owned())));
        }
    }
    assert_eq!(
        &r("2 FETCH (UID 3 FLAGS (\\Recent 3501flfc))"),
        &responses[1].response
    );
    ok_command!(client, c("XCRY FLAGS OFF"));

    // No-op without .SILENT produces fetch response anyway
    command!(mut responses = client, c("STORE 2 -FLAGS (\\Deleted)"));
    assert_eq!(2, responses.len());
    assert_tagged_ok(responses.pop().unwrap());
    assert_eq!(
        &r("2 FETCH (UID 3 FLAGS (\\Recent 3501flfc))"),
        &responses[0].response
    );

    // No-op with .SILENT results in no spurious FETCH
    command!([response] = client, c("STORE 2 -FLAGS.SILENT (\\Deleted)"));
    assert_tagged_ok(response);

    // Check behaviours involving concurrently-expunged messages
    let mut client2 = setup.connect("3501flfc2");
    quick_log_in(&mut client2);
    quick_select(&mut client2, "3501flfc");
    ok_command!(client2, c("XVANQUISH 1"));

    // STORE with .SILENT = return OK, no fetches.
    // Also we must not be notified about the expunge yet, but we do get the
    // RFC 5530 [EXPUNGEISSUED] code. We *do*, however, get notified about the
    // change we just made to the flag.
    command!(mut responses = client, c("STORE 1 +FLAGS.SILENT (\\Answered)"));
    assert_eq!(2, responses.len());
    unpack_cond_response! {
        (Some(_), s::RespCondType::Ok,
         Some(s::RespTextCode::ExpungeIssued(())), _) =
            responses.pop().unwrap() => ()
    };
    has_untagged_response_matching! {
        s::Response::Fetch(..) in responses
    };

    // STORE without .SILENT = as above
    command!(mut responses = client, c("STORE 1 +FLAGS (\\Answered)"));
    assert_eq!(2, responses.len());
    unpack_cond_response! {
        (Some(_), s::RespCondType::Ok,
         Some(s::RespTextCode::ExpungeIssued(())), _) =
            responses.pop().unwrap() => ()
    };
    has_untagged_response_matching! {
        s::Response::Fetch(..) in responses
    };
}

#[test]
fn error_conditions() {
    let setup = set_up();
    let mut client = setup.connect("3501flec");
    quick_log_in(&mut client);
    quick_create(&mut client, "3501flec");
    quick_append_enron(&mut client, "3501flec", 1);
    quick_select(&mut client, "3501flec");

    command!([response] = client, c("STORE 2 +FLAGS (\\Answered)"));
    unpack_cond_response! {
        (Some(_), s::RespCondType::Bad, _, _) = response => { }
    }

    client
        .write_raw(b"N STORE 1 +FLAGS (\\Nonstandard)\r\n")
        .unwrap();
    let mut buffer = Vec::new();
    let response = client.read_one_response(&mut buffer).unwrap();
    unpack_cond_response! {
        (Some(_), s::RespCondType::Bad, _, _) = response => { }
    }

    command!([response] = client, c("UID STORE 2 +FLAGS (\\Answered)"));
    assert_tagged_no(response);

    // Create a situation in which `client` knows about a message by UID but
    // doesn't have it in its snapshot.
    let mut client2 = setup.connect("3501flec2");
    quick_log_in(&mut client2);
    quick_append_enron(&mut client2, "3501flec", 1);
    quick_select(&mut client2, "3501flec");
    ok_command!(client2, c("STORE 2 +FLAGS (\\Answered)"));

    // Running a successful STORE against the first client causes it to
    // discover the above STORE and thus UID 2
    ok_command!(client, c("STORE 1 +FLAGS (\\Answered)"));

    command!(mut responses = client, c("UID STORE 2 +FLAGS (\\Seen)"));
    // It returns NO and has no effect.
    // Since UID STORE is not a cursed command, we also get the asynchronous
    // updates here:
    // 2 EXISTS, 1 RECENT, 2 FETCH ..., TAG OK NIL
    assert_eq!(4, responses.len());
    assert_tagged_no(responses.pop().unwrap());
    assert_eq!(
        &r("2 FETCH (UID 2 FLAGS (\\Answered))"),
        &responses[2].response
    );

    // To double-check, add another flag and ensure that \\Seen didn't show up
    // If we try to remove \\Seen with .SILENT, we get no response only if
    // \\Seen isn't on the message.
    command!([response] = client, c("UID STORE 2 -FLAGS.SILENT (\\Seen)"));
    assert_tagged_ok(response);

    ok_command!(client, c("EXAMINE 3501flec"));
    command!([response] = client, c("STORE 1 +FLAGS (\\Deleted)"));
    assert_error_response(
        response,
        Some(s::RespTextCode::Cannot(())),
        Error::MailboxReadOnly,
    );
}
