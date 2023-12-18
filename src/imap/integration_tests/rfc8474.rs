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

use super::defs::*;

#[test]
fn capability_declared() {
    test_require_capability("8474capa", "OBJECTID");
}

#[test]
fn mailbox_ids() {
    let setup = set_up();
    let mut client = setup.connect("8474mbid");
    quick_log_in(&mut client);

    // Creating mailboxes returns their IDs in the tagged responses, and
    // different mailboxes have different IDs
    command!([response] = client, c("CREATE 8474mbid"));
    let parent_id = unpack_cond_response! {
        (Some(_), s::RespCondType::Ok,
         Some(s::RespTextCode::MailboxId(id)), _) = response => id
    };

    command!([response] = client, c("CREATE 8474mbid/foo"));
    let child_id = unpack_cond_response! {
        (Some(_), s::RespCondType::Ok,
         Some(s::RespTextCode::MailboxId(id)), _) = response => id
    };

    assert_ne!(parent_id, child_id);

    // Selecting a mailbox includes an untagged response with the mailbox's ID
    command!(mut responses = client, c("SELECT 8474mbid"));
    assert_tagged_ok_any(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Ok,
            code: Some(s::RespTextCode::MailboxId(ref id)),
            quip: _,
        }) in responses => {
            assert_eq!(parent_id, *id);
        }
    };

    command!(mut responses = client, c("EXAMINE 8474mbid/foo"));
    assert_tagged_ok_any(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Ok,
            code: Some(s::RespTextCode::MailboxId(ref id)),
            quip: _,
        }) in responses => {
            assert_eq!(child_id, *id);
        }
    };

    ok_command!(client, c("CLOSE"));

    // STATUS can return the mailbox id
    command!(mut responses = client, c("STATUS 8474mbid (MAILBOXID)"));
    assert_eq!(2, responses.len());
    assert_tagged_ok_any(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Status(ref sr) in responses => {
            assert!(sr.atts.contains(
                &s::StatusResponseAtt::MailboxId(
                    Cow::Borrowed(&parent_id))));
        }
    };

    // Mailbox id survives a rename
    ok_command!(client, c("RENAME 8474mbid/foo 8474mbid/bar"));
    command!(mut responses = client, c("STATUS 8474mbid/bar (MAILBOXID)"));
    assert_eq!(2, responses.len());
    assert_tagged_ok_any(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Status(ref sr) in responses => {
            assert!(sr.atts.contains(
                &s::StatusResponseAtt::MailboxId(
                    Cow::Borrowed(&child_id))));
        }
    };
}

#[test]
fn inbox_rename_vs_mailbox_id() {
    // Need to use a unique root since we'll be destroying INBOX
    let setup = set_up_new_root();
    let mut client = setup.connect("8474reni");
    quick_log_in(&mut client);

    command!(mut responses = client, c("EXAMINE INBOX"));
    assert_tagged_ok_any(responses.pop().unwrap());
    let inbox_id = has_untagged_response_matching! {
        s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Ok,
            code: Some(s::RespTextCode::MailboxId(ref id)),
            quip: _,
        }) in responses => {
            id.to_owned()
        }
    };

    ok_command!(client, c("CLOSE"));
    ok_command!(client, c("RENAME INBOX 8474reni"));

    command!(mut responses = client, c("EXAMINE INBOX"));
    assert_tagged_ok_any(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Ok,
            code: Some(s::RespTextCode::MailboxId(ref id)),
            quip: _,
        }) in responses => {
            assert_eq!(inbox_id, *id);
        }
    };

    command!(mut responses = client, c("EXAMINE 8474reni"));
    assert_tagged_ok_any(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Ok,
            code: Some(s::RespTextCode::MailboxId(ref id)),
            quip: _,
        }) in responses => {
            assert_ne!(inbox_id, *id);
        }
    };
}

#[test]
fn email_id() {
    let setup = set_up();
    let mut client = setup.connect("8474emid");
    quick_log_in(&mut client);
    quick_create(&mut client, "8474emid");
    quick_append_enron(&mut client, "8474emid", 2);
    quick_select(&mut client, "8474emid");

    // Can fetch EMAILID assigned to each message
    let email_id1 = fetch_single!(client, c("FETCH 1 EMAILID"), fr => {
        has_msgatt_matching! {
            move s::MsgAtt::EmailId(id) in fr => id.into_owned()
        }
    });
    let email_id2 = fetch_single!(client, c("FETCH 2 EMAILID"), fr => {
        has_msgatt_matching! {
            move s::MsgAtt::EmailId(id) in fr => id.into_owned()
        }
    });

    // They must be different
    assert_ne!(email_id1, email_id2);

    // Email id survives copy
    ok_command!(client, c("COPY 1 8474emid"));
    let email_id3 = fetch_single!(client, c("FETCH 3 EMAILID"), fr => {
        has_msgatt_matching! {
            move s::MsgAtt::EmailId(id) in fr => id.into_owned()
        }
    });
    assert_eq!(email_id1, email_id3);

    // Can "fetch" the THREADID, but we don't support that so it's always NIL
    fetch_single!(client, c("FETCH 1 THREADID"), fr => {
        has_msgatt_matching! {
            s::MsgAtt::ThreadIdNil(()) in fr
        }
    });

    // Can search by EMAILID
    command!(mut responses = client, cb(&format!(
        "SEARCH EMAILID {}", email_id2
    )));
    assert_eq!(2, responses.len());
    assert_tagged_ok_any(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Search(ref sr) in responses => {
            assert_eq!(vec![2], sr.hits);
        }
    };

    // Comparison is case-sensitive
    // We have 'E' as a prefix, so making the whole thing lowercase should
    // always prevent a match
    command!(mut responses = client, cb(&format!(
        "SEARCH EMAILID {}", email_id2.to_ascii_lowercase()
    )));
    assert_eq!(2, responses.len());
    assert_tagged_ok_any(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Search(ref sr) in responses => {
            assert!(sr.hits.is_empty());
        }
    };

    // ThreadID query is accepted, but returns no results
    command!(mut responses = client, cb(&format!(
        "SEARCH THREADID {}", email_id2
    )));
    assert_eq!(2, responses.len());
    assert_tagged_ok_any(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Search(ref sr) in responses => {
            assert!(sr.hits.is_empty());
        }
    };
}
