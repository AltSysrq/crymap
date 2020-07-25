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

use super::defs::*;
use crate::account::model::Flag;

#[test]
fn capability_declared() {
    test_require_capability("6851capa", "MOVE");
}

#[test]
fn test_move() {
    let setup = set_up();

    let mut client = setup.connect("6851move");
    quick_log_in(&mut client);
    quick_create(&mut client, "6851move/src");
    quick_create(&mut client, "6851move/dst");
    quick_select(&mut client, "6851move/src");
    quick_append_enron(&mut client, "6851move/src", 3);

    let mut client2 = setup.connect("6851move2");
    quick_log_in(&mut client2);
    quick_select(&mut client2, "6851move/dst");

    ok_command!(client, c("STORE 2 +FLAGS (\\Seen plugh)"));
    ok_command!(client, c("STORE 3 +FLAGS (\\Answered)"));

    command!(mut responses = client, c("UID MOVE 2 6851move/dst"));
    // Tagged response should have no code
    assert_tagged_ok(responses.pop().unwrap());
    // COPYUID is found in the first, untagged OK response
    // We don't look too hard at its contents here because the underlying logic
    // is the same as COPY, which is already thoroughly tested by
    // rfc3501/messages.rs.
    unpack_cond_response! {
        (None, s::RespCondType::Ok, Some(s::RespTextCode::CopyUid(..)), _)
            = responses.drain(..1).next().unwrap()
    };
    has_untagged_response_matching! {
        s::Response::Expunge(2) in responses
    };

    command!(responses = client2, c("NOOP"));
    has_untagged_response_matching! {
        s::Response::Exists(1) in responses
    };
    has_untagged_response_matching! {
        s::Response::Fetch(ref fr) in responses => {
            has_msgatt_matching! {
                s::MsgAtt::Uid(_) in fr
            };
            has_msgatt_matching! {
                s::MsgAtt::Flags(s::FlagsFetch::Recent(ref flags)) in fr => {
                    assert_eq!(2, flags.len());
                    assert!(flags.contains(&Flag::Seen));
                    assert!(flags.contains(&Flag::Keyword("plugh".to_owned())));
                }
            };
        }
    };

    command!(mut responses = client, c("MOVE 2 6851move/dst"));
    // Tagged response should have no code
    assert_tagged_ok(responses.pop().unwrap());
    // COPYUID is found in the first, untagged OK response
    // We don't look too hard at its contents here because the underlying logic
    // is the same as COPY, which is already thoroughly tested by
    // rfc3501/messages.rs.
    unpack_cond_response! {
        (None, s::RespCondType::Ok, Some(s::RespTextCode::CopyUid(..)), _)
            = responses.drain(..1).next().unwrap()
    };
    has_untagged_response_matching! {
        s::Response::Expunge(2) in responses
    };

    command!(responses = client2, c("NOOP"));
    has_untagged_response_matching! {
        s::Response::Exists(2) in responses
    };
    has_untagged_response_matching! {
        s::Response::Fetch(ref fr) in responses => {
            has_msgatt_matching! {
                s::MsgAtt::Uid(_) in fr
            };
            has_msgatt_matching! {
                s::MsgAtt::Flags(s::FlagsFetch::Recent(ref flags)) in fr => {
                    assert_eq!(1, flags.len());
                    assert!(flags.contains(&Flag::Answered));
                }
            };
        }
    };
}
