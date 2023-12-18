//-
// Copyright (c) 2020, 2023, Jason Lingle
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
fn basic_success() {
    let setup = set_up();
    let mut client = setup.connect("3501sebs");
    quick_log_in(&mut client);
    quick_create(&mut client, "3501sebs");
    quick_append_enron(&mut client, "3501sebs", 3);

    command!(mut responses = client, c("EXAMINE 3501sebs"));
    unpack_cond_response! {
        (Some(_), s::RespCondType::Ok, Some(s::RespTextCode::ReadOnly(_)), _) =
            responses.pop().unwrap() => ()
    };
    has_untagged_response_matching! {
        s::Response::Flags(ref flags) in responses => {
            assert!(flags.len() >= 5);
        }
    };
    has_untagged_response_matching! {
        s::Response::Exists(3) in responses
    };
    has_untagged_response_matching! {
        s::Response::Recent(3) in responses
    };
    has_untagged_response_matching! {
        s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Ok,
            code: Some(s::RespTextCode::Unseen(1)),
            ..
        }) in responses
    };
    has_untagged_response_matching! {
        s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Ok,
            code: Some(s::RespTextCode::PermanentFlags(ref flags)),
            ..
        }) in responses => {
            assert!(flags.len() >= 5);
        }
    };
    has_untagged_response_matching! {
        s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Ok,
            code: Some(s::RespTextCode::UidValidity(_)),
            ..
        }) in responses
    };
    has_untagged_response_matching! {
        s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Ok,
            code: Some(s::RespTextCode::UidNext(4)),
            ..
        }) in responses
    };

    command!(mut responses = client, c("SELECT 3501sebs"));
    unpack_cond_response! {
        (Some(_), s::RespCondType::Ok, Some(s::RespTextCode::ReadWrite(_)), _) =
            responses.pop().unwrap() => ()
    };
    has_untagged_response_matching! {
        s::Response::Flags(ref flags) in responses => {
            assert!(flags.len() >= 5);
        }
    };
    has_untagged_response_matching! {
        s::Response::Exists(3) in responses
    };
    // The EXAMINE shouldn't have affected \Recent
    has_untagged_response_matching! {
        s::Response::Recent(3) in responses
    };
    has_untagged_response_matching! {
        s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Ok,
            code: Some(s::RespTextCode::Unseen(1)),
            ..
        }) in responses
    };
    has_untagged_response_matching! {
        s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Ok,
            code: Some(s::RespTextCode::PermanentFlags(ref flags)),
            ..
        }) in responses => {
            assert!(flags.len() >= 5);
        }
    };
    has_untagged_response_matching! {
        s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Ok,
            code: Some(s::RespTextCode::UidValidity(_)),
            ..
        }) in responses
    };
    has_untagged_response_matching! {
        s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Ok,
            code: Some(s::RespTextCode::UidNext(4)),
            ..
        }) in responses
    };

    command!(responses = client, c("SELECT 3501sebs"));
    // The previous SELECT claimed all the \Recent flags
    has_untagged_response_matching! {
        s::Response::Recent(0) in responses
    };

    ok_command!(client, c("STORE 1:* +FLAGS (\\Seen)"));

    command!(responses = client, c("SELECT 3501sebs"));
    // Nothing is unseen, so there should be no Unseen response
    for response in responses {
        if matches!(
            response.response,
            s::Response::Cond(s::CondResponse {
                code: Some(s::RespTextCode::Unseen(_)),
                ..
            })
        ) {
            panic!("Unexpected UNSEEN response: {:?}", response);
        }
    }

    // Switch back to a read-only view so we don't claim \Recent on the message
    // we're about to append.
    ok_command!(client, c("EXAMINE 3501sebs"));

    quick_append_enron(&mut client, "3501sebs", 1);

    command!(responses = client, c("EXAMINE 3501sebs"));
    has_untagged_response_matching! {
        s::Response::Recent(1) in responses
    };
    has_untagged_response_matching! {
        s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Ok,
            code: Some(s::RespTextCode::Unseen(4)),
            ..
        }) in responses
    };
}

#[test]
fn close_and_expunge() {
    let setup = set_up();
    let mut client = setup.connect("3501sece");
    quick_log_in(&mut client);
    quick_create(&mut client, "3501sece");
    quick_append_enron(&mut client, "3501sece", 3);

    ok_command!(client, c("SELECT 3501sece"));
    ok_command!(client, c("STORE 1:2 +FLAGS (\\Deleted)"));

    command!(responses = client, c("EXAMINE 3501sece"));
    // Re-selecting must not expunge anything
    has_untagged_response_matching! {
        s::Response::Exists(3) in responses
    };

    command!([response] = client, c("CLOSE"));
    assert_tagged_ok(response);

    command!(responses = client, c("SELECT 3501sece"));
    // CLOSE on a read-only mailbox must not expunge anything
    has_untagged_response_matching! {
        s::Response::Exists(3) in responses
    };

    command!([response] = client, c("CLOSE"));
    assert_tagged_ok(response);

    command!(responses = client, c("EXAMINE 3501sece"));
    // But now that we CLOSEd a read-write mailbox, the two \Deleted messages
    // were expunged.
    has_untagged_response_matching! {
        s::Response::Exists(1) in responses
    };
}

#[test]
fn error_conditions() {
    let setup = set_up();
    let mut client = setup.connect("3501seec");
    quick_log_in(&mut client);
    quick_create(&mut client, "3501seec/noselect/child");

    ok_command!(client, c("DELETE 3501seec/noselect"));

    ok_command!(client, c("SELECT 3501seec"));
    // This particular command is a workaround some clients use in the absence
    // of UNSELECT.
    command!(_responses = client, c("EXAMINE \"&#-&#/#\""));
    // The above fails, but we should still be unselected
    command!([response] = client, c("EXPUNGE"));
    unpack_cond_response! {
        (Some(_), s::RespCondType::Bad, _, _) = response => ()
    };

    command!([response] = client, c("SELECT nonexistent"));
    assert_error_response(
        response,
        Some(s::RespTextCode::Nonexistent(())),
        Error::NxMailbox,
    );

    command!([response] = client, c("SELECT 3501seec/noselect"));
    assert_error_response(
        response,
        Some(s::RespTextCode::Nonexistent(())),
        Error::MailboxUnselectable,
    );

    command!([response] = client, c("SELECT ../foo"));
    assert_error_response(
        response,
        Some(s::RespTextCode::Nonexistent(())),
        Error::NxMailbox,
    );

    command!([response] = client, c("SELECT \"\""));
    assert_error_response(
        response,
        Some(s::RespTextCode::Nonexistent(())),
        Error::NxMailbox,
    );

    command!([response] = client, c("CLOSE"));
    unpack_cond_response! {
        (Some(_), s::RespCondType::Bad, _, _) = response => ()
    };
}

#[test]
fn keywords_included_in_flags() {
    let setup = set_up();
    let mut client = setup.connect("3501sekf");
    quick_log_in(&mut client);
    quick_create(&mut client, "3501sekf");
    quick_append_enron(&mut client, "3501sekf", 1);

    ok_command!(client, c("SELECT 3501sekf"));
    ok_command!(client, c("STORE 1 +FLAGS ($Important)"));

    command!(responses = client, c("EXAMINE 3501sekf"));
    has_untagged_response_matching! {
        s::Response::Flags(ref flags) in responses => {
            assert!(flags.contains(&Flag::Keyword("$Important".to_owned())));
        }
    };
    has_untagged_response_matching! {
        s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Ok,
            code: Some(s::RespTextCode::PermanentFlags(ref flags)),
            ..
        }) in responses => {
            assert!(flags.contains(&Flag::Keyword("$Important".to_owned())));
        }
    };
}
