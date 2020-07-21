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
use crate::support::error::Error;
use crate::test_data::*;

#[test]
fn capability_declared() {
    let setup = set_up();
    let mut client = setup.connect("4315capa");

    let mut buffer = Vec::new();
    let response = client.read_one_response(&mut buffer).unwrap();
    unpack_cond_response! {
        (None, s::RespCondType::Ok, Some(s::RespTextCode::Capability(caps)), _)
            = response
        => {
            assert!(caps.capabilities.contains(&Cow::Borrowed("UIDPLUS")));
        }
    }
}

#[test]
fn uid_expunge() {
    let setup = set_up();
    let mut client = setup.connect("4315uidx");
    quick_log_in(&mut client);
    quick_create(&mut client, "4315uidx");
    quick_append_enron(&mut client, "4315uidx", 5);
    quick_select(&mut client, "4315uidx");

    ok_command!(client, c("XVANQUISH 2"));
    ok_command!(client, c("UID STORE 3 +FLAGS (\\Deleted)"));

    command!(mut responses = client, c("UID EXPUNGE 3,4"));

    assert_tagged_ok(responses.pop().unwrap());
    assert_eq!(1, responses.len());
    has_untagged_response_matching! {
        s::Response::Expunge(2) in responses
    };

    ok_command!(client, c("EXAMINE 4315uidx"));

    command!([response] = client, c("UID EXPUNGE 1:*"));
    assert_error_response(
        response,
        Some(s::RespTextCode::Cannot(())),
        Error::MailboxReadOnly,
    );
}

#[test]
fn append_uid() {
    let setup = set_up();
    let mut client = setup.connect("4315appu");
    quick_log_in(&mut client);
    quick_create(&mut client, "4315appu");

    client
        .start_append(
            "4315appu",
            s::AppendFragment::default(),
            ENRON_SMALL_MULTIPARTS[0],
        )
        .unwrap();
    client
        .append_item(s::AppendFragment::default(), ENRON_SMALL_MULTIPARTS[1])
        .unwrap();

    let mut buffer = Vec::new();
    let responses = client.finish_append(&mut buffer).unwrap();
    assert_eq!(1, responses.len());
    let data = unpack_cond_response! {
        (Some(_), s::RespCondType::Ok,
         Some(s::RespTextCode::AppendUid(data)), _) =
            responses.into_iter().next().unwrap() => data
    };
    assert_eq!("256:257", data.uids);

    command!(responses = client, c("SELECT 4315appu"));
    has_untagged_response_matching! {
        s::Response::Cond(s::CondResponse {
            code: Some(s::RespTextCode::UidValidity(uv)),
            ..
        }) in responses => {
            assert_eq!(uv, data.uid_validity);
        }
    };
}

#[test]
fn copy_uid() {
    let setup = set_up();
    let mut client = setup.connect("4315copu");
    quick_log_in(&mut client);
    quick_create(&mut client, "4315copu/src");
    quick_create(&mut client, "4315copu/dst");
    quick_select(&mut client, "4315copu/src");

    quick_append_enron(&mut client, "4315copu/src", 3);
    ok_command!(client, c("XVANQUISH 2"));

    command!([response] = client, c("UID COPY 1:3 4315copu/dst"));
    let data = unpack_cond_response! {
        (Some(_), s::RespCondType::Ok,
         Some(s::RespTextCode::CopyUid(data)), _) = response => data
    };
    assert_eq!("1,3", data.from_uids);
    assert_eq!("256:257", data.to_uids);

    command!(responses = client, c("SELECT 4315copu/dst"));
    has_untagged_response_matching! {
        s::Response::Cond(s::CondResponse {
            code: Some(s::RespTextCode::UidValidity(uv)),
            ..
        }) in responses => {
            assert_eq!(uv, data.uid_validity);
        }
    };
}
