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
    let setup = set_up();
    let mut client = setup.connect("5161capa");

    let mut buffer = Vec::new();
    let response = client.read_one_response(&mut buffer).unwrap();
    unpack_cond_response! {
        (None, s::RespCondType::Ok, Some(s::RespTextCode::Capability(caps)), _)
            = response
        => {
            assert!(caps.capabilities.contains(&Cow::Borrowed("ENABLE")));
        }
    }
}

#[test]
fn command_works() {
    let setup = set_up();
    let mut client = setup.connect("5161test");

    // Try to enable non-existent extension
    command!(mut responses = client, c("ENABLE RANDOMLY-LOSE"));
    assert_tagged_ok(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Enabled(ref exts) in responses => {
            assert!(exts.is_empty());
        }
    }

    // Try to enable extension which cannot be enabled
    command!(mut responses = client, c("ENABLE ENABLE"));
    assert_tagged_ok(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Enabled(ref exts) in responses => {
            assert!(exts.is_empty());
        }
    }

    // Enable an extension which can be enabled
    command!(mut responses = client, c("ENABLE XYZZY"));
    assert_tagged_ok(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Enabled(ref exts) in responses => {
            assert_eq!(1, exts.len());
            assert!(exts.contains(&Cow::Borrowed("XYZZY")));
        }
    }

    // Mix valid and invalid extensions
    command!(mut responses = client, c("ENABLE XYZZY ENABLE RANDOMLY-LOSE"));
    assert_tagged_ok(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Enabled(ref exts) in responses => {
            assert_eq!(1, exts.len());
            assert!(exts.contains(&Cow::Borrowed("XYZZY")));
        }
    }

    command!(mut responses = client, c("ENABLE ENABLE XYZZY RANDOMLY-LOSE"));
    assert_tagged_ok(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Enabled(ref exts) in responses => {
            assert_eq!(1, exts.len());
            assert!(exts.contains(&Cow::Borrowed("XYZZY")));
        }
    }
}
