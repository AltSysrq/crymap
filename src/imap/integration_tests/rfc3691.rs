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

#[test]
fn capability_declared() {
    test_require_capability("3691capa", "UNSELECT");
}

#[test]
fn unselect() {
    let setup = set_up();
    let mut client = setup.connect("3691unsl");
    quick_log_in(&mut client);
    quick_create(&mut client, "3691unsl");
    quick_append_enron(&mut client, "3691unsl", 2);
    quick_select(&mut client, "3691unsl");

    ok_command!(client, c("STORE 1:* +FLAGS (\\Deleted)"));
    ok_command!(client, c("UNSELECT"));

    // Ensure we really did unselect
    command!([response] = client, c("UNSELECT"));
    unpack_cond_response! {
        (Some(_), s::RespCondType::Bad, _, _) = response
    };

    command!([response] = client, c("EXPUNGE"));
    unpack_cond_response! {
        (Some(_), s::RespCondType::Bad, _, _) = response
    };

    // When we SELECT again, the two messages should still exist
    command!(mut responses = client, c("SELECT 3691unsl"));
    assert_tagged_ok_any(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Exists(2) in responses
    };

    // CLOSE will then expunge those two messages
    ok_command!(client, c("CLOSE"));

    command!(mut responses = client, c("SELECT 3691unsl"));
    assert_tagged_ok_any(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Exists(0) in responses
    };
}
