//-
// Copyright (c) 2020 Jason Lingle
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
    test_require_capability("4978capa", "COMPRESS=DEFLATE");
}

#[test]
fn compress() {
    let setup = set_up();
    let mut client = setup.connect("4978comp");

    ok_command!(client, c("COMPRESS DEFLATE"));

    let mut client = client.compress();

    ok_command!(client, c("LOGIN azure hunter2"));

    command!(mut responses = client, c("SELECT INBOX"));
    assert_tagged_ok_any(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Exists(0) in responses
    };

    command!([response] = client, c("COMPRESS DEFLATE"));
    assert_matches!(
        s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::No,
            code: Some(s::RespTextCode::CompressionActive(())),
            quip: _,
        }),
        response.response
    );
}
