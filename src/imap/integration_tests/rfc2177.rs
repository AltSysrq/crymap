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
    test_require_capability("2177capa", "IDLE");
}

#[test]
fn bad_idle() {
    let setup = set_up();
    let mut client = setup.connect("2177badi");
    quick_log_in(&mut client);

    command!([response] = client, c("IDLE"));
    unpack_cond_response! {
        (Some(_), s::RespCondType::Bad, _, _) = response
    };

    // Ensure the server isn't broken
    ok_command!(client, c("SELECT INBOX"));
}

#[test]
fn test_idle() {
    let setup = set_up();
    let mut client = setup.connect("2177idle");
    quick_log_in(&mut client);
    quick_create(&mut client, "2177idle");
    quick_select(&mut client, "2177idle");

    let mut idler = setup.connect("2177idler");
    quick_log_in(&mut idler);
    quick_select(&mut idler, "2177idle");

    idler.write_raw(b"I1 IDLE\r\n").unwrap();
    let mut buffer = Vec::new();
    idler.read_logical_line(&mut buffer).unwrap();
    assert!(buffer.starts_with(b"+ "));

    quick_append_enron(&mut client, "2177idle", 1);

    buffer.clear();
    let response = idler.read_one_response(&mut buffer).unwrap();
    assert_matches!(
        s::ResponseLine {
            tag: None,
            response: s::Response::Exists(1),
        },
        response
    );

    buffer.clear();
    let response = idler.read_one_response(&mut buffer).unwrap();
    assert_matches!(s::ResponseLine {
        tag: None,
        response: s::Response::Recent(_),
    }, response);

    buffer.clear();
    let response = idler.read_one_response(&mut buffer).unwrap();
    assert_matches!(
        s::ResponseLine {
            tag: None,
            response: s::Response::Fetch(..),
        },
        response
    );

    ok_command!(client, c("STORE 1 +FLAGS (\\Flagged)"));

    buffer.clear();
    let response = idler.read_one_response(&mut buffer).unwrap();
    assert_matches!(
        s::ResponseLine {
            tag: None,
            response: s::Response::Fetch(..),
        },
        response
    );

    ok_command!(client, c("XVANQUISH 1"));

    buffer.clear();
    let response = idler.read_one_response(&mut buffer).unwrap();
    assert_matches!(
        s::ResponseLine {
            tag: None,
            response: s::Response::Expunge(1),
        },
        response
    );

    idler.write_raw(b"DONE\r\n").unwrap();
    buffer.clear();
    let response = idler.read_one_response(&mut buffer).unwrap();
    assert_tagged_ok(response);

    ok_command!(idler, c("NOOP"));
}
