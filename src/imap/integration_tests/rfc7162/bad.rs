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

#[test]
fn condstore_bad_usage() {
    let setup = set_up();
    let mut client = setup.connect("7162bacs");
    quick_log_in(&mut client);

    assert_bad_command(
        &mut client,
        Some(s::RespTextCode::ClientBug(())),
        "SELECT INBOX (CONDSTORE CONDSTORE)",
    );

    quick_select(&mut client, "INBOX");
    assert_bad_command(
        &mut client,
        Some(s::RespTextCode::ClientBug(())),
        "FETCH 1 UID (CHANGEDSINCE 1 CHANGEDSINCE 2)",
    );
}

#[test]
fn qresync_bad_usage() {
    let setup = set_up();
    let mut client = setup.connect("7162baqr");
    quick_log_in(&mut client);

    // Using QRESYNC without enabling it is forbidden
    assert_bad_command(
        &mut client,
        Some(s::RespTextCode::ClientBug(())),
        "SELECT INBOX (QRESYNC (1 2))",
    );
    quick_select(&mut client, "INBOX");
    assert_bad_command(
        &mut client,
        Some(s::RespTextCode::ClientBug(())),
        "UID FETCH 1 UID (CHANGEDSINCE 1 VANISHED)",
    );

    // New client to get to known state and since, strictly speaking, ENABLE is
    // not allowed after selecting something
    let mut client = setup.connect("7162baqr");
    quick_log_in(&mut client);
    ok_command!(client, c("ENABLE QRESYNC"));

    assert_bad_command(
        &mut client,
        Some(s::RespTextCode::Parse(())),
        "SELECT INBOX (QRESYNC (1 2 1:*))",
    );
    assert_bad_command(
        &mut client,
        Some(s::RespTextCode::Parse(())),
        "SELECT INBOX (QRESYNC (1 2 :1))",
    );
    assert_bad_command(
        &mut client,
        Some(s::RespTextCode::ClientBug(())),
        "SELECT INBOX (QRESYNC (1 2 (1:3 1:2)))",
    );
    assert_bad_command(
        &mut client,
        Some(s::RespTextCode::ClientBug(())),
        "SELECT INBOX (QRESYNC (1 2) QRESYNC (1 2))",
    );

    quick_select(&mut client, "INBOX");

    assert_bad_command(
        &mut client,
        Some(s::RespTextCode::ClientBug(())),
        "UID FETCH 1 UID (VANISHED)",
    );
    assert_bad_command(
        &mut client,
        Some(s::RespTextCode::ClientBug(())),
        "UID FETCH 1 UID (CHANGEDSINCE 1 VANISHED VANISHED)",
    );
    assert_bad_command(
        &mut client,
        Some(s::RespTextCode::ClientBug(())),
        "FETCH 1 UID (CHANGEDSINCE 1 VANISHED)",
    );
}
