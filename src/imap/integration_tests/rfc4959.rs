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
    test_require_capability("4959capa", "SASL-IR");
}

#[test]
fn sasl_ir() {
    let setup = set_up();
    let mut client = setup.connect("4959sair");
    skip_greeting(&mut client);

    // azure\0azure\0hunter2
    client
        .write_raw(b"A1 AUTHENTICATE PLAIN YXp1cmUAYXp1cmUAaHVudGVyMg==\r\n")
        .unwrap();

    let mut buffer = Vec::new();
    let response = client.read_one_response(&mut buffer).unwrap();
    unpack_cond_response! {
        (Some(_), s::RespCondType::Ok, _, _) = response => ()
    };

    // Make sure we actually logged in
    ok_command!(client, c("EXAMINE INBOX"));
}
