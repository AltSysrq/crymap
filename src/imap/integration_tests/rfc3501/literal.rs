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

use super::super::defs::*;

// This doesn't test APPEND with synchronising literals since all the tests
// that append messages already use it.
#[test]
fn command_synchronising_literals() {
    let setup = set_up();
    let mut client = setup.connect("3501lics");
    quick_log_in(&mut client);
    quick_select(&mut client, "INBOX");

    client.write_raw(b"A1 SEARCH TEXT {5}\r\n").unwrap();

    let mut buffer = Vec::new();
    client.read_logical_line(&mut buffer).unwrap();
    assert!(buffer.starts_with(b"+ "));

    client.write_raw(b"enron TEXT {5}\r\n").unwrap();
    buffer.clear();
    client.read_logical_line(&mut buffer).unwrap();
    assert!(buffer.starts_with(b"+ "));

    client.write_raw(b"plugh\r\n").unwrap();

    buffer.clear();
    let mut responses =
        client.read_responses_until_tagged(&mut buffer).unwrap();

    assert_tagged_ok(responses.pop().unwrap());

    // Server must not get confused by literal text itself ending with
    // something that looks like a literal.
    client.write_raw(b"A2 SEARCH TEXT {3}\r\n").unwrap();
    buffer.clear();
    client.read_logical_line(&mut buffer).unwrap();
    assert!(buffer.starts_with(b"+ "));

    client.write_raw(b"{3} TEXT {5}\r\n").unwrap();
    buffer.clear();
    client.read_logical_line(&mut buffer).unwrap();
    assert!(buffer.starts_with(b"+ "));

    client.write_raw(b"{3}\r\n\r\n").unwrap();

    buffer.clear();
    let mut responses =
        client.read_responses_until_tagged(&mut buffer).unwrap();

    assert_tagged_ok(responses.pop().unwrap());

    // Ensure the connection state is still consistent
    ok_command!(client, c("NOOP"));
}
