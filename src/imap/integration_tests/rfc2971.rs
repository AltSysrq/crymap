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
    test_require_capability("2971capa", "ID");
}

#[test]
fn command_works() {
    let setup = set_up();
    let mut client = setup.connect("2971test");

    command!(mut responses = client,
             c(r#"ID ("name" "test" "version" "1.0")"#));
    assert_tagged_ok(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Id(ref ids) in responses => {
            assert!(ids.contains(&Some(Cow::Borrowed("name"))));
            assert!(ids.contains(&Some(Cow::Borrowed(env!("CARGO_PKG_NAME")))));
        }
    };

    // Check some corner cases
    // New connection each time to ensure we go through the full logic
    client = setup.connect("2971test");
    ok_command!(client, c("ID NIL"));

    client = setup.connect("2971test");
    ok_command!(client, c(r#"ID ("name" NIL "version" "0.1")"#));

    client = setup.connect("2971test");
    ok_command!(client, c(r#"ID ("name" "foo" "version" NIL)"#));

    client = setup.connect("2971test");
    ok_command!(client, c(r#"ID ("name" "foo" "x-foo" "bar")"#));
}
