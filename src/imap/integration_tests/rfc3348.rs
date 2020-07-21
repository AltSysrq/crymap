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
    test_require_capability("3348capa", "CHILDREN");
}

#[test]
fn children_attributes_returned() {
    let setup = set_up();
    let mut client = setup.connect("3348attr");
    quick_log_in(&mut client);
    quick_create(&mut client, "3348attr/foo");
    quick_create(&mut client, "3348attr/bar");
    quick_create(&mut client, "3348attr/bar/baz");

    command!(mut responses = client, c("LIST \"\" 3348attr*"));
    assert_tagged_ok(responses.pop().unwrap());
    assert_eq!(
        "3348attr \\HasChildren\n\
         3348attr/bar \\HasChildren\n\
         3348attr/bar/baz \\HasNoChildren\n\
         3348attr/foo \\HasNoChildren\n",
        list_results_to_str(responses)
    );

    command!(mut responses = client, c("LIST \"\" INBOX"));
    assert_tagged_ok(responses.pop().unwrap());
    // RFC 3348 does not explicitly say that clients need to infer
    // \HasNoChildren from \Noinferiors (while RFC 5258 does require it).
    // However, RFC 3348 allows us to return neither child marker, and does
    // weakly imply that clients should infer the absence of children from
    // \Noinferiors.
    assert_eq!("INBOX \\Noinferiors\n", list_results_to_str(responses));
}
