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
fn capabilities_declared() {
    test_require_capability("6154capa", "SPECIAL-USE");
}

#[test]
fn list_special_use() {
    let setup = set_up();
    let mut client = setup.connect("6154list");
    quick_log_in(&mut client);
    quick_create(&mut client, "Spam2");

    command!(mut responses = client, c("LIST (SPECIAL-USE) \"\" %"));
    assert_tagged_ok(responses.pop().unwrap());
    assert_eq!(
        "Archive \\Archive\n\
         Drafts \\Drafts\n\
         Sent \\Sent\n\
         Spam \\Junk\n\
         Trash \\Trash\n",
        list_results_to_str(responses)
    );

    command!(mut responses = client, c("LIST \"\" Spa% RETURN (SPECIAL-USE)"));
    assert_tagged_ok(responses.pop().unwrap());
    assert_eq!(
        "Spam \\Junk\n\
         Spam2\n",
        list_results_to_str(responses)
    );
}
