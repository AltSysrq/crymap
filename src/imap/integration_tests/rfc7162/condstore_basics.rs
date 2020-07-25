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

use super::super::defs::*;
use super::extract_highest_modseq;

#[test]
fn capability_declared() {
    test_require_capability("7162cbcd", "CONDSTORE");
}

#[test]
fn condstore_enable() {
    let setup = set_up();
    let mut client = setup.connect("7162cbce");
    skip_greeting(&mut client);

    command!(mut responses = client, c("ENABLE CONDSTORE"));
    assert_eq!(2, responses.len());
    assert_tagged_ok(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Enabled(ref what) in responses => {
            assert!(what.contains(&Cow::Borrowed("CONDSTORE")));
        }
    };
}

// Test that we get the primordial modseq of 1 when selecting an empty mailbox
#[test]
fn select_primordial() {
    let setup = set_up();
    let mut client = setup.connect("7162cbsp");
    quick_log_in(&mut client);
    quick_create(&mut client, "7162cbsp");

    command!(mut responses = client, c("SELECT 7162cbsp (CONDSTORE)"));
    assert_tagged_ok_any(responses.pop().unwrap());
    assert_eq!(1, extract_highest_modseq(&responses));
}
