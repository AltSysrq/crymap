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
fn condstore_status_highest_modseq() {
    let setup = set_up();
    let mut client = setup.connect("7162cshm");
    quick_log_in(&mut client);
    quick_create(&mut client, "7162cshm");

    command!(mut responses = client, c("STATUS 7162cshm (HIGHESTMODSEQ)"));
    assert_tagged_ok_any(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Status(ref sr) in responses => {
            assert_eq!(1, sr.atts.len());
            assert_eq!(s::StatusAtt::HighestModseq, sr.atts[0].att);
            assert_eq!(1, sr.atts[0].value);
        }
    };

    quick_append_enron(&mut client, "7162cshm", 1);

    command!(mut responses = client, c("STATUS 7162cshm (HIGHESTMODSEQ)"));
    assert_tagged_ok_any(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Status(ref sr) in responses => {
            assert_eq!(1, sr.atts.len());
            assert_eq!(s::StatusAtt::HighestModseq, sr.atts[0].att);
            assert!(sr.atts[0].value > 1);
        }
    };
}
