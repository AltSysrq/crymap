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
    test_require_capability("8438capa", "STATUS=SIZE");
}

#[test]
fn size_is_reported_and_correct_lower_bound() {
    let setup = set_up();
    let mut client = setup.connect("8438size");
    quick_log_in(&mut client);
    examine_shared(&mut client);

    command!(mut responses = client, c("STATUS shared (SIZE)"));
    assert_tagged_ok_any(responses.pop().unwrap());
    let approx_size = has_untagged_response_matching! {
        s::Response::Status(ref sr) in responses => {
            assert_eq!(1, sr.atts.len());
            match sr.atts[0] {
                s::StatusResponseAtt::Size(size) => size,
                ref a => panic!("Unexpected attribute: {:?}", a),
            }
        }
    };

    command!(mut responses = client, c("FETCH 1:* RFC822.SIZE"));
    assert_tagged_ok_any(responses.pop().unwrap());
    let actual_size = responses
        .into_iter()
        .filter_map(|r| {
            if let s::ResponseLine {
                tag: None,
                response: s::Response::Fetch(fr),
            } = r
            {
                has_msgatt_matching! {
                    s::MsgAtt::Rfc822Size(sz) in fr => Some(sz as u64)
                }
            } else {
                None
            }
        })
        .sum::<u64>();

    assert!(actual_size <= approx_size);
}
