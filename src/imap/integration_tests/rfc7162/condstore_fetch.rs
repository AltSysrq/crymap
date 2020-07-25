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
use super::extract_highest_modseq;

#[test]
fn condstore_fetch() {
    let setup = set_up();
    let mut client = setup.connect("7162cfcf");
    quick_log_in(&mut client);
    quick_create(&mut client, "7162cfcf");
    quick_append_enron(&mut client, "7162cfcf", 2);

    command!(mut responses = client, c("SELECT 7162cfcf (CONDSTORE)"));
    assert_tagged_ok_any(responses.pop().unwrap());
    let max_modseq = extract_highest_modseq(&responses);

    command!(mut responses = client, c("FETCH 1:* UID (CHANGEDSINCE 0)"));
    assert_eq!(3, responses.len());
    assert_tagged_ok(responses.pop().unwrap());

    // CHANGEDSINCE implicitly includes MODSEQ
    has_untagged_response_matching! {
        s::Response::Fetch(ref fr @ s::FetchResponse {
            seqnum: 1,
            ..
        }) in responses => {
            has_msgatt_matching! {
                s::MsgAtt::Modseq(m) in fr => {
                    assert!(m < max_modseq);
                }
            };
        }
    };
    has_untagged_response_matching! {
        s::Response::Fetch(ref fr @ s::FetchResponse {
            seqnum: 2,
            ..
        }) in responses => {
            has_msgatt_matching! {
                s::MsgAtt::Modseq(m) in fr => {
                    assert_eq!(max_modseq, m);
                }
            };
        }
    };

    command!(mut responses = client, c("FETCH 1 MODSEQ"));
    assert_eq!(2, responses.len());
    assert_tagged_ok(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Fetch(ref fr @ s::FetchResponse {
            seqnum: 1,
            ..
        }) in responses => {
            has_msgatt_matching! {
                s::MsgAtt::Modseq(m) in fr => {
                    assert!(m < max_modseq);
                }
            };
        }
    };

    // CHANGEDSINCE equal to max_modseq excludes everything
    command!(mut responses = client, cb(&format!(
        "FETCH 1:* UID (CHANGEDSINCE {})", max_modseq
    )));
    assert_eq!(1, responses.len());
    assert_tagged_ok(responses.pop().unwrap());

    ok_command!(client, c("STORE 1 +FLAGS (\\deleted)"));

    // Now that we changed message 1, it is returned with the same CHANGEDSINCE
    // filter
    command!(mut responses = client, cb(&format!(
        "FETCH 1:* UID (CHANGEDSINCE {})", max_modseq
    )));
    assert_eq!(2, responses.len());
    assert_tagged_ok(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Fetch(ref fr @ s::FetchResponse {
            seqnum: 1,
            ..
        }) in responses => {
            has_msgatt_matching! {
                s::MsgAtt::Modseq(m) in fr => {
                    assert!(m > max_modseq);
                }
            };
        }
    };
}
