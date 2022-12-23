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

// Current as of IMAP4rev2 2020-07 draft

use super::defs::*;

#[test]
fn capability_declared() {
    test_require_capability("i4r2capa", "IMAP4rev2");
}

#[test]
fn status_deleted() {
    let setup = set_up();
    let mut client = setup.connect("i4r2stde");
    quick_log_in(&mut client);
    ok_command!(client, c("ENABLE IMAP4rev2"));
    quick_create(&mut client, "i4r2stde");
    quick_append_enron(&mut client, "i4r2stde", 3);
    quick_select(&mut client, "i4r2stde");

    ok_command!(client, c("STORE 2:3 +FLAGS \\Deleted"));

    command!(mut responses = client, c("STATUS i4r2stde (DELETED)"));
    assert_eq!(2, responses.len());
    assert_tagged_ok_any(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Status(ref sr) in responses => {
            assert_eq!(1, sr.atts.len());
            match sr.atts[0] {
                s::StatusResponseAtt::Deleted(n) => {
                    assert_eq!(2, n);
                }
                ref a => panic!("Unexpected attribute: {:?}", a),
            }
        }
    };
}

#[test]
fn unicode_enabled() {
    let setup = set_up();
    let mut client = setup.connect("i4r2unic");
    quick_log_in(&mut client);
    ok_command!(client, c("ENABLE IMAP4rev2"));
    quick_create(&mut client, "i4r2unic/ünicöde");

    command!(mut responses = client, c("LIST \"\" i4r2unic/%"));
    assert_eq!(2, responses.len());
    assert_tagged_ok_any(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::List(ref ml) in responses => {
            assert_eq!("i4r2unic/ünicöde", ml.name.raw);
        }
    };
}

#[test]
fn esearch_replaces_search() {
    let setup = set_up();
    let mut client = setup.connect("i4r2srch");
    quick_log_in(&mut client);
    ok_command!(client, c("ENABLE IMAP4rev2"));
    examine_shared(&mut client);

    command!(mut responses = client, c("SEARCH HEADER x-origin dasovich-j"));
    assert_eq!(2, responses.len());
    assert_tagged_ok(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Esearch(s::EsearchResponse {
            uid: false,
            all: Some(_),
            ..
        }) in responses
    };

    command!(mut responses = client, c("UID SEARCH HEADER x-origin dasovich-j"));
    assert_eq!(2, responses.len());
    assert_tagged_ok(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Esearch(s::EsearchResponse {
            uid: true,
            all: Some(_),
            ..
        }) in responses
    };
}
