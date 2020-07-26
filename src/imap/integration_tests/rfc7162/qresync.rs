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
fn capability_declared() {
    test_require_capability("7162qrca", "QRESYNC");
}

#[test]
fn qresync_select() {
    let setup = set_up();
    let mut client = setup.connect("7162qrqs");
    quick_log_in(&mut client);
    quick_create(&mut client, "7162qrqs");
    quick_append_enron(&mut client, "7162qrqs", 10);

    ok_command!(client, c("ENABLE QRESYNC"));

    command!(responses = client, c("STATUS 7162qrqs (UIDVALIDITY)"));
    let uid_validity = has_untagged_response_matching! {
        s::Response::Status(ref s) in responses => {
            s.atts[0].value as u32
        }
    };

    command!(mut responses = client, c("SELECT 7162qrqs"));
    assert_tagged_ok_any(responses.pop().unwrap());
    let modseq_after_append = extract_highest_modseq(&responses);

    command!(mut responses = client, c("XVANQUISH 3,7"));
    assert_tagged_ok_any(responses.pop().unwrap());

    command!(mut responses = client, c("UID STORE 4 +FLAGS (keyword)"));
    assert_tagged_ok_any(responses.pop().unwrap());
    let modseq_after_store = extract_highest_modseq(&responses);

    // QRESYNC using just the UV and modseq_after_append will give us the two
    // vanished messages and one FETCH
    command!(mut responses = client, cb(&format!(
        "SELECT 7162qrqs (QRESYNC ({} {}))",
        uid_validity,
        modseq_after_append,
    )));
    assert_tagged_ok_any(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Vanished(ref vr) in responses => {
            assert!(vr.earlier);
            assert_eq!("3,7", &vr.uids);
        }
    };
    has_untagged_response_matching! {
        s::Response::Fetch(s::FetchResponse {
            // UID 3 is gone, so seqnum 3 is UID 4
            seqnum: 3,
            ..
        }) in responses
    };
    // Also ensure we got the CLOSED response, which must have been the first
    // one
    has_untagged_response_matching! {
        s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Ok,
            code: Some(s::RespTextCode::Closed(())),
            quip: _,
        }) in &responses[..1]
    };

    // QRESYNC using the UV and the latest modseq gives no results
    command!(mut responses = client, cb(&format!(
        "SELECT 7162qrqs (QRESYNC ({} {}))",
        uid_validity,
        modseq_after_store,
    )));
    assert_tagged_ok_any(responses.pop().unwrap());
    for response in responses {
        if matches!(response.response, s::Response::Vanished(_))
            || matches!(response.response, s::Response::Fetch(_))
        {
            panic!("Unexpected response: {:?}", response);
        }
    }

    // QRESYNC with the wrong UV also gives no results
    command!(mut responses = client, cb(&format!(
        "SELECT 7162qrqs (QRESYNC ({} {}))",
        uid_validity ^ 1,
        modseq_after_append,
    )));
    assert_tagged_ok_any(responses.pop().unwrap());
    for response in responses {
        if matches!(response.response, s::Response::Vanished(_))
            || matches!(response.response, s::Response::Fetch(_))
        {
            panic!("Unexpected response: {:?}", response);
        }
    }

    // The optional third parameter lets us filter to just those messages
    command!(mut responses = client, cb(&format!(
        "SELECT 7162qrqs (QRESYNC ({} {} 4:7))",
        uid_validity,
        modseq_after_append,
    )));
    assert_tagged_ok_any(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Vanished(ref vr) in responses => {
            assert!(vr.earlier);
            assert_eq!("7", &vr.uids);
        }
    };
    has_untagged_response_matching! {
        s::Response::Fetch(s::FetchResponse {
            // UID 3 is gone, so seqnum 3 is UID 4
            seqnum: 3,
            ..
        }) in responses
    };

    // A request with modseq 1 would normally dump all expunges from all time,
    // since it predates the first expunge we remember. However, the optional
    // fourth parameter lets us provide enough correlation to the server for it
    // to figure out that we already know about 3's demise.
    command!(mut responses = client, cb(&format!(
        "SELECT 7162qrqs (QRESYNC ({} 1 (1,3,9 1,4,10)))",
        uid_validity,
    )));
    assert_tagged_ok_any(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Vanished(ref vr) in responses => {
            assert!(vr.earlier);
            assert_eq!("7", &vr.uids);
        }
    };
    has_untagged_response_matching! {
        s::Response::Fetch(s::FetchResponse {
            // UID 3 is gone, so seqnum 3 is UID 4
            seqnum: 3,
            ..
        }) in responses
    };
}

#[test]
fn qresync_expunge() {
    let setup = set_up();
    let mut client = setup.connect("7162qrex");
    quick_log_in(&mut client);
    quick_create(&mut client, "7162qrex");
    quick_append_enron(&mut client, "7162qrex", 3);

    ok_command!(client, c("ENABLE QRESYNC"));
    quick_select(&mut client, "7162qrex");
    ok_command!(client, c("UID STORE 1:3 +FLAGS (\\Deleted)"));

    command!(mut responses = client, c("UID EXPUNGE 1:3"));
    // UID EXPUNGE is special in that it also has HIGHESTMODSEQ on the tagged
    // response
    unpack_cond_response! {
        (Some(_), s::RespCondType::Ok,
         Some(s::RespTextCode::HighestModseq(_)), _) = responses.pop().unwrap()
    };
    has_untagged_response_matching! {
        s::Response::Vanished(ref vr) in responses => {
            assert!(!vr.earlier);
            assert_eq!("1:3", &vr.uids);
        }
    };

    // EXPUNGE is similarly special
    quick_append_enron(&mut client, "7162qrex", 1);
    ok_command!(client, c("STORE 1:* +FLAGS (\\Deleted)"));
    command!(mut responses = client, c("EXPUNGE"));
    unpack_cond_response! {
        (Some(_), s::RespCondType::Ok,
         Some(s::RespTextCode::HighestModseq(_)), _) = responses.pop().unwrap()
    };
    has_untagged_response_matching! {
        s::Response::Vanished(ref vr) in responses => {
            assert!(!vr.earlier);
            assert_eq!("4", &vr.uids);
        }
    };
}

#[test]
fn qresync_delayed_vanished() {
    let setup = set_up();
    let mut client = setup.connect("7162qrdv");
    quick_log_in(&mut client);
    quick_create(&mut client, "7162qrdv");
    quick_append_enron(&mut client, "7162qrdv", 2);

    ok_command!(client, c("ENABLE QRESYNC"));
    quick_select(&mut client, "7162qrdv");

    let mut client2 = setup.connect("7162qrdv2");
    quick_log_in(&mut client2);
    quick_select(&mut client2, "7162qrdv");
    ok_command!(client2, c("XVANQUISH 1"));

    // The original client now makes a cursed command that causes the server to
    // become aware of 1's expungement but unable to report it. The server
    // needs to send a HIGHESTMODSEQ lower than the MODSEQ on the fetch
    // response returned here to ensure the client does not use the new MODSEQ
    // for a later QRESYNC operation.
    command!(mut responses = client, c("STORE 2 +FLAGS (keyword)"));
    assert_tagged_ok_any(responses.pop().unwrap());
    let reported_max_modseq = extract_highest_modseq(&responses);
    has_untagged_response_matching! {
        s::Response::Fetch(ref fr) in responses => {
            has_msgatt_matching! {
                s::MsgAtt::Modseq(m) in fr => {
                    assert!(reported_max_modseq < m);
                }
            };
        }
    };
}

#[test]
fn qresync_fetch_vanished() {
    let setup = set_up();
    let mut client = setup.connect("7162qrfv");
    quick_log_in(&mut client);
    quick_create(&mut client, "7162qrfv");
    quick_append_enron(&mut client, "7162qrfv", 2);

    ok_command!(client, c("ENABLE QRESYNC"));
    quick_select(&mut client, "7162qrfv");

    command!(responses = client, c("XVANQUISH 1"));
    let first_expunged = extract_highest_modseq(&responses);

    command!(responses = client, c("XVANQUISH 2"));
    let second_expunged = extract_highest_modseq(&responses);

    command!(mut responses = client, c(
        "UID FETCH 1:2 ALL (CHANGEDSINCE 1 VANISHED)"
    ));
    assert_eq!(2, responses.len());
    assert_tagged_ok_any(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Vanished(ref vr) in responses => {
            assert!(vr.earlier);
            assert_eq!("1:2", &vr.uids);
        }
    };

    command!(mut responses = client, cb(&format!(
        "UID FETCH 1:2 ALL (CHANGEDSINCE {} VANISHED)",
        first_expunged,
    )));
    assert_eq!(2, responses.len());
    assert_tagged_ok_any(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Vanished(ref vr) in responses => {
            assert!(vr.earlier);
            assert_eq!("2", &vr.uids);
        }
    };

    command!(mut responses = client, cb(&format!(
        "UID FETCH 1:2 ALL (CHANGEDSINCE {} VANISHED)",
        second_expunged,
    )));
    assert_eq!(1, responses.len());
    assert_tagged_ok_any(responses.pop().unwrap());
}
