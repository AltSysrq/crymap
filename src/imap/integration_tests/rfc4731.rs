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
    test_require_capability("4731capa", "ESEARCH");
}

#[test]
fn test_esearch() {
    let setup = set_up();
    let mut client = setup.connect("4731esrc");
    quick_log_in(&mut client);
    examine_shared(&mut client);

    // RETURN () results in vanilla SEARCH
    command!(mut responses = client, c("SEARCH RETURN () ALL"));
    assert_eq!(2, responses.len());
    assert_tagged_ok(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Search(..) in responses
    };

    esearch_eq(
        s::EsearchResponse {
            tag: Cow::Borrowed(""),
            uid: false,
            min: Some(3),
            max: None,
            all: None,
            count: None,
            modseq: None,
        },
        &mut client,
        "SEARCH RETURN (MIN) 3:5",
    );
    esearch_eq(
        s::EsearchResponse {
            tag: Cow::Borrowed(""),
            uid: false,
            min: None,
            max: Some(5),
            all: None,
            count: None,
            modseq: None,
        },
        &mut client,
        "SEARCH RETURN (MAX) 3:5",
    );
    esearch_eq(
        s::EsearchResponse {
            tag: Cow::Borrowed(""),
            uid: false,
            min: None,
            max: None,
            all: Some(Cow::Borrowed("3:5")),
            count: None,
            modseq: None,
        },
        &mut client,
        "SEARCH RETURN (ALL) 3:5",
    );
    esearch_eq(
        s::EsearchResponse {
            tag: Cow::Borrowed(""),
            uid: false,
            min: None,
            max: None,
            all: None,
            count: Some(3),
            modseq: None,
        },
        &mut client,
        "SEARCH RETURN (COUNT) 3:5",
    );
    esearch_eq(
        s::EsearchResponse {
            tag: Cow::Borrowed(""),
            uid: true,
            min: Some(3),
            max: Some(7),
            all: Some(Cow::Borrowed("3:5,7")),
            count: Some(4),
            modseq: None,
        },
        &mut client,
        "UID SEARCH RETURN (COUNT MIN MAX ALL) 3:6",
    );
}

#[test]
fn condstore_interaction() {
    let setup = set_up();
    let mut client = setup.connect("4731csia");
    quick_log_in(&mut client);
    examine_shared(&mut client);

    command!(responses = client, c("FETCH 1,21 MODSEQ"));
    let max_modseq = has_untagged_response_matching! {
        s::Response::Cond(s::CondResponse {
            code: Some(s::RespTextCode::HighestModseq(m)),
            ..
        }) in responses => m
    };
    let first_modseq = has_untagged_response_matching! {
        s::Response::Fetch(ref fr @ s::FetchResponse {
            seqnum: 1,
            ..
        }) in responses => {
            has_msgatt_matching! {
                s::MsgAtt::Modseq(m) in fr => m
            }
        }
    };
    let last_modseq = has_untagged_response_matching! {
        s::Response::Fetch(ref fr @ s::FetchResponse {
            seqnum: 21,
            ..
        }) in responses => {
            has_msgatt_matching! {
                s::MsgAtt::Modseq(m) in fr => m
            }
        }
    };

    esearch_eq(
        s::EsearchResponse {
            tag: Cow::Borrowed(""),
            uid: false,
            min: None,
            max: None,
            all: Some(Cow::Borrowed("1:21")),
            count: None,
            modseq: Some(max_modseq),
        },
        &mut client,
        "SEARCH RETURN (ALL) 1:* MODSEQ 1",
    );
    esearch_eq(
        s::EsearchResponse {
            tag: Cow::Borrowed(""),
            uid: false,
            min: None,
            max: None,
            all: None,
            count: Some(21),
            modseq: Some(max_modseq),
        },
        &mut client,
        "SEARCH RETURN (COUNT) 1:* MODSEQ 1",
    );
    esearch_eq(
        s::EsearchResponse {
            tag: Cow::Borrowed(""),
            uid: false,
            min: Some(1),
            max: None,
            all: None,
            count: None,
            modseq: Some(first_modseq),
        },
        &mut client,
        "SEARCH RETURN (MIN) 1:* MODSEQ 1",
    );
    esearch_eq(
        s::EsearchResponse {
            tag: Cow::Borrowed(""),
            uid: false,
            min: None,
            max: Some(21),
            all: None,
            count: None,
            modseq: Some(last_modseq),
        },
        &mut client,
        "SEARCH RETURN (MAX) 1:* MODSEQ 1",
    );
    esearch_eq(
        s::EsearchResponse {
            tag: Cow::Borrowed(""),
            uid: false,
            min: Some(1),
            max: Some(21),
            all: None,
            count: None,
            modseq: Some(first_modseq.max(last_modseq)),
        },
        &mut client,
        "SEARCH RETURN (MAX MIN) 1:* MODSEQ 1",
    );
    esearch_eq(
        s::EsearchResponse {
            tag: Cow::Borrowed(""),
            uid: false,
            min: Some(1),
            max: Some(21),
            all: None,
            count: Some(21),
            modseq: Some(max_modseq),
        },
        &mut client,
        "SEARCH RETURN (MAX COUNT MIN) 1:* MODSEQ 1",
    );
}

fn esearch_eq(
    mut expected: s::EsearchResponse<'_>,
    client: &mut PipeClient,
    command: &str,
) {
    command!(mut responses = client, cb(command));
    assert_eq!(2, responses.len());
    assert_tagged_ok(responses.pop().unwrap());

    match responses.pop().unwrap() {
        s::ResponseLine {
            tag: None,
            response: s::Response::Esearch(er),
        } => {
            expected.tag = Cow::Owned(er.tag.clone().into_owned());
            assert_eq!(expected, er);
        },

        r => panic!("Unexpected response: {:?}", r),
    }
}
