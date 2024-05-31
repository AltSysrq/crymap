//-
// Copyright (c) 2020, 2023, Jason Lingle
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

use std::io::Write;

use super::defs::*;
use crate::test_data::*;

#[test]
fn capability_declared() {
    test_require_capability("4978capa", "COMPRESS=DEFLATE");
}

#[test]
fn compress() {
    let setup = set_up();
    let mut client = setup.connect("4978comp");

    ok_command!(client, c("COMPRESS DEFLATE"));
    let mut client = client.compress();

    ok_command!(client, c("LOGIN azure hunter2"));
    command!(mut responses = client, c("SELECT INBOX"));
    assert_tagged_ok_any(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Exists(0) in responses
    };

    command!([response] = client, c("COMPRESS DEFLATE"));
    assert_matches!(
        s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::No,
            code: Some(s::RespTextCode::CompressionActive(())),
            quip: _,
        }),
        response.response
    );
}

#[test]
fn pipelined_append() {
    let setup = set_up();
    let mut client = setup.connect("4978pipe");

    ok_command!(client, c("COMPRESS DEFLATE"));
    let mut client = client.compress();

    ok_command!(client, c("LOGIN azure hunter2"));
    ok_command!(client, c("CREATE 4978pipe"));
    ok_command!(client, c("SELECT 4978pipe"));

    // Throw a bunch of data at the server at once. This causes a situation
    // where the first bit of the APPEND literals are in the text buffer, and
    // the follow-up pipelined FETCH command will be in the compression buffer
    // when the last literal is read.
    let mut pipelined_data = Vec::<u8>::new();
    write!(
        pipelined_data,
        "A APPEND 4978pipe {{{}+}}\r\n",
        TORTURE_TEST.len(),
    )
    .unwrap();
    pipelined_data.extend_from_slice(TORTURE_TEST);
    write!(pipelined_data, " {{{}+}}\r\n", CHRISTMAS_TREE.len()).unwrap();
    pipelined_data.extend_from_slice(CHRISTMAS_TREE);
    write!(pipelined_data, "\r\n").unwrap();
    write!(pipelined_data, "B FETCH 1:2 RFC822\r\n").unwrap();
    // This should work because the server buffers several responses before it
    // stops processing inputs, so the fact that we aren't reading our own
    // input while sending this won't cause a deadlock.
    client.write_raw(&pipelined_data).unwrap();

    let mut buffer = Vec::new();
    let mut append_responses =
        client.read_responses_until_tagged(&mut buffer).unwrap();
    assert_tagged_ok_any(append_responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Exists(2) in append_responses
    };

    let mut fetch_responses =
        client.read_responses_until_tagged(&mut buffer).unwrap();
    assert_tagged_ok_any(fetch_responses.pop().unwrap());

    let mut has_torture_test = false;
    let mut has_christmas_tree = false;
    for response in fetch_responses {
        let s::Response::Fetch(fetch) = response.response else {
            continue;
        };

        let Some(mut body) =
            fetch.atts.atts.into_iter().find_map(|att| match att {
                s::MsgAtt::Rfc822Full(body) => Some(body),
                _ => None,
            })
        else {
            continue;
        };

        let mut data = Vec::<u8>::new();
        body.data.read_to_end(&mut data).unwrap();

        match fetch.seqnum {
            1 => {
                assert!(!has_torture_test);
                has_torture_test = true;
                assert!(
                    TORTURE_TEST == data.as_slice(),
                    "TORTURE_TEST was corrupted",
                );
            },

            2 => {
                assert!(!has_christmas_tree);
                has_christmas_tree = true;
                assert!(
                    CHRISTMAS_TREE == data.as_slice(),
                    "CHRISTMAS_TREE was corrupted",
                );
            },

            n => panic!("unexpected seqnum {n}"),
        };
    }

    assert!(has_torture_test);
    assert!(has_christmas_tree);
}
