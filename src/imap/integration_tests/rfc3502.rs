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

use chrono::prelude::*;

use super::defs::*;
use crate::account::model::Flag;
use crate::test_data::*;

#[test]
fn capability_declared() {
    test_require_capability("3502capa", "MULTIAPPEND");
}

#[test]
fn happy_paths() {
    let setup = set_up();
    let mut client = setup.connect("3502hapy");
    quick_log_in(&mut client);
    quick_create(&mut client, "3502hapy");
    quick_select(&mut client, "3502hapy");

    client
        .start_append("3502hapy", s::AppendFragment::default(), CHRISTMAS_TREE)
        .unwrap();
    client
        .append_item(s::AppendFragment::default(), ENRON_SMALL_MULTIPARTS[0])
        .unwrap();
    client
        .append_item(s::AppendFragment::default(), ENRON_SMALL_MULTIPARTS[1])
        .unwrap();

    let mut buffer = Vec::new();
    let mut responses = client.finish_append(&mut buffer).unwrap();
    assert_tagged_ok_any(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Exists(3) in responses
    };
    has_untagged_response_matching! {
        s::Response::Recent(3) in responses
    };

    client
        .start_append(
            "3502hapy",
            s::AppendFragment {
                flags: Some(vec![Flag::Draft, Flag::Seen]),
                ..s::AppendFragment::default()
            },
            ENRON_SMALL_MULTIPARTS[2],
        )
        .unwrap();
    client
        .append_item(
            s::AppendFragment {
                flags: Some(vec![Flag::Answered]),
                internal_date: Some(
                    FixedOffset::east(0)
                        .from_utc_datetime(&Utc::now().naive_local()),
                ),
                ..s::AppendFragment::default()
            },
            ENRON_SMALL_MULTIPARTS[3],
        )
        .unwrap();
    let mut buffer = Vec::new();
    let mut responses = client.finish_append(&mut buffer).unwrap();
    assert_tagged_ok_any(responses.pop().unwrap());

    has_untagged_response_matching! {
        s::Response::Exists(5) in responses
    };

    has_untagged_response_matching! {
        s::Response::Fetch(ref fr @ s::FetchResponse {
            seqnum: 4,
            ..
        }) in responses => {
            has_msgatt_matching! {
                s::MsgAtt::Flags(s::FlagsFetch::Recent(ref flags)) in fr => {
                    assert_eq!(2, flags.len());
                    assert!(flags.contains(&Flag::Draft));
                    assert!(flags.contains(&Flag::Seen));
                }
            };
        }
    };

    has_untagged_response_matching! {
        s::Response::Fetch(ref fr @ s::FetchResponse {
            seqnum: 5,
            ..
        }) in responses => {
            has_msgatt_matching! {
                s::MsgAtt::Flags(s::FlagsFetch::Recent(ref flags)) in fr => {
                    assert_eq!(1, flags.len());
                    assert!(flags.contains(&Flag::Answered));
                }
            };
        }
    };
}

#[test]
fn literal_plus_interaction() {
    let setup = set_up();
    let mut client = setup.connect("3502lit+");
    quick_log_in(&mut client);
    quick_create(&mut client, "3502lit+");
    quick_select(&mut client, "3502lit+");

    client
        .write_raw(
            b"A1 APPEND 3502lit+ {3+}\r\n\
                       foo {4+}\r\n\
                       baar\r\n",
        )
        .unwrap();
    let mut buffer = Vec::new();
    let mut responses =
        client.read_responses_until_tagged(&mut buffer).unwrap();
    assert_tagged_ok_any(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Exists(2) in responses
    };
}

#[test]
fn abort_on_zero() {
    let setup = set_up();
    let mut client = setup.connect("3502abrt");
    quick_log_in(&mut client);
    quick_create(&mut client, "3502abrt");
    quick_select(&mut client, "3502abrt");

    client.write_raw(b"A1 APPEND 3502abrt {0}\r\n").unwrap();
    let mut buffer = Vec::new();
    let mut responses =
        client.read_responses_until_tagged(&mut buffer).unwrap();
    unpack_cond_response! {
        (Some(_), s::RespCondType::Bad, None, _) = responses.pop().unwrap()
    };

    client.write_raw(b"A2 APPEND 3502abrt {3}\r\n").unwrap();
    buffer.clear();
    client.read_logical_line(&mut buffer).unwrap();
    assert!(buffer.starts_with(b"+ "));

    client.write_raw(b"foo {0}\r\n").unwrap();
    buffer.clear();
    let mut responses =
        client.read_responses_until_tagged(&mut buffer).unwrap();
    unpack_cond_response! {
        (Some(_), s::RespCondType::Bad, None, _) = responses.pop().unwrap()
    };

    client
        .write_raw(
            b"A3 APPEND 3502abrt {0+}\r\n\
                       {3+}\r\n\
                       foo\r\n",
        )
        .unwrap();
    buffer.clear();
    let mut responses =
        client.read_responses_until_tagged(&mut buffer).unwrap();
    unpack_cond_response! {
        (Some(_), s::RespCondType::Bad, None, _) = responses.pop().unwrap()
    };

    client
        .write_raw(
            b"A4 APPEND 3502abrt {3+}\r\n\
                       foo {0+}\r\n\
                       {3+}\r\n\
                       bar\r\n",
        )
        .unwrap();
    buffer.clear();
    let mut responses =
        client.read_responses_until_tagged(&mut buffer).unwrap();
    unpack_cond_response! {
        (Some(_), s::RespCondType::Bad, None, _) = responses.pop().unwrap()
    };

    // Make sure nothing was written
    ok_command!(client, c("NOOP"));
    command!([response] = client, c("UID FETCH 1:* UID"));
    assert_tagged_ok(response);
}

#[test]
fn abort_on_over_length() {
    let setup = set_up();
    let mut client = setup.connect("3502maxl");
    quick_log_in(&mut client);
    quick_create(&mut client, "3502maxl");
    quick_select(&mut client, "3502maxl");

    client
        .write_raw(b"A1 APPEND 3502maxl {1000000000}\r\n")
        .unwrap();
    let mut buffer = Vec::new();
    let mut responses =
        client.read_responses_until_tagged(&mut buffer).unwrap();
    unpack_cond_response! {
        (Some(_), s::RespCondType::Bad,
         Some(s::RespTextCode::Limit(())), _) = responses.pop().unwrap()
    };

    client.write_raw(b"A2 APPEND 3502maxl {3}\r\n").unwrap();
    buffer.clear();
    client.read_logical_line(&mut buffer).unwrap();
    assert!(buffer.starts_with(b"+ "));

    client.write_raw(b"foo {1000000000}\r\n").unwrap();
    buffer.clear();
    let mut responses =
        client.read_responses_until_tagged(&mut buffer).unwrap();
    unpack_cond_response! {
        (Some(_), s::RespCondType::Bad,
         Some(s::RespTextCode::Limit(())), _) = responses.pop().unwrap()
    };
}

#[test]
fn syntax_errors_in_continuation() {
    let setup = set_up();
    let mut client = setup.connect("3502syne");
    quick_log_in(&mut client);
    quick_create(&mut client, "3502syne");
    quick_select(&mut client, "3502syne");

    client
        .write_raw(
            "A1 APPEND 3502syne {3+}\r\n\
                      foo ‽ {42}\r\n"
                .as_bytes(),
        )
        .unwrap();
    let mut buffer = Vec::new();
    let mut responses =
        client.read_responses_until_tagged(&mut buffer).unwrap();
    unpack_cond_response! {
        (Some(_), s::RespCondType::Bad,
         Some(s::RespTextCode::Parse(())), _) = responses.pop().unwrap()
    };

    ok_command!(client, c("NOOP"));

    client
        .write_raw(
            "A2 APPEND 3502syne {3+}\r\n\
                      foo bar\r\n"
                .as_bytes(),
        )
        .unwrap();
    buffer.clear();
    let mut responses =
        client.read_responses_until_tagged(&mut buffer).unwrap();
    unpack_cond_response! {
        (Some(_), s::RespCondType::Bad,
         Some(s::RespTextCode::Parse(())), _) = responses.pop().unwrap()
    };

    ok_command!(client, c("NOOP"));

    client
        .write_raw(
            "A2 APPEND 3502syne {3+}\r\n\
                      foo ‽{3+}\r\n\
                      bar\r\n"
                .as_bytes(),
        )
        .unwrap();
    buffer.clear();
    let mut responses =
        client.read_responses_until_tagged(&mut buffer).unwrap();
    unpack_cond_response! {
        (Some(_), s::RespCondType::Bad,
         Some(s::RespTextCode::Parse(())), _) = responses.pop().unwrap()
    };

    ok_command!(client, c("NOOP"));
}
