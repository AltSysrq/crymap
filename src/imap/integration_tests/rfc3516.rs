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
use crate::account::model::Flag;
use crate::support::error::Error;
use crate::test_data::*;

#[test]
fn capability_declared() {
    test_require_capability("3516capa", "BINARY");
}

#[test]
fn binary_append() {
    let setup = set_up();
    let mut client = setup.connect("3516bapp");
    quick_log_in(&mut client);
    quick_create(&mut client, "3516bapp");

    client.write_raw(b"A1 APPEND 3516bapp ~{3}\r\n").unwrap();
    let mut buffer = Vec::new();
    client.read_logical_line(&mut buffer).unwrap();
    assert!(buffer.starts_with(b"+ "));

    client.write_raw(b"f\0o\r\n").unwrap();
    buffer.clear();
    let mut responses =
        client.read_responses_until_tagged(&mut buffer).unwrap();
    assert_tagged_ok_any(responses.pop().unwrap());

    client
        .write_raw(b"A2 APPEND 3516bapp ~{3+}\r\nb\xAAr\r\n")
        .unwrap();
    buffer.clear();
    let mut responses =
        client.read_responses_until_tagged(&mut buffer).unwrap();
    assert_tagged_ok_any(responses.pop().unwrap());

    ok_command!(client, c("NOOP"));
}

#[test]
fn fetch_binary_content() {
    let setup = set_up();
    let mut client = setup.connect("3516fetc");
    quick_log_in(&mut client);
    quick_create(&mut client, "3516fetc");

    client
        .start_append(
            "3516fetc",
            s::AppendFragment::default(),
            SINGLE_PART_BASE64,
        )
        .unwrap();
    client
        .append_item(s::AppendFragment::default(), MULTI_PART_BASE64)
        .unwrap();
    let mut buffer = Vec::new();
    let mut responses = client.finish_append(&mut buffer).unwrap();
    assert_tagged_ok_any(responses.pop().unwrap());

    quick_select(&mut client, "3516fetc");

    fetch_single!(client, c("FETCH 1 BINARY.PEEK[]"), fr => {
        has_msgatt_matching! {
            move s::MsgAtt::Body(s::MsgAttBody {
                kind: s::FetchAttBodyKind::Binary,
                section: None,
                slice_origin: None,
                data: lit
            }) in fr => {
                assert_literal_like(
                    b"From: from",
                    b"bGQ=\r\n",
                    218,
                    false,
                    lit);
            }
        };
    });

    fetch_single!(client, c("FETCH 1 BINARY.SIZE[]"), fr => {
        has_msgatt_matching! {
            move s::MsgAtt::BinarySize(s::MsgAttBinarySize {
                section: None,
                size: 218,
            }) in fr
        };
    });

    fetch_single!(client, c("FETCH 1 BINARY.PEEK[1]"), fr => {
        has_msgatt_matching! {
            move s::MsgAtt::Body(s::MsgAttBody {
                kind: s::FetchAttBodyKind::Binary,
                section: Some(s::SectionSpec::Sub(s::SubSectionSpec {
                    subscripts,
                    text: None,
                })),
                slice_origin: None,
                data: lit
            }) in fr => {
                assert_eq!(vec![1], subscripts);
                assert_literal_like(
                    b"hello ",
                    b"world",
                    11,
                    false,
                    lit);
            }
        };
    });

    fetch_single!(client, c("FETCH 1 BINARY.SIZE[1]"), fr => {
        has_msgatt_matching! {
            move s::MsgAtt::BinarySize(s::MsgAttBinarySize {
                section: Some(s::SectionSpec::Sub(s::SubSectionSpec {
                    subscripts,
                    text: None,
                })),
                size: 11,
            }) in fr => {
                assert_eq!(vec![1], subscripts);
            }
        };
    });

    fetch_single!(client, c("FETCH 1 BINARY.PEEK[1]<2.3>"), fr => {
        has_msgatt_matching! {
            move s::MsgAtt::Body(s::MsgAttBody {
                kind: s::FetchAttBodyKind::Binary,
                section: Some(s::SectionSpec::Sub(s::SubSectionSpec {
                    subscripts,
                    text: None,
                })),
                slice_origin: Some(2),
                data: lit
            }) in fr => {
                assert_eq!(vec![1], subscripts);
                assert_literal_like(
                    b"llo",
                    b"",
                    3,
                    false,
                    lit);
            }
        };
    });

    fetch_single!(client, c("FETCH 2 BINARY.PEEK[1]"), fr => {
        has_msgatt_matching! {
            move s::MsgAtt::Body(s::MsgAttBody {
                kind: s::FetchAttBodyKind::Binary,
                section: Some(s::SectionSpec::Sub(s::SubSectionSpec {
                    subscripts,
                    text: None,
                })),
                slice_origin: None,
                data: lit
            }) in fr => {
                assert_eq!(vec![1], subscripts);
                assert_literal_like(
                    b"hello ",
                    b"world",
                    11,
                    false,
                    lit);
            }
        };
    });

    fetch_single!(client, c("FETCH 2 BINARY.PEEK[2]"), fr => {
        has_msgatt_matching! {
            move s::MsgAtt::Body(s::MsgAttBody {
                kind: s::FetchAttBodyKind::Binary,
                section: Some(s::SectionSpec::Sub(s::SubSectionSpec {
                    subscripts,
                    text: None,
                })),
                slice_origin: None,
                data: lit
            }) in fr => {
                assert_eq!(vec![2], subscripts);
                assert_literal_like(
                    b"hell\0 ",
                    b"w\0rld",
                    11,
                    true,
                    lit);
            }
        };
    });

    fetch_single!(client, c("FETCH 2 BINARY.SIZE[2]"), fr => {
        has_msgatt_matching! {
            move s::MsgAtt::BinarySize(s::MsgAttBinarySize {
                section: Some(s::SectionSpec::Sub(s::SubSectionSpec {
                    subscripts,
                    text: None,
                })),
                size: 11,
            }) in fr => {
                assert_eq!(vec![2], subscripts);
            }
        };
    });
}

#[test]
fn fetch_unknown_cte() {
    let setup = set_up();
    let mut client = setup.connect("3516ucte");
    quick_log_in(&mut client);
    quick_create(&mut client, "3516ucte");

    client
        .start_append("3516ucte", s::AppendFragment::default(), UNKNOWN_CTE)
        .unwrap();
    let mut buffer = Vec::new();
    let mut responses = client.finish_append(&mut buffer).unwrap();
    assert_tagged_ok_any(responses.pop().unwrap());

    quick_select(&mut client, "3516ucte");

    command!([response] = client, c("FETCH 1 BINARY.PEEK[1]"));
    assert_error_response(
        response,
        Some(s::RespTextCode::UnknownCte(())),
        Error::UnknownCte,
    );
}

#[test]
fn implicit_seen_on_fetch() {
    let setup = set_up();
    let mut client = setup.connect("3516seen");
    quick_log_in(&mut client);
    quick_create(&mut client, "3516seen");
    quick_append_enron(&mut client, "3516seen", 1);
    quick_select(&mut client, "3516seen");

    // BINARY.PEEK[] and BINARY.SIZE[] must not set \Seen
    ok_command!(client, c("FETCH 1 BINARY.PEEK[]"));
    ok_command!(client, c("FETCH 1 BINARY.SIZE[]"));
    ok_command!(client, c("NOOP"));

    fetch_single!(client, c("FETCH 1 FLAGS"), fr => {
        has_msgatt_matching! {
            s::MsgAtt::Flags(s::FlagsFetch::Recent(ref flags)) in fr => {
                assert!(!flags.contains(&Flag::Seen));
            }
        };
    });

    // BINARY[] will set \Seen
    ok_command!(client, c("FETCH 1 BINARY[]"));

    fetch_single!(client, c("FETCH 1 FLAGS"), fr => {
        has_msgatt_matching! {
            s::MsgAtt::Flags(s::FlagsFetch::Recent(ref flags)) in fr => {
                assert!(flags.contains(&Flag::Seen));
            }
        };
    });
}
