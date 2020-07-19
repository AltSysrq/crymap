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

//! Integration tests for the happy paths of RFC 7888.
//!
//! Note that some tests involving LITERAL+ handling in unusual situations is
//! handled by `rfc3501::bad_commands` due to its lower-level nature.

use std::borrow::Cow;

use super::defs::*;
use crate::test_data;

#[test]
fn capability_declared() {
    let setup = set_up();
    let mut client = setup.connect("7888capa");

    let mut buffer = Vec::new();
    let response = client.read_one_response(&mut buffer).unwrap();
    unpack_cond_response! {
        (None, s::RespCondType::Ok, Some(s::RespTextCode::Capability(caps)), _)
            = response
        => {
            assert!(caps.capabilities.contains(&Cow::Borrowed("LITERAL+")));
        }
    }
}

#[test]
fn command_non_synchronising_literal() {
    let setup = set_up();
    let mut client = setup.connect("7888cnsl");
    quick_log_in(&mut client);
    quick_select(&mut client, "INBOX");

    client
        .write_raw(
            b"A1 SEARCH TEXT {5+}\r\n\
              enron TEXT {5+}\r\n\
              plugh\r\n",
        )
        .unwrap();
    let mut buffer = Vec::new();
    let mut responses =
        client.read_responses_until_tagged(&mut buffer).unwrap();
    assert_tagged_ok(responses.pop().unwrap());

    // Server must not get confused by literal text itself ending with
    // something that looks like a literal.
    client
        .write_raw(
            b"A2 SEARCH TEXT {4+}\r\n\
              {3+} TEXT {6+}\r\n\
              {3+}\r\n\r\n",
        )
        .unwrap();
    buffer.clear();
    let mut responses =
        client.read_responses_until_tagged(&mut buffer).unwrap();
    assert_tagged_ok(responses.pop().unwrap());

    // Ensure connection is still consistent
    ok_command!(client, c("NOOP"));
}

#[test]
fn append_non_synchronising_literal() {
    let setup = set_up();
    let mut client = setup.connect("7888ansl");
    quick_log_in(&mut client);
    quick_create(&mut client, "7888ansl");

    client
        .write_raw(
            format!(
                "A1 APPEND 7888ansl {{{}+}}\r\n",
                test_data::CHRISTMAS_TREE.len()
            )
            .as_bytes(),
        )
        .unwrap();
    client.write_raw(test_data::CHRISTMAS_TREE).unwrap();
    client.write_raw(b"\r\n").unwrap();

    let mut buffer = Vec::new();
    let mut responses =
        client.read_responses_until_tagged(&mut buffer).unwrap();
    assert_tagged_ok_any(responses.pop().unwrap());

    // Ensure connection is still consistent
    ok_command!(client, c("NOOP"));
}
