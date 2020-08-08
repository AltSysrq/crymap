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

//! Note that the APPEND aspect of RFC 6855 isn't something we do, strictly
//! speaking. We understand the syntax, but ignore it and treat it as a regular
//! append. We don't enforce that literal8 syntax is used instead of regular
//! literals. That's because the UTF8 extension to APPEND is a waste of
//! everyone's time and also calls for us to violate the prime directive of not
//! corrupting the user's mail.
//!
//! 1. RFC 3501 already allows UTF-8 in literals. There's no reason to give a
//! way for clients to announce that they're going to append UTF-8.
//!
//! 2. Forbidding 8BITMIME without the UTF-8 syntax breaks clients that were
//! already correctly working properly with that standard but weren't aware of
//! the UTF8=ACCEPT extension.
//!
//! 3. The notions of "downgrading" 8BITMIME for IMAP clients that haven't
//! enabled UTF8=ACCEPT is sheer lunacy. IMAP stores without that extension
//! don't have to do that, and clients are (should) already be designed to
//! tolerate MIME data with 8-bit values in the headers.

use super::defs::*;
use crate::test_data::*;

#[test]
fn capability_declared() {
    test_require_capability("6855capa", "UTF8=ACCEPT");
}

#[test]
fn mailbox_names() {
    let setup = set_up();
    let mut clientu = setup.connect("6855manaU");
    let mut clienta = setup.connect("6855manaA");

    quick_log_in(&mut clientu);
    quick_log_in(&mut clienta);

    ok_command!(clientu, c("ENABLE UTF8=ACCEPT"));

    ok_command!(clientu, c(r#"CREATE "6855mana/ünicöde""#));
    ok_command!(clientu, c(r#"CREATE "6855mana/&AOQ-scii""#));
    ok_command!(clienta, c(r#"CREATE "6855mana/&AOQ-scii""#));

    command!(responses = clientu, c(r#"LIST "" 6855mana/*"#));
    assert_eq!(4, responses.len());
    // This implementation always returns the mailboxes in code-point order
    let mut it = responses.into_iter();
    match it.next().unwrap().response {
        s::Response::List(ml) => assert_eq!("6855mana/&AOQ-scii", ml.name.raw),
        r => panic!("Unexpected response: {:?}", r),
    }
    match it.next().unwrap().response {
        s::Response::List(ml) => assert_eq!("6855mana/äscii", ml.name.raw),
        r => panic!("Unexpected response: {:?}", r),
    }
    match it.next().unwrap().response {
        s::Response::List(ml) => assert_eq!("6855mana/ünicöde", ml.name.raw),
        r => panic!("Unexpected response: {:?}", r),
    }
    assert_tagged_ok(it.next().unwrap());

    command!(responses = clienta, c(r#"LIST "" 6855mana/*"#));
    assert_eq!(4, responses.len());
    // This implementation always returns the mailboxes in code-point order
    let mut it = responses.into_iter();
    match it.next().unwrap().response {
        s::Response::List(ml) => assert_eq!("6855mana/&-AOQ-scii", ml.name.raw),
        r => panic!("Unexpected response: {:?}", r),
    }
    match it.next().unwrap().response {
        s::Response::List(ml) => assert_eq!("6855mana/&AOQ-scii", ml.name.raw),
        r => panic!("Unexpected response: {:?}", r),
    }
    match it.next().unwrap().response {
        s::Response::List(ml) => {
            assert_eq!("6855mana/&APw-nic&APY-de", ml.name.raw)
        }
        r => panic!("Unexpected response: {:?}", r),
    }
    assert_tagged_ok(it.next().unwrap());
}

#[test]
fn utf8_literal_append() {
    let setup = set_up();
    let mut client = setup.connect("6855ulia");
    quick_log_in(&mut client);
    quick_create(&mut client, "6855ulia");

    client
        .start_append(
            "6855ulia",
            s::AppendFragment {
                utf8: true,
                ..s::AppendFragment::default()
            },
            ENRON_SMALL_MULTIPARTS[0],
        )
        .unwrap();
    let mut buffer = Vec::new();
    let mut responses = client.finish_append(&mut buffer).unwrap();
    assert_tagged_no(responses.pop().unwrap());

    ok_command!(client, c("ENABLE UTF8=ACCEPT"));

    client
        .start_append(
            "6855ulia",
            s::AppendFragment {
                utf8: true,
                ..s::AppendFragment::default()
            },
            ENRON_SMALL_MULTIPARTS[0],
        )
        .unwrap();
    buffer.clear();
    let mut responses = client.finish_append(&mut buffer).unwrap();
    assert_tagged_ok_any(responses.pop().unwrap());

    client
        .start_append(
            "6855ulia",
            s::AppendFragment {
                utf8: true,
                ..s::AppendFragment::default()
            },
            ENRON_SMALL_MULTIPARTS[1],
        )
        .unwrap();
    client
        .append_item(s::AppendFragment::default(), ENRON_SMALL_MULTIPARTS[2])
        .unwrap();
    buffer.clear();
    let mut responses = client.finish_append(&mut buffer).unwrap();
    assert_tagged_ok_any(responses.pop().unwrap());

    client
        .start_append(
            "6855ulia",
            s::AppendFragment::default(),
            ENRON_SMALL_MULTIPARTS[3],
        )
        .unwrap();
    client
        .append_item(
            s::AppendFragment {
                utf8: true,
                ..s::AppendFragment::default()
            },
            ENRON_SMALL_MULTIPARTS[4],
        )
        .unwrap();
    buffer.clear();
    let mut responses = client.finish_append(&mut buffer).unwrap();
    assert_tagged_ok_any(responses.pop().unwrap());
}
