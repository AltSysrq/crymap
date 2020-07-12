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

use super::super::defs::*;

#[test]
fn greeting_goodbye() {
    let setup = set_up();
    let mut client = setup.connect("3501fcgg");

    let mut buffer = Vec::new();
    let greeting = client.read_one_response(&mut buffer).unwrap();
    match greeting {
        s::ResponseLine {
            tag: None,
            response:
                s::Response::Cond(s::CondResponse {
                    cond: s::RespCondType::Ok,
                    code: Some(s::RespTextCode::Capability(caps)),
                    quip: _,
                }),
        } => {
            assert!(caps.capabilities.contains(&Cow::Borrowed("IMAP4rev1")));
            assert!(caps.capabilities.contains(&Cow::Borrowed("LITERAL+")));
        }
        g => panic!("Unexpected greeting: {:?}", g),
    }

    client.write_raw(b"1 LOGOUT\r\n").unwrap();
    receive_line_like(&mut client, r#"^* BYE BYE\r\n$"#);
}

#[test]
fn request_capabilities() {
    let setup = set_up();
    let mut client = setup.connect("3501fcrc");

    skip_greeting(&mut client);

    let mut buffer = Vec::new();
    let responses = client
        .command(
            s::Command::Simple(s::SimpleCommand::Capability),
            &mut buffer,
        )
        .unwrap();
    assert_eq!(2, responses.len());

    let mut responses = responses.into_iter();
    match responses.next().unwrap() {
        s::ResponseLine {
            tag: None,
            response: s::Response::Capability(caps),
        } => {
            assert!(caps.capabilities.contains(&Cow::Borrowed("IMAP4rev1")));
            assert!(caps.capabilities.contains(&Cow::Borrowed("LITERAL+")));
        }
        r => panic!("Unexpected response: {:?}", r),
    }
    assert_tagged_ok(responses.next().unwrap());
}
