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
fn login_basic() {
    let setup = set_up();
    let mut client = setup.connect("3501aulb");
    skip_greeting(&mut client);

    let mut buffer = Vec::new();
    let responses = client
        .command(c("LOGIN azure hunter2"), &mut buffer)
        .unwrap();

    assert_eq!(1, responses.len());
    match responses.into_iter().next().unwrap() {
        s::ResponseLine {
            tag: Some(_),
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
        r => panic!("Unexpected response: {:?}", r),
    }
}

#[test]
fn login_invalid() {
    let setup = set_up();
    let mut client = setup.connect("3501auli");
    skip_greeting(&mut client);

    {
        let mut buffer = Vec::new();
        let responses = client
            .command(c("LOGIN azure letmein"), &mut buffer)
            .unwrap();

        assert_eq!(1, responses.len());
        assert_tagged_no(responses.into_iter().next().unwrap());
    }

    {
        let mut buffer = Vec::new();
        let responses = client
            .command(c("LOGIN root hunter2"), &mut buffer)
            .unwrap();

        assert_eq!(1, responses.len());
        assert_tagged_no(responses.into_iter().next().unwrap());
    }
}
