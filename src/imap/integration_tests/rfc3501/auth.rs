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
        let mut responses = client
            .command(c("LOGIN azure letmein"), &mut buffer)
            .unwrap();

        assert_eq!(1, responses.len());
        unpack_cond_response! {
            (Some(_), s::RespCondType::No,
             Some(s::RespTextCode::AuthenticationFailed(())), _) =
                responses.pop().unwrap() => ()
        };
    }

    {
        let mut buffer = Vec::new();
        let mut responses = client
            .command(c("LOGIN root hunter2"), &mut buffer)
            .unwrap();

        assert_eq!(1, responses.len());
        unpack_cond_response! {
            (Some(_), s::RespCondType::No,
             Some(s::RespTextCode::AuthenticationFailed(())), _) =
                responses.pop().unwrap() => ()
        };
    }
}

#[test]
fn authenticate_plain() {
    let setup = set_up();
    let mut client = setup.connect("3501auap");
    skip_greeting(&mut client);

    client.write_raw(b"A1 AUTHENTICATE PLAIN\r\n").unwrap();

    let mut buffer = Vec::new();
    client.read_logical_line(&mut buffer).unwrap();
    assert_eq!(b"+ \r\n", &buffer[..]);

    // azure\0azure\0hunter2
    client
        .write_raw(b"YXp1cmUAYXp1cmUAaHVudGVyMg==\r\n")
        .unwrap();

    buffer.clear();
    let response = client.read_one_response(&mut buffer).unwrap();
    unpack_cond_response! {
        (Some(_), s::RespCondType::Ok, _, _) = response => ()
    };

    let mut client = setup.connect("3501auap");
    skip_greeting(&mut client);

    client.write_raw(b"A2 AUTHENTICATE PLAIN\r\n").unwrap();

    buffer.clear();
    client.read_logical_line(&mut buffer).unwrap();
    assert_eq!(b"+ \r\n", &buffer[..]);

    // \0azure\0hunter2
    client.write_raw(b"AGF6dXJlAGh1bnRlcjI=\r\n").unwrap();

    buffer.clear();
    let response = client.read_one_response(&mut buffer).unwrap();
    unpack_cond_response! {
        (Some(_), s::RespCondType::Ok, _, _) = response => ()
    };
}

#[test]
fn authenticate_invalid() {
    let setup = set_up();
    let mut client = setup.connect("3501auai");
    skip_greeting(&mut client);

    fn reject_authenticate(
        client: &mut PipeClient,
        base64: &[u8],
        expected_cond: s::RespCondType,
        expected_code: Option<s::RespTextCode<'_>>,
    ) {
        client.write_raw(b"A1 AUTHENTICATE plain\r\n").unwrap();

        let mut buffer = Vec::new();
        client.read_logical_line(&mut buffer).unwrap();
        assert_eq!(b"+ \r\n", &buffer[..]);

        client.write_raw(base64).unwrap();

        buffer.clear();
        let response = client.read_one_response(&mut buffer).unwrap();
        unpack_cond_response! {
            (Some(_), cond, code, _) = response => {
                assert_eq!(expected_cond, cond);
                assert_eq!(expected_code, code);
            }
        };
    }

    // azure\0azure\0hunter3
    reject_authenticate(
        &mut client,
        b"YXp1cmUAYXp1cmUAaHVudGVyMw==\r\n",
        s::RespCondType::No,
        Some(s::RespTextCode::AuthenticationFailed(())),
    );
    // azure\0root\0hunter2
    reject_authenticate(
        &mut client,
        b"YXp1cmUAcm9vdABodW50ZXIy\r\n",
        s::RespCondType::No,
        Some(s::RespTextCode::Cannot(())),
    );
    // root\0azure\0hunter2
    reject_authenticate(
        &mut client,
        b"cm9vdABhenVyZQBodW50ZXIy\r\n",
        s::RespCondType::No,
        Some(s::RespTextCode::Cannot(())),
    );
    // azüre\0azüre\0hünter2, but in ISO-8859-1
    reject_authenticate(
        &mut client,
        b"YXr8cmUAYXr8cmUAOmj8bnRlcjI=\r\n",
        s::RespCondType::Bad,
        Some(s::RespTextCode::Parse(())),
    );
    // azure\0hunter2
    reject_authenticate(
        &mut client,
        b"YXp1cmUAaHVudGVyMg==\r\n",
        s::RespCondType::Bad,
        Some(s::RespTextCode::Parse(())),
    );
    // azure\0azure\0hunter2\0plugh
    reject_authenticate(
        &mut client,
        b"YXp1cmUAYXp1cmUAaHVudGVyMgBwbHVnaA==\r\n",
        s::RespCondType::Bad,
        Some(s::RespTextCode::Parse(())),
    );

    reject_authenticate(&mut client, b"*\r\n", s::RespCondType::Bad, None);
    reject_authenticate(
        &mut client,
        b"azure:hunter2\r\n",
        s::RespCondType::Bad,
        Some(s::RespTextCode::Parse(())),
    );
    reject_authenticate(
        &mut client,
        b"\r\n",
        s::RespCondType::Bad,
        Some(s::RespTextCode::Parse(())),
    );

    client.write_raw(b"A1 AUTHENTICATE plain\r\n").unwrap();
    let mut buffer = Vec::new();
    client.read_logical_line(&mut buffer).unwrap();
    assert_eq!(b"+ \r\n", &buffer[..]);

    // Ignore errors since the server might hang up first
    let _ = client.write_raw("x".repeat(100_000).as_bytes());
    buffer.clear();
    let response = client.read_one_response(&mut buffer).unwrap();
    unpack_cond_response! {
        (None, s::RespCondType::Bye, _, _) = response => ()
    };
}

#[test]
fn authenticate_unsupported() {
    let setup = set_up();
    let mut client = setup.connect("3501auau");
    skip_greeting(&mut client);

    client.write_raw(b"A1 AUTHENTICATE NLTM\r\n").unwrap();
    let mut buffer = Vec::new();
    let response = client.read_one_response(&mut buffer).unwrap();
    unpack_cond_response! {
        (Some(_), s::RespCondType::Bad,
         Some(s::RespTextCode::Cannot(())), _) = response => ()
    };
}
