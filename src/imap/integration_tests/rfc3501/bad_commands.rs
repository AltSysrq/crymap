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

use super::super::defs::*;

#[test]
fn unknown_commands() {
    let setup = set_up();
    let mut client = setup.connect("3501bcuc");
    // Log in so that long-line recovery is enabled.
    quick_log_in(&mut client);

    client.write_raw(b"1 PLUGH\r\n").unwrap();
    let mut buffer = Vec::new();
    let r = client.read_one_response(&mut buffer).unwrap();
    unpack_cond_response! {
        (Some(tag), s::RespCondType::Bad,
         Some(s::RespTextCode::Parse(())), _) = r => {
            assert_eq!("1", tag);
        }
    }

    client.write_raw(b"2 NOOP NOOP\r\n").unwrap();
    let mut buffer = Vec::new();
    let r = client.read_one_response(&mut buffer).unwrap();
    unpack_cond_response! {
        (Some(tag), s::RespCondType::Bad,
         Some(s::RespTextCode::Parse(())), _) = r => {
            assert_eq!("2", tag);
        }
    }

    // With regular literals, the server can immediately reject the literal by
    // replying NO.
    client.write_raw(b"3 CREATE {1000000}\r\n").unwrap();
    let mut buffer = Vec::new();
    let r = client.read_one_response(&mut buffer).unwrap();
    unpack_cond_response! {
        (Some(tag), s::RespCondType::No, None, Some(quip)) = r => {
            assert_eq!("3", tag);
            assert_eq!("Command line too long", quip);
        }
    }

    ok_command!(client, s::Command::Simple(s::SimpleCommand::Noop));

    // Using LITERAL+, the server actually needs to swallow all the literals we
    // throw at it until it finds the actual end of the command.
    client.write_raw(b"4 CREATE {100000+}\r\n").unwrap();
    // The NO has already been sent, but keep writing to ensure the server
    // doesn't get stuck on it.
    client.write_raw("x".repeat(100000).as_bytes()).unwrap();
    client
        .write_raw(b"5 still part of big create... {3+}\r\nfoo\r\n")
        .unwrap();
    let mut buffer = Vec::new();
    let r = client.read_one_response(&mut buffer).unwrap();
    unpack_cond_response! {
        (Some(tag), s::RespCondType::No, None, Some(quip)) = r => {
            assert_eq!("4", tag);
            assert_eq!("Command line too long", quip);
        }
    }

    ok_command!(client, s::Command::Simple(s::SimpleCommand::Noop));

    // Ensure that command discarding does not end up recurring if a continued
    // line is itself too long.
    client.write_raw(b"5 CREATE {100000+}\r\n").unwrap();
    client.write_raw("x".repeat(100000).as_bytes()).unwrap();
    client.write_raw(b"\r\n").unwrap();
    // Now that we've completed the huge "line", we get the NO.
    let mut buffer = Vec::new();
    let r = client.read_one_response(&mut buffer).unwrap();
    unpack_cond_response! {
        (Some(tag), s::RespCondType::No, None, Some(quip)) = r => {
            assert_eq!("5", tag);
            assert_eq!("Command line too long", quip);
        }
    }

    client.write_raw("6 ".repeat(50000).as_bytes()).unwrap();
    client.write_raw(b"\r\n").unwrap();
    let mut buffer = Vec::new();
    let r = client.read_one_response(&mut buffer).unwrap();
    unpack_cond_response! {
        (Some(tag), s::RespCondType::No, None, Some(quip)) = r => {
            assert_eq!("6", tag);
            assert_eq!("Command line too long", quip);
        }
    }

    client = setup.connect("3501bcuc");
    skip_greeting(&mut client);

    // Ignore errors here since the server may hang up before we write the full
    // payload, as long line recovery is disabled while logged out.
    let _ = client.write_raw("x".repeat(100_000).as_bytes());
    let mut buffer = Vec::new();
    let r = client.read_one_response(&mut buffer).unwrap();
    unpack_cond_response! {
        (None, s::RespCondType::Bye, _, _) = r => { }
    }

    client = setup.connect("3501bcuc");
    skip_greeting(&mut client);
    let _ = client.write_raw("x ".repeat(50_000).as_bytes());
    let mut buffer = Vec::new();
    let r = client.read_one_response(&mut buffer).unwrap();
    unpack_cond_response! {
        (None, s::RespCondType::Bye, _, _) = r => { }
    }

    client = setup.connect("3501bcuc");
    skip_greeting(&mut client);
    client.write_raw(b"HELO\r\n").unwrap();
    let mut buffer = Vec::new();
    let r = client.read_one_response(&mut buffer).unwrap();
    unpack_cond_response! {
        (None, s::RespCondType::Bye, _, _) = r => { }
    }
}

#[test]
fn inappropriate_commands() {
    let setup = set_up();
    let mut client = setup.connect("3501bcic");
    skip_greeting(&mut client);

    command!([response] = client, c("DELETE azure"));
    unpack_cond_response! {
        (Some(_), s::RespCondType::Bad, _, _) = response => { }
    }

    command!([response] = client, c("EXPUNGE"));
    unpack_cond_response! {
        (Some(_), s::RespCondType::Bad, _, _) = response => { }
    }

    command!([response] = client, c("LOGIN ../foo hunter2"));
    unpack_cond_response! {
        (Some(_), s::RespCondType::No, _, _) = response => { }
    }

    ok_command!(client, c("LOGIN azure hunter2"));

    command!([response] = client, c("EXPUNGE"));
    unpack_cond_response! {
        (Some(_), s::RespCondType::Bad, _, _) = response => { }
    }

    command!([response] = client, c("LOGIN azure hunter2"));

    unpack_cond_response! {
        (Some(_), s::RespCondType::Bad, _, _) = response => { }
    }
}

#[test]
fn bad_append_recovery() {
    let setup = set_up();
    let mut client = setup.connect("3501bcar");
    quick_log_in(&mut client);
    quick_create(&mut client, "3501bcar");
    quick_select(&mut client, "3501bcar");

    // Invalid start of append with synchronising literals
    // Parser doesn't actually recognise it as an APPEND, so we fall through to
    // regular command handling, which will buffer the literal onto the command
    // line and then reject the whole thing.
    client.write_raw(b"A1 APPEND  {5}\r\n").unwrap();

    let mut buffer = Vec::new();
    client.read_logical_line(&mut buffer).unwrap();
    assert!(buffer.starts_with(b"+ "));

    client.write_raw(b"plugh\r\n").unwrap();

    buffer.clear();
    let response = client.read_one_response(&mut buffer).unwrap();
    unpack_cond_response! {
        (Some(_), s::RespCondType::Bad,
         Some(s::RespTextCode::Parse(())), _) = response => ()
    };

    // Invalid start of append using LITERAL+.
    // As before, the parser doesn't recognise it as an append, so it
    // ultimately buffers the literal and then rejects it.
    client.write_raw(b"A2 APPEND  {5+}\r\nplugh\r\n").unwrap();

    buffer.clear();
    let response = client.read_one_response(&mut buffer).unwrap();
    unpack_cond_response! {
        (Some(_), s::RespCondType::Bad,
         Some(s::RespTextCode::Parse(())), _) = response => ()
    };

    // Ensure connection remains consistent
    ok_command!(client, c("NOOP"));

    // Testing issues with any part of APPEND after the first literal is the
    // demesne of MULTIAPPEND in the rfc3502 test module.

    // None of the above should have inserted anything
    command!(responses = client, c("EXAMINE 3501bcar"));
    has_untagged_response_matching! {
        s::Response::Exists(0) in responses
    }
}

#[test]
fn connection_closed_after_too_many_unauthed_commands() {
    let setup = set_up();
    let mut client = setup.connect("3501ccuc");
    skip_greeting(&mut client);

    for i in 0..100 {
        let mut buffer = Vec::new();
        // If the server is done with us, we may or may not succeed to write
        // the request onto the wire depending on when exactly the server
        // closes its side of the pipe.
        match client.write_raw(format!("N{i} NOOP\r\n").as_bytes()) {
            Ok(()) => {
                let response = client.read_one_response(&mut buffer).unwrap();
                match response.response {
                    s::Response::Cond(s::CondResponse {
                        cond: s::RespCondType::Ok,
                        ..
                    }) => continue,

                    s::Response::Cond(s::CondResponse {
                        cond: s::RespCondType::Bye,
                        ..
                    }) => {
                        // The connection should be disconnected.
                        assert!(client.read_one_response(&mut buffer).is_err());
                        return;
                    },

                    _ => panic!("unexpected response: {response:?}"),
                }
            },

            Err(_) => {
                // The server closed the pipe before we could write the
                // request, but the BYE should still be on the wire.
                let response = client.read_one_response(&mut buffer).unwrap();
                assert_matches!(
                    s::Response::Cond(s::CondResponse {
                        cond: s::RespCondType::Bye,
                        ..
                    }),
                    response.response,
                );
                return;
            },
        }
    }

    panic!("connection was never closed");
}
