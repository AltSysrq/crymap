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

use super::super::defs::*;

#[test]
fn unknown_commands() {
    let setup = set_up();
    let mut client = setup.connect("3501bcuc");
    skip_greeting(&mut client);

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
    // The initial NO is actually sent after the first line
    let mut buffer = Vec::new();
    let r = client.read_one_response(&mut buffer).unwrap();
    unpack_cond_response! {
        (Some(tag), s::RespCondType::No, None, Some(quip)) = r => {
            assert_eq!("5", tag);
            assert_eq!("Command line too long", quip);
        }
    }
    client.write_raw("x".repeat(100000).as_bytes()).unwrap();
    // Server may hang up on this one
    let _ = client.write_raw("6 ".repeat(50000).as_bytes()).unwrap();
    // Now we get a BYE due to rejecting the continuation line
    let mut buffer = Vec::new();
    let r = client.read_one_response(&mut buffer).unwrap();
    unpack_cond_response! {
        (None, s::RespCondType::Bye, None, _) = r => { }
    }

    client = setup.connect("3501bcuc");
    skip_greeting(&mut client);

    // Ignore errors here since the server may hang up before we write the full
    // payload
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

// TODO Test bad APPEND operations

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
