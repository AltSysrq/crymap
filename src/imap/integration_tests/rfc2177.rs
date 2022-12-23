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

#[test]
fn capability_declared() {
    test_require_capability("2177capa", "IDLE");
}

#[test]
fn bad_idle() {
    let setup = set_up();
    let mut client = setup.connect("2177badi");
    quick_log_in(&mut client);

    command!([response] = client, c("IDLE"));
    unpack_cond_response! {
        (Some(_), s::RespCondType::Bad, _, _) = response
    };

    // Ensure the server isn't broken
    ok_command!(client, c("SELECT INBOX"));
}

#[test]
fn test_idle() {
    let setup = set_up();
    let mut client = setup.connect("2177idle");
    quick_log_in(&mut client);
    quick_create(&mut client, "2177idle");
    quick_select(&mut client, "2177idle");

    let mut idler = setup.connect("2177idler");
    quick_log_in(&mut idler);
    quick_select(&mut idler, "2177idle");

    idler.write_raw(b"I1 IDLE\r\n").unwrap();
    let mut buffer = Vec::new();
    idler.read_logical_line(&mut buffer).unwrap();
    assert!(buffer.starts_with(b"+ "));

    quick_append_enron(&mut client, "2177idle", 1);

    buffer.clear();
    let response = idler.read_one_response(&mut buffer).unwrap();
    assert_matches!(
        s::ResponseLine {
            tag: None,
            response: s::Response::Exists(1),
        },
        response
    );

    buffer.clear();
    let response = idler.read_one_response(&mut buffer).unwrap();
    assert_matches!(
        s::ResponseLine {
            tag: None,
            response: s::Response::Recent(_),
        },
        response
    );

    buffer.clear();
    let response = idler.read_one_response(&mut buffer).unwrap();
    assert_matches!(
        s::ResponseLine {
            tag: None,
            response: s::Response::Fetch(..),
        },
        response
    );

    ok_command!(client, c("STORE 1 +FLAGS (\\Flagged)"));

    buffer.clear();
    let response = idler.read_one_response(&mut buffer).unwrap();
    assert_matches!(
        s::ResponseLine {
            tag: None,
            response: s::Response::Fetch(..),
        },
        response
    );

    ok_command!(client, c("XVANQUISH 1"));

    buffer.clear();
    let response = idler.read_one_response(&mut buffer).unwrap();
    assert_matches!(
        s::ResponseLine {
            tag: None,
            response: s::Response::Expunge(1),
        },
        response
    );

    idler.write_raw(b"DONE\r\n").unwrap();
    buffer.clear();
    let response = idler.read_one_response(&mut buffer).unwrap();
    assert_tagged_ok(response);

    ok_command!(idler, c("NOOP"));
}

#[test]
fn delete_mailbox_during_idle() {
    let setup = set_up();
    let mut client = setup.connect("2177dmdi");
    quick_log_in(&mut client);
    quick_create(&mut client, "2177dmdi");

    let mut victim = setup.connect("2177dmdiV");
    quick_log_in(&mut victim);
    quick_select(&mut victim, "2177dmdi");

    victim.write_raw(b"I1 IDLE\r\n").unwrap();
    let mut buffer = Vec::new();
    victim.read_logical_line(&mut buffer).unwrap();
    assert!(buffer.starts_with(b"+ "));

    ok_command!(client, c("DELETE 2177dmdi"));

    victim.write_raw(b"DONE\r\n").unwrap();

    buffer.clear();
    let response = victim.read_one_response(&mut buffer).unwrap();
    unpack_cond_response! {
        (None, s::RespCondType::Bye, None, _) = response
    };
}

#[test]
fn idle_works_with_extremely_long_paths() {
    const MXNAME: &str = "2177ixlp/\
         01234567891123456789212345678931234567894123456789\
         51234567896123456789712345678981234567899123456789/\
         averylongpath";

    let setup = set_up();
    let mut client = setup.connect("2177ixlp");
    quick_log_in(&mut client);
    quick_create(&mut client, MXNAME);
    quick_select(&mut client, MXNAME);

    client.write_raw(b"I1 IDLE\r\n").unwrap();
    let mut buffer = Vec::new();
    client.read_logical_line(&mut buffer).unwrap();
    assert!(buffer.starts_with(b"+ "));

    let mut client2 = setup.connect("2177ixlp2");
    quick_log_in(&mut client2);
    quick_append_enron(&mut client2, MXNAME, 1);

    buffer.clear();
    let response = client.read_one_response(&mut buffer).unwrap();
    assert_matches!(
        s::ResponseLine {
            tag: None,
            response: s::Response::Exists(_),
        },
        response
    );
}
