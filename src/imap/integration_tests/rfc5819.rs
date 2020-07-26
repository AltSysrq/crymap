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

use super::defs::*;

#[test]
fn capability_declared() {
    test_require_capability("5819capa", "LIST-STATUS");
}

#[test]
fn test_list_status() {
    let setup = set_up();
    let mut client = setup.connect("5819lsst");
    quick_log_in(&mut client);
    quick_create(&mut client, "5819lsst/foo");
    quick_create(&mut client, "5819lsst/noselect/bar");
    quick_append_enron(&mut client, "5819lsst/foo", 2);
    quick_append_enron(&mut client, "5819lsst/noselect/bar", 3);

    ok_command!(client, c("DELETE 5819lsst/noselect"));

    command!(
        responses = client,
        c("LIST 5819lsst/ * RETURN (STATUS (RECENT UIDNEXT))")
    );
    assert_eq!(6, responses.len());
    let mut responses = responses.into_iter();

    // RETURN STATUS is highly order-sensitive, so manually verify each
    // response in sequence.
    match responses.next().unwrap() {
        s::ResponseLine {
            tag: None,
            response: s::Response::List(lr),
        } => assert_eq!("5819lsst/foo", lr.name.raw),
        r => panic!("Unexpected response: {:?}", r),
    }

    match responses.next().unwrap() {
        s::ResponseLine {
            tag: None,
            response: s::Response::Status(sr),
        } => {
            assert_eq!("5819lsst/foo", sr.mailbox.raw);
            assert!(sr.atts.contains(&s::StatusResponseAtt {
                att: s::StatusAtt::Recent,
                value: 2,
            }));
            assert!(sr.atts.contains(&s::StatusResponseAtt {
                att: s::StatusAtt::UidNext,
                value: 3,
            }));
        }
        r => panic!("Unexpected response: {:?}", r),
    }

    match responses.next().unwrap() {
        s::ResponseLine {
            tag: None,
            response: s::Response::List(lr),
        } => {
            assert_eq!("5819lsst/noselect", lr.name.raw);
            assert!(lr.flags.contains(&Cow::Borrowed("\\Noselect")));
        }
        r => panic!("Unexpected response: {:?}", r),
    }

    match responses.next().unwrap() {
        s::ResponseLine {
            tag: None,
            response: s::Response::List(lr),
        } => assert_eq!("5819lsst/noselect/bar", lr.name.raw),
        r => panic!("Unexpected response: {:?}", r),
    }

    match responses.next().unwrap() {
        s::ResponseLine {
            tag: None,
            response: s::Response::Status(sr),
        } => {
            assert_eq!("5819lsst/noselect/bar", sr.mailbox.raw);
            assert!(sr.atts.contains(&s::StatusResponseAtt {
                att: s::StatusAtt::Recent,
                value: 3,
            }));
            assert!(sr.atts.contains(&s::StatusResponseAtt {
                att: s::StatusAtt::UidNext,
                value: 4,
            }));
        }
        r => panic!("Unexpected response: {:?}", r),
    }

    assert_tagged_ok(responses.next().unwrap());

    assert_bad_command(
        &mut client,
        Some(s::RespTextCode::ClientBug(())),
        "LIST \"\" * RETURN (STATUS (RECENT) STATUS (UNSEEN))",
    );
}
