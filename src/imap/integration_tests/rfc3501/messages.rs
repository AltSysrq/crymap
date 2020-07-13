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
use std::marker::PhantomData;

use super::super::defs::*;
use crate::test_data::*;

#[test]
fn append_message() {
    let setup = set_up();
    let mut client = setup.connect("3501meam");
    quick_log_in(&mut client);
    quick_create(&mut client, "3501meam");

    client
        .start_append(
            "3501meam",
            s::AppendFragment {
                flags: None,
                internal_date: None,
                _marker: PhantomData,
            },
            ENRON_SMALL_MULTIPARTS[0],
        )
        .unwrap();
    let mut buffer = Vec::new();
    let mut responses = client.finish_append(&mut buffer).unwrap();
    assert!(responses.len() >= 1);
    assert_tagged_ok(responses.pop().unwrap());

    command!(mut responses = client, s::Command::Examine(s::ExamineCommand {
        mailbox: Cow::Borrowed("3501meam"),
    }));
    assert_tagged_ok_any(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Exists(1) in responses
    };

    client
        .start_append(
            "3501meam",
            s::AppendFragment {
                flags: None,
                internal_date: None,
                _marker: PhantomData,
            },
            ENRON_SMALL_MULTIPARTS[1],
        )
        .unwrap();

    let mut buffer = Vec::new();
    let mut responses = client.finish_append(&mut buffer).unwrap();
    assert!(responses.len() >= 1);
    assert_tagged_ok(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::Exists(2) in responses
    };
}

#[test]
fn copy_messages() {
    let setup = set_up();
    let mut client = setup.connect("3501mecm");
    quick_log_in(&mut client);
    quick_create(&mut client, "3501mecm/src");
    quick_create(&mut client, "3501mecm/dst1");
    quick_create(&mut client, "3501mecm/dst2");

    let num_messages = 5;
    quick_append_enron(&mut client, "3501mecm/src", num_messages);

    ok_command!(
        client,
        s::Command::Select(s::SelectCommand {
            mailbox: Cow::Borrowed("3501mecm/src"),
        })
    );
    ok_command!(
        client,
        s::Command::Copy(s::CopyCommand {
            dst: Cow::Borrowed("3501mecm/dst1"),
            messages: Cow::Borrowed("3:*"),
        })
    );

    ok_command!(client, s::Command::XVanquish(Cow::Borrowed("2:3")));

    ok_command!(
        client,
        s::Command::Uid(s::UidCommand::Copy(s::CopyCommand {
            dst: Cow::Borrowed("3501mecm/dst2"),
            messages: Cow::Borrowed("1:4"),
        }))
    );

    command!(
        responses = client,
        s::Command::Examine(s::ExamineCommand {
            mailbox: Cow::Borrowed("3501mecm/dst1"),
        })
    );

    has_untagged_response_matching! {
        s::Response::Exists(n) in responses => {
            assert_eq!(num_messages as u32 - 2, n);
        }
    };

    command!(
        responses = client,
        s::Command::Examine(s::ExamineCommand {
            mailbox: Cow::Borrowed("3501mecm/dst2"),
        })
    );
    has_untagged_response_matching! {
        s::Response::Exists(2) in responses
    };
}

#[test]
fn expunge_messages() {
    let setup = set_up();
    let mut client = setup.connect("3501mexm");
    quick_log_in(&mut client);
    quick_create(&mut client, "3501mexm");
    quick_append_enron(&mut client, "3501mexm", 5);
    quick_select(&mut client, "3501mexm");

    ok_command!(
        client,
        s::Command::Store(s::StoreCommand {
            messages: Cow::Borrowed("2"),
            typ: s::StoreCommandType::Plus,
            silent: false,
            flags: vec![Flag::Deleted],
            _marker: PhantomData,
        })
    );
    command!(mut responses = client, s::Command::Simple(s::SimpleCommand::Expunge));
    assert_tagged_ok(responses.pop().unwrap());
    assert_eq!(1, responses.len());
    has_untagged_response_matching! {
        s::Response::Expunge(2) in responses
    };

    ok_command!(
        client,
        s::Command::Uid(s::UidCommand::Store(s::StoreCommand {
            messages: Cow::Borrowed("3"),
            typ: s::StoreCommandType::Plus,
            silent: false,
            flags: vec![Flag::Deleted],
            _marker: PhantomData,
        }))
    );
    command!(mut responses = client, s::Command::Uid(s::UidCommand::Expunge(
        Cow::Borrowed("3,4"),
    )));

    assert_tagged_ok(responses.pop().unwrap());
    assert_eq!(1, responses.len());
    has_untagged_response_matching! {
        s::Response::Expunge(2) in responses
    };
}
