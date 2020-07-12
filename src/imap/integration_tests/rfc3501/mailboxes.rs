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

fn list_results_to_str(lines: Vec<s::ResponseLine<'_>>) -> String {
    let mut ret = String::new();
    for line in lines {
        match line {
            s::ResponseLine {
                tag: None,
                response: s::Response::List(s::MailboxList { flags, name }),
            } => {
                ret.push_str(&name);
                for flag in flags {
                    ret.push(' ');
                    ret.push_str(&flag);
                }
                ret.push('\n');
            }

            line => panic!("Unexpected response line: {:?}", line),
        }
    }

    ret
}

#[test]
fn mailbox_management() {
    let setup = set_up();
    let mut client = setup.connect("3501mbmm");
    quick_log_in(&mut client);

    ok_command!(
        client,
        s::Command::Create(s::CreateCommand {
            mailbox: Cow::Borrowed("3501mbmm/noselect/foo"),
        })
    );
    ok_command!(
        client,
        s::Command::Create(s::CreateCommand {
            mailbox: Cow::Borrowed("3501mbmm/parent/bar"),
        })
    );

    command!(mut responses = client, s::Command::List(s::ListCommand {
        reference: Cow::Borrowed(""),
        pattern: Cow::Borrowed("3501mbmm/*"),
    }));
    assert_tagged_ok(responses.pop().unwrap());

    assert_eq!(
        "3501mbmm/noselect\n\
         3501mbmm/noselect/foo\n\
         3501mbmm/parent\n\
         3501mbmm/parent/bar\n",
        list_results_to_str(responses)
    );

    ok_command!(
        client,
        s::Command::Delete(s::DeleteCommand {
            mailbox: Cow::Borrowed("3501mbmm/noselect"),
        })
    );

    command!(
        responses = client,
        s::Command::Delete(s::DeleteCommand {
            mailbox: Cow::Borrowed("3501mbmm/noselect"),
        })
    );
    assert_eq!(1, responses.len());
    assert_tagged_no(responses.into_iter().next().unwrap());

    ok_command!(
        client,
        s::Command::Rename(s::RenameCommand {
            src: Cow::Borrowed("3501mbmm/noselect/foo"),
            dst: Cow::Borrowed("3501mbmm/parent/foo"),
        })
    );

    command!(mut responses = client, s::Command::List(s::ListCommand {
        reference: Cow::Borrowed("3501mbmm/"),
        pattern: Cow::Borrowed("*"),
    }));
    assert_tagged_ok(responses.pop().unwrap());

    assert_eq!(
        "3501mbmm/noselect \\Noselect\n\
         3501mbmm/parent\n\
         3501mbmm/parent/bar\n\
         3501mbmm/parent/foo\n",
        list_results_to_str(responses)
    );

    ok_command!(
        client,
        s::Command::Delete(s::DeleteCommand {
            mailbox: Cow::Borrowed("3501mbmm/noselect"),
        })
    );

    command!(mut responses = client, s::Command::List(s::ListCommand {
        reference: Cow::Borrowed("3501mbmm/"),
        pattern: Cow::Borrowed("*"),
    }));
    assert_tagged_ok(responses.pop().unwrap());
    assert_eq!(
        "3501mbmm/parent\n\
         3501mbmm/parent/bar\n\
         3501mbmm/parent/foo\n",
        list_results_to_str(responses)
    );
}
