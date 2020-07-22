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

fn xlist_results_to_str(lines: Vec<s::ResponseLine<'_>>) -> String {
    let mut ret = String::new();
    for line in lines {
        match line {
            s::ResponseLine {
                tag: None,
                response:
                    s::Response::Xlist(s::MailboxList {
                        mut flags, name, ..
                    }),
            } => {
                flags.sort();
                ret.push_str(&name.raw);
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
fn capability_declared() {
    test_require_capability("XLSTcapa", "XLIST");
}

#[test]
fn xlist_results() {
    let setup = set_up();
    let mut client = setup.connect("XLSTlist");
    quick_log_in(&mut client);

    ok_command!(client, c("CREATE XLSTlist/flagged USE (\\Flagged)"));
    ok_command!(client, c("CREATE XLSTlist/flagged/child"));
    ok_command!(client, c("CREATE XLSTlist/sub/trash USE (\\Trash)"));

    command!(mut responses = client, c("XLIST \"\" XLSTlist/*"));
    assert_tagged_ok(responses.pop().unwrap());
    assert_eq!(
        "XLSTlist/flagged \\Flagged \\HasChildren\n\
         XLSTlist/flagged/child \\HasNoChildren\n\
         XLSTlist/sub \\HasChildren\n\
         XLSTlist/sub/trash \\HasNoChildren \\Trash\n",
        xlist_results_to_str(responses)
    );
}
