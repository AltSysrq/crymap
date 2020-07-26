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
    test_require_capability("5182capa", "SEARCHRES");
}

#[test]
fn test_searchres() {
    let setup = set_up();
    let mut client = setup.connect("5182sres");
    quick_log_in(&mut client);
    quick_create(&mut client, "5182sres");
    quick_append_enron(&mut client, "5182sres", 5);
    quick_select(&mut client, "5182sres");

    ok_command!(client, c("XVANQUISH 3"));

    assert_searchres(
        &mut client,
        "SEARCH RETURN (SAVE) ALL",
        false,
        &[1, 2, 3, 4],
    );

    // UID search behaves the same way
    assert_searchres(
        &mut client,
        "UID SEARCH RETURN (SAVE) 1:2",
        false,
        &[1, 2],
    );

    // A different search without SAVE doesn't change the results
    assert_searchres(&mut client, "SEARCH RETURN (ALL) 4", true, &[1, 2]);

    // MIN and MAX exclude other results unless COUNT or ALL is present
    assert_searchres(&mut client, "SEARCH RETURN (MIN SAVE) ALL", true, &[1]);
    assert_searchres(&mut client, "SEARCH RETURN (MAX SAVE) ALL", true, &[4]);
    assert_searchres(
        &mut client,
        "SEARCH RETURN (MAX MIN SAVE) ALL",
        true,
        &[1, 4],
    );
    assert_searchres(
        &mut client,
        "SEARCH RETURN (MIN ALL SAVE) ALL",
        true,
        &[1, 2, 3, 4],
    );
    assert_searchres(
        &mut client,
        "SEARCH RETURN (MIN COUNT SAVE) ALL",
        true,
        &[1, 2, 3, 4],
    );

    // Special case when MIN and MAX are the same value
    assert_searchres(&mut client, "SEARCH RETURN (MIN MAX SAVE) 2", true, &[2]);

    // Empty results are handled properly
    assert_searchres(
        &mut client,
        "SEARCH RETURN (SAVE) KEYWORD nonexistent",
        false,
        &[],
    );

    // $ continues to work if one of its messages is expunged
    assert_searchres(
        &mut client,
        "SEARCH RETURN (SAVE) ALL",
        false,
        &[1, 2, 3, 4],
    );
    ok_command!(client, c("XVANQUISH 2"));
    assert_searchres(
        &mut client,
        // Doesn't change $
        "SEARCH 1",
        true,
        &[1, 2, 3],
    );

    // SELECT resets $
    quick_select(&mut client, "5182sres");
    assert_searchres(
        &mut client,
        // Doesn't change $
        "SEARCH RETURN (ALL) ALL",
        true,
        &[],
    );
}

fn assert_searchres(
    client: &mut PipeClient,
    search_command: &str,
    expect_search_result: bool,
    expected_seqnums: &[u32],
) {
    command!(mut responses = client, cb(search_command));
    if expect_search_result {
        assert_eq!(2, responses.len());
    } else {
        assert_eq!(1, responses.len());
    }
    assert_tagged_ok(responses.pop().unwrap());

    command!(responses = client, c("FETCH $ UID"));
    let actual_seqnums = responses
        .into_iter()
        .filter_map(|r| match r {
            s::ResponseLine {
                tag: None,
                response: s::Response::Fetch(fr),
            } => Some(fr.seqnum),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(expected_seqnums, &actual_seqnums[..]);

    // Using $ for UIDs emits the same results
    command!(responses = client, c("UID FETCH $ UID"));
    let actual_seqnums = responses
        .into_iter()
        .filter_map(|r| match r {
            s::ResponseLine {
                tag: None,
                response: s::Response::Fetch(fr),
            } => Some(fr.seqnum),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(expected_seqnums, &actual_seqnums[..]);
}
