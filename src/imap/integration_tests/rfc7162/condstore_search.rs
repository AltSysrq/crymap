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
use super::extract_highest_modseq;

#[test]
fn condstore_search() {
    let setup = set_up();
    let mut client = setup.connect("7162cscs");
    quick_log_in(&mut client);
    quick_create(&mut client, "7162cscs");
    quick_append_enron(&mut client, "7162cscs", 2);

    command!(mut responses = client, c("SELECT 7162cscs (CONDSTORE)"));
    assert_tagged_ok_any(responses.pop().unwrap());
    let max_modseq = extract_highest_modseq(&responses);

    // STORE doesn't emit an up-to-date HIGHESTMODSEQ since it isn't allowed to
    // send EXPUNGE responses
    ok_command!(client, c("STORE 1 +FLAGS (\\deleted)"));

    // NOOP lets us get the latest HIGHESTMODSEQ
    command!(responses = client, c("NOOP"));
    let new_modseq = extract_highest_modseq(&responses);

    fn search_test(
        client: &mut PipeClient,
        command: &str,
        expected_hits: &[u32],
        expected_max_modseq: Option<u64>,
    ) {
        command!(mut responses = client, cb(command));
        assert_eq!(2, responses.len());
        assert_tagged_ok(responses.pop().unwrap());
        has_untagged_response_matching! {
            s::Response::Search(ref sr) in responses => {
                assert_eq!(expected_hits, &sr.hits[..]);
                assert_eq!(expected_max_modseq, sr.max_modseq);
            }
        };
    }

    // Everything matches MODSEQ 0, and we implicitly get the max_modseq value.
    search_test(&mut client, "SEARCH MODSEQ 0", &[1, 2], Some(new_modseq));

    // This also matches everything, since the modseq of 2 is equal to
    // max_modseq, and of 1 is greater than max_modseq
    search_test(
        &mut client,
        &format!("SEARCH MODSEQ {}", max_modseq),
        &[1, 2],
        Some(new_modseq),
    );

    // Only message 1 has a modseq >= new_modseq
    search_test(
        &mut client,
        &format!("SEARCH MODSEQ {}", new_modseq),
        &[1],
        Some(new_modseq),
    );

    // Nothing had a modseq > new_modseq
    search_test(
        &mut client,
        &format!("SEARCH MODSEQ {}", new_modseq + 1),
        &[],
        None,
    );

    // The max_modseq return is taken from the returned messages, not the full
    // state
    search_test(
        &mut client,
        &format!("SEARCH NOT MODSEQ {}", new_modseq),
        &[2],
        Some(max_modseq),
    );

    // The weird extension thing is parsed but ignored
    // We use "keyword" rather than "\Flagged" because otherwise the client
    // mis-formats the content (since using literals in place of this one
    // particular string is forbidden).
    search_test(
        &mut client,
        &format!(r#"SEARCH MODSEQ "/flags/keyword" all {}"#, new_modseq),
        &[1],
        Some(new_modseq),
    );

    // MODSEQ is not returned if the query doesn't use it
    search_test(&mut client, "SEARCH DELETED", &[1], None);
}
