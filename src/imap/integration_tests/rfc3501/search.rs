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

fn search(client: &mut PipeClient, command: &'static str) -> Vec<u32> {
    command!(mut responses = client, c(command));
    assert_eq!(2, responses.len());
    assert_tagged_ok(responses.pop().unwrap());

    match responses.pop().unwrap() {
        s::ResponseLine {
            tag: None,
            response: s::Response::Search(v),
        } => v.hits,
        r => panic!("Unexpected response: {:?}", r),
    }
}

#[test]
fn search_queries() {
    let setup = set_up();
    let mut client = setup.connect("3501sesq");
    quick_log_in(&mut client);
    examine_shared(&mut client);

    // This test is a rough mirror of `test_search_queries()` in
    // `account::mailbox::search`. In order to maximise the similarity, it uses
    // 0-based message indices for its expectations, which are adjusted into
    // 1-based UIDs by the macros.
    //
    // The tests involving the internal date are different since the messages
    // here have distinct internal dates. Similarly, tests involving \Recent
    // and \Seen are a bit different since the exact state the lower-level test
    // constructs is much harder to achieve over the IMAP protocol.
    macro_rules! uids {
        ($($ix:expr),*) => {
            vec![$($ix + 1u32),*] as Vec<u32>
        }
    }

    macro_rules! uids_compl {
        ($($ix:expr),*) => {{
            let mut v: Vec<u32> = (1u32..=22).into_iter().collect();
            let to_remove: &[usize] = &[$($ix),*];
            for &ix in to_remove.iter().rev() {
                v.remove(ix);
            }
            v
        }}
    }

    assert_eq!(uids![4, 6, 7], search(&mut client, "UID SEARCH 5:7"));
    assert_eq!(uids_compl![5], search(&mut client, "UID SEARCH ALL"));
    assert_eq!(uids![0], search(&mut client, "UID SEARCH ANSWERED"));
    assert_eq!(
        uids![0],
        search(&mut client, r#"UID SEARCH BCC "bcc@example.com""#)
    );
    assert_eq!(
        uids![],
        search(&mut client, r#"UID SEARCH BCC "foo@bar.com""#)
    );
    assert_eq!(
        uids![0, 1],
        search(&mut client, "UID SEARCH BEFORE 3-Jan-2020")
    );
    assert_eq!(
        uids![2, 3],
        search(&mut client, r#"UID SEARCH BODY "prezo""#)
    );
    assert_eq!(
        uids![0],
        search(&mut client, r#"UID SEARCH CC "cc@example.com""#)
    );
    assert_eq!(
        uids![],
        search(&mut client, r#"UID SEARCH CC "bcc@example.com""#)
    );
    assert_eq!(uids![1], search(&mut client, "UID SEARCH DELETED"));
    assert_eq!(uids![2], search(&mut client, "UID SEARCH DRAFT"));
    assert_eq!(uids![3], search(&mut client, "UID SEARCH FLAGGED"));
    assert_eq!(
        uids![4, 6, 7],
        search(&mut client, r#"UID SEARCH FROM "tom.acton""#)
    );
    assert_eq!(
        uids![0],
        search(&mut client, "UID SEARCH HEADER Xyzzy nothing")
    );
    assert_eq!(
        uids![2, 3],
        search(&mut client, "UID SEARCH HEADER x-origin dasovich-j")
    );
    assert_eq!(
        uids![6],
        search(&mut client, "UID SEARCH KEYWORD $Important")
    );
    assert_eq!(
        uids![6],
        search(&mut client, "UID SEARCH KEYWORD $important")
    );
    assert_eq!(uids![], search(&mut client, "UID SEARCH KEYWORD plugh"));
    assert_eq!(
        uids![1, 12, 13],
        search(&mut client, "UID SEARCH LARGER 4002")
    );
    assert_eq!(
        uids_compl![0, 1, 2, 3, 4, 5, 6, 21],
        search(&mut client, "UID SEARCH NEW")
    );
    assert_eq!(
        uids_compl![2, 3, 5],
        search(&mut client, r#"UID SEARCH NOT BODY "prezo""#)
    );
    assert_eq!(
        uids![0, 1, 2, 3, 4, 6],
        search(&mut client, "UID SEARCH OLD")
    );
    assert_eq!(uids![2], search(&mut client, "UID SEARCH ON 3-Jan-2020"));
    assert_eq!(
        uids![2, 3, 6],
        search(
            &mut client,
            r#"UID SEARCH OR KEYWORD $Important BODY "prezo""#
        )
    );
    assert_eq!(
        uids_compl![0, 1, 2, 3, 4, 5, 6],
        search(&mut client, "UID SEARCH RECENT")
    );
    assert_eq!(uids![4, 21], search(&mut client, "UID SEARCH SEEN"));
    assert_eq!(
        uids![0, 1],
        search(&mut client, "UID SEARCH SENTBEFORE 2-Apr-2001")
    );
    assert_eq!(
        uids![4, 6, 7],
        search(&mut client, "UID SEARCH SENTON 2-Apr-2001")
    );
    assert_eq!(
        uids_compl![0, 1, 5],
        search(&mut client, "UID SEARCH SENTSINCE 2-Apr-2001")
    );
    assert_eq!(
        uids_compl![0, 1, 5],
        search(&mut client, "UID SEARCH SINCE 3-Jan-2020")
    );
    assert_eq!(uids![0, 6], search(&mut client, "UID SEARCH SMALLER 1245"));
    assert_eq!(
        uids![4, 6, 7],
        search(&mut client, r#"UID SEARCH SUBJECT "entex""#)
    );
    assert_eq!(
        uids![],
        search(&mut client, r#"UID SEARCH SUBJECT "prezo""#)
    );
    assert_eq!(
        uids![4, 6, 7],
        search(&mut client, r#"UID SEARCH TEXT "entex""#)
    );
    assert_eq!(
        uids![2, 3],
        search(&mut client, r#"UID SEARCH TEXT "prezo""#)
    );
    assert_eq!(
        uids![4, 6, 7],
        search(&mut client, r#"UID SEARCH TO "daren""#)
    );
    assert_eq!(uids![3, 4, 6, 7], search(&mut client, "UID SEARCH UID 4:8"));
    assert_eq!(
        uids_compl![0, 5],
        search(&mut client, "UID SEARCH UNANSWERED")
    );
    assert_eq!(
        uids_compl![1, 5],
        search(&mut client, "UID SEARCH UNDELETED")
    );
    assert_eq!(uids_compl![2, 5], search(&mut client, "UID SEARCH UNDRAFT"));
    assert_eq!(
        uids_compl![3, 5],
        search(&mut client, "UID SEARCH UNFLAGGED")
    );
    assert_eq!(
        uids_compl![5, 6],
        search(&mut client, "UID SEARCH UNKEYWORD $Important")
    );
    assert_eq!(
        uids_compl![5, 6],
        search(&mut client, "UID SEARCH UNKEYWORD $important")
    );
    assert_eq!(
        uids_compl![5],
        search(&mut client, "UID SEARCH UNKEYWORD plugh")
    );
    assert_eq!(
        uids_compl![4, 5, 21],
        search(&mut client, "UID SEARCH UNSEEN")
    );
    assert_eq!(
        uids![2, 3],
        search(&mut client, r#"UID SEARCH 1:4 TEXT "enron""#)
    );
    assert_eq!(
        uids![2, 3],
        search(&mut client, r#"UID SEARCH (1:4 TEXT "enron")"#)
    );

    // End of parallel test cases
    // Now just check that seqnum translation works
    assert_eq!(vec![5, 6], search(&mut client, "SEARCH UID 5:7"));
}

#[test]
fn charsets() {
    let setup = set_up();
    let mut client = setup.connect("3501secs");
    quick_log_in(&mut client);
    examine_shared(&mut client);

    ok_command!(client, c(r#"SEARCH CHARSET "us-ascii" TEXT "enron""#));
    ok_command!(client, c(r#"SEARCH CHARSET "utf-8" TEXT "enron""#));
    ok_command!(client, c(r#"SEARCH CHARSET "US-ASCII" TEXT "enron""#));
    ok_command!(client, c(r#"SEARCH CHARSET "UTF-8" TEXT "enron""#));

    command!(
        [response] = client,
        c(r#"SEARCH CHARSET "CP-437" TEXT "enron""#)
    );
    unpack_cond_response! {
        (Some(_), s::RespCondType::No,
         Some(s::RespTextCode::BadCharset(charsets)), _) = response => {
            assert_eq!(
                vec![Cow::Borrowed("us-ascii"), Cow::Borrowed("utf-8")],
                charsets);
        }
    };
}
