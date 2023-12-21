//-
// Copyright (c) 2023, Jason Lingle
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

use std::sync::Arc;

use log::warn;
use regex::{self, Regex};

use super::defs::*;
use crate::account::{
    model::*,
    search_backend::{self, Op},
};
use crate::mime::{
    fetch::search::{OptionalSearchParts, SearchFetcher},
    grovel,
};
use crate::support::error::Error;

impl Account {
    /// The `SEARCH` command.
    pub fn seqnum_search(
        &mut self,
        mailbox: &Mailbox,
        request: &SearchRequest,
    ) -> Result<SearchResponse<Seqnum>, Error> {
        let result = self.search(mailbox, request)?;

        Ok(SearchResponse {
            max_modseq: result.max_modseq,
            first_modseq: result.first_modseq,
            last_modseq: result.last_modseq,
            hit_uids: result.hit_uids,
            hits: result
                .hits
                .into_iter()
                .map(|uid| {
                    Seqnum::from_index(
                        mailbox
                            .uid_index(uid)
                            // We only find things which are in the snapshot,
                            // so the case of being unable to map back to a
                            // sequence number should never come up.
                            .expect("Search found unaddressable UID?"),
                    )
                })
                .collect(),
        })
    }

    /// The `UID SEARCH` command.
    pub fn search(
        &mut self,
        mailbox: &Mailbox,
        request: &SearchRequest,
    ) -> Result<SearchResponse<Uid>, Error> {
        let mut ops = Vec::new();
        mailbox.compile_and(&mut ops, &request.queries);
        let want = search_backend::want(&ops);

        let ops = Arc::new(ops);
        let mut hits = mailbox
            .messages
            .iter()
            .filter(|message| {
                self.search_one(mailbox, message, Arc::clone(&ops), want)
            })
            .collect::<Vec<_>>();
        // RFC 3501 doesn't require the results to be in any particular order,
        // but this step is very cheap and there could be clients depending on
        // it. We also need the output sorted for ESEARCH.
        hits.sort_unstable_by_key(|m| m.uid);

        let hit_uids = hits.iter().map(|m| m.uid).collect::<Vec<_>>();

        Ok(SearchResponse {
            first_modseq: hits.first().map(|m| m.last_modified),
            last_modseq: hits.last().map(|m| m.last_modified),
            max_modseq: hits.iter().map(|m| m.last_modified).max(),
            hits: hit_uids.clone(),
            hit_uids,
        })
    }

    fn search_one(
        &mut self,
        mailbox: &Mailbox,
        message: &MessageStatus,
        ops: Arc<Vec<Op>>,
        want: OptionalSearchParts,
    ) -> bool {
        let result = self.access_message(mailbox, message.uid).and_then(
            |mut accessor| {
                grovel::grovel(
                    &mut accessor,
                    SearchFetcher::new(want, move |sd| {
                        search_backend::eval(&ops, sd)
                    }),
                )
            },
        );

        match result {
            Ok(r) => r,
            // If the message is gone meanwhile, just ignore it
            Err(Error::ExpungedMessage) | Err(Error::NxMessage) => false,
            Err(e) => {
                warn!(
                    // TODO log prefix
                    "error evaluating UID {} for search: {}",
                    message.uid.0.get(),
                    e,
                );
                false
            },
        }
    }
}

impl Mailbox {
    fn compile_and(&self, dst: &mut Vec<Op>, queries: &[SearchQuery]) {
        if queries.is_empty() {
            dst.push(Op::True);
            return;
        }

        let mut first = true;
        for q in queries {
            self.compile_one(dst, q);
            if !first {
                dst.push(Op::And);
            }
            first = false;
        }
    }

    fn compile_one(&self, dst: &mut Vec<Op>, query: &SearchQuery) {
        match *query {
            SearchQuery::SequenceSet(ref seqnums) => {
                let uids = self.seqnum_range_to_uid(seqnums, true).unwrap();
                dst.push(Op::UidIn(uids));
            },

            SearchQuery::All => dst.push(Op::True),

            SearchQuery::Answered => dst.push(Op::Flag(Flag::Answered)),

            SearchQuery::Bcc(ref pat) => {
                dst.push(Op::Bcc(to_regex(pat)));
            },

            SearchQuery::Before(date) => {
                dst.push(Op::InternalDateCompare(date, true, false, false));
            },

            SearchQuery::Body(ref pat) => {
                dst.push(Op::Content(Arc::new(to_regex(pat))));
            },

            SearchQuery::Cc(ref pat) => {
                dst.push(Op::Cc(to_regex(pat)));
            },

            SearchQuery::Deleted => dst.push(Op::Flag(Flag::Deleted)),

            SearchQuery::Draft => dst.push(Op::Flag(Flag::Draft)),

            SearchQuery::Flagged => dst.push(Op::Flag(Flag::Flagged)),

            SearchQuery::From(ref pat) => {
                dst.push(Op::From(to_regex(pat)));
            },

            SearchQuery::Header(ref name, ref value) => {
                let mut name = name.to_owned();
                name.make_ascii_lowercase();
                dst.push(Op::Header(name, to_regex(value)));
            },

            SearchQuery::Keyword(ref name) => {
                dst.push(Op::Flag(Flag::Keyword(name.to_owned())));
            },

            SearchQuery::Larger(thresh) => {
                dst.push(Op::SizeCompare(thresh, false, false, true));
            },

            SearchQuery::New => {
                dst.push(Op::Recent);
                dst.push(Op::Flag(Flag::Seen));
                dst.push(Op::Not);
                dst.push(Op::And);
            },

            SearchQuery::Not(ref sub) => {
                self.compile_one(dst, sub);
                dst.push(Op::Not);
            },

            SearchQuery::Old => {
                dst.push(Op::Recent);
                dst.push(Op::Not);
            },

            SearchQuery::On(date) => {
                dst.push(Op::InternalDateCompare(date, false, true, false));
            },

            SearchQuery::Or(ref a, ref b) => {
                self.compile_one(dst, a);
                self.compile_one(dst, b);
                dst.push(Op::Or);
            },

            SearchQuery::Recent => dst.push(Op::Recent),

            SearchQuery::Seen => dst.push(Op::Flag(Flag::Seen)),

            SearchQuery::SentBefore(date) => {
                dst.push(Op::DateCompare(date, true, false, false));
            },

            SearchQuery::SentOn(date) => {
                dst.push(Op::DateCompare(date, false, true, false));
            },

            SearchQuery::SentSince(date) => {
                // RFC 3501 specifies >=, not >
                dst.push(Op::DateCompare(date, false, true, true));
            },

            SearchQuery::Since(date) => {
                // RFC 3501 specifies >=, not >
                dst.push(Op::InternalDateCompare(date, false, true, true));
            },

            SearchQuery::Smaller(thresh) => {
                dst.push(Op::SizeCompare(thresh, true, false, false));
            },

            SearchQuery::Subject(ref pat) => {
                dst.push(Op::Subject(to_regex(pat)));
            },

            SearchQuery::Text(ref pat) => {
                let regex = Arc::new(to_regex(pat));
                dst.push(Op::AnyHeader(Arc::clone(&regex)));
                dst.push(Op::Content(regex));
                dst.push(Op::Or);
            },

            SearchQuery::To(ref pat) => {
                dst.push(Op::To(to_regex(pat)));
            },

            SearchQuery::UidSet(ref uids) => {
                dst.push(Op::UidIn(uids.to_owned()))
            },

            SearchQuery::Unanswered => {
                dst.push(Op::Flag(Flag::Answered));
                dst.push(Op::Not);
            },

            SearchQuery::Undeleted => {
                dst.push(Op::Flag(Flag::Deleted));
                dst.push(Op::Not);
            },

            SearchQuery::Undraft => {
                dst.push(Op::Flag(Flag::Draft));
                dst.push(Op::Not);
            },

            SearchQuery::Unflagged => {
                dst.push(Op::Flag(Flag::Flagged));
                dst.push(Op::Not);
            },

            SearchQuery::Unkeyword(ref name) => {
                dst.push(Op::Flag(Flag::Keyword(name.to_owned())));
                dst.push(Op::Not);
            },

            SearchQuery::Unseen => {
                dst.push(Op::Flag(Flag::Seen));
                dst.push(Op::Not);
            },

            SearchQuery::And(ref queries) => self.compile_and(dst, queries),

            SearchQuery::Modseq(ms) => {
                dst.push(Op::Modseq(ms.raw()));
            },

            SearchQuery::EmailId(ref email_id) => {
                dst.push(Op::EmailId(email_id.clone()));
            },

            SearchQuery::ThreadId(_) => {
                // We don't support THREADID, so this never matches
                dst.push(Op::True);
                dst.push(Op::Not);
            },

            SearchQuery::SaveDateSupported => {
                dst.push(Op::True);
            },

            SearchQuery::SavedBefore(date) => {
                dst.push(Op::SaveDateCompare(date, true, false, false));
            },
            SearchQuery::SavedOn(date) => {
                dst.push(Op::SaveDateCompare(date, false, true, false));
            },
            SearchQuery::SavedSince(date) => {
                dst.push(Op::SaveDateCompare(date, false, false, true));
            },
        }
    }
}

/// We use the regex library for substring matching both for its excellent
/// performance and to take advantage of its Unicode-aware case insensitivity.
///
/// The case-insensitivity this implements is not the `i;unicode-casemap`
/// comparison that Crispin designed in RFC 5051 (formally required by the
/// I18NLEVEL=1 extension, RFC 5255), but is preferable since it is actually a
/// comparison sanctioned by the Unicode Consortium and isn't 13+ years out of
/// date.
fn to_regex(pat: &str) -> Regex {
    let mut regex_str = String::new();
    for (ix, chunk) in
        pat.split_whitespace().filter(|s| !s.is_empty()).enumerate()
    {
        if 0 != ix {
            regex_str.push_str("[ \r\n\t]+");
        }
        regex_str.push_str(&regex::escape(chunk));
    }

    regex::RegexBuilder::new(&regex_str)
        .case_insensitive(true)
        .build()
        .expect("Created bad regex")
}

#[cfg(test)]
mod test {
    use super::*;

    use chrono::prelude::*;

    use crate::support::chronox::*;
    use crate::test_data::*;

    #[test]
    fn creates_proper_regexen() {
        let regex = to_regex("foo \\bar");
        assert!(regex.is_match("foo \\bar"));
        assert!(regex.is_match("FOO \\BAR"));
        assert!(regex.is_match("foo  \\bar"));
        assert!(regex.is_match("foo\t\\bar"));
        assert!(regex.is_match("foo\r\n\\bar"));
        assert!(regex.is_match("xfoo  \\barx"));
        assert!(!regex.is_match("foo\\bar"));
    }

    #[test]
    fn test_search_queries() {
        use crate::account::model::SearchQuery::*;

        let mut fixture = TestFixture::new();
        let mut mb1 = fixture.select("INBOX", true, None).unwrap().0;
        let mut mb2 = fixture.select("INBOX", true, None).unwrap().0;

        let mut uids = [CHRISTMAS_TREE, TORTURE_TEST]
            .iter()
            .map(|data| fixture.simple_append_data("INBOX", data))
            .collect::<Vec<_>>();
        // Claim \Recent for the first two messages in the second session,
        // which we have only for this purpose.
        fixture.poll(&mut mb2).unwrap();

        uids.extend(
            ENRON_SMALL_MULTIPARTS
                .iter()
                .map(|data| fixture.simple_append_data("INBOX", data)),
        );
        // Claim the ENRON messages as \Recent in the first session (the one
        // under test).
        fixture.poll(&mut mb1).unwrap();

        // Create a gap in the sequence number / UID mapping
        fixture.vanquish(&mb1, &SeqRange::just(uids[5])).unwrap();

        // Set each flag on a distinct message
        fixture
            .store(
                &mut mb1,
                &StoreRequest {
                    ids: &SeqRange::just(uids[0]),
                    flags: &[Flag::Answered],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                },
            )
            .unwrap();
        fixture
            .store(
                &mut mb1,
                &StoreRequest {
                    ids: &SeqRange::just(uids[1]),
                    flags: &[Flag::Deleted],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                },
            )
            .unwrap();
        fixture
            .store(
                &mut mb1,
                &StoreRequest {
                    ids: &SeqRange::just(uids[2]),
                    flags: &[Flag::Draft],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                },
            )
            .unwrap();
        fixture
            .store(
                &mut mb1,
                &StoreRequest {
                    ids: &SeqRange::just(uids[3]),
                    flags: &[Flag::Flagged],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                },
            )
            .unwrap();
        fixture
            .store(
                &mut mb1,
                &StoreRequest {
                    ids: &SeqRange::just(uids[4]),
                    flags: &[Flag::Seen],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                },
            )
            .unwrap();
        fixture
            .store(
                &mut mb1,
                &StoreRequest {
                    ids: &SeqRange::just(uids[6]),
                    flags: &[Flag::Keyword("$Important".to_owned())],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                },
            )
            .unwrap();
        fixture.poll(&mut mb1).unwrap();

        macro_rules! uids {
            ($($ix:expr),*) => {
                vec![$(uids[$ix],)*] as Vec<Uid>
            }
        }

        macro_rules! uids_compl {
            ($($ix:expr),*) => {
                uids.iter()
                    .copied()
                    .enumerate()
                    .filter(|&(ix, _)| $($ix != ix)&&*)
                    .map(|(_, uid)| uid)
                    .collect::<Vec<_>>()
            }
        }

        macro_rules! search {
            ($($query:expr),*) => {
                fixture.search(&mb1, &SearchRequest {
                    queries: vec![$($query),*],
                }).unwrap().hits
            }
        }

        let today = Utc::now().date_naive();

        assert_eq!(
            uids![4, 6, 7],
            search!(SequenceSet(SeqRange::range(Seqnum::u(5), Seqnum::u(7))))
        );

        assert_eq!(uids_compl![5], search!(All));

        assert_eq!(uids![0], search!(Answered));

        assert_eq!(uids![0], search!(Bcc("bcc@example.com".to_owned())));
        assert_eq!(uids![], search!(Bcc("foo@bar.com".to_owned())));

        assert_eq!(uids![], search!(Before(NaiveDate::from_ymdx(2000, 1, 1))));
        assert_eq!(uids![], search!(Before(today)));
        assert_eq!(
            uids_compl![5],
            search!(Before(NaiveDate::from_ymdx(3000, 1, 1)))
        );

        assert_eq!(uids![2, 3], search!(Body("prezo".to_owned())));

        assert_eq!(uids![0], search!(Cc("cc@example.com".to_owned())));
        assert_eq!(uids![], search!(Cc("bcc@example.com".to_owned())));

        assert_eq!(uids![1], search!(Deleted));

        assert_eq!(uids![2], search!(Draft));

        assert_eq!(uids![3], search!(Flagged));

        assert_eq!(uids![4, 6, 7], search!(From("tom.acton".to_owned())));

        assert_eq!(
            uids![0],
            search!(Header("Xyzzy".to_owned(), "nothing".to_owned()))
        );
        assert_eq!(
            uids![2, 3],
            search!(Header("x-origin".to_owned(), "dasovich-j".to_owned()))
        );

        assert_eq!(uids![6], search!(Keyword("$Important".to_owned())));
        assert_eq!(uids![6], search!(Keyword("$important".to_owned())));
        assert_eq!(uids![], search!(Keyword("plugh".to_owned())));

        // There's a message with size 4002, so we're also testing here that
        // equality is excluded
        assert_eq!(uids![1, 12, 13], search!(Larger(4002)));

        // 0 and 1 are not \Recent, 4 is \Seen, 5 was expunged
        assert_eq!(uids_compl![0, 1, 4, 5], search!(New));

        assert_eq!(
            uids_compl![2, 3, 5],
            search!(Not(Box::new(Body("prezo".to_owned()))))
        );

        assert_eq!(uids![0, 1], search!(Old));

        assert_eq!(uids_compl![5], search!(On(today)));
        assert_eq!(uids![], search!(On(NaiveDate::from_ymdx(2000, 1, 1))));
        assert_eq!(uids![], search!(On(NaiveDate::from_ymdx(3000, 1, 1))));

        assert_eq!(
            uids![2, 3, 6],
            search!(Or(
                Box::new(Keyword("$Important".to_owned())),
                Box::new(Body("prezo".to_owned()))
            ))
        );

        assert_eq!(uids_compl![0, 1, 5], search!(Recent));

        assert_eq!(uids![4], search!(Seen));

        assert_eq!(
            uids![0, 1],
            search!(SentBefore(NaiveDate::from_ymdx(2001, 4, 2)))
        );
        assert_eq!(
            uids![4, 6, 7],
            search!(SentOn(NaiveDate::from_ymdx(2001, 4, 2)))
        );
        assert_eq!(
            uids_compl![0, 1, 5],
            search!(SentSince(NaiveDate::from_ymdx(2001, 4, 2)))
        );

        assert_eq!(uids_compl![5], search!(Since(today)));
        assert_eq!(
            uids_compl![5],
            search!(Since(NaiveDate::from_ymdx(1970, 1, 1)))
        );
        assert_eq!(uids![], search!(Since(NaiveDate::from_ymdx(3000, 1, 1))));

        // There's a message with size 1245, so this also tests exclusion of
        // equality
        assert_eq!(uids![0, 6], search!(Smaller(1245)));

        assert_eq!(uids![4, 6, 7], search!(Subject("entex".to_owned())));

        assert_eq!(uids![4, 6, 7], search!(Text("entex".to_owned())));
        assert_eq!(uids![2, 3], search!(Text("prezo".to_owned())));

        assert_eq!(uids![4, 6, 7], search!(To("daren".to_owned())));

        assert_eq!(
            uids![3, 4, 6, 7],
            search!(UidSet(SeqRange::range(uids[3], uids[7])))
        );

        assert_eq!(uids_compl![0, 5], search!(Unanswered));

        assert_eq!(uids_compl![1, 5], search!(Undeleted));

        assert_eq!(uids_compl![2, 5], search!(Undraft));

        assert_eq!(uids_compl![3, 5], search!(Unflagged));

        assert_eq!(
            uids_compl![5, 6],
            search!(Unkeyword("$Important".to_owned()))
        );
        assert_eq!(
            uids_compl![5, 6],
            search!(Unkeyword("$important".to_owned()))
        );
        assert_eq!(uids_compl![5], search!(Unkeyword("plugh".to_owned())));

        assert_eq!(uids_compl![4, 5], search!(Unseen));

        assert_eq!(
            uids![2, 3],
            search!(
                UidSet(SeqRange::range(uids[0], uids[3])),
                Text("enron".to_owned())
            )
        );
        assert_eq!(
            uids![2, 3],
            search!(And(vec![
                UidSet(SeqRange::range(uids[0], uids[3])),
                Text("enron".to_owned())
            ]))
        );
    }

    #[test]
    fn search_encoded_bodies() {
        let mut fixture = TestFixture::new();
        let uid1 = fixture.simple_append_data(
            "INBOX",
            b"Content-Type: text/plain; charset=\"SHIFT-JIS\"\n\
              Content-Transfer-Encoding: base64\n\
              \n\
              iOqPj4LJiOqU1IuWgrOC6oLIgqKCsYLGgvCCtYLmgqQ=\n",
        );
        let uid2 = fixture.simple_append_data(
            "INBOX",
            b"Content-Type: text/plain; charset=UTF-7\n\
              Content-Transfer-Encoding: quoted-printable\n\
              \n\
              That is not dead which can eternal lie.\n\
              And with strange +AOY-=\n\
              ons even death may die.\n",
        );
        let mb = fixture.select("INBOX", false, None).unwrap().0;

        let result = fixture
            .search(
                &mb,
                &SearchRequest {
                    queries: vec![SearchQuery::Text("許されない".to_owned())],
                },
            )
            .unwrap();
        assert_eq!(vec![uid1], result.hits);

        let result = fixture
            .search(
                &mb,
                &SearchRequest {
                    queries: vec![SearchQuery::Text("ÆONS".to_owned())],
                },
            )
            .unwrap();
        assert_eq!(vec![uid2], result.hits);
    }

    #[test]
    fn test_seqnum_search() {
        let mut fixture = TestFixture::new();

        for _ in 0..3 {
            fixture.simple_append("INBOX");
        }

        let mut mb = fixture.select("INBOX", true, None).unwrap().0;
        fixture.vanquish(&mb, &SeqRange::just(Uid::MIN)).unwrap();
        fixture.poll(&mut mb).unwrap();

        let result = fixture
            .seqnum_search(
                &mb,
                &SearchRequest {
                    queries: vec![SearchQuery::All],
                },
            )
            .unwrap();

        assert_eq!(vec![Seqnum::u(1), Seqnum::u(2)], result.hits);
    }

    #[test]
    fn purged_messages_ignored() {
        let mut fixture = TestFixture::new();
        let uids = ENRON_SMALL_MULTIPARTS
            .iter()
            .map(|data| fixture.simple_append_data("INBOX", data))
            .collect::<Vec<_>>();

        let mb1 = fixture.select("INBOX", false, None).unwrap().0;
        let mb2 = fixture.select("INBOX", true, None).unwrap().0;

        fixture
            .vanquish(&mb2, &SeqRange::range(uids[1], *uids.last().unwrap()))
            .unwrap();
        fixture.purge_all().unwrap();

        let result = fixture
            .search(
                &mb1,
                &SearchRequest {
                    // Use Text search to force loading of the message (and subsequent
                    // failure since most of them are gone).
                    queries: vec![SearchQuery::Text("@".to_owned())],
                },
            )
            .unwrap();

        assert_eq!(vec![uids[0]], result.hits);
    }

    #[test]
    fn correct_modseqs_returned() {
        let mut fixture = TestFixture::new();
        let uids = ENRON_SMALL_MULTIPARTS[..5]
            .iter()
            .map(|data| fixture.simple_append_data("INBOX", data))
            .collect::<Vec<_>>();

        let mut mb = fixture.select("INBOX", true, None).unwrap().0;

        // Give UID 2 the highest modseq
        fixture
            .store(
                &mut mb,
                &StoreRequest {
                    ids: &SeqRange::just(uids[1]),
                    flags: &[Flag::Answered],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                },
            )
            .unwrap();
        fixture.poll(&mut mb).unwrap();

        let result = fixture
            .search(
                &mb,
                &SearchRequest {
                    queries: vec![SearchQuery::All],
                },
            )
            .unwrap();
        assert_eq!(Some(Modseq::of(2)), result.first_modseq);
        assert_eq!(Some(Modseq::of(6)), result.last_modseq);
        assert_eq!(Some(Modseq::of(7)), result.max_modseq);

        let result = fixture
            .search(
                &mb,
                &SearchRequest {
                    queries: vec![SearchQuery::Text("gaap".to_owned())],
                },
            )
            .unwrap();
        assert_eq!(None, result.first_modseq);
        assert_eq!(None, result.last_modseq);
        assert_eq!(None, result.max_modseq);
    }
}
