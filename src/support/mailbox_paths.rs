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

/// Given a raw mailbox path, emit the parts that comprise the actual path.
///
/// This accounts for the path delimiter, empty segments, and the required
/// case-insensitivity of the root `inbox` mailbox.
///
/// It does not check for name safety.
pub fn parse_mailbox_path(path: &str) -> impl Iterator<Item = &str> + '_ {
    path.split('/')
        .filter(|s| !s.is_empty())
        .enumerate()
        .map(|(ix, s)| {
            if 0 == ix && "inbox".eq_ignore_ascii_case(s) {
                "INBOX"
            } else {
                s
            }
        })
}

/// Creates a predicate which identifies which normalised mailbox names match
/// any element of `patterns`, with pattern matching performed as per RFC 3501.
///
/// Each pattern is first normalised by `parse_mailbox_path`.
///
/// This design means that any `LIST` operation needs to fetch all mailboxes
/// and then narrow it down, instead of a more ideal recursive filtering.
/// However, the semantics of `*`, particularly the fact that it's permitted in
/// the _middle_ of the path, preclude doing that in any sane (i.e.,
/// non-exponential) way. Since we _only_ iterate actual mailboxes (and not,
/// say, all of USENET, or the user's whole home directory as UW-IMAP), this
/// shouldn't be a problem.
pub fn mailbox_path_matcher<'a>(
    patterns: impl IntoIterator<Item = &'a str>,
) -> impl Fn(&str) -> bool + 'a {
    let mut rx = "^(".to_owned();
    for (pattern_ix, pattern) in patterns.into_iter().enumerate() {
        if pattern_ix > 0 {
            rx.push('|');
        }

        for (part_ix, part) in parse_mailbox_path(pattern).enumerate() {
            if part_ix > 0 {
                rx.push('/');
            }

            let mut start = 0;
            for end in part
                .match_indices(|c| '%' == c || '*' == c)
                .map(|(ix, _)| ix)
                .chain(part.len()..=part.len())
            {
                let chunk = &part[start..end];
                start = (end + 1).min(part.len());

                rx.push_str(&regex::escape(chunk));
                match part.get(end..end + 1) {
                    Some("*") => rx.push_str(".*"),
                    Some("%") => rx.push_str("[^/]*"),
                    _ => (),
                }
            }
        }
    }
    rx.push_str(")$");

    let rx = regex::Regex::new(&rx).expect("Built invalid regex?");
    move |s| rx.is_match(s)
}

#[cfg(test)]
mod test {
    use std::iter;

    use super::*;

    #[test]
    fn test_parse_mailbox_path() {
        fn p(p: &'static str) -> Vec<&'static str> {
            parse_mailbox_path(p).collect()
        }

        assert_eq!(vec!["INBOX"], p("inbox"));
        assert_eq!(vec!["INBOX", "foo"], p("Inbox/foo"));
        assert_eq!(vec!["bar"], p("/bar"));
        assert_eq!(vec!["bar"], p("bar/"));
        assert_eq!(vec!["foo", "bar"], p("foo//bar"));
        assert_eq!(vec!["foo", "InBoX"], p("foo/InBoX"));
    }

    #[test]
    fn test_mailbox_patterns() {
        fn matches(pat: &str, mb: &str) -> bool {
            mailbox_path_matcher(iter::once(pat))(mb)
        }

        assert!(matches("*", "INBOX"));
        assert!(matches("%", "INBOX"));

        assert!(matches("INB*X", "INBOX"));
        assert!(matches("INB*X", "INB/BOX"));
        assert!(!matches("INB*X", "INBOX/plugh"));
        assert!(!matches("INB*X", "foo/INBOX"));
        assert!(matches("INB%X", "INBOX"));
        assert!(!matches("INB%X", "INB/BOX"));
        assert!(!matches("INB%X", "INBOX/plugh"));

        assert!(matches("INB*", "INBOX"));
        assert!(matches("INB*", "INBOX/plugh"));
        assert!(matches("INB%", "INBOX"));
        assert!(!matches("INB%", "INBOX/plugh"));
        assert!(!matches("INB%", "foo/INBOX"));

        assert!(matches("*X", "INBOX"));
        assert!(matches("*X", "foo/boX"));
        assert!(matches("%X", "INBOX"));
        assert!(!matches("%X", "foo/boX"));

        assert!(matches("foo/bar", "foo/bar"));
        assert!(!matches("foo/bar", "foo/bar/baz"));
        assert!(!matches("foo/*", "foo"));
        assert!(matches("foo/*", "foo/bar"));
        assert!(matches("foo/*", "foo/bar/baz"));
        assert!(matches("foo/%", "foo/bar"));
        assert!(!matches("foo/%", "foo/bar/baz"));

        assert!(matches("inbox", "INBOX"));
    }
}
