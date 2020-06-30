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

//! Backend for evaluating search matches.
//!
//! Searches are evaluated by a simple stack machine whose values are a
//! false/true/unknown tri-state. The maximum stack height is 32, after which
//! old values are forgotten. Stack underflow results in false.

use std::cmp::{Ord, Ordering};
use std::sync::Arc;

use chrono::prelude::*;
use regex::Regex;

use crate::account::model::*;
use crate::mime::fetch::search::{OptionalSearchParts, SearchData};

/// A single operation on the stack machine.
///
/// Most operations should be fairly self-explanatory.
///
/// Regex matching is unanchored.
///
/// "Comparison" operations take 3 booleans indicating the results for
/// less-than, equals, and greater-than comparisons, respectively. Comparison
/// is performed as `<value-in-message> <op> <value-in-op>`.
#[derive(Debug)]
pub enum Op {
    True,
    And,
    Or,
    Not,
    Flag(Flag),
    Recent,
    From(Regex),
    Bcc(Regex),
    Cc(Regex),
    To(Regex),
    Subject(Regex),
    Header(String, Regex),
    AnyHeader(Arc<Regex>),
    Content(Arc<Regex>),
    InternalDateCompare(NaiveDate, bool, bool, bool),
    DateCompare(NaiveDate, bool, bool, bool),
    SizeCompare(u32, bool, bool, bool),
    UidIn(SeqRange<Uid>),
    #[cfg(test)]
    _Const(u64),
}

const UNKNOWN: u64 = 2;
const TRUE: u64 = 1;

struct Stack(u64);

impl Stack {
    fn push(&mut self, val: u64) {
        self.0 <<= 2;
        self.0 |= val;
    }

    fn o(&mut self, val: Option<bool>) {
        self.push(val.map(|v| v as u64).unwrap_or(UNKNOWN));
    }

    fn and(&mut self) {
        let key = self.0 & 15;
        self.0 >>= 2;
        self.0 &= !3;
        const TABLE: u64 =
        // A: 11 11 11 11 10 10 10 10 01 01 01 01 00 00 00 00
        // B: 11 10 01 00 11 10 01 00 11 10 01 00 11 10 01 00
            0b11_11_11_00_11_11_11_00_11_11_01_00_00_00_00_00;
        self.0 |= (TABLE >> (2 * key)) & 3;
    }

    fn or(&mut self) {
        let key = self.0 & 15;
        self.0 >>= 2;
        self.0 &= !3;
        const TABLE: u64 =
        // A: 11 11 11 11 10 10 10 10 01 01 01 01 00 00 00 00
        // B: 11 10 01 00 11 10 01 00 11 10 01 00 11 10 01 00
            0b11_11_01_11_11_11_01_11_01_01_01_01_11_11_01_00;
        self.0 |= (TABLE >> (2 * key)) & 3;
    }

    fn not(&mut self) {
        self.0 ^= TRUE;
    }
}

/// Evaluate whether `data` is matched by the stack machine given in `ops`.
pub fn eval(ops: &[Op], data: &SearchData) -> Option<bool> {
    let mut s = Stack(0u64);

    for op in ops {
        match op {
            &Op::True => s.push(TRUE),
            &Op::And => s.and(),
            &Op::Or => s.or(),
            &Op::Not => s.not(),
            #[cfg(test)]
            &Op::_Const(v) => s.push(v),

            &Op::Flag(ref flag) => {
                s.o(data.flags.as_ref().map(|f| f.contains(flag)))
            }
            &Op::Recent => s.o(data.recent),

            &Op::From(ref r) => s.o(data.from.as_ref().map(|v| r.is_match(v))),
            &Op::Cc(ref r) => s.o(data.cc.as_ref().map(|v| r.is_match(v))),
            &Op::Bcc(ref r) => s.o(data.bcc.as_ref().map(|v| r.is_match(v))),
            &Op::To(ref r) => s.o(data.to.as_ref().map(|v| r.is_match(v))),
            &Op::Subject(ref r) => {
                s.o(data.subject.as_ref().map(|v| r.is_match(v)))
            }
            &Op::Header(ref name, ref r) => {
                s.o(data.headers.as_ref().map(|h| {
                    h.get(name).map(|v| r.is_match(v)).unwrap_or(false)
                }));
            }
            &Op::AnyHeader(ref r) => {
                s.o(data
                    .headers
                    .as_ref()
                    .map(|h| h.values().any(|v| r.is_match(v))));
            }
            &Op::Content(ref r) => {
                s.o(data.content.as_ref().map(|v| r.is_match(v)))
            }

            &Op::InternalDateCompare(ref relative, lt, eq, gt) => {
                s.o(cmp_date(
                    data.metadata.as_ref().map(|md| &md.internal_date),
                    relative,
                    lt,
                    eq,
                    gt,
                ));
            }
            &Op::DateCompare(ref relative, lt, eq, gt) => {
                s.o(cmp_date(data.date.as_ref(), relative, lt, eq, gt));
            }
            &Op::SizeCompare(ref relative, lt, eq, gt) => {
                s.o(cmp(
                    data.metadata.as_ref().map(|md| &md.size),
                    relative,
                    lt,
                    eq,
                    gt,
                ));
            }

            &Op::UidIn(ref set) => s.o(data.uid.map(|u| set.contains(u))),
        }
    }

    if UNKNOWN == s.0 & UNKNOWN {
        None
    } else {
        Some(TRUE == s.0 & TRUE)
    }
}

fn cmp<T: Ord>(
    value: Option<&T>,
    relative: &T,
    lt: bool,
    eq: bool,
    gt: bool,
) -> Option<bool> {
    value.map(|value| match value.cmp(relative) {
        Ordering::Less => lt,
        Ordering::Equal => eq,
        Ordering::Greater => gt,
    })
}

fn cmp_date(
    value: Option<&DateTime<FixedOffset>>,
    relative: &NaiveDate,
    lt: bool,
    eq: bool,
    gt: bool,
) -> Option<bool> {
    let value = value.map(|v| v.naive_local().date());
    cmp(value.as_ref(), relative, lt, eq, gt)
}

/// Determine what `OptionalSearchParts` are needed to properly evaluate the
/// given stack matcher.
pub fn want(ops: &[Op]) -> OptionalSearchParts {
    let mut accum = OptionalSearchParts::empty();

    for op in ops {
        accum |= match op {
            &Op::True
            | &Op::And
            | &Op::Or
            | &Op::Not
            | &Op::Content(..)
            | &Op::InternalDateCompare(..)
            | &Op::SizeCompare(..)
            | &Op::UidIn(..) => OptionalSearchParts::empty(),

            #[cfg(test)]
            &Op::_Const(..) => OptionalSearchParts::empty(),

            &Op::Flag(..) | &Op::Recent => OptionalSearchParts::FLAGS,

            &Op::From(..) => OptionalSearchParts::FROM,
            &Op::Cc(..) => OptionalSearchParts::CC,
            &Op::Bcc(..) => OptionalSearchParts::BCC,
            &Op::To(..) => OptionalSearchParts::TO,
            &Op::Subject(..) => OptionalSearchParts::SUBJECT,
            &Op::Header(..) | &Op::AnyHeader(..) => {
                OptionalSearchParts::HEADER_MAP
            }

            &Op::DateCompare(..) => OptionalSearchParts::DATE,
        }
    }

    accum
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use super::*;

    fn singleton_map(key: &str, value: &str) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert(key.to_owned(), value.to_owned());
        map
    }

    #[test]
    fn single_primitive_fields() {
        let ops = &[Op::UidIn(SeqRange::range(Uid::u(10), Uid::u(20)))];
        assert_eq!(None, eval(ops, &SearchData::default()));
        assert_eq!(
            Some(false),
            eval(
                ops,
                &SearchData {
                    uid: Some(Uid::u(9)),
                    ..SearchData::default()
                }
            )
        );
        assert_eq!(
            Some(true),
            eval(
                ops,
                &SearchData {
                    uid: Some(Uid::u(20)),
                    ..SearchData::default()
                }
            )
        );
        assert_eq!(
            Some(false),
            eval(
                ops,
                &SearchData {
                    uid: Some(Uid::u(21)),
                    ..SearchData::default()
                }
            )
        );
    }

    #[test]
    fn single_flaglike_fields() {
        let ops = &[Op::Flag(Flag::Flagged)];
        assert_eq!(None, eval(ops, &SearchData::default()));
        assert_eq!(
            Some(true),
            eval(
                ops,
                &SearchData {
                    flags: Some(vec![Flag::Flagged]),
                    ..SearchData::default()
                }
            )
        );
        assert_eq!(
            Some(false),
            eval(
                ops,
                &SearchData {
                    flags: Some(vec![Flag::Deleted]),
                    ..SearchData::default()
                }
            )
        );

        let ops = &[Op::Recent];
        assert_eq!(None, eval(ops, &SearchData::default()));
        assert_eq!(
            Some(true),
            eval(
                ops,
                &SearchData {
                    recent: Some(true),
                    ..SearchData::default()
                }
            )
        );
        assert_eq!(
            Some(false),
            eval(
                ops,
                &SearchData {
                    recent: Some(false),
                    ..SearchData::default()
                }
            )
        );
    }

    #[test]
    fn single_string_header_fields() {
        let ops = &[Op::From(Regex::new("foo").unwrap())];
        assert_eq!(None, eval(ops, &SearchData::default()));
        assert_eq!(
            Some(true),
            eval(
                ops,
                &SearchData {
                    from: Some("\"Foo Bar\" <foo@bar.com>, ".to_owned()),
                    ..SearchData::default()
                }
            )
        );
        assert_eq!(
            Some(false),
            eval(
                ops,
                &SearchData {
                    from: Some("\"John Doe\" <jdoe@bar.com>, ".to_owned()),
                    ..SearchData::default()
                }
            )
        );

        let ops = &[Op::Cc(Regex::new("foo").unwrap())];
        assert_eq!(None, eval(ops, &SearchData::default()));
        assert_eq!(
            Some(true),
            eval(
                ops,
                &SearchData {
                    cc: Some("\"Foo Bar\" <foo@bar.com>, ".to_owned()),
                    ..SearchData::default()
                }
            )
        );
        assert_eq!(
            Some(false),
            eval(
                ops,
                &SearchData {
                    cc: Some("\"John Doe\" <jdoe@bar.com>, ".to_owned()),
                    ..SearchData::default()
                }
            )
        );

        let ops = &[Op::Bcc(Regex::new("foo").unwrap())];
        assert_eq!(None, eval(ops, &SearchData::default()));
        assert_eq!(
            Some(true),
            eval(
                ops,
                &SearchData {
                    bcc: Some("\"Foo Bar\" <foo@bar.com>, ".to_owned()),
                    ..SearchData::default()
                }
            )
        );
        assert_eq!(
            Some(false),
            eval(
                ops,
                &SearchData {
                    bcc: Some("\"John Doe\" <jdoe@bar.com>, ".to_owned()),
                    ..SearchData::default()
                }
            )
        );

        let ops = &[Op::To(Regex::new("foo").unwrap())];
        assert_eq!(None, eval(ops, &SearchData::default()));
        assert_eq!(
            Some(true),
            eval(
                ops,
                &SearchData {
                    to: Some("\"Foo Bar\" <foo@bar.com>, ".to_owned()),
                    ..SearchData::default()
                }
            )
        );
        assert_eq!(
            Some(false),
            eval(
                ops,
                &SearchData {
                    to: Some("\"John Doe\" <jdoe@bar.com>, ".to_owned()),
                    ..SearchData::default()
                }
            )
        );

        let ops = &[Op::Subject(Regex::new("foo").unwrap())];
        assert_eq!(None, eval(ops, &SearchData::default()));
        assert_eq!(
            Some(true),
            eval(
                ops,
                &SearchData {
                    subject: Some("Where is the food".to_owned()),
                    ..SearchData::default()
                }
            )
        );
        assert_eq!(
            Some(false),
            eval(
                ops,
                &SearchData {
                    subject: Some("Where is the f00d".to_owned()),
                    ..SearchData::default()
                }
            )
        );

        let ops = &[Op::Header("xyzzy".to_owned(), Regex::new("foo").unwrap())];
        assert_eq!(None, eval(ops, &SearchData::default()));
        assert_eq!(
            Some(true),
            eval(
                ops,
                &SearchData {
                    headers: Some(singleton_map("xyzzy", "x-foobar")),
                    ..SearchData::default()
                }
            )
        );
        assert_eq!(
            Some(false),
            eval(
                ops,
                &SearchData {
                    headers: Some(singleton_map("xyzzy", "nothing happens")),
                    ..SearchData::default()
                }
            )
        );
        assert_eq!(
            Some(false),
            eval(
                ops,
                &SearchData {
                    headers: Some(singleton_map("plugh", "nothing happens")),
                    ..SearchData::default()
                }
            )
        );

        let ops = &[Op::AnyHeader(Arc::new(Regex::new("foo").unwrap()))];
        assert_eq!(None, eval(ops, &SearchData::default()));
        assert_eq!(
            Some(true),
            eval(
                ops,
                &SearchData {
                    headers: Some(singleton_map("xyzzy", "x-foobar")),
                    ..SearchData::default()
                }
            )
        );
        assert_eq!(
            Some(false),
            eval(
                ops,
                &SearchData {
                    headers: Some(singleton_map("xyzzy", "nothing happens")),
                    ..SearchData::default()
                }
            )
        );
    }

    #[test]
    fn single_datecmp_fields() {
        let datetime0 =
            DateTime::parse_from_rfc3339("2020-06-28T12:34:56+23:59").unwrap();
        let datetime1 =
            DateTime::parse_from_rfc3339("2020-06-29T23:12:01-12:34").unwrap();
        let datetime2 =
            DateTime::parse_from_rfc3339("2020-06-30T08:04:02-23:59").unwrap();
        let date1 = NaiveDate::from_ymd(2020, 6, 29);

        let ops = &[Op::InternalDateCompare(date1, true, false, false)];
        assert_eq!(None, eval(ops, &SearchData::default()));
        assert_eq!(
            Some(true),
            eval(
                ops,
                &SearchData {
                    metadata: Some(MessageMetadata {
                        size: 0,
                        internal_date: datetime0,
                    }),
                    ..SearchData::default()
                }
            )
        );
        assert_eq!(
            Some(false),
            eval(
                ops,
                &SearchData {
                    metadata: Some(MessageMetadata {
                        size: 0,
                        internal_date: datetime1,
                    }),
                    ..SearchData::default()
                }
            )
        );
        assert_eq!(
            Some(false),
            eval(
                ops,
                &SearchData {
                    metadata: Some(MessageMetadata {
                        size: 0,
                        internal_date: datetime2,
                    }),
                    ..SearchData::default()
                }
            )
        );

        let ops = &[Op::InternalDateCompare(date1, false, true, false)];
        assert_eq!(None, eval(ops, &SearchData::default()));
        assert_eq!(
            Some(false),
            eval(
                ops,
                &SearchData {
                    metadata: Some(MessageMetadata {
                        size: 0,
                        internal_date: datetime0,
                    }),
                    ..SearchData::default()
                }
            )
        );
        assert_eq!(
            Some(true),
            eval(
                ops,
                &SearchData {
                    metadata: Some(MessageMetadata {
                        size: 0,
                        internal_date: datetime1,
                    }),
                    ..SearchData::default()
                }
            )
        );
        assert_eq!(
            Some(false),
            eval(
                ops,
                &SearchData {
                    metadata: Some(MessageMetadata {
                        size: 0,
                        internal_date: datetime2,
                    }),
                    ..SearchData::default()
                }
            )
        );

        let ops = &[Op::InternalDateCompare(date1, false, false, true)];
        assert_eq!(None, eval(ops, &SearchData::default()));
        assert_eq!(
            Some(false),
            eval(
                ops,
                &SearchData {
                    metadata: Some(MessageMetadata {
                        size: 0,
                        internal_date: datetime0,
                    }),
                    ..SearchData::default()
                }
            )
        );
        assert_eq!(
            Some(false),
            eval(
                ops,
                &SearchData {
                    metadata: Some(MessageMetadata {
                        size: 0,
                        internal_date: datetime1,
                    }),
                    ..SearchData::default()
                }
            )
        );
        assert_eq!(
            Some(true),
            eval(
                ops,
                &SearchData {
                    metadata: Some(MessageMetadata {
                        size: 0,
                        internal_date: datetime2,
                    }),
                    ..SearchData::default()
                }
            )
        );

        let ops = &[Op::DateCompare(date1, true, false, false)];
        assert_eq!(None, eval(ops, &SearchData::default()));
        assert_eq!(
            Some(true),
            eval(
                ops,
                &SearchData {
                    date: Some(datetime0),
                    ..SearchData::default()
                }
            )
        );
        assert_eq!(
            Some(false),
            eval(
                ops,
                &SearchData {
                    date: Some(datetime1),
                    ..SearchData::default()
                }
            )
        );
        assert_eq!(
            Some(false),
            eval(
                ops,
                &SearchData {
                    date: Some(datetime2),
                    ..SearchData::default()
                }
            )
        );

        let ops = &[Op::DateCompare(date1, false, true, false)];
        assert_eq!(None, eval(ops, &SearchData::default()));
        assert_eq!(
            Some(false),
            eval(
                ops,
                &SearchData {
                    date: Some(datetime0),
                    ..SearchData::default()
                }
            )
        );
        assert_eq!(
            Some(true),
            eval(
                ops,
                &SearchData {
                    date: Some(datetime1),
                    ..SearchData::default()
                }
            )
        );
        assert_eq!(
            Some(false),
            eval(
                ops,
                &SearchData {
                    date: Some(datetime2),
                    ..SearchData::default()
                }
            )
        );

        let ops = &[Op::DateCompare(date1, false, false, true)];
        assert_eq!(None, eval(ops, &SearchData::default()));
        assert_eq!(
            Some(false),
            eval(
                ops,
                &SearchData {
                    date: Some(datetime0),
                    ..SearchData::default()
                }
            )
        );
        assert_eq!(
            Some(false),
            eval(
                ops,
                &SearchData {
                    date: Some(datetime1),
                    ..SearchData::default()
                }
            )
        );
        assert_eq!(
            Some(true),
            eval(
                ops,
                &SearchData {
                    date: Some(datetime2),
                    ..SearchData::default()
                }
            )
        );
    }

    #[test]
    fn single_size_compare() {
        let datetime0 =
            DateTime::parse_from_rfc3339("2020-06-28T12:34:56+23:59").unwrap();

        let ops = &[Op::SizeCompare(100, true, false, false)];
        assert_eq!(None, eval(ops, &SearchData::default()));
        assert_eq!(
            Some(true),
            eval(
                ops,
                &SearchData {
                    metadata: Some(MessageMetadata {
                        size: 99,
                        internal_date: datetime0,
                    }),
                    ..SearchData::default()
                }
            )
        );
        assert_eq!(
            Some(false),
            eval(
                ops,
                &SearchData {
                    metadata: Some(MessageMetadata {
                        size: 100,
                        internal_date: datetime0,
                    }),
                    ..SearchData::default()
                }
            )
        );
        assert_eq!(
            Some(false),
            eval(
                ops,
                &SearchData {
                    metadata: Some(MessageMetadata {
                        size: 101,
                        internal_date: datetime0,
                    }),
                    ..SearchData::default()
                }
            )
        );

        let ops = &[Op::SizeCompare(100, false, true, false)];
        assert_eq!(None, eval(ops, &SearchData::default()));
        assert_eq!(
            Some(false),
            eval(
                ops,
                &SearchData {
                    metadata: Some(MessageMetadata {
                        size: 99,
                        internal_date: datetime0,
                    }),
                    ..SearchData::default()
                }
            )
        );
        assert_eq!(
            Some(true),
            eval(
                ops,
                &SearchData {
                    metadata: Some(MessageMetadata {
                        size: 100,
                        internal_date: datetime0,
                    }),
                    ..SearchData::default()
                }
            )
        );
        assert_eq!(
            Some(false),
            eval(
                ops,
                &SearchData {
                    metadata: Some(MessageMetadata {
                        size: 101,
                        internal_date: datetime0,
                    }),
                    ..SearchData::default()
                }
            )
        );

        let ops = &[Op::SizeCompare(100, false, false, true)];
        assert_eq!(None, eval(ops, &SearchData::default()));
        assert_eq!(
            Some(false),
            eval(
                ops,
                &SearchData {
                    metadata: Some(MessageMetadata {
                        size: 99,
                        internal_date: datetime0,
                    }),
                    ..SearchData::default()
                }
            )
        );
        assert_eq!(
            Some(false),
            eval(
                ops,
                &SearchData {
                    metadata: Some(MessageMetadata {
                        size: 100,
                        internal_date: datetime0,
                    }),
                    ..SearchData::default()
                }
            )
        );
        assert_eq!(
            Some(true),
            eval(
                ops,
                &SearchData {
                    metadata: Some(MessageMetadata {
                        size: 101,
                        internal_date: datetime0,
                    }),
                    ..SearchData::default()
                }
            )
        );
    }

    #[test]
    fn single_content() {
        let ops = &[Op::Content(Arc::new(Regex::new("foo").unwrap()))];
        assert_eq!(None, eval(ops, &SearchData::default()));
        assert_eq!(
            Some(true),
            eval(
                ops,
                &SearchData {
                    content: Some("Where is the food?".to_owned()),
                    ..SearchData::default()
                }
            )
        );
        assert_eq!(
            Some(false),
            eval(
                ops,
                &SearchData {
                    content: Some("Where is the f00d?".to_owned()),
                    ..SearchData::default()
                }
            )
        );
    }

    #[test]
    fn test_and() {
        for i in 0..16 {
            let a_known = 0 != i & 1;
            let a_true = 0 != i & 2;
            let b_known = 0 != i & 4;
            let b_true = 0 != i & 8;

            let mut a = 0;
            if !a_known {
                a |= UNKNOWN;
            }
            if a_true {
                a |= TRUE;
            }

            let mut b = 0;
            if !b_known {
                b |= UNKNOWN;
            }
            if b_true {
                b |= TRUE;
            }

            let ops = &[Op::_Const(a), Op::_Const(b), Op::And];
            let result = eval(ops, &SearchData::default());

            if (a_known && !a_true) || (b_known && !b_true) {
                assert_eq!(Some(false), result);
            } else if a_known && a_true && b_known && b_true {
                assert_eq!(Some(true), result);
            } else {
                assert_eq!(None, result);
            }
        }
    }

    #[test]
    fn test_or() {
        for i in 0..16 {
            let a_known = 0 != i & 1;
            let a_true = 0 != i & 2;
            let b_known = 0 != i & 4;
            let b_true = 0 != i & 8;

            let mut a = 0;
            if !a_known {
                a |= UNKNOWN;
            }
            if a_true {
                a |= TRUE;
            }

            let mut b = 0;
            if !b_known {
                b |= UNKNOWN;
            }
            if b_true {
                b |= TRUE;
            }

            let ops = &[Op::_Const(a), Op::_Const(b), Op::Or];
            let result = eval(ops, &SearchData::default());

            if (a_known && a_true) || (b_known && b_true) {
                assert_eq!(Some(true), result);
            } else if a_known && !a_true && b_known && !b_true {
                assert_eq!(Some(false), result);
            } else {
                assert_eq!(None, result);
            }
        }
    }

    #[test]
    fn test_or_nested() {
        // This test is mainly to ensure that the bit twiddling in the and/or
        // combinators doesn't disturb other stack elements.
        for i in 0..63 {
            let a_known = 0 != i & 1;
            let a_true = 0 != i & 2;
            let b_known = 0 != i & 4;
            let b_true = 0 != i & 8;
            let c_known = 0 != i & 16;
            let c_true = 0 != i & 32;

            let mut a = 0;
            if !a_known {
                a |= UNKNOWN;
            }
            if a_true {
                a |= TRUE;
            }

            let mut b = 0;
            if !b_known {
                b |= UNKNOWN;
            }
            if b_true {
                b |= TRUE;
            }

            let mut c = 0;
            if !c_known {
                c |= UNKNOWN;
            }
            if c_true {
                c |= TRUE;
            }

            let ops =
                &[Op::_Const(a), Op::_Const(b), Op::Or, Op::_Const(c), Op::Or];
            let result = eval(ops, &SearchData::default());

            if (a_known && a_true) || (b_known && b_true) || (c_known && c_true)
            {
                assert_eq!(Some(true), result);
            } else if a_known
                && !a_true
                && b_known
                && !b_true
                && c_known
                && !c_true
            {
                assert_eq!(Some(false), result);
            } else {
                assert_eq!(None, result);
            }
        }
    }

    #[test]
    fn test_not() {
        let ops = &[Op::Recent, Op::Not];
        assert_eq!(None, eval(ops, &SearchData::default()));
        assert_eq!(
            Some(true),
            eval(
                ops,
                &SearchData {
                    recent: Some(false),
                    ..SearchData::default()
                }
            )
        );
        assert_eq!(
            Some(false),
            eval(
                ops,
                &SearchData {
                    recent: Some(true),
                    ..SearchData::default()
                }
            )
        );
    }
}
