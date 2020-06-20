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

//! Utilities for working with individual RFC 2822 headers.

use std::borrow::Cow;
use std::str;

use chrono::*;
use nom::*;

use super::model::*;

fn ascii_digit(b: u8) -> bool {
    b >= b'0' && b <= b'9'
}

// RFC 2822 3.2.1 "text", including the "obsolete text" syntax that's 8-bit
// clean.
// RFC 6532 updates the definition to include all non-ASCII characters.
named!(text, is_not!("\r\n"));
// RFC 2822 3.2.2 "quoted-pair", including the 8-bit clean "obsolete" syntax
named!(quoted_pair, preceded!(char!('\\'), take!(1)));

// RFC 2822 3.2.3 "Folding white space".
// The formal syntax describes the folding syntax itself, but unfolding is
// partially performed by a different mechanism, so we just treat the
// line-ending characters as simple whitespace.
named!(fws, map!(is_a!(" \t\r\n"), |_| &b" "[..]));
// RFC 2822 3.2.3 "Comment text".
named!(ctext, is_not!("()\\ \t\r\n"));
// RFC 2822 3.2.3 "Comment content".
// The original definition includes FWS in the comment syntax instead of here,
// which makes it a lot more complicated.
named!(
    ccontent<()>,
    alt!(
        map!(ctext, |_| ())
            | map!(quoted_pair, |_| ())
            | map!(fws, |_| ())
            | comment
    )
);
// RFC 2822 3.2.3 "Comment". Note it is recursive.
named!(
    comment<()>,
    delimited!(char!('('), map!(many0_count!(ccontent), |_| ()), char!(')'))
);
// RFC 2822 3.2.3 "Comment or folding white space".
named!(
    cfws<()>,
    map!(many0_count!(alt!(map!(fws, |_| ()) | comment)), |_| ())
);

// RFC 2822 3.2.4 "Atom text"
// Amended by RFC 6532 to include all non-ASCII characters
named!(
    atext,
    take_while!(|ch| {
        // RFC2822 ALPHA
        (ch >= b'A' && ch <= b'Z') ||
            (ch >= b'a' && ch <= b'z') ||
            // RFC 2822 DIGIT
            (ch >= b'0' && ch <= b'9') ||
            // RFC 2822 non-specials
            ch == b'!' ||
            (ch >= b'#' && ch <= b'\'') || // #$%&'
            ch == b'*' ||
            ch == b'+' ||
            ch == b'-' ||
            ch == b'/' ||
            ch == b'=' ||
            ch == b'?' ||
            ch == b'^' ||
            ch == b'_' ||
            ch == b'`' ||
            (ch >= b'{' && ch <= b'~') || // {|}~
            // RFC 6532 Unicode
            ch >= 0x80
    })
);

// RFC 2822 3.2.4 "Atom"
named!(atom, delimited!(opt!(cfws), atext, opt!(cfws)));

// RFC 2822 3.2.4 "Dot atom text"
named!(
    dot_atom_text<Vec<&[u8]>>,
    separated_nonempty_list!(char!('.'), atext)
);

// RFC 2822 3.2.4 "Dot atom"
named!(
    dot_atom<Vec<&[u8]>>,
    delimited!(opt!(cfws), dot_atom_text, opt!(cfws))
);

// RFC 2822 3.2.5 "Quoted [string] text"
// Amended by RFC 6532 to include all non-ASCII characters
named!(qtext, is_not!(" \t\r\n\\\""));
// RFC 2822 3.2.5 "Quoted [string] content
// The original spec puts FWS in the quoted-string definition for some reason,
// which would make it much more complex.
named!(qcontent, alt!(qtext | quoted_pair | fws));
// RFC 2822 3.2.5 "Quoted string"
named!(
    quoted_string<Cow<[u8]>>,
    delimited!(
        pair!(opt!(cfws), char!('"')),
        fold_many0!(
            qcontent,
            Cow::Borrowed(&[] as &[u8]),
            |mut acc: Cow<[u8]>, item| {
                if acc.is_empty() {
                    acc = Cow::Borrowed(item);
                } else {
                    acc.to_mut().extend_from_slice(item);
                }
                acc
            }
        ),
        pair!(char!('"'), opt!(cfws))
    )
);

// RFC 2822 3.2.6 "word"
named!(
    word<Cow<[u8]>>,
    alt!(map!(atom, Cow::Borrowed) | quoted_string)
);

// Not formally specified by RFC 2822, but part of the `obs-phrase` grammar.
// Defined here as a separate element for simplicity.
named!(
    obs_dot<Cow<[u8]>>,
    // Only need to handle CFWS at end since there is always a preceding token
    // that allows CFWS.
    terminated!(
        map!(char!('.'), |_| Cow::Borrowed(b"." as &[u8])),
        opt!(cfws)
    )
);

// RFC 2822 3.2.6 "phrase", plus "obsolete phrase" syntax which accounts for
// the '.' that many agents put unquoted into display names.
named!(
    phrase<Vec<Cow<[u8]>>>,
    map!(pair!(word, many0!(alt!(word | obs_dot))), |(
        head,
        mut tail,
    )| {
        tail.insert(0, head);
        tail
    })
);

// RFC 2822 3.2.6 also defines "unstructured text", but once the "obsolete"
// syntax and RFC 6532 revision is considered, there is no syntax at all and it
// is just a raw byte string, so there's nothing to define here.

// RFC 2822 3.3 date/time syntax, including obsolete forms.
// In general, the obsolete forms allow CFWS between all terms, so we just
// write that in the whole date/time definitions instead of the rather
// arbitrary distribution the RFC uses.
named!(
    year<u32>,
    map!(take_while_m_n!(2, 4, ascii_digit), |s| {
        // Infallible since we know s is [0-9]{2,4}
        let mut y: u32 = str::from_utf8(s).unwrap().parse().unwrap();
        // Y2K compliance workarounds described by RFC 2822 4.3
        if s.len() == 2 && y < 50 {
            y += 2000;
        } else if s.len() < 4 {
            y += 1900;
        }
        y
    })
);

named!(
    month<u32>,
    alt!(
        map!(tag_no_case!("jan"), |_| 1)
            | map!(tag_no_case!("feb"), |_| 2)
            | map!(tag_no_case!("mar"), |_| 3)
            | map!(tag_no_case!("apr"), |_| 4)
            | map!(tag_no_case!("may"), |_| 5)
            | map!(tag_no_case!("jun"), |_| 6)
            | map!(tag_no_case!("jul"), |_| 7)
            | map!(tag_no_case!("aug"), |_| 8)
            | map!(tag_no_case!("sep"), |_| 9)
            | map!(tag_no_case!("oct"), |_| 10)
            | map!(tag_no_case!("nov"), |_| 11)
            | map!(tag_no_case!("dec"), |_| 12)
    )
);

named!(
    day<u32>,
    map!(
        take_while_m_n!(1, 2, ascii_digit),
        // Infallible since we know the exact format
        |s| str::from_utf8(s).unwrap().parse::<u32>().unwrap()
    )
);

named!(
    date<(u32, u32, u32)>,
    map!(
        tuple!(
            terminated!(day, opt!(cfws)),
            terminated!(month, opt!(cfws)),
            terminated!(year, opt!(cfws))
        ),
        |(d, m, y)| (y, m, d)
    )
);

named!(
    two_digit<u32>,
    map!(
        take_while_m_n!(2, 2, ascii_digit),
        // Infallible since we know the exact format
        |s| str::from_utf8(s).unwrap().parse::<u32>().unwrap()
    )
);

named!(
    time_of_day<(u32, u32, u32)>,
    tuple!(
        terminated!(two_digit, tuple!(opt!(cfws), char!(':'), opt!(cfws))),
        terminated!(two_digit, tuple!(opt!(cfws), char!(':'), opt!(cfws))),
        terminated!(two_digit, opt!(cfws))
    )
);

named!(
    numeric_zone<i32>,
    map!(
        pair!(
            alt!(char!('+') | char!('-')),
            take_while_m_n!(4, 4, ascii_digit)
        ),
        |(sign, s)| {
            let mut n = str::from_utf8(s).unwrap().parse::<i32>().unwrap();
            if '-' == sign {
                n = -n;
            }
            n
        }
    )
);

named!(
    zone<i32>,
    alt!(
        numeric_zone |
        // UTC
        map!(alt!(tag_no_case!("ut") | tag_no_case!("gmt")), |_| 0) |
        // US time zones
        map!(tag_no_case!("edt"), |_| -400) |
        map!(alt!(tag_no_case!("est") | tag_no_case!("cdt")), |_| -500) |
        map!(alt!(tag_no_case!("cst") | tag_no_case!("mdt")), |_| -600) |
        map!(alt!(tag_no_case!("mst") | tag_no_case!("pdt")), |_| -700) |
        map!(tag_no_case!("pst"), |_| -800) |
        // (US?) Military time zones and unrecognised zones
        // RFC 2822 indicates that the military time zones were so poorly
        // defined that they must be treated as 0 unless additional information
        // is available. Unknown time zones must also be treated as 0.
        map!(atext, |_| 0)
    )
);

named!(
    time<((u32, u32, u32), i32)>,
    // time already allows a CFWS at the end so we don't need something between
    // time and zone.
    terminated!(pair!(time_of_day, zone), opt!(cfws))
);

named!(
    date_time<Option<DateTime<FixedOffset>>>,
    map!(
        // We don't care what day of week it was
        preceded!(
            tuple!(atom, char!(','), cfws),
            // Each of these ends with CFWS so we don't need to add more here
            tuple!(date, time)
        ),
        |((year, month, day), ((hour, minute, second), zone))| {
            FixedOffset::east_opt(zone)
                .and_then(|off| off.ymd_opt(year as i32, month, day).latest())
                .and_then(|date| date.and_hms_opt(hour, minute, second))
        }
    )
);

// RFC 2822 3.4.1 local part of address
// Formally, this is `dot-atom / quoted-string / obs-local-part`, with
// `obs-local-part` being `word *("." word)`. Any dot-atom or quoted-string
// conforms to obs-local-part, so we just parse that.
named!(
    local_part<Vec<Cow<[u8]>>>,
    separated_nonempty_list!(char!('.'), word)
);

// RFC 2822 4.4 obsolete domain format
named!(
    obs_domain<Vec<Cow<[u8]>>>,
    separated_nonempty_list!(char!('.'), map!(atom, Cow::Borrowed))
);

// RFC 2822 3.4.1 domain name text
// Amended by RFC 6532 to include all non-ASCII
named!(dtext, is_not!("[]\\ \t\r\n"));

// RFC 2822 3.4.1 domain literal content
// As with quoted strings, we move the FWS part into the content to simplify
// the syntax definition.
named!(dcontent, alt!(dtext | quoted_pair | fws));

// RFC 2822 3.4.1 domain literal
named!(
    domain_literal<Vec<u8>>,
    map!(
        delimited!(
            pair!(opt!(cfws), char!('[')),
            fold_many0!(dcontent, vec![b'['], |mut acc, item| {
                acc.extend_from_slice(item);
                acc
            }),
            pair!(char!(']'), opt!(cfws))
        ),
        |mut res| {
            res.push(b']');
            res
        }
    )
);

// RFC 2822 3.4.1 domain
// dot-atom is encompassed by obs_domain
named!(
    domain<Vec<Cow<[u8]>>>,
    alt!(obs_domain | map!(domain_literal, |v| vec![Cow::Owned(v)]))
);

// RFC 2822 3.4.1 address specification
named!(
    addr_spec<AddrSpec>,
    map!(pair!(local_part, preceded!(char!('@'), domain)), |(
        local,
        domain,
    )| {
        AddrSpec { local, domain }
    })
);

// RFC 2822 4.4 obsolete routing information
// We just discard all this
named!(
    obs_domain_list<()>,
    map!(
        tuple!(
            char!('@'),
            domain,
            many0_count!(tuple!(
                many0_count!(alt!(cfws | map!(char!(','), |_| ()))),
                opt!(cfws),
                char!('@'),
                domain
            ))
        ),
        |_| ()
    )
);

// RFC 2822 3.4 angle-delimited address, including the 4.4 obsolete routing
// information.
named!(
    angle_addr<AddrSpec>,
    delimited!(
        tuple!(opt!(cfws), char!('<'), opt!(obs_domain_list)),
        addr_spec,
        pair!(char!('>'), opt!(cfws))
    )
);

// RFC 2822 3.4 mailbox
named!(
    mailbox<MailboxSpec>,
    map!(
        alt!(pair!(opt!(phrase), angle_addr) | map!(addr_spec, |a| (None, a))),
        |(name, addr)| MailboxSpec {
            name: name.unwrap_or(vec![]),
            addr
        }
    )
);

// Used in obsolete list syntax
named!(
    obs_list_delim<()>,
    map!(
        many1_count!(tuple!(opt!(cfws), char!(','), opt!(cfws))),
        |_| ()
    )
);

// RFC 2822 3.4 mailbox list, including 4.4 obsolete syntax
named!(
    mailbox_list<Vec<MailboxSpec>>,
    delimited!(
        obs_list_delim,
        separated_nonempty_list!(obs_list_delim, mailbox),
        obs_list_delim
    )
);

// RFC 2822 3.4 group
named!(
    group<GroupSpec>,
    map!(
        pair!(
            terminated!(phrase, char!(':')),
            terminated!(
                opt!(mailbox_list),
                tuple!(opt!(cfws), char!(';'), opt!(cfws))
            )
        ),
        |(name, boxes)| GroupSpec {
            name,
            boxes: boxes.unwrap_or(vec![]),
        }
    )
);

// RFC 2822 3.4 address
named!(
    address<Address>,
    alt!(map!(mailbox, Address::Mailbox) | map!(group, Address::Group))
);

// RFC 2822 3.4 address list, including 4.4 obsolete syntax
named!(
    address_list<Vec<Address>>,
    delimited!(
        obs_list_delim,
        separated_nonempty_list!(obs_list_delim, address),
        obs_list_delim
    )
);
