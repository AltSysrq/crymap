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

// TODO RFC 2822 was obsoleted by RFC 5322. It looks like it's mostly just more
// regression away from 8-bit cleanliness, but we'll want to update our
// references here to match.

use std::borrow::Cow;
use std::str;

use chrono::prelude::*;
use nom::bytes::complete::{is_a, is_not, tag};
use nom::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddrSpec<'a> {
    pub local: Vec<Cow<'a, [u8]>>,
    pub domain: Vec<Cow<'a, [u8]>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mailbox<'a> {
    pub addr: AddrSpec<'a>,
    pub name: Vec<Cow<'a, [u8]>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group<'a> {
    pub name: Vec<Cow<'a, [u8]>>,
    pub boxes: Vec<Mailbox<'a>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Address<'a> {
    Mailbox(Mailbox<'a>),
    Group(Group<'a>),
}

pub fn parse_datetime(date_str: &str) -> Option<DateTime<FixedOffset>> {
    date_time(date_str.as_bytes()).ok().and_then(|r| r.1)
}

// RFC 2822 3.2.1 "text", including the "obsolete text" syntax that's 8-bit
// clean.
// RFC 6532 updates the definition to include all non-ASCII characters.
fn text(i: &[u8]) -> IResult<&[u8], &[u8]> {
    is_not("\r\n")(i)
}

// RFC 2822 3.2.2 "quoted-pair", including the 8-bit clean "obsolete" syntax
fn quoted_pair(i: &[u8]) -> IResult<&[u8], &[u8]> {
    let (i, _) = tag(b"\\")(i)?;
    bytes::complete::take(1usize)(i)
}

// RFC 2822 3.2.3 "Folding white space".
// The formal syntax describes the folding syntax itself, but unfolding is
// partially performed by a different mechanism, so we just treat the
// line-ending characters as simple whitespace.
fn fws(i: &[u8]) -> IResult<&[u8], &[u8]> {
    let (i, _) = is_a(" \t\r\n")(i)?;
    Ok((i, b" "))
}

// RFC 2822 3.2.3 "Comment text".
fn ctext(i: &[u8]) -> IResult<&[u8], &[u8]> {
    is_not("()\\ \t\r\n")(i)
}

// RFC 2822 3.2.3 "Comment content".
// The original definition includes FWS in the comment syntax instead of here,
// which makes it a lot more complicated.
fn ccontent(i: &[u8]) -> IResult<&[u8], ()> {
    let (i, _) = branch::alt((ctext, quoted_pair, fws))(i)?;
    Ok((i, ()))
}

// RFC 2822 3.2.3 "Comment". Note it is recursive.
fn comment(i: &[u8]) -> IResult<&[u8], ()> {
    let (i, _) = sequence::delimited(
        tag(b"("),
        multi::many0_count(ccontent),
        tag(b")"),
    )(i)?;
    Ok((i, ()))
}

// RFC 2822 3.2.3 "Comment or folding white space".
fn cfws(i: &[u8]) -> IResult<&[u8], ()> {
    let (i, _) = multi::many1_count(branch::alt((
        comment,
        combinator::map(fws, |_| ()),
    )))(i)?;
    Ok((i, ()))
}

// Convenience for opt(cfws)
fn ocfws(i: &[u8]) -> IResult<&[u8], ()> {
    let (i, _) = combinator::opt(cfws)(i)?;
    Ok((i, ()))
}

// RFC 2822 3.2.4 "Atom text"
// Amended by RFC 6532 to include all non-ASCII characters
fn atext(i: &[u8]) -> IResult<&[u8], &[u8]> {
    bytes::complete::take_while1(|ch| {
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
    })(i)
}

// RFC 2822 3.2.4 "Atom"
fn atom(i: &[u8]) -> IResult<&[u8], &[u8]> {
    sequence::delimited(ocfws, atext, ocfws)(i)
}

// RFC 2822 3.2.4 "Dot atom text"
fn dot_atom_text(i: &[u8]) -> IResult<&[u8], Vec<&[u8]>> {
    multi::separated_nonempty_list(tag(b"."), atext)(i)
}

// RFC 2822 3.2.4 "Dot atom"
fn dot_atom(i: &[u8]) -> IResult<&[u8], Vec<&[u8]>> {
    sequence::delimited(ocfws, dot_atom_text, ocfws)(i)
}

// RFC 2822 3.2.5 "Quoted [string] text"
// Amended by RFC 6532 to include all non-ASCII characters
// The RFC describes the syntax as if FWS has its normal folding behaviour
// between the quotes, but it doesn't, so we just treat it as part of qtext.
fn qtext(i: &[u8]) -> IResult<&[u8], &[u8]> {
    is_not("\\\"")(i)
}

// RFC 2822 3.2.5 "Quoted [string] content
// The original spec puts FWS in the quoted-string definition for some reason,
// which would make it much more complex.
fn qcontent(i: &[u8]) -> IResult<&[u8], &[u8]> {
    branch::alt((qtext, quoted_pair))(i)
}

// RFC 2822 3.2.5 "Quoted string"
fn quoted_string(i: &[u8]) -> IResult<&[u8], Cow<'_, [u8]>> {
    sequence::delimited(
        sequence::pair(ocfws, tag(b"\"")),
        multi::fold_many0(
            qcontent,
            Cow::Borrowed(&[] as &[u8]),
            |mut acc: Cow<[u8]>, item| {
                if acc.is_empty() {
                    acc = Cow::Borrowed(item);
                } else {
                    acc.to_mut().extend_from_slice(item);
                }
                acc
            },
        ),
        sequence::pair(tag(b"\""), ocfws),
    )(i)
}

// RFC 2822 3.2.6 "word"
fn word(i: &[u8]) -> IResult<&[u8], Cow<'_, [u8]>> {
    branch::alt((combinator::map(atom, Cow::Borrowed), quoted_string))(i)
}

// Not formally specified by RFC 2822, but part of the `obs-phrase` grammar.
// Defined here as a separate element for simplicity.
fn obs_dot(i: &[u8]) -> IResult<&[u8], Cow<'_, [u8]>> {
    // Only need to handle CFWS at end since there is always a preceding token
    // that allows CFWS.
    sequence::terminated(combinator::map(tag(b"."), Cow::Borrowed), ocfws)(i)
}

// RFC 2822 3.2.6 "phrase", plus "obsolete phrase" syntax which accounts for
// the '.' that many agents put unquoted into display names.
fn phrase(i: &[u8]) -> IResult<&[u8], Vec<Cow<'_, [u8]>>> {
    combinator::map(
        sequence::pair(word, multi::many0(branch::alt((word, obs_dot)))),
        |(head, mut tail)| {
            tail.insert(0, head);
            tail
        },
    )(i)
}

// RFC 2822 3.2.6 also defines "unstructured text", but once the "obsolete"
// syntax and RFC 6532 revision is considered, there is no syntax at all and it
// is just a raw byte string, so there's nothing to define here.

fn parse_u32_infallible(i: &[u8]) -> u32 {
    str::from_utf8(i).unwrap().parse::<u32>().unwrap()
}

// RFC 2822 3.3 date/time syntax, including obsolete forms.
// In general, the obsolete forms allow CFWS between all terms, so we just
// write that in the whole date/time definitions instead of the rather
// arbitrary distribution the RFC uses.
fn year(i: &[u8]) -> IResult<&[u8], u32> {
    combinator::map(
        bytes::complete::take_while_m_n(2, 4, character::is_digit),
        |s| {
            // Infallible since we know s is [0-9]{2,4}
            let mut y = parse_u32_infallible(s);
            // Y2K compliance workarounds described by RFC 2822 4.3
            if s.len() == 2 && y < 50 {
                y += 2000;
            } else if s.len() < 4 {
                y += 1900;
            }
            y
        },
    )(i)
}

static MONTH_NAMES: [&str; 12] = [
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct",
    "nov", "dec",
];
fn month(i: &[u8]) -> IResult<&[u8], u32> {
    combinator::map_opt(atext, |name| {
        str::from_utf8(name)
            .ok()
            // RFC 2822 doesn't allow full month names even in the obsolete
            // syntax, but some agents use them anyway, so just look at the
            // first 3 letters.
            .and_then(|name| name.get(..3))
            .and_then(|name| {
                MONTH_NAMES
                    .iter()
                    .enumerate()
                    .filter(|&(_, n)| n.eq_ignore_ascii_case(name))
                    .map(|(ix, _)| ix as u32 + 1)
                    .next()
            })
    })(i)
}

fn day(i: &[u8]) -> IResult<&[u8], u32> {
    combinator::map(
        bytes::complete::take_while_m_n(1, 2, character::is_digit),
        parse_u32_infallible,
    )(i)
}

fn date(i: &[u8]) -> IResult<&[u8], (u32, u32, u32)> {
    let (i, d) = sequence::terminated(day, ocfws)(i)?;
    let (i, m) = sequence::terminated(month, ocfws)(i)?;
    let (i, y) = sequence::terminated(year, ocfws)(i)?;
    Ok((i, (y, m, d)))
}

fn two_digit(i: &[u8]) -> IResult<&[u8], u32> {
    combinator::map(
        bytes::complete::take_while_m_n(2, 2, character::is_digit),
        parse_u32_infallible,
    )(i)
}

fn time_colon(i: &[u8]) -> IResult<&[u8], ()> {
    let (i, _) = sequence::tuple((ocfws, tag(b":"), ocfws))(i)?;
    Ok((i, ()))
}

fn time_of_day(i: &[u8]) -> IResult<&[u8], (u32, u32, u32)> {
    sequence::terminated(
        sequence::tuple((
            two_digit,
            sequence::preceded(time_colon, two_digit),
            // RFC 2822 does not describe optional seconds in the obsolete
            // syntax, but does have it in an example.
            combinator::map(
                combinator::opt(sequence::preceded(time_colon, two_digit)),
                |sec| sec.unwrap_or(0),
            ),
        )),
        ocfws,
    )(i)
}

fn numeric_zone(i: &[u8]) -> IResult<&[u8], i32> {
    combinator::map(
        sequence::pair(
            branch::alt((tag(b"+"), tag(b"-"))),
            sequence::pair(two_digit, two_digit),
        ),
        |(sign, (h, m))| {
            let n = (h * 60 + m) as i32;
            if b"-" == sign {
                -n
            } else {
                n
            }
        },
    )(i)
}

static OBSOLETE_ZONES: &[(&str, i32)] = &[
    // UTC
    ("ut", 0),
    ("gmt", 0),
    // US time zones
    ("edt", -4 * 60),
    ("est", -5 * 60),
    ("cdt", -5 * 60),
    ("cst", -6 * 60),
    ("mdt", -6 * 60),
    ("mst", -7 * 60),
    ("pdt", -7 * 60),
    ("pst", -8 * 60),
];

fn obsolete_zone(i: &[u8]) -> IResult<&[u8], i32> {
    combinator::map(atext, |name| {
        str::from_utf8(name)
            .ok()
            .and_then(|name| {
                OBSOLETE_ZONES
                    .iter()
                    .filter(|&&(zone, _)| zone.eq_ignore_ascii_case(name))
                    .map(|&(_, offset)| offset)
                    .next()
            })
            // (US?) Military time zones and unrecognised zones RFC 2822
            // indicates that the military time zones were so poorly defined
            // that they must be treated as 0 unless additional information is
            // available. Unknown time zones must also be treated as 0.
            .unwrap_or(0)
    })(i)
}

fn zone(i: &[u8]) -> IResult<&[u8], i32> {
    combinator::map(
        combinator::opt(branch::alt((numeric_zone, obsolete_zone))),
        |zone| zone.unwrap_or(0),
    )(i)
}

fn time(i: &[u8]) -> IResult<&[u8], ((u32, u32, u32), i32)> {
    // time already allows a CFWS at the end so we don't need anything between
    // time and zone.
    sequence::terminated(sequence::pair(time_of_day, zone), ocfws)(i)
}

fn date_time(i: &[u8]) -> IResult<&[u8], Option<DateTime<FixedOffset>>> {
    // We don't care what day of week it was
    let (i, _) = sequence::tuple((
        ocfws,
        bytes::complete::take_while(character::is_alphabetic),
        ocfws,
        combinator::opt(tag(b",")),
        ocfws,
    ))(i)?;
    let (i, (year, month, day)) = date(i)?;
    let (i, ((hour, minute, second), zone)) = time(i)?;

    let res = FixedOffset::east_opt(zone * 60)
        .and_then(|off| off.ymd_opt(year as i32, month, day).latest())
        .and_then(|date| date.and_hms_opt(hour, minute, second));

    Ok((i, res))
}

// RFC 2822 3.4.1 local part of address
// Formally, this is `dot-atom / quoted-string / obs-local-part`, with
// `obs-local-part` being `word *("." word)`. Any dot-atom or quoted-string
// conforms to obs-local-part, so we just parse that.
fn local_part(i: &[u8]) -> IResult<&[u8], Vec<Cow<'_, [u8]>>> {
    multi::separated_nonempty_list(tag(b"."), word)(i)
}

// RFC 2822 4.4 obsolete domain format
fn obs_domain(i: &[u8]) -> IResult<&[u8], Vec<Cow<'_, [u8]>>> {
    multi::separated_nonempty_list(
        tag(b"."),
        combinator::map(atom, Cow::Borrowed),
    )(i)
}

// RFC 2822 3.4.1 domain name text
// Amended by RFC 6532 to include all non-ASCII
fn dtext(i: &[u8]) -> IResult<&[u8], &[u8]> {
    is_not("[]\\ \t\r\n")(i)
}

// RFC 2822 3.4.1 domain literal content
// As with quoted strings, we move the FWS part into the content to simplify
// the syntax definition.
fn dcontent(i: &[u8]) -> IResult<&[u8], &[u8]> {
    branch::alt((dtext, quoted_pair, fws))(i)
}

// RFC 2822 3.4.1 domain literal
fn domain_literal(i: &[u8]) -> IResult<&[u8], Vec<u8>> {
    combinator::map(
        sequence::delimited(
            sequence::pair(ocfws, tag(b"[")),
            multi::fold_many0(dcontent, vec![b'['], |mut acc, item| {
                acc.extend_from_slice(item);
                acc
            }),
            sequence::pair(tag(b"]"), ocfws),
        ),
        |mut res| {
            res.push(b']');
            res
        },
    )(i)
}

// RFC 2822 3.4.1 domain
// dot-atom is encompassed by obs_domain
fn domain(i: &[u8]) -> IResult<&[u8], Vec<Cow<'_, [u8]>>> {
    branch::alt((
        obs_domain,
        combinator::map(domain_literal, |v| vec![Cow::Owned(v)]),
    ))(i)
}

// RFC 2822 3.4.1 address specification
fn addr_spec(i: &[u8]) -> IResult<&[u8], AddrSpec<'_>> {
    let (i, local) = local_part(i)?;
    let (i, domain) = sequence::preceded(tag(b"@"), domain)(i)?;
    Ok((i, AddrSpec { local, domain }))
}

// RFC 2822 4.4 obsolete routing information
// We just discard all this
fn obs_domain_list(i: &[u8]) -> IResult<&[u8], ()> {
    let (i, _) = sequence::tuple((
        tag(b"@"),
        domain,
        multi::many0_count(sequence::tuple((
            multi::many0_count(branch::alt((
                cfws,
                combinator::map(tag(b","), |_| ()),
            ))),
            ocfws,
            tag(b"@"),
            domain,
        ))),
    ))(i)?;
    Ok((i, ()))
}

// RFC 2822 3.4 angle-delimited address, including the 4.4 obsolete routing
// information.
fn angle_addr(i: &[u8]) -> IResult<&[u8], AddrSpec<'_>> {
    sequence::delimited(
        sequence::tuple((ocfws, tag(b"<"), combinator::opt(obs_domain_list))),
        addr_spec,
        sequence::pair(tag(b">"), ocfws),
    )(i)
}

// RFC 2822 3.4 mailbox
fn mailbox(i: &[u8]) -> IResult<&[u8], Mailbox<'_>> {
    combinator::map(
        branch::alt((
            sequence::pair(
                combinator::map(combinator::opt(phrase), |o| {
                    o.unwrap_or(vec![])
                }),
                angle_addr,
            ),
            combinator::map(addr_spec, |a| (vec![], a)),
        )),
        |(name, addr)| Mailbox { name, addr },
    )(i)
}

// Used in obsolete list syntax
fn obs_list_delim(i: &[u8]) -> IResult<&[u8], ()> {
    combinator::map(
        multi::many1_count(sequence::tuple((ocfws, tag(b","), ocfws))),
        |_| (),
    )(i)
}

// RFC 2822 3.4 mailbox list, including 4.4 obsolete syntax
fn mailbox_list(i: &[u8]) -> IResult<&[u8], Vec<Mailbox<'_>>> {
    sequence::delimited(
        obs_list_delim,
        multi::separated_nonempty_list(obs_list_delim, mailbox),
        obs_list_delim,
    )(i)
}

// RFC 2822 3.4 group
fn group(i: &[u8]) -> IResult<&[u8], Group<'_>> {
    let (i, name) = sequence::terminated(phrase, tag(b":"))(i)?;
    let (i, boxes) = sequence::terminated(
        combinator::opt(mailbox_list),
        sequence::tuple((ocfws, tag(";"), ocfws)),
    )(i)?;

    let boxes = boxes.unwrap_or(vec![]);
    Ok((i, Group { name, boxes }))
}

// RFC 2822 3.4 address
fn address(i: &[u8]) -> IResult<&[u8], Address<'_>> {
    branch::alt((
        combinator::map(mailbox, Address::Mailbox),
        combinator::map(group, Address::Group),
    ))(i)
}

// RFC 2822 3.4 address list, including 4.4 obsolete syntax
fn address_list(i: &[u8]) -> IResult<&[u8], Vec<Address<'_>>> {
    sequence::delimited(
        obs_list_delim,
        multi::separated_nonempty_list(obs_list_delim, address),
        obs_list_delim,
    )(i)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_date_parsing() {
        fn dt(input: &str) -> String {
            if let Some(result) = parse_datetime(input) {
                result.to_rfc3339()
            } else {
                panic!("Failed to parse {}", input);
            }
        }

        // Examples from RFC 2822
        assert_eq!(
            "1997-11-21T09:55:06-06:00",
            dt("Fri, 21 Nov 1997 09:55:06 -0600")
        );
        assert_eq!(
            "2003-07-01T10:52:37+02:00",
            dt("Tue, 1 Jul 2003 10:52:37 +0200")
        );
        assert_eq!(
            "1969-02-13T23:32:54-03:30",
            dt("Thu, 13 Feb 1969 23:32:54 -0330")
        );
        assert_eq!(
            "1997-11-21T10:01:10-06:00",
            dt("Fri, 21 Nov 1997 10:01:10 -0600")
        );
        assert_eq!(
            "1969-02-13T23:32:00-03:30",
            dt("Thu 13 Feb 1969 23:32 -0330")
        );
        assert_eq!(
            "1969-02-13T23:32:00-03:30",
            dt(concat!(
                "Thu\r\n      13\r\n        Feb\r\n          1969\r\n",
                "      23:32\r\n               -0330 (Newfoundland Time)"
            ))
        );
        assert_eq!("1997-11-21T09:55:06+00:00", dt("21 Nov 97 09:55:06 GMT"));
        assert_eq!(
            "1997-11-21T09:55:06-06:00",
            dt("Fri, 21 Nov 1997 09(comment):   55  :  06 -0600")
        );
        // Other specific examples found in the wild
        assert_eq!(
            "2011-03-21T03:12:57+00:00",
            dt("Mon, 21 Mar 2011 03:12:57")
        );
    }

    // I was planning on having an ENRON corpus too, but as far as I can tell,
    // the Date headers in the ENRON email corpus are entirely uniform and
    // uninteresting.
    #[test]
    fn date_parse_jlingle_corpus() {
        let data = include_str!("date-corpus-jlingle.txt");
        for date_string in data.split('\n') {
            if date_string.is_empty() {
                continue;
            }
            if parse_datetime(date_string).is_none() {
                panic!("Failed to parse: {}", date_string);
            }
        }
    }
}
