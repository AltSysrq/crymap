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

//! Utilities for working with individual RFC 5322 headers.
//!
//! IMAP4rev1 is defined in terms of RFC 2822 but under the name of the
//! obsoleted RFC 822. RFC 5322 has obsoleted 2822 with no real changes for
//! parsers (it just moved some more syntax into "obsolete"). RFC 6532
//! additionally extends it to allow UTF-8 everywhere.
//!
//! Also supports the RFC 2045 content headers.
//!
//! The public functions here are permissive in that they silently succeed with
//! partial results if part of, but not the whole, header is parsable. This is
//! to support things like ENVELOPE, SEARCH, and SORT which must work with
//! whatever they can instead of failing.

use std::borrow::Cow;
use std::fmt;
use std::str;

use chrono::prelude::*;
use nom::bytes::complete::{is_a, is_not, tag};
use nom::*;

#[derive(Clone, PartialEq, Eq)]
pub struct AddrSpec<'a> {
    pub local: Vec<Cow<'a, [u8]>>,
    pub domain: Vec<Cow<'a, [u8]>>,
}

impl<'a> fmt::Debug for AddrSpec<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<")?;
        for part in &self.local {
            write!(f, "({})", String::from_utf8_lossy(part))?;
        }
        write!(f, "@")?;
        for part in &self.domain {
            write!(f, "({})", String::from_utf8_lossy(part))?;
        }
        write!(f, ">")?;
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Mailbox<'a> {
    pub addr: AddrSpec<'a>,
    pub name: Vec<Cow<'a, [u8]>>,
}

impl<'a> fmt::Debug for Mailbox<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for part in &self.name {
            write!(f, "({})", String::from_utf8_lossy(part))?;
        }
        write!(f, "{:?}", self.addr)?;
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Group<'a> {
    pub name: Vec<Cow<'a, [u8]>>,
    pub boxes: Vec<Mailbox<'a>>,
}

impl<'a> fmt::Debug for Group<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for part in &self.name {
            write!(f, "({})", String::from_utf8_lossy(part))?;
        }
        for mbox in &self.boxes {
            write!(f, "[{:?}]", mbox)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Address<'a> {
    Mailbox(Mailbox<'a>),
    Group(Group<'a>),
}

#[derive(Clone, PartialEq, Eq)]
pub struct ContentType<'a> {
    pub typ: Cow<'a, [u8]>,
    pub subtype: Cow<'a, [u8]>,
    pub parms: Vec<(Cow<'a, [u8]>, Cow<'a, [u8]>)>,
}

impl<'a> fmt::Debug for ContentType<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "({})/({})",
            String::from_utf8_lossy(&self.typ),
            String::from_utf8_lossy(&self.subtype)
        )?;

        for &(ref attr, ref val) in &self.parms {
            write!(
                f,
                "; ({})=({})",
                String::from_utf8_lossy(attr),
                String::from_utf8_lossy(val)
            )?;
        }

        Ok(())
    }
}

pub fn parse_datetime(date_str: &str) -> Option<DateTime<FixedOffset>> {
    date_time(date_str.as_bytes()).ok().and_then(|r| r.1)
}

pub fn parse_mailbox(i: &[u8]) -> Option<Mailbox<'_>> {
    mailbox(i).ok().map(|r| r.1)
}

pub fn parse_mailbox_list(i: &[u8]) -> Option<Vec<Mailbox<'_>>> {
    mailbox_list(i).ok().map(|r| r.1)
}

pub fn parse_address_list(i: &[u8]) -> Option<Vec<Address<'_>>> {
    address_list(i).ok().map(|r| r.1)
}

pub fn parse_content_type(i: &[u8]) -> Option<ContentType<'_>> {
    content_type(i).ok().map(|r| r.1)
}

// RFC 5322 3.2.1 "quoted-pair", including the 8-bit clean "obsolete" syntax
fn quoted_pair(i: &[u8]) -> IResult<&[u8], &[u8]> {
    let (i, _) = tag(b"\\")(i)?;
    bytes::complete::take(1usize)(i)
}

// RFC 5322 3.2.2 "Folding white space".
// The formal syntax describes the folding syntax itself, but unfolding is
// partially performed by a different mechanism, so we just treat the
// line-ending characters as simple whitespace.
fn fws(i: &[u8]) -> IResult<&[u8], &[u8]> {
    let (i, _) = is_a(" \t\r\n")(i)?;
    Ok((i, b" "))
}

// RFC 5322 3.2.2 "Comment text".
fn ctext(i: &[u8]) -> IResult<&[u8], &[u8]> {
    is_not("()\\ \t\r\n")(i)
}

// RFC 5322 3.2.2 "Comment content".
// The original definition includes FWS in the comment syntax instead of here,
// which makes it a lot more complicated.
// We don't recur to `comment` here because `comment` handles nesting
// procedurally itself.
fn ccontent(i: &[u8]) -> IResult<&[u8], ()> {
    branch::alt((
        combinator::map(ctext, |_| ()),
        combinator::map(quoted_pair, |_| ()),
        combinator::map(fws, |_| ()),
    ))(i)
}

// RFC 5322 3.2.2 "Comment".
//
// The implementation here is procedural with manual nesting counting instead
// of recursive to ensure we never overflow the stack.
fn comment(i: &[u8]) -> IResult<&[u8], ()> {
    let enter_comment = tag(b"(");
    let (mut i, _) = enter_comment(i)?;

    let mut nesting_depth = 1u32;
    while nesting_depth > 0 {
        if let Ok((j, _)) = ccontent(i) {
            i = j;
        } else if let Ok((j, _)) = enter_comment(i) {
            nesting_depth += 1;
            i = j;
        } else {
            let (j, _) = tag(b")")(i)?;
            nesting_depth -= 1;
            i = j;
        }
    }

    Ok((i, ()))
}

// RFC 5322 3.2.2 "Comment or folding white space".
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

// RFC 5322 3.2.3 "Atom text"
// Amended by RFC 6532 to include all non-ASCII characters
fn atext(i: &[u8]) -> IResult<&[u8], &[u8]> {
    bytes::complete::take_while1(|ch| {
        // RFC5322 ALPHA
        (ch >= b'A' && ch <= b'Z') ||
            (ch >= b'a' && ch <= b'z') ||
            // RFC 5322 DIGIT
            (ch >= b'0' && ch <= b'9') ||
            // RFC 5322 non-specials
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

// RFC 5322 3.2.3 "Atom"
fn atom(i: &[u8]) -> IResult<&[u8], &[u8]> {
    sequence::delimited(ocfws, atext, ocfws)(i)
}

// RFC 5322 3.2.3 "Dot atom text"
fn dot_atom_text(i: &[u8]) -> IResult<&[u8], Vec<&[u8]>> {
    multi::separated_nonempty_list(tag(b"."), atext)(i)
}

// RFC 5322 3.2.3 "Dot atom"
fn dot_atom(i: &[u8]) -> IResult<&[u8], Vec<&[u8]>> {
    sequence::delimited(ocfws, dot_atom_text, ocfws)(i)
}

// RFC 5322 3.2.4 "Quoted [string] text"
// Amended by RFC 6532 to include all non-ASCII characters
// The RFC describes the syntax as if FWS has its normal folding behaviour
// between the quotes, but it doesn't, so we just treat the horizontal
// whitespace as part of qtext.
fn qtext(i: &[u8]) -> IResult<&[u8], &[u8]> {
    is_not("\\\"\r\n")(i)
}

// Whitespace in a quoted string which gets deleted by folding.
fn qfws(i: &[u8]) -> IResult<&[u8], &[u8]> {
    let (i, _) = is_a("\r\n")(i)?;
    Ok((i, &[]))
}

// RFC 5322 3.2.4 "Quoted [string] content
// The original spec puts FWS in the quoted-string definition for some reason,
// which would make it much more complex.
fn qcontent(i: &[u8]) -> IResult<&[u8], &[u8]> {
    branch::alt((qtext, quoted_pair, qfws))(i)
}

// RFC 5322 3.2.4 "Quoted string"
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

// RFC 5322 3.2.5 "word"
fn word(i: &[u8]) -> IResult<&[u8], Cow<'_, [u8]>> {
    branch::alt((combinator::map(atom, Cow::Borrowed), quoted_string))(i)
}

// Not formally specified by RFC 5322, but part of the `obs-phrase` grammar.
// Defined here as a separate element for simplicity.
fn obs_dot(i: &[u8]) -> IResult<&[u8], Cow<'_, [u8]>> {
    // Only need to handle CFWS at end since there is always a preceding token
    // that allows CFWS.
    sequence::terminated(combinator::map(tag(b"."), Cow::Borrowed), ocfws)(i)
}

// RFC 5322 3.2.5 "phrase", plus "obsolete phrase" syntax which accounts for
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

// RFC 5322 3.2.5 also defines "unstructured text", but once the "obsolete"
// syntax and RFC 6532 revision is considered, there is no syntax at all and it
// is just a raw byte string, so there's nothing to define here.

fn parse_u32_infallible(i: &[u8]) -> u32 {
    str::from_utf8(i).unwrap().parse::<u32>().unwrap()
}

// RFC 5322 3.3 date/time syntax, including obsolete forms.
// In general, the obsolete forms allow CFWS between all terms, so we just
// write that in the whole date/time definitions instead of the rather
// arbitrary distribution the RFC uses.
fn year(i: &[u8]) -> IResult<&[u8], u32> {
    combinator::map(
        bytes::complete::take_while_m_n(2, 4, character::is_digit),
        |s| {
            // Infallible since we know s is [0-9]{2,4}
            let mut y = parse_u32_infallible(s);
            // Y2K compliance workarounds described by RFC 5322 4.3
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
            // RFC 5322 doesn't allow full month names even in the obsolete
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
            // RFC 5322 does not describe optional seconds in the obsolete
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
            // (US?) Military time zones and unrecognised zones RFC 5322
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

// RFC 5322 3.4.1 local part of address
// Formally, this is `dot-atom / quoted-string / obs-local-part`, with
// `obs-local-part` being `word *("." word)`. Any dot-atom or quoted-string
// conforms to obs-local-part, so we just parse that.
// Samples from the ENRON corpus frequently have consecutive dots, so we allow
// the word to be totally empty.
fn local_part(i: &[u8]) -> IResult<&[u8], Vec<Cow<'_, [u8]>>> {
    combinator::map(
        sequence::tuple((
            // Need to parse leading dots in separately because
            // separated_nonempty_list won't allow the first element to be
            // empty.
            local_leading_dots,
            multi::separated_nonempty_list(
                local_separator,
                combinator::map(combinator::opt(word), |o| {
                    o.unwrap_or(Cow::Borrowed(&[]))
                }),
            ),
            // Some agent (possibly Mailman?) indicates mailing lists by
            // placing an unquoted colon immediately before the @
            combinator::opt(tag(b":")),
        )),
        |(leading, mut parts, colon)| {
            if let Some(colon) = colon {
                parts.push(Cow::Borrowed(colon));
            }

            if 0 == leading {
                parts
            } else {
                let mut v = Vec::new();
                for _ in 0..leading {
                    v.push(Cow::Borrowed(&[] as &[u8]));
                }
                v.append(&mut parts);
                v
            }
        },
    )(i)
}

fn local_leading_dots(i: &[u8]) -> IResult<&[u8], usize> {
    multi::many0_count(sequence::pair(ocfws, local_separator))(i)
}

fn local_separator(i: &[u8]) -> IResult<&[u8], &[u8]> {
    branch::alt((
        // Some agent (JavaMail?) would improperly quote (?) dots in email
        // addresses like this. It's unclear if it's supposed to have some
        // other meaning, but in any case it's so far away from being valid
        // syntax that the best we can do is munch through it and hope for the
        // best.
        tag(b"\".'\""),
        tag(b".\".'\""),
        tag(b"\".\""),
        tag(b"."),
    ))(i)
}

// RFC 5322 4.4 obsolete domain format
fn obs_domain(i: &[u8]) -> IResult<&[u8], Vec<Cow<'_, [u8]>>> {
    multi::separated_nonempty_list(
        tag(b"."),
        combinator::map(atom, Cow::Borrowed),
    )(i)
}

// RFC 5322 3.4.1 domain name text
// Amended by RFC 6532 to include all non-ASCII
fn dtext(i: &[u8]) -> IResult<&[u8], &[u8]> {
    is_not("[]\\ \t\r\n")(i)
}

// RFC 5322 3.4.1 domain literal content
// As with quoted strings, we move the FWS part into the content to simplify
// the syntax definition.
fn dcontent(i: &[u8]) -> IResult<&[u8], &[u8]> {
    branch::alt((dtext, quoted_pair, fws))(i)
}

// RFC 5322 3.4.1 domain literal
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

// RFC 5322 3.4.1 domain
// dot-atom is encompassed by obs_domain
fn domain(i: &[u8]) -> IResult<&[u8], Vec<Cow<'_, [u8]>>> {
    branch::alt((
        obs_domain,
        combinator::map(domain_literal, |v| vec![Cow::Owned(v)]),
    ))(i)
}

// RFC 5322 3.4.1 address specification
fn addr_spec(i: &[u8]) -> IResult<&[u8], AddrSpec<'_>> {
    let (i, local) = local_part(i)?;
    let (i, domain) = sequence::preceded(tag(b"@"), domain)(i)?;
    Ok((i, AddrSpec { local, domain }))
}

// RFC 5322 4.4 obsolete routing information
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

// RFC 5322 3.4 angle-delimited address, including the 4.4 obsolete routing
// information.
fn angle_addr(i: &[u8]) -> IResult<&[u8], AddrSpec<'_>> {
    sequence::delimited(
        sequence::tuple((
            ocfws,
            tag(b"<"),
            combinator::opt(sequence::pair(obs_domain_list, tag(b":"))),
            // Older versions of Outlook stick a spurious apostrophe before the
            // local part. We can generally take a GIGO approach to this, but
            // parsing would fail if we didn't handle the case where the local
            // part starts with '".
            combinator::opt(sequence::pair(
                tag(b"'"),
                combinator::peek(tag(b"\"")),
            )),
            // Another agent would put empty double quotes immediately abutting
            // the local part.
            combinator::opt(tag(b"\"\"")),
        )),
        // Though not described by RFC 5322, some agents will include a totally
        // empty <> pair. Some will also include only a local part.
        combinator::map(
            combinator::opt(branch::alt((
                addr_spec,
                combinator::map(local_part, |l| AddrSpec {
                    local: l,
                    domain: vec![],
                }),
            ))),
            |a| {
                a.unwrap_or_else(|| AddrSpec {
                    local: vec![],
                    domain: vec![],
                })
            },
        ),
        sequence::pair(tag(b">"), ocfws),
    )(i)
}

// RFC 5322 3.4 mailbox
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

// RFC 5322 3.4 mailbox list, including 4.4 obsolete syntax
fn mailbox_list(i: &[u8]) -> IResult<&[u8], Vec<Mailbox<'_>>> {
    sequence::delimited(
        combinator::opt(obs_list_delim),
        multi::separated_nonempty_list(obs_list_delim, mailbox),
        combinator::opt(obs_list_delim),
    )(i)
}

// RFC 5322 3.4 group
fn group(i: &[u8]) -> IResult<&[u8], Group<'_>> {
    let (i, name) = sequence::terminated(phrase, tag(b":"))(i)?;
    // RFC 5322 doesn't allow ; to be missing even in the obsolete syntax.
    // However, Mark Crispin mentioned the possibility of it being missing
    // on the IMAP mailing list, so we allow it to be missing here too.
    // Further (and again not mentioned in RFC 5322), some agents place
    // *multiple* semicolons here for some reason. Even worse, some agents
    // don't include the comma to separate multiple groups. For all these
    // reasons, we don't handle semicolon here, but instead treat it as another
    // address list delimiter.
    let (i, boxes) = combinator::opt(mailbox_list)(i)?;
    let boxes = boxes.unwrap_or(vec![]);
    Ok((i, Group { name, boxes }))
}

fn obs_addr_list_delim(i: &[u8]) -> IResult<&[u8], ()> {
    combinator::map(
        multi::many1_count(sequence::tuple((ocfws, is_a(",;"), ocfws))),
        |_| (),
    )(i)
}

// RFC 5322 3.4 address
fn address(i: &[u8]) -> IResult<&[u8], Address<'_>> {
    branch::alt((
        combinator::map(mailbox, Address::Mailbox),
        combinator::map(group, Address::Group),
    ))(i)
}

// RFC 5322 3.4 address list, including 4.4 obsolete syntax
fn address_list(i: &[u8]) -> IResult<&[u8], Vec<Address<'_>>> {
    sequence::delimited(
        combinator::opt(obs_addr_list_delim),
        multi::separated_nonempty_list(obs_addr_list_delim, address),
        combinator::opt(obs_addr_list_delim),
    )(i)
}

// General notes about RFC 2045
// The formal syntax permits *no whitespace whatsoever*. However, even the
// RFC's own examples have whitespace. In this implementation, we just allow
// CFWS around every value. (The standard never allows adjacent
// non-tokens/values so we only need to add it around token since quoted_string
// already comes with its own.)

// RFC 2045 5.1 token
// Why couldn't they just reuse the atom definition? This one is subtly
// different.
fn token(i: &[u8]) -> IResult<&[u8], &[u8]> {
    sequence::delimited(ocfws, is_not("()<>@,;:\\\"/[]?= \t\r\n"), ocfws)(i)
}

// RFC 2045 5.1 value
// Basically RFC 822/2822/5322's "word", but with their special _token_
// replacing _atom_. At least they kept the same definition for quoted_string.
fn value(i: &[u8]) -> IResult<&[u8], Cow<'_, [u8]>> {
    branch::alt((combinator::map(token, Cow::Borrowed), quoted_string))(i)
}

// RFC 2045 5.1 type parameter
fn content_type_parm(
    i: &[u8],
) -> IResult<&[u8], (Cow<'_, [u8]>, Cow<'_, [u8]>)> {
    // Due the critcality of parsing Content-Type, if we can't parse the proper
    // syntax, just gobble everything up through the next ; and call it a parm
    // with a name but no value.
    branch::alt((
        sequence::separated_pair(
            combinator::map(token, Cow::Borrowed),
            tag(b"="),
            value,
        ),
        combinator::map(is_not(";"), |s| {
            (Cow::Borrowed(s), Cow::Borrowed(&[] as &[u8]))
        }),
    ))(i)
}

// RFC 2045 5.1 Content-Type
fn content_type(i: &[u8]) -> IResult<&[u8], ContentType<'_>> {
    let (i, typ) = token(i)?;
    let (i, subtyp) = sequence::preceded(tag(b"/"), token)(i)?;
    let (i, parms) =
        multi::many0(sequence::preceded(tag(b";"), content_type_parm))(i)?;
    Ok((
        i,
        ContentType {
            typ: Cow::Borrowed(typ),
            subtype: Cow::Borrowed(subtyp),
            parms,
        },
    ))
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

    fn mbox(input: &str) -> String {
        if let Some(m) = parse_mailbox(input.as_bytes()) {
            format!("{:?}", m)
        } else {
            panic!("Failed to parse: {}", input);
        }
    }

    #[test]
    fn test_parse_mailbox() {
        assert_eq!("<(foo)@(bar)(com)>", mbox("foo@bar.com"));
        assert_eq!("<(foo)@(bar)(com)>", mbox("<foo@bar.com>"));
        // Examples from RFC 2822
        // There aren't many single mailboxes, so this also pulls some out of
        // lists.
        assert_eq!(
            "(Michael)(Jones)<(mjones)@(machine)(example)>",
            mbox("Michael Jones <mjones@machine.example>")
        );
        assert_eq!(
            "(Joe Q. Public)<(john)(q)(public)@(example)(com)>",
            mbox("\"Joe Q. Public\" <john.q.public@example.com>")
        );
        assert_eq!(
            "(Giant; \"Big\" Box)<(sysservices)@(example)(net)>",
            mbox("\"Giant; \\\"Big\\\" Box\" <sysservices@example.net>")
        );
        assert_eq!("(Who?)<(one)@(y)(test)>", mbox("Who? <one@y.test>"));
        assert_eq!(
            "(Pete)<(pete)@(silly)(test)>",
            mbox(concat!(
                "Pete(A wonderful \\) chap) ",
                "<pete(his account)@silly.test(his host)>"
            ))
        );
        assert_eq!(
            "(Mary)(Smith)<(mary)@(example)(net)>",
            mbox("Mary Smith <@machine.tld:mary@example.net>")
        );
        assert_eq!(
            "(John)(Doe)<(jdoe)@(machine)(example)>",
            mbox("John Doe <jdoe@machine(comment).  example>")
        );
        // ENRON-style with illegal dots
        assert_eq!("<()(ed)()(dy)()@(enron)(com)>", mbox(".ed..dy.@enron.com"));
        // Mailman's (?) illegal list syntax
        assert_eq!(
            "<(the.desk)(:)@(enron)(com)>",
            mbox("<\"the.desk\":@enron.com>")
        );
        // Whatever this is, found commonly in the ENRON corpus
        assert_eq!(
            "<(katz)(andy)@(enron)(com)>",
            mbox("<katz\".'\"andy@enron.com>")
        );
        assert_eq!(
            "<(katz)(andy)@(enron)(com)>",
            mbox("<katz.\".'\"andy@enron.com>")
        );
        assert_eq!(
            "<(katz)(andy)@(enron)(com)>",
            mbox("<katz\".\"andy@enron.com>")
        );
        // Older versions of outlook's apostrophe bug
        assert_eq!("<(foo)@(bar)(com)>", mbox("<'\"foo\"@bar.com>"));
        // Ensure quoted strings interpret whitespace properly
        assert_eq!(
            "<(foo \tbar)@(baz)(com)>",
            mbox("<\"foo\r\n \tbar\"@baz.com>")
        );
        // Ensure comments are nestable
        assert_eq!("<(foo)@(bar)(com)>", mbox("((comment))foo@bar.com"));
    }

    fn mbox_list(input: &str) -> String {
        if let Some(m) = parse_mailbox_list(input.as_bytes()) {
            format!("{:?}", m)
        } else {
            panic!("Failed to parse: {}", input);
        }
    }

    #[test]
    fn test_parse_mailbox_list() {
        assert_eq!("[<(foo)@(bar)(com)>]", mbox_list("foo@bar.com"));
        assert_eq!("[<(foo)@(bar)(com)>]", mbox_list("<foo@bar.com>"));
        // RFC 2822 examples
        assert_eq!(
            "[(Joe Q. Public)<(john)(q)(public)@(example)(com)>]",
            mbox_list("\"Joe Q. Public\" <john.q.public@example.com>")
        );
        assert_eq!(
            concat!(
                "[",
                "(Mary)(Smith)<(mary)@(x)(test)>, ",
                "<(jdoe)@(example)(org)>, ",
                "(Who?)<(one)@(y)(test)>",
                "]"
            ),
            mbox_list(concat!(
                "Mary Smith <mary@x.test>, jdoe@example.org, ",
                "Who? <one@y.test>"
            ))
        );
        assert_eq!(
            concat!(
                "[",
                "<(boss)@(nil)(test)>, ",
                "(Giant; \"Big\" Box)<(sysservices)@(example)(net)>",
                "]"
            ),
            mbox_list(concat!(
                "<boss@nil.test>, ",
                "\"Giant; \\\"Big\\\" Box\" <sysservices@example.net>"
            ))
        );
    }

    fn addr_list(input: &str) -> String {
        if let Some(m) = parse_address_list(input.as_bytes()) {
            format!("{:?}", m)
        } else {
            panic!("Failed to parse: {}", input);
        }
    }

    #[test]
    fn test_parse_address_list() {
        assert_eq!("[Mailbox(<(foo)@(bar)(com)>)]", addr_list("foo@bar.com"));
        assert_eq!("[Mailbox(<(foo)@(bar)(com)>)]", addr_list("<foo@bar.com>"));
        // RFC 2822 examples
        assert_eq!(
            "[Mailbox((Joe Q. Public)<(john)(q)(public)@(example)(com)>)]",
            addr_list("\"Joe Q. Public\" <john.q.public@example.com>")
        );
        assert_eq!(
            concat!(
                "[",
                "Mailbox((Mary)(Smith)<(mary)@(x)(test)>), ",
                "Mailbox(<(jdoe)@(example)(org)>), ",
                "Mailbox((Who?)<(one)@(y)(test)>)",
                "]"
            ),
            addr_list(concat!(
                "Mary Smith <mary@x.test>, jdoe@example.org, ",
                "Who? <one@y.test>"
            ))
        );
        assert_eq!(
            concat!(
                "[",
                "Mailbox(<(boss)@(nil)(test)>), ",
                "Mailbox((Giant; \"Big\" Box)<(sysservices)@(example)(net)>)",
                "]"
            ),
            addr_list(concat!(
                "<boss@nil.test>, ",
                "\"Giant; \\\"Big\\\" Box\" <sysservices@example.net>"
            ))
        );

        assert_eq!(
            concat!(
                "[Group((A)(Group)",
                "[(Chris)(Jones)<(c)@(a)(test)>]",
                "[<(joe)@(where)(test)>]",
                "[(John)<(jdoe)@(one)(test)>]",
                ")]"
            ),
            addr_list(concat!(
                "A Group:Chris Jones <c@a.test>,",
                "joe@where.test,John <jdoe@one.test>;"
            ))
        );
        assert_eq!(
            "[Group((Undisclosed)(recipients))]",
            addr_list("Undisclosed recipients:;")
        );
        assert_eq!(
            concat!(
                "[Group((A)(Group)",
                "[(Chris)(Jones)<(c)@(public)(example)>]",
                "[<(joe)@(example)(org)>]",
                "[(John)<(jdoe)@(one)(test)>]",
                ")]"
            ),
            addr_list(concat!(
                "A Group(Some people)\r\n",
                "     :Chris Jones <c@(Chris's host.)public.example>,\r\n",
                "         joe@example.org,\r\n",
                "  John <jdoe@one.test> (my dear friend); ",
                "(the end of the group)"
            ))
        );

        // Test address lists including more than just one group
        assert_eq!(
            "[Group((A)[<(foo)@(bar)(com)>]), Group((B)[<(bar)@(baz)(com)>])]",
            // Note missing terminator on the last group
            addr_list("A:foo@bar.com;,B:bar@baz.com")
        );
        assert_eq!(
            "[Mailbox(<(foo)@(bar)(com)>), Group((B)[<(bar)@(baz)(com)>])]",
            addr_list("foo@bar.com,B:bar@baz.com")
        );
        assert_eq!(
            "[Group((A)[<(foo)@(bar)(com)>]), Mailbox(<(bar)@(baz)(com)>)]",
            addr_list("A:foo@bar.com;,bar@baz.com")
        );
    }

    #[test]
    fn address_list_parse_jlingle_corpus() {
        // This holds the unfolded content of every From, To, CC, and BCC
        // header of every email I (Jason Lingle) have ever received as of
        // 2020-06-20, with all alphanumerics replaced with 'X' (since the
        // actual values do not affect syntax), and finally deduplicated. A few
        // uncensored Unicode characters are present in there as well.
        //
        // There was some samples that were removed manually:
        //
        // "XXXXX! XXXXXXXX"
        // Since the parser is greedy, supporting this would require manual
        // look-ahead. But since this is abjectly an invalid address list, we
        // just don't support it.
        //
        // XXXXXXXXXXX-XXXXXXXXXX:;;;;XXXXXXXXXXX-XXXXXXXXXX:;@XXX.XXX;;;;;;
        // originally:
        // undisclosed-recipients:;;;;undisclosed-recipients:;@MIT.EDU;;;;;;
        // The main problem here, as far as our permissive parser is concerned,
        // is the @MIT.EDU part with no local part. This was also excluded
        // since there's not really any meaning we can ascribe to this
        // regardless.
        let data = include_str!("address-list-corpus-jlingle.txt");
        address_list_parse_corpus(data);
    }

    #[test]
    fn address_list_parse_enron_corpus() {
        // Similar to the above, but the text is pulled from the entire ENRON
        // email corpus. The text is still censored just to reduce the number
        // of distinct strings.
        //
        // Removed:
        //
        // No address:
        // XXXX.X
        // XXXXXXXXXX: XXXX
        // XXXXX.XXXXXX@XXXXX.XXX, XXXX.XXXXXXX@XXXX, XXXX XXXX
        // And other variations of this
        //
        // No ascribable meaning:
        // <"XXXXX".@XXXXX@XXXXX.XXX>
        // <"X@XXXXXXXX".@XXXXX@XXXXX.XXX>
        // <"XXXXX"@XXXXXX.XXX.XXX@XXXXX.XXX>
        // <"XXX/XXXXXXX"@XXXXX.XX.XXX@XXXXX.XXX>
        // <"XXXXX"@XXXXXX.XXX.XXX@XXXXX.XXX>
        // and other variations of this double-@ syntax
        //
        // Using an email address as a list name (and several much larger
        // variants of this line):
        // XXXX.XXXXXXX@XXXXXXX-XX: <XXXXXXXX.XXXXXXXXXXXXX.XXXXXXXX.XXXXX@XXXXX>
        //
        // A line containing this, which is probably corruption and not actual
        // syntax (and a couple similar):
        // <XXXXXXXXX\"@XXXXX.<??X"X.@XXXXX.XXX>
        //
        // A line which ended with a stray ')'. The rest of the line was
        // parsed.
        //
        // A line which had a closing, but no opening, double-quote around a
        // string.
        //
        // All lines after 55482 were removed due to decreasing value of the
        // test data (i.e. more and more common occurrences of the above
        // issues due to each line having more and more items).
        let data = include_str!("address-list-corpus-enron.txt");
        address_list_parse_corpus(data);
    }

    fn address_list_parse_corpus(data: &str) {
        for (lineno, line) in data.lines().enumerate() {
            if line.is_empty() {
                continue;
            }

            if let Ok((remaining, _)) = address_list(line.as_bytes()) {
                assert!(
                    remaining.is_empty(),
                    "Didn't parse all of line {}:\n{}\nRemaining:\n{}",
                    lineno + 1,
                    line,
                    String::from_utf8_lossy(remaining)
                );
            } else {
                panic!("Failed to parse line {}:\n{}", lineno + 1, line);
            }
        }
    }

    #[test]
    fn no_stack_overflow_on_nested_comments() {
        let s = "(".repeat(50000);
        assert!(mailbox(s.as_bytes()).is_err());
    }

    fn ctype(input: &str) -> String {
        if let Some(ct) = parse_content_type(input.as_bytes()) {
            format!("{:?}", ct)
        } else {
            panic!("Failed to parse: {}", input);
        }
    }

    #[test]
    fn test_parse_content_type() {
        assert_eq!("(text)/(plain)", ctype("text/plain"));
        assert_eq!(
            "(text)/(plain); (foo)=(bar)",
            ctype("\ttext / plain ; foo = \"bar\"\t")
        );
        // Examples from RFC 2045
        assert_eq!(
            "(text)/(plain); (charset)=(ISO-8859-1)",
            ctype("text/plain; charset=ISO-8859-1")
        );
        assert_eq!(
            "(text)/(plain); (charset)=(us-ascii)",
            ctype("text/plain; charset=us-ascii (Plain text)")
        );
        assert_eq!(
            "(text)/(plain); (charset)=(us-ascii)",
            ctype("text/plain; charset=\"us-ascii\"")
        );

        // Examples found in the wild
        assert_eq!(
            concat!(
                "(application)/(msword); ",
                "(name)=(123456 Participant Fee Disclosure.doc)"
            ),
            ctype(concat!(
                "application/msword;",
                "\tname=\"123456 Participant Fee Disclosure.doc\""
            ))
        );
        assert_eq!(
            "(application)/(octet-stream); (name)=(PGPipe-1000.asc)",
            ctype("application/octet-stream;\tname=\"PGPipe-1000.asc\"")
        );
        assert_eq!(
            "(application)/(pdf); (name)=(SPDs & SMMs.pdf)",
            ctype("application/pdf; name=\"SPDs & SMMs.pdf\"")
        );
        assert_eq!(
            concat!(
                "(application)/(pkcs7-mime); ",
                "(smime-type)=(signed-data); (name)=(smime.p7m)"
            ),
            ctype(concat!(
                "application/pkcs7-mime; ",
                "smime-type=signed-data; name=\"smime.p7m\""
            ))
        );
        assert_eq!(
            concat!(
                "(multipart)/(alternative); ",
                "(boundary)=(Apple-Mail=_01B5A0AD-",
                "9508-48B2-B309-1FA4444F1310)"
            ),
            ctype(concat!(
                "multipart/alternative;  ",
                "boundary=\"Apple-Mail=_01B5A0AD-",
                "9508-48B2-B309-1FA4444F1310\""
            ))
        );
        assert_eq!(
            concat!(
                "(multipart)/(signed); ",
                "(boundary)=(----=_NextPart_000_004B_01D04D20.0C896ED0); ",
                "(protocol)=(application/x-pkcs7-signature); ",
                "(micalg)=(2.16.840.1.101.3.4.2.3)"
            ),
            ctype(concat!(
                "multipart/signed;       ",
                "boundary=\"----=_NextPart_000_004B_01D04D20.0C896ED0\";  ",
                "protocol=\"application/x-pkcs7-signature\"; ",
                "micalg=2.16.840.1.101.3.4.2.3"
            ))
        );

        // Test for recovery
        assert_eq!(
            "(text)/(plain); ( foo)=(); (xyzzy)=(plugh)",
            ctype("text/plain; foo; xyzzy=plugh")
        );
        assert_eq!(
            "(text)/(plain); ( foo=)=(); (xyzzy)=(plugh)",
            ctype("text/plain; foo=; xyzzy=plugh")
        );
    }
}
