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

//! The syntax for SPF TXT records.
//! RFC 7208 § 12

use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};

use lazy_static::lazy_static;
use regex::Regex;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Term<'a> {
    Directive(Directive<'a>),
    Modifier(Modifier<'a>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Directive<'a> {
    pub qualifier: Qualifier,
    pub mechanism: Mechanism<'a>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Qualifier {
    Pass,
    Fail,
    SoftFail,
    Neutral,
}

// Starting here, we lots of `domain-spec`. We have these definitions:
//
//   domain-spec        = macro-string domain-end
//   domain-end         = ( "." toplabel ["."] ) / macro-expand
//   toplabel           = <rules for DNS names>
//   macro-string       = *( macro-expand / macro-literal )
//   macro-literal      = <characters other than %>
//
// `toplabel` with its adjacent decorations is a subset of `macro-literal`, so
// `domain-end` itself is effectively `macro-expand / macro-literal`, and in
// turn we can just consider the entire `domain-spec` to be a `macro-string`
// where we validate the domain after expansion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mechanism<'a> {
    All,
    Include(MacroString<'a>),
    A(Option<MacroString<'a>>, Option<u32>, Option<u32>),
    Mx(Option<MacroString<'a>>, Option<u32>, Option<u32>),
    Ptr(Option<MacroString<'a>>),
    Ip4(Ipv4Addr, Option<u32>),
    Ip6(Ipv6Addr, Option<u32>),
    Exists(MacroString<'a>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Modifier<'a> {
    Redirect(MacroString<'a>),
    Explanation(MacroString<'a>),
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MacroString<'a>(&'a str);

impl<'a> MacroString<'a> {
    pub fn new(s: &'a str) -> Self {
        Self(s)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacroElement<'a> {
    Literal(&'a str),
    Expand(MacroExpand<'a>),
}

/// The actually-a-macro case of `macro-expand`.
///
/// The `%%`, `%_`, and `%-` cases of `macro-expand` are converted into
/// `MacroElement::Literal` with the output text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MacroExpand<'a> {
    pub kind: Macro,
    pub keep_parts: Option<usize>,
    pub reverse: bool,
    pub delimiters: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd)]
pub enum Macro {
    Sender,
    SenderLocalPart,
    SenderDomain,
    Domain,
    Ip,
    Ptr,
    IpVersion,
    HeloDomain,
    // Below this point: `exp` only
    SmtpClientIp,
    ReceivingHost,
    CurrentTimestamp,
}

impl Macro {
    pub fn is_exp_only(self) -> bool {
        self >= Self::SmtpClientIp
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum Error {
    #[error("invalid integer")]
    InvalidInteger,
    #[error("invalid IP address")]
    InvalidIpAddress,
    #[error("unknown character: {0}")]
    UnknownCharacter(char),
    #[error("unknown mechanism")]
    UnknownMechanism,
    #[error("unknown macro transformer: {0}")]
    UnknownMacroTransformer(char),
    #[error("unknown macro: {0}")]
    UnknownMacro(char),
    #[error("unused argument for {0}")]
    UnusedArgument(&'static str),
    #[error("missing argument for {0}")]
    MissingArgument(&'static str),
    #[error("empty directive")]
    EmptyDirective,
    #[error("isolated percent sign")]
    IsolatedPercent,
    #[error("unterminated macro expand")]
    UnterminatedMacroExpand,
    #[error("empty macro")]
    EmptyMacro,
}

impl<'a> Term<'a> {
    /// Parses a single term.
    ///
    /// `word` is a non-empty item from the SPF record after splitting on
    /// space. The version term doesn't need to be discarded explicitly because
    /// it is simply an "unknown modifier" that gets ignored.
    pub fn parse(word: &'a str) -> Result<Self, Error> {
        lazy_static! {
            static ref MODIFIER: Regex =
                Regex::new("^([a-zA-Z][a-zA-Z0-9._-]*)=(.*)$",).unwrap();
        }

        if let Some(captures) = MODIFIER.captures(word) {
            Modifier::parse(
                captures.get(1).unwrap().as_str(),
                captures.get(2).unwrap().as_str(),
            )
            .map(Self::Modifier)
        } else {
            Directive::parse(word).map(Self::Directive)
        }
    }
}

impl<'a> Modifier<'a> {
    fn parse(name: &str, value: &'a str) -> Result<Self, Error> {
        if name.eq_ignore_ascii_case("redirect") {
            Ok(Self::Redirect(MacroString(value)))
        } else if name.eq_ignore_ascii_case("exp") {
            Ok(Self::Explanation(MacroString(value)))
        } else {
            Ok(Self::Unknown)
        }
    }
}

impl<'a> Directive<'a> {
    fn parse(word: &'a str) -> Result<Self, Error> {
        let mut chars = word.chars();
        let (qualifier, rest) = match chars.next() {
            None => return Err(Error::EmptyDirective),
            Some('+') => (Qualifier::Pass, chars.as_str()),
            Some('-') => (Qualifier::Fail, chars.as_str()),
            Some('?') => (Qualifier::Neutral, chars.as_str()),
            Some('~') => (Qualifier::SoftFail, chars.as_str()),
            Some(c) if !c.is_ascii_alphabetic() => {
                return Err(Error::UnknownCharacter(c));
            },
            Some(_) => (Qualifier::Pass, word),
        };

        let mechanism = Mechanism::parse(rest)?;
        Ok(Self {
            qualifier,
            mechanism,
        })
    }
}

impl<'a> Mechanism<'a> {
    fn parse(word: &'a str) -> Result<Self, Error> {
        fn parse_ipv4_cidr_length(s: &str) -> Result<u32, Error> {
            let l = s.parse::<u32>().map_err(|_| Error::InvalidInteger)?;
            if l > 32 {
                return Err(Error::InvalidInteger);
            }

            Ok(l)
        }

        fn parse_ipv6_cidr_length(s: &str) -> Result<u32, Error> {
            let l = s.parse::<u32>().map_err(|_| Error::InvalidInteger)?;
            if l > 128 {
                return Err(Error::InvalidInteger);
            }

            Ok(l)
        }

        fn parse_arg_dual_cidr_length(
            arg: &str,
        ) -> Result<(&str, Option<u32>, Option<u32>), Error> {
            lazy_static! {
                static ref R: Regex =
                    Regex::new("/([0-9]+)(/([0-9]+))?$",).unwrap();
            }

            if let Some(captures) = R.captures(arg) {
                let v4 = parse_ipv4_cidr_length(&captures[1])?;
                let v6 = captures
                    .get(3)
                    .map(|c| parse_ipv6_cidr_length(c.as_str()))
                    .transpose()?;
                Ok((&arg[..captures.get(0).unwrap().start()], Some(v4), v6))
            } else {
                Ok((arg, None, None))
            }
        }

        let (name, arg) = word
            .split_once(':')
            .map(|(n, a)| (n, Some(a)))
            .unwrap_or((word, None));

        if "all".eq_ignore_ascii_case(name) {
            if arg.is_some() {
                return Err(Error::UnusedArgument("all"));
            }

            Ok(Self::All)
        } else if "include".eq_ignore_ascii_case(name) {
            let arg = arg.ok_or(Error::MissingArgument("include"))?;
            Ok(Self::Include(MacroString(arg)))
        } else if "a".eq_ignore_ascii_case(name) {
            let (arg, v4, v6) = arg
                .map(|a| parse_arg_dual_cidr_length(a))
                .transpose()?
                .map_or((None, None, None), |(a, b, c)| (Some(a), b, c));
            Ok(Self::A(arg.map(MacroString), v4, v6))
        } else if "mx".eq_ignore_ascii_case(name) {
            let (arg, v4, v6) = arg
                .map(|a| parse_arg_dual_cidr_length(a))
                .transpose()?
                .map_or((None, None, None), |(a, b, c)| (Some(a), b, c));
            Ok(Self::Mx(arg.map(MacroString), v4, v6))
        } else if "ptr".eq_ignore_ascii_case(name) {
            Ok(Self::Ptr(arg.map(MacroString)))
        } else if "ip4".eq_ignore_ascii_case(name) {
            let arg = arg.ok_or(Error::MissingArgument("ip4"))?;
            let (addr, cidr_len) = arg
                .split_once('/')
                .map(|(addr, cidr_len)| (addr, Some(cidr_len)))
                .unwrap_or((arg, None));

            let addr = addr
                .parse::<Ipv4Addr>()
                .map_err(|_| Error::InvalidIpAddress)?;
            let cidr_len = cidr_len.map(parse_ipv4_cidr_length).transpose()?;

            Ok(Self::Ip4(addr, cidr_len))
        } else if "ip6".eq_ignore_ascii_case(name) {
            let arg = arg.ok_or(Error::MissingArgument("ip6"))?;

            let (addr, cidr_len) = arg
                .split_once('/')
                .map(|(addr, cidr_len)| (addr, Some(cidr_len)))
                .unwrap_or((arg, None));

            let addr = addr
                .parse::<Ipv6Addr>()
                .map_err(|_| Error::InvalidIpAddress)?;
            let cidr_len = cidr_len.map(parse_ipv6_cidr_length).transpose()?;

            Ok(Self::Ip6(addr, cidr_len))
        } else if "exists".eq_ignore_ascii_case(name) {
            let arg = arg.ok_or(Error::MissingArgument("exists"))?;
            Ok(Self::Exists(MacroString(arg)))
        } else {
            // The a and mx mechanisms can take a CIDR without any argument.
            if let Ok((prefix, Some(v4), v6)) = parse_arg_dual_cidr_length(word)
            {
                if "a".eq_ignore_ascii_case(prefix) {
                    return Ok(Self::A(None, Some(v4), v6));
                } else if "mx".eq_ignore_ascii_case(prefix) {
                    return Ok(Self::Mx(None, Some(v4), v6));
                }
            }

            Err(Error::UnknownMechanism)
        }
    }
}

impl<'a> IntoIterator for MacroString<'a> {
    type Item = Result<MacroElement<'a>, Error>;
    type IntoIter = MacroElements<'a>;

    fn into_iter(self) -> MacroElements<'a> {
        MacroElements(self.0)
    }
}

#[derive(Clone, Debug)]
pub struct MacroElements<'a>(&'a str);

impl<'a> Iterator for MacroElements<'a> {
    type Item = Result<MacroElement<'a>, Error>;

    fn next(&mut self) -> Option<Result<MacroElement<'a>, Error>> {
        if self.0.is_empty() {
            return None;
        }

        let elt = match self.0.find('%') {
            None => MacroElement::Literal(mem::take(&mut self.0)),

            Some(0) => {
                if self.0.len() < 2 {
                    return Some(Err(Error::IsolatedPercent));
                }

                let (head, tail) = self.0.split_at(2);
                self.0 = tail;

                match head {
                    "%%" => MacroElement::Literal("%"),
                    "%_" => MacroElement::Literal(" "),
                    "%-" => MacroElement::Literal("%20"),
                    "%{" => {
                        let Some((macrow, rest)) = tail.split_once('}') else {
                            return Some(Err(Error::UnterminatedMacroExpand));
                        };

                        self.0 = rest;
                        return Some(parse_macro_expand(macrow));
                    },

                    _ => return Some(Err(Error::IsolatedPercent)),
                }
            },

            Some(n) => {
                let literal = &self.0[..n];
                self.0 = &self.0[n..];
                MacroElement::Literal(literal)
            },
        };

        Some(Ok(elt))
    }
}

fn parse_macro_expand(mut s: &str) -> Result<MacroElement<'_>, Error> {
    let mut chars = s.chars();
    let kind = match chars.next().map(|c| c.to_ascii_lowercase()) {
        None => return Err(Error::EmptyMacro),
        Some('s') => Macro::Sender,
        Some('l') => Macro::SenderLocalPart,
        Some('o') => Macro::SenderDomain,
        Some('d') => Macro::Domain,
        Some('i') => Macro::Ip,
        Some('p') => Macro::Ptr,
        Some('v') => Macro::IpVersion,
        Some('h') => Macro::HeloDomain,
        Some('c') => Macro::SmtpClientIp,
        Some('r') => Macro::ReceivingHost,
        Some('t') => Macro::CurrentTimestamp,
        Some(c) => return Err(Error::UnknownMacro(c)),
    };

    s = chars.as_str();
    let keep_parts =
        if let Some(last_digit) = s.rfind(|c: char| c.is_ascii_digit()) {
            let digit_str = &s[..=last_digit];
            s = &s[last_digit + 1..];

            Some(
                digit_str
                    .parse::<usize>()
                    .map_err(|_| Error::InvalidInteger)?,
            )
        } else {
            None
        };

    let reverse = if s.starts_with('r') || s.starts_with('R') {
        s = &s[1..];
        true
    } else {
        false
    };

    for ch in s.chars() {
        if !matches!(ch, '.' | '-' | '+' | ',' | '/' | '_' | '=') {
            return Err(Error::UnknownMacroTransformer(ch));
        }
    }

    Ok(MacroElement::Expand(MacroExpand {
        kind,
        keep_parts,
        reverse,
        delimiters: s,
    }))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn term_parse() {
        use super::{MacroString as Ms, Mechanism as Me, Qualifier as Q};

        fn directive(
            qualifier: Qualifier,
            mechanism: Me,
        ) -> Result<Term, Error> {
            Ok(Term::Directive(Directive {
                qualifier,
                mechanism,
            }))
        }

        assert_eq!(
            Ok(Term::Modifier(Modifier::Unknown)),
            Term::parse("v=spf1"),
        );
        assert_eq!(
            Ok(Term::Modifier(Modifier::Redirect(Ms("foo.bar")))),
            Term::parse("redirect=foo.bar"),
        );
        assert_eq!(
            Ok(Term::Modifier(Modifier::Redirect(Ms("foo.bar")))),
            Term::parse("REDIRECT=foo.bar"),
        );
        assert_eq!(
            Ok(Term::Modifier(Modifier::Explanation(Ms("foo.bar")))),
            Term::parse("exp=foo.bar"),
        );
        assert_eq!(
            Ok(Term::Modifier(Modifier::Explanation(Ms("foo.bar")))),
            Term::parse("EXP=foo.bar"),
        );

        assert_eq!(directive(Q::Pass, Me::All), Term::parse("all"),);
        assert_eq!(directive(Q::Pass, Me::All), Term::parse("+all"),);
        assert_eq!(directive(Q::Fail, Me::All), Term::parse("-aLl"),);
        assert_eq!(directive(Q::Neutral, Me::All), Term::parse("?ALL"),);
        assert_eq!(directive(Q::SoftFail, Me::All), Term::parse("~all"),);
        assert_eq!(
            Err(Error::UnusedArgument("all")),
            Term::parse("all:foo.bar"),
        );

        assert_eq!(
            directive(Q::Pass, Me::Include(Ms("foo.bar"))),
            Term::parse("include:foo.bar"),
        );
        assert_eq!(
            directive(Q::Fail, Me::Include(Ms("foo/bar"))),
            Term::parse("-INCLUDE:foo/bar"),
        );
        assert_eq!(
            Err(Error::MissingArgument("include")),
            Term::parse("include"),
        );
        assert_eq!(
            directive(Q::Pass, Me::A(None, None, None)),
            Term::parse("a"),
        );
        assert_eq!(
            directive(Q::Fail, Me::A(Some(Ms("foo.bar")), None, None)),
            Term::parse("-A:foo.bar"),
        );
        assert_eq!(
            directive(Q::Pass, Me::A(Some(Ms("foo/bar")), None, None)),
            Term::parse("a:foo/bar"),
        );
        assert_eq!(
            directive(Q::Pass, Me::A(Some(Ms("foo")), Some(4), None)),
            Term::parse("a:foo/4"),
        );
        assert_eq!(
            directive(Q::Pass, Me::A(Some(Ms("foo/bar")), Some(4), None)),
            Term::parse("a:foo/bar/4"),
        );
        assert_eq!(
            directive(Q::Pass, Me::A(Some(Ms("foo")), Some(4), Some(6))),
            Term::parse("a:foo/4/6"),
        );
        assert_eq!(
            directive(Q::Pass, Me::A(Some(Ms("foo/bar")), Some(4), Some(6))),
            Term::parse("a:foo/bar/4/6"),
        );
        assert_eq!(
            directive(Q::Pass, Me::A(None, Some(4), None)),
            Term::parse("a/4"),
        );
        assert_eq!(
            directive(Q::Pass, Me::A(None, Some(4), Some(6))),
            Term::parse("A/4/6"),
        );
        assert_eq!(Err(Error::InvalidInteger), Term::parse("a:foo.bar/33"),);
        assert_eq!(
            Err(Error::InvalidInteger),
            Term::parse("a:foo.bar/99999999999999"),
        );
        assert_eq!(Err(Error::InvalidInteger), Term::parse("a:foo.bar/32/129"),);
        assert_eq!(
            directive(Q::Pass, Me::A(None, Some(32), Some(128))),
            Term::parse("a/32/128"),
        );

        assert_eq!(
            directive(Q::Pass, Me::Mx(None, None, None)),
            Term::parse("mx"),
        );
        assert_eq!(
            directive(Q::Fail, Me::Mx(Some(Ms("foo.bar")), None, None)),
            Term::parse("-MX:foo.bar"),
        );
        assert_eq!(
            directive(Q::Pass, Me::Mx(Some(Ms("foo/bar")), None, None)),
            Term::parse("mX:foo/bar"),
        );
        assert_eq!(
            directive(Q::Pass, Me::Mx(Some(Ms("foo")), Some(4), None)),
            Term::parse("mx:foo/4"),
        );
        assert_eq!(
            directive(Q::Pass, Me::Mx(Some(Ms("foo/bar")), Some(4), None)),
            Term::parse("mx:foo/bar/4"),
        );
        assert_eq!(
            directive(Q::Pass, Me::Mx(Some(Ms("foo")), Some(4), Some(6))),
            Term::parse("mx:foo/4/6"),
        );
        assert_eq!(
            directive(Q::Pass, Me::Mx(Some(Ms("foo/bar")), Some(4), Some(6))),
            Term::parse("mx:foo/bar/4/6"),
        );
        assert_eq!(
            directive(Q::Pass, Me::Mx(None, Some(4), None)),
            Term::parse("mx/4"),
        );
        assert_eq!(
            directive(Q::Pass, Me::Mx(None, Some(4), Some(6))),
            Term::parse("MX/4/6"),
        );
        assert_eq!(Err(Error::InvalidInteger), Term::parse("mx:foo.bar/33"),);
        assert_eq!(
            Err(Error::InvalidInteger),
            Term::parse("mx:foo.bar/99999999999999"),
        );
        assert_eq!(
            Err(Error::InvalidInteger),
            Term::parse("mx:foo.bar/32/129"),
        );
        assert_eq!(
            directive(Q::Pass, Me::Mx(None, Some(32), Some(128))),
            Term::parse("mx/32/128"),
        );

        assert_eq!(directive(Q::Pass, Me::Ptr(None)), Term::parse("ptr"),);
        assert_eq!(
            directive(Q::Fail, Me::Ptr(Some(Ms("foo.bar")))),
            Term::parse("-PTR:foo.bar"),
        );

        let ipv4_addr = Ipv4Addr::new(192, 168, 10, 199);
        assert_eq!(
            directive(Q::Pass, Me::Ip4(ipv4_addr, None)),
            Term::parse("ip4:192.168.10.199"),
        );
        assert_eq!(
            directive(Q::Pass, Me::Ip4(ipv4_addr, Some(8))),
            Term::parse("IP4:192.168.10.199/8"),
        );
        assert_eq!(
            Err(Error::InvalidIpAddress),
            Term::parse("IP4:192.168.10.1999"),
        );
        assert_eq!(
            Err(Error::InvalidInteger),
            Term::parse("ip4:192.168.10.199/33"),
        );
        assert_eq!(
            Err(Error::InvalidInteger),
            Term::parse("ip4:192.168.10.199/999999999999"),
        );
        assert_eq!(Err(Error::MissingArgument("ip4")), Term::parse("ip4"),);
        assert_eq!(Err(Error::UnknownMechanism), Term::parse("ip4/8"),);

        let ipv6_addr = Ipv6Addr::new(0xDEAD, 0, 0, 0, 0, 0, 0xC0DE, 0xBEEF);
        assert_eq!(
            directive(Q::Pass, Me::Ip6(ipv6_addr, None)),
            Term::parse("ip6:dead::c0de:beef"),
        );
        assert_eq!(
            directive(Q::Pass, Me::Ip6(ipv6_addr, Some(128))),
            Term::parse("IP6:dead::c0de:beef/128"),
        );
        assert_eq!(
            Err(Error::InvalidInteger),
            Term::parse("ip6:dead::c0de:beef/129"),
        );
        assert_eq!(Err(Error::InvalidIpAddress), Term::parse("ip6:plugh"),);
        assert_eq!(Err(Error::MissingArgument("ip6")), Term::parse("ip6"),);
        assert_eq!(Err(Error::UnknownMechanism), Term::parse("ip6/8"),);

        assert_eq!(
            directive(Q::Pass, Me::Exists(Ms("foo.bar"))),
            Term::parse("exists:foo.bar"),
        );
        assert_eq!(
            directive(Q::SoftFail, Me::Exists(Ms("foo/bar"))),
            Term::parse("~EXISTS:foo/bar"),
        );
        assert_eq!(
            Err(Error::MissingArgument("exists")),
            Term::parse("exists"),
        );
    }

    #[test]
    fn parse_macro_string() {
        fn lit(s: &str) -> MacroElement<'_> {
            MacroElement::Literal(s)
        }

        fn mac(
            kind: Macro,
            reverse: bool,
            keep_parts: Option<usize>,
            delimiters: &str,
        ) -> MacroElement<'_> {
            MacroElement::Expand(MacroExpand {
                kind,
                reverse,
                keep_parts,
                delimiters,
            })
        }

        fn parse(s: &str) -> Result<Vec<MacroElement<'_>>, Error> {
            MacroString(s).into_iter().collect()
        }

        assert_eq!(Ok(vec![]), parse(""));
        assert_eq!(Ok(vec![lit("foo")]), parse("foo"));
        assert_eq!(
            Ok(vec![
                lit("foo"),
                mac(Macro::Sender, false, None, ""),
                lit("bar"),
            ]),
            parse("foo%{s}bar"),
        );
        assert_eq!(
            Ok(vec![
                lit("foo"),
                lit("%"),
                lit("bar"),
                lit(" "),
                lit("baz"),
                lit("%20"),
            ]),
            parse("foo%%bar%_baz%-"),
        );
        assert_eq!(
            Ok(vec![
                lit("foo"),
                mac(Macro::Sender, true, Some(42), ".-+,/_="),
                lit("bar"),
            ]),
            parse("foo%{s42r.-+,/_=}bar"),
        );
        assert_eq!(
            Ok(vec![
                lit("foo"),
                mac(Macro::Sender, true, None, ".-+,/_="),
                lit("bar"),
            ]),
            parse("foo%{SR.-+,/_=}bar"),
        );
        assert_eq!(
            Ok(vec![
                mac(Macro::SenderLocalPart, false, Some(4), "-"),
                mac(Macro::SenderDomain, true, None, ""),
                mac(Macro::Domain, false, None, ""),
                mac(Macro::Ip, false, None, ""),
                mac(Macro::Ptr, false, None, ""),
                mac(Macro::IpVersion, false, None, ""),
                mac(Macro::HeloDomain, false, None, ""),
                mac(Macro::SmtpClientIp, false, None, ""),
                mac(Macro::ReceivingHost, false, None, ""),
                mac(Macro::CurrentTimestamp, false, None, ""),
            ]),
            parse("%{l4-}%{or}%{d}%{i}%{p}%{v}%{h}%{c}%{r}%{t}"),
        );
        assert_eq!(Err(Error::IsolatedPercent), parse("foo%"));
        assert_eq!(Err(Error::IsolatedPercent), parse("foo%bar"));
        assert_eq!(Err(Error::UnknownMacro('x')), parse("%{x}"));
        assert_eq!(Err(Error::EmptyMacro), parse("%{}"));
        assert_eq!(Err(Error::UnterminatedMacroExpand), parse("%{foobar"));
        assert_eq!(Err(Error::UnknownMacroTransformer('x')), parse("%{ox}"));
        assert_eq!(
            Err(Error::InvalidInteger),
            parse("%{o9999999999999999999999999999}"),
        );
    }
}
