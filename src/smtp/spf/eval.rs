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

use std::borrow::Cow;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::rc::Rc;

use chrono::prelude::*;
use hickory_resolver::Name as DnsName;
use itertools::Itertools;

use super::syntax as s;

// RFC 7208 § 4.6.4
/// The maximum number of directives which trigger DNS queries which may be
/// processed.
///
/// If this limit is reached without finding a conclusive result, return error.
const MAX_DNS_DIRECTIVES: u32 = 10;
/// The maximum number of names returned by an MX query. If this limit is
/// exceeded, return error.
const MAX_MX_SIZE: usize = 10;
/// The maximum number of names returned by a PTR query. If this limit is
/// exceeded, ignore the extra names.
const MAX_PTR_SIZE: usize = 10;

/// Immutable context used during the evaluation of an SPF record.
pub struct Context<'a> {
    /// The full sender email address; i.e., from the `MAIL FROM` line.
    ///
    /// If `None`, the implicit "postmaster@{domain}" value is supplied by the
    /// evaluator.
    pub sender: Option<Cow<'a, str>>,
    /// The local part of the sender email address.
    ///
    /// If `None`, the implicit "postmaster" value is supplied by the
    /// evaluator.
    pub sender_local: Option<Cow<'a, str>>,
    /// The `HELO` domain or domain part of the `MAIL FROM`.
    pub sender_domain: Cow<'a, str>,
    /// The parsed representation of `sender_domain`.
    pub sender_domain_parsed: DnsName,
    /// The `HELO` domain.
    pub helo_domain: Cow<'a, str>,
    /// The sender IP address.
    ///
    /// This should not be an IPv6-encapsulated IPv4 address. Such addresses
    /// should be converted to IPv4 first.
    pub ip: IpAddr,
    /// The receiver host.
    pub receiver_host: Cow<'a, str>,
    /// The current time.
    pub now: DateTime<Utc>,
}

/// Internal state carried through a single SPF evaluation pass.
#[derive(Default)]
struct EvaluatorState {
    /// The number of DNS directives triggered so far (not including
    /// sub-queries from `ptr` or `mx` directives).
    dns_directives: u32,
    /// Whether a `ptr` directive has been executed.
    ///
    /// If `false`, the `%{p}` macro does nothing. If `true`, the `%{p}` macro
    /// repeats the `ptr` logic to find its expansion value.
    ///
    /// RFC 7208 § 7.3 is unclear as to whether `%{p}` itself should trigger
    /// the PTR queries. For now, we assume it does not, as allowing macros to
    /// initiate DNS queries makes the code more complicated, use of this macro
    /// is already both esoteric and deprecated, and SPF authors need to be
    /// prepared for the PTR query to fail anyway.
    has_ptr: bool,
    /// Set to `true` when the evaluator skipped processing a directive because
    /// it required a DNS query that has not yet completed, in order to
    /// discover new DNS queries further down the line.
    skipped_directive: bool,
}

/// A cache of DNS records used by SPF evaluation.
///
/// The evaluator creates entries with status `New` as it discovers them. The
/// driver is responsible for actually fetching them and updating their status
/// as they become available.
#[derive(Default)]
pub struct DnsCache {
    pub name_intern: HashMap<String, Rc<DnsName>>,
    pub a: DnsCacheMap<Vec<Ipv4Addr>>,
    pub aaaa: DnsCacheMap<Vec<Ipv6Addr>>,
    pub txt: DnsCacheMap<Rc<str>>,
    pub mx: DnsCacheMap<Vec<Rc<DnsName>>>,
    pub ptr: HashMap<IpAddr, DnsEntry<Vec<Rc<DnsName>>>>,
}

// These are association lists instead of hash maps because <DnsName as Hash>
// allocates like there's no tomorrow, and ultimately these won't be very big.
type DnsCacheMap<T> = Vec<(Rc<DnsName>, DnsEntry<T>)>;

/// An entry in the DNS cache passed to the SPF evaluator.
pub enum DnsEntry<T> {
    /// The query succeeded, and these are its results.
    Ok(T),
    /// The query succeeded and returned no results.
    NotFound,
    /// The query failed.
    Error,
    /// The query is in-flight.
    Pending,
    /// The evaluator newly discovered the need for this query.
    New,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DnsCacheError {
    NotFound,
    Error,
    NotReady,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DirectiveError {
    TempFail,
    PermFail,
    NotReady,
    SyntaxError(s::Error),
}

impl EvaluatorState {
    fn expand_macro_string<'s>(
        &self,
        ctx: &'s Context<'s>,
        dns_cache: &mut DnsCache,
        domain: &'s str,
        in_exp: bool,
        ms: s::MacroString<'s>,
    ) -> Result<Cow<'s, str>, DirectiveError> {
        let mut ret = Cow::Borrowed("");
        for e in ms {
            let expansion = match e {
                Ok(s::MacroElement::Literal(s)) => Cow::Borrowed(s),

                Ok(s::MacroElement::Expand(me)) => {
                    if !in_exp && me.kind.is_exp_only() {
                        return Err(DirectiveError::PermFail);
                    }

                    let expansion = self.basic_macro_expansion(
                        ctx, dns_cache, domain, me.kind,
                    )?;
                    let effective_delimiters = if me.delimiters.is_empty() {
                        "."
                    } else {
                        me.delimiters
                    };
                    let is_delimiter =
                        |c: char| effective_delimiters.chars().any(|d| d == c);
                    let keep_parts = me.keep_parts.unwrap_or(usize::MAX);

                    // Per RFC 7208 § 7.3, splitting is done naïvely, with no
                    // special handling for adjacent delimiters or delimiters
                    // at the start/end of the string.
                    if me.reverse {
                        let it = expansion.rsplit(is_delimiter);
                        let parts = it.clone().count();
                        Cow::Owned(
                            it.skip(parts.saturating_sub(keep_parts)).join("."),
                        )
                    } else if me.keep_parts.is_some()
                        || !me.delimiters.is_empty()
                    {
                        let it = expansion.split(is_delimiter);
                        let parts = it.clone().count();
                        Cow::Owned(
                            it.skip(parts.saturating_sub(keep_parts)).join("."),
                        )
                    } else {
                        expansion
                    }
                },

                Err(e) => return Err(DirectiveError::SyntaxError(e)),
            };

            if ret.is_empty() {
                ret = expansion;
            } else {
                ret.to_mut().push_str(&expansion);
            }
        }

        Ok(ret)
    }

    fn basic_macro_expansion<'s>(
        &self,
        ctx: &'s Context<'s>,
        dns_cache: &mut DnsCache,
        domain: &'s str,
        kind: s::Macro,
    ) -> Result<Cow<'s, str>, DirectiveError> {
        // RFC 7208 § 7.2, 7.3

        use super::syntax::Macro as M;

        let expansion = match kind {
            M::Sender => match ctx.sender {
                None => Cow::Owned(format!("postmaster@{}", ctx.sender_domain)),
                Some(ref s) => Cow::Borrowed(&**s),
            },

            M::SenderLocalPart => match ctx.sender_local {
                None => Cow::Borrowed("postmaster"),
                Some(ref s) => Cow::Borrowed(&**s),
            },

            M::SenderDomain => Cow::Borrowed(&*ctx.sender_domain),
            M::Domain => Cow::Borrowed(domain),

            M::Ip => match ctx.ip {
                IpAddr::V4(ip) => Cow::Owned(ip.to_string()),
                IpAddr::V6(ip) => {
                    // The obsolete dotted-hex format is required. RFC 7208 §
                    // 7.4 shows an example where it is, indeed, 32 hexadecimal
                    // nybbles.
                    let octets = ip.octets();
                    let mut s = String::with_capacity(63);
                    for (i, octet) in octets.into_iter().enumerate() {
                        let octet = u32::from(octet);
                        if 0 != i {
                            s.push('.');
                        }
                        s.push(char::from_digit(octet >> 4, 16).unwrap());
                        s.push('.');
                        s.push(char::from_digit(octet & 0xF, 16).unwrap());
                    }
                    Cow::Owned(s)
                },
            },

            M::Ptr => {
                let validated_name = if self.has_ptr {
                    find_validated_name(dns_cache, ctx)?
                } else {
                    None
                };

                match validated_name {
                    None => Cow::Borrowed("unknown"),
                    Some(name) => Cow::Owned(name.to_ascii()),
                }
            },

            M::IpVersion => match ctx.ip {
                IpAddr::V4(_) => Cow::Borrowed("in-addr"),
                IpAddr::V6(_) => Cow::Borrowed("ip6"),
            },

            M::HeloDomain => Cow::Borrowed(&*ctx.helo_domain),
            M::SmtpClientIp => Cow::Owned(ctx.ip.to_string()),
            M::ReceivingHost => Cow::Borrowed(&*ctx.receiver_host),
            M::CurrentTimestamp => Cow::Owned(ctx.now.timestamp().to_string()),
        };

        Ok(expansion)
    }
}

/// Identifies the "validated name" for the given context.
///
/// This is the process described in RFC 7208 § 5.5
fn find_validated_name<'d>(
    dns_cache: &'d mut DnsCache,
    ctx: &Context<'_>,
) -> Result<Option<&'d Rc<DnsName>>, DirectiveError> {
    let ptr = match dns_ptr(&mut dns_cache.ptr, ctx.ip) {
        Ok(ptr) => ptr,
        Err(DnsCacheError::NotFound) => return Ok(None),
        // > If a DNS error occurs while doing the PTR RR lookup, then [ptr]
        // > fails to match.
        Err(DnsCacheError::Error) => return Ok(None),
        Err(DnsCacheError::NotReady) => return Err(DirectiveError::NotReady),
    };

    // Prefer an exact match on the sender domain, then look at subdomains. If
    // we exceed the limit, just ignore the rest.
    let candidates = ptr
        .iter()
        .find(|n| ctx.sender_domain_parsed == ***n)
        .into_iter()
        .chain(ptr.iter().filter(|n| {
            ctx.sender_domain_parsed != ***n
                && ctx.sender_domain_parsed.zone_of(n)
        }))
        .take(MAX_PTR_SIZE);

    for candidate in candidates {
        let matches = match ctx.ip {
            IpAddr::V4(ip) => dns(&mut dns_cache.a, candidate)
                .map(|records| records.iter().any(|&r| r == ip)),

            IpAddr::V6(ip) => dns(&mut dns_cache.aaaa, candidate)
                .map(|records| records.iter().any(|&r| r == ip)),
        };

        match matches {
            Ok(false) => {},
            Ok(true) => return Ok(Some(candidate)),
            // > If a DNS error occurs while doing an A RR lookup, then that
            // > domain name is skipped and the search continues.
            Err(DnsCacheError::NotFound | DnsCacheError::Error) => {},
            Err(DnsCacheError::NotReady) => {
                // In order to be fully deterministic, we stop looking at
                // entries once we find one still in flight. This does make
                // this part of the process effectively sequential, but that's
                // probably preferable for the sake of DNS load anyway.
                return Err(DirectiveError::NotReady);
            },
        }
    }

    Ok(None)
}

trait MaybeBorrowedName {
    fn as_dns_name_ref(&self) -> &DnsName;
    fn into_rc_dns_name(self) -> Rc<DnsName>;
}

impl MaybeBorrowedName for DnsName {
    fn as_dns_name_ref(&self) -> &DnsName {
        self
    }

    fn into_rc_dns_name(self) -> Rc<DnsName> {
        Rc::new(self)
    }
}

impl MaybeBorrowedName for &DnsName {
    fn as_dns_name_ref(&self) -> &DnsName {
        self
    }

    fn into_rc_dns_name(self) -> Rc<DnsName> {
        Rc::new(self.clone())
    }
}

impl MaybeBorrowedName for Rc<DnsName> {
    fn as_dns_name_ref(&self) -> &DnsName {
        self
    }

    fn into_rc_dns_name(self) -> Rc<DnsName> {
        self
    }
}

impl MaybeBorrowedName for &Rc<DnsName> {
    fn as_dns_name_ref(&self) -> &DnsName {
        self
    }

    fn into_rc_dns_name(self) -> Rc<DnsName> {
        Rc::clone(self)
    }
}

/// Look `name` up in `cache`.
///
/// If `name` is not in the cache, put it into the `New` status and return
/// `NotReady`.
fn dns<T>(
    cache: &mut DnsCacheMap<T>,
    name: impl MaybeBorrowedName,
) -> Result<&T, DnsCacheError> {
    // Work around https://github.com/rust-lang/rust/issues/54663
    let position = cache.iter().position(|e| &*e.0 == name.as_dns_name_ref());
    if let Some(position) = position {
        match cache[position].1 {
            DnsEntry::Ok(ref v) => Ok(v),
            DnsEntry::NotFound => Err(DnsCacheError::NotFound),
            DnsEntry::Error => Err(DnsCacheError::Error),
            DnsEntry::Pending | DnsEntry::New => Err(DnsCacheError::NotReady),
        }
    } else {
        cache.push((name.into_rc_dns_name(), DnsEntry::New));
        Err(DnsCacheError::NotReady)
    }
}

fn dns_ptr(
    cache: &mut HashMap<IpAddr, DnsEntry<Vec<Rc<DnsName>>>>,
    ip: IpAddr,
) -> Result<&'_ [Rc<DnsName>], DnsCacheError> {
    match *cache.entry(ip).or_insert(DnsEntry::New) {
        DnsEntry::Ok(ref v) => Ok(v),
        DnsEntry::NotFound => Err(DnsCacheError::NotFound),
        DnsEntry::Error => Err(DnsCacheError::Error),
        DnsEntry::Pending | DnsEntry::New => Err(DnsCacheError::NotReady),
    }
}

#[cfg(test)]
mod test {
    use std::cell::RefCell;

    use super::*;

    fn example_context() -> Context<'static> {
        Context {
            sender: Some(Cow::Borrowed("strong-bad@email.example.com")),
            sender_local: Some(Cow::Borrowed("strong-bad")),
            sender_domain: Cow::Borrowed("email.example.com"),
            sender_domain_parsed: DnsName::from_ascii("email.example.com")
                .unwrap(),
            helo_domain: Cow::Borrowed("email.example.com"),
            ip: Ipv4Addr::new(192, 0, 2, 3).into(),
            receiver_host: Cow::Borrowed("unused"),
            now: Utc::now(),
        }
    }

    fn dn(s: &str) -> DnsName {
        DnsName::from_ascii(s).unwrap()
    }

    fn rdn(s: &str) -> Rc<DnsName> {
        Rc::new(dn(s))
    }

    fn put_dns<T>(cache: &mut DnsCacheMap<T>, k: &str, v: DnsEntry<T>) {
        let k = rdn(k);
        if let Some(existing) = cache.iter_mut().find(|e| k == e.0) {
            existing.1 = v;
        } else {
            cache.push((k, v));
        }
    }

    #[test]
    fn test_find_validated_name() {
        let ctx = example_context();
        let mut dns_cache = DnsCache::default();

        assert_matches!(
            Err(DirectiveError::NotReady),
            find_validated_name(&mut dns_cache, &ctx),
        );
        dns_cache.ptr.insert(ctx.ip, DnsEntry::NotFound);
        assert_matches!(Ok(None), find_validated_name(&mut dns_cache, &ctx),);
        dns_cache.ptr.insert(ctx.ip, DnsEntry::Error);
        assert_matches!(Ok(None), find_validated_name(&mut dns_cache, &ctx),);

        dns_cache.ptr.insert(
            ctx.ip,
            DnsEntry::Ok(vec![
                rdn("unrelated.site"),
                rdn("sub.email.example.com"),
                rdn("email.example.com"),
            ]),
        );
        assert_matches!(
            Err(DirectiveError::NotReady),
            find_validated_name(&mut dns_cache, &ctx),
        );

        // The subdomain resolving first doesn't make it ready, because we need
        // to validate the main domain first.
        put_dns(
            &mut dns_cache.a,
            "sub.email.example.com",
            DnsEntry::Ok(vec![Ipv4Addr::new(192, 0, 2, 3)]),
        );
        assert_matches!(
            Err(DirectiveError::NotReady),
            find_validated_name(&mut dns_cache, &ctx),
        );

        // Failure => fall through
        put_dns(&mut dns_cache.a, "email.example.com", DnsEntry::NotFound);
        assert_eq!(
            Some(&rdn("sub.email.example.com")),
            find_validated_name(&mut dns_cache, &ctx).unwrap(),
        );
        put_dns(&mut dns_cache.a, "email.example.com", DnsEntry::Error);
        assert_eq!(
            Some(&rdn("sub.email.example.com")),
            find_validated_name(&mut dns_cache, &ctx).unwrap(),
        );
        // IP address mismatch => fall through
        put_dns(
            &mut dns_cache.a,
            "email.example.com",
            DnsEntry::Ok(vec![Ipv4Addr::new(192, 1, 1, 1)]),
        );
        assert_eq!(
            Some(&rdn("sub.email.example.com")),
            find_validated_name(&mut dns_cache, &ctx).unwrap(),
        );
        // We prefer the main site over the subdomain
        put_dns(
            &mut dns_cache.a,
            "email.example.com",
            DnsEntry::Ok(vec![Ipv4Addr::new(192, 0, 2, 3)]),
        );
        assert_eq!(
            Some(&rdn("email.example.com")),
            find_validated_name(&mut dns_cache, &ctx).unwrap(),
        );
        // If nothing matches, we give up rather than consulting the unrelated
        // domain.
        put_dns(
            &mut dns_cache.a,
            "email.example.com",
            DnsEntry::Ok(vec![Ipv4Addr::new(192, 1, 1, 1)]),
        );
        put_dns(
            &mut dns_cache.a,
            "sub.email.example.com",
            DnsEntry::Ok(vec![Ipv4Addr::new(192, 1, 1, 1)]),
        );
        assert_matches!(Ok(None), find_validated_name(&mut dns_cache, &ctx),);
    }

    #[test]
    fn macro_expand_rfc7208_74_examples() {
        let ctx = RefCell::new(example_context());
        let eval = EvaluatorState::default();
        let mut dns_cache = DnsCache::default();

        let mut expand = |ms: &str| {
            eval.expand_macro_string(
                &ctx.borrow(),
                &mut dns_cache,
                "email.example.com",
                false,
                s::MacroString::new(ms),
            )
            .unwrap()
            .into_owned()
        };

        assert_eq!("strong-bad@email.example.com", expand("%{s}"));
        assert_eq!("email.example.com", expand("%{o}"));
        assert_eq!("email.example.com", expand("%{d}"));
        assert_eq!("email.example.com", expand("%{d4}"));
        assert_eq!("email.example.com", expand("%{d3}"));
        assert_eq!("example.com", expand("%{d2}"));
        assert_eq!("com", expand("%{d1}"));
        assert_eq!("com.example.email", expand("%{dr}"));
        assert_eq!("example.email", expand("%{d2r}"));
        assert_eq!("strong-bad", expand("%{l}"));
        assert_eq!("strong.bad", expand("%{l-}"));
        assert_eq!("strong-bad", expand("%{lr}"));
        assert_eq!("bad.strong", expand("%{lr-}"));
        assert_eq!("strong", expand("%{l1r-}"));

        assert_eq!(
            "3.2.0.192.in-addr._spf.example.com",
            expand("%{ir}.%{v}._spf.%{d2}"),
        );
        assert_eq!(
            "bad.strong.lp._spf.example.com",
            expand("%{lr-}.lp._spf.%{d2}"),
        );
        assert_eq!(
            "bad.strong.lp.3.2.0.192.in-addr._spf.example.com",
            expand("%{lr-}.lp.%{ir}.%{v}._spf.%{d2}"),
        );
        assert_eq!(
            "3.2.0.192.in-addr.strong.lp._spf.example.com",
            expand("%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}"),
        );
        assert_eq!(
            "example.com.trusted-domains.example.net",
            expand("%{d2}.trusted-domains.example.net"),
        );

        ctx.borrow_mut().ip = "2001:db8::cb01".parse().unwrap();
        assert_eq!(
            // A truly spectacular DNS name
            "1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6._spf.example.com",
            expand("%{ir}.%{v}._spf.%{d2}"),
        );
    }

    #[test]
    fn macro_expand_p() {
        let ms = s::MacroString::new("%{p}");
        let ctx = example_context();
        let mut eval = EvaluatorState::default();
        let mut dns_cache = DnsCache::default();

        // With having seen a `ptr` directive, we don't even try.
        assert_eq!(
            Ok(Cow::Borrowed("unknown")),
            eval.expand_macro_string(&ctx, &mut dns_cache, "unused", false, ms),
        );

        // With `ptr`, we try to do the lookup.
        eval.has_ptr = true;
        assert_eq!(
            Err(DirectiveError::NotReady),
            eval.expand_macro_string(&ctx, &mut dns_cache, "unused", false, ms),
        );
        // Failure => unknown
        dns_cache.ptr.insert(ctx.ip, DnsEntry::NotFound);
        assert_eq!(
            Ok(Cow::Borrowed("unknown")),
            eval.expand_macro_string(&ctx, &mut dns_cache, "unused", false, ms),
        );
        // Success => expansion
        dns_cache
            .ptr
            .insert(ctx.ip, DnsEntry::Ok(vec![rdn("sub.email.example.com")]));
        put_dns(
            &mut dns_cache.a,
            "sub.email.example.com",
            DnsEntry::Ok(vec![Ipv4Addr::new(192, 0, 2, 3)]),
        );
        assert_eq!(
            Ok(Cow::Borrowed("sub.email.example.com")),
            eval.expand_macro_string(&ctx, &mut dns_cache, "unused", false, ms),
        );
    }

    #[test]
    fn macro_expand_all_simple() {
        let ctx = RefCell::new(Context {
            sender: Some(Cow::Borrowed("john@example.com")),
            sender_local: Some(Cow::Borrowed("john")),
            sender_domain: Cow::Borrowed("example.com"),
            sender_domain_parsed: dn("example.com"),
            helo_domain: Cow::Borrowed("helo.example.com"),
            ip: "dead::beef".parse().unwrap(),
            receiver_host: Cow::Borrowed("receiver.example.net"),
            now: DateTime::from_timestamp(42, 0).unwrap(),
        });
        let mut dns_cache = DnsCache::default();
        let eval = EvaluatorState::default();

        let mut expand = |ms: &str| {
            eval.expand_macro_string(
                &ctx.borrow(),
                &mut dns_cache,
                "domain.example.org",
                true,
                s::MacroString::new(ms),
            )
            .unwrap()
            .into_owned()
        };

        assert_eq!("john@example.com", expand("%{s}"));
        assert_eq!("john", expand("%{l}"));
        assert_eq!("example.com", expand("%{o}"));
        assert_eq!("domain.example.org", expand("%{d}"));
        assert_eq!(
            "d.e.a.d.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.b.e.e.f",
            expand("%{i}"),
        );
        assert_eq!("ip6", expand("%{v}"));
        assert_eq!("helo.example.com", expand("%{h}"));
        assert_eq!("dead::beef", expand("%{c}"));
        assert_eq!("receiver.example.net", expand("%{r}"));
        assert_eq!("42", expand("%{t}"));

        ctx.borrow_mut().sender = None;
        ctx.borrow_mut().sender_local = None;

        assert_eq!("postmaster@example.com", expand("%{s}"));
        assert_eq!("postmaster", expand("%{l}"));
    }
}
