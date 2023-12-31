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

//! An interpreter for the esoteric programming language known as "Sender
//! Policy Framework".
//!
//! Without the DNS query count limit and DNS name size limits, it would almost
//! be Turing-complete: If there were a way to "pop" an element off a list, a
//! Turing machine would be easy to implement with chains of `redirect` using
//! `%{d}`.

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

/// The fundamental SPF result types.
///
/// RFC 7208 § 2.6
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpfResult {
    None,
    Neutral,
    Pass,
    Fail,
    SoftFail,
    TempError,
    PermError,
}

/// The "explanation" string which can be produced on failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Explanation {
    /// There is definitely no explanation. Either SPF didn't fail, or the
    /// failing record does not issue an explanation.
    None,
    /// There might be an explanation in the future, but it is pending on
    /// fetching more DNS records.
    NotReady,
    /// The given explanation was generated.
    Some(String),
}

/// The (possibly, see `skipped_directive`) conclusive result of evaluating an
/// SPF record.
struct ResultInfo {
    /// The SPF result itself.
    result: SpfResult,

    /// The `spf_domain` where the conclusion was reached.
    spf_domain: Rc<DnsName>,
    /// The TXT record where the conclusion was reached. This can later be used
    /// to generate an explanation.
    spf_txt: Option<Rc<str>>,
}

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
    pub sender_domain_parsed: Rc<DnsName>,
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
    pub txt: DnsCacheMap<Vec<Rc<str>>>,
    pub mx: DnsCacheMap<Vec<Rc<DnsName>>>,
    pub ptr: HashMap<IpAddr, DnsEntry<Vec<Rc<DnsName>>>>,
}

// These are association lists instead of hash maps because <DnsName as Hash>
// allocates like there's no tomorrow, and ultimately these won't be very big.
pub(super) type DnsCacheMap<T> = Vec<(Rc<DnsName>, DnsEntry<T>)>;

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

/// Performs full evaluation of SPF starting with `ctx.sender_domain`.
///
/// Returns `Some` once a conclusive result is available; i.e., at the point
/// where no further DNS information is needed to determine the SPF result. If
/// `Explanation` is `NotReady`, more DNS information is needed to generate the
/// explanation.
///
/// If this returns `None`, `New` entries may be added to `DnsCache`. The
/// driver must arrange to perform these queries (changing them to `NotReady`)
/// and re-run `eval` when more data is available.
pub fn eval(
    ctx: &Context<'_>,
    dns_cache: &mut DnsCache,
) -> Option<(SpfResult, Explanation)> {
    let mut evaluator = EvaluatorState::default();
    let result = evaluator
        .eval_spf_chain(ctx, dns_cache, Rc::clone(&ctx.sender_domain_parsed))
        .unwrap_or_else(|| ResultInfo {
            result: SpfResult::Neutral,
            spf_domain: Rc::clone(&ctx.sender_domain_parsed),
            spf_txt: None,
        });

    if evaluator.skipped_directive {
        // If we skipped any directives before coming to a conclusion, we're
        // not ready to give an actual result.
        None
    } else {
        let explanation = match result {
            ResultInfo {
                result: SpfResult::Fail,
                spf_domain,
                spf_txt: Some(spf_txt),
            } => evaluator.explain(ctx, dns_cache, &spf_domain, &spf_txt),
            _ => Explanation::None,
        };

        Some((result.result, explanation))
    }
}

impl EvaluatorState {
    /// Evaluates a complete SPF chain (i.e. following redirects) starting from
    /// `spf_domain`.
    ///
    /// Returns `None` if no conclusive result is available, or `Some` if there
    /// may be a conclusive result. `Some` results are bogus if
    /// `skipped_directive` is true.
    fn eval_spf_chain(
        &mut self,
        ctx: &Context<'_>,
        dns_cache: &mut DnsCache,
        mut spf_domain: Rc<DnsName>,
    ) -> Option<ResultInfo> {
        for i in 0.. {
            match self.eval_one_spf(ctx, dns_cache, Rc::clone(&spf_domain)) {
                Ok(mut result) => {
                    if i != 0 {
                        // "None" result on redirect => permanent error
                        if result.result == SpfResult::None {
                            result.result = SpfResult::PermError;
                        }
                    }

                    return Some(result);
                },

                // Inconclusive because the TXT record isn't available yet.
                // Therefore, also inconclusive here.
                Err(None) => return None,

                Err(Some(txt)) => {
                    // Inconclusive, but look for a redirect to continue
                    // evaluation. If no redirect, this step is also
                    // inconclusive.
                    let redirect = txt
                        .split(' ')
                        .map(s::Term::parse)
                        .find_map(|r| match r {
                            Ok(s::Term::Modifier(s::Modifier::Redirect(s))) => {
                                Some(s)
                            },
                            _ => None,
                        })?;

                    // Redirect counts as a DNS directive. This is also the
                    // only thing preventing us from evaluating a self-redirect
                    // infinitely.
                    if self.incr_dns_directive().is_err() {
                        return Some(ResultInfo {
                            result: SpfResult::PermError,
                            spf_domain,
                            spf_txt: Some(txt),
                        });
                    }

                    // Expanding and parsing the domain can only fail if %{p}
                    // is pending, or the expanded domain is invalid. For the
                    // latter, we've necessarily already saved
                    // skipped_directive from the ptr directive which enabled
                    // %{p}, so we can treat any error here as a hard error
                    let Ok(new_domain) = self.expand_and_parse_domain(
                        ctx,
                        dns_cache,
                        &spf_domain,
                        Some(redirect),
                    ) else {
                        return Some(ResultInfo {
                            result: SpfResult::PermError,
                            spf_domain,
                            spf_txt: Some(txt),
                        });
                    };

                    spf_domain = new_domain;
                },
            }
        }

        // Unreachable
        None
    }

    /// Run the SPF evaluation process on the SPF record at `spf_domain`.
    ///
    /// If a conclusive result is available, returns that result. The result
    /// will be bogus if `self.skipped_directive` is true; in this case, the
    /// evaluator carried on solely to discover additional DNS queries.
    ///
    /// Returns `Err` if inconclusive, along with the TXT record (if
    /// available).
    fn eval_one_spf(
        &mut self,
        ctx: &Context<'_>,
        dns_cache: &mut DnsCache,
        spf_domain: Rc<DnsName>,
    ) -> Result<ResultInfo, Option<Rc<str>>> {
        let txt_records = match dns(&mut dns_cache.txt, &spf_domain) {
            Ok(records) => records,
            Err(DnsCacheError::NotFound) => {
                return Ok(ResultInfo {
                    result: SpfResult::None,
                    spf_domain,
                    spf_txt: None,
                })
            },
            Err(DnsCacheError::Error) => {
                return Ok(ResultInfo {
                    result: SpfResult::TempError,
                    spf_domain,
                    spf_txt: None,
                })
            },
            Err(DnsCacheError::NotReady) => {
                self.skipped_directive = true;
                return Err(None);
            },
        };

        const PREFIX: &str = "v=spf1";
        let Some(spf_txt) = txt_records
            .iter()
            .find(|r| {
                r.get(..PREFIX.len())
                    .is_some_and(|s| s.eq_ignore_ascii_case(PREFIX))
            })
            .map(Rc::clone)
        else {
            return Ok(ResultInfo {
                result: SpfResult::None,
                spf_domain,
                spf_txt: None,
            });
        };

        for word in spf_txt.split(' ') {
            if word.is_empty() {
                continue;
            }

            match s::Term::parse(word) {
                Err(_) => {
                    return Ok(ResultInfo {
                        result: SpfResult::PermError,
                        spf_domain,
                        spf_txt: Some(spf_txt),
                    })
                },

                Ok(s::Term::Modifier(..)) => {},

                Ok(s::Term::Directive(directive)) => {
                    match self.eval_directive(
                        ctx,
                        dns_cache,
                        &spf_domain,
                        directive,
                    ) {
                        Ok(None) => {},
                        Ok(Some(q)) => {
                            let result = match q {
                                s::Qualifier::Pass => SpfResult::Pass,
                                s::Qualifier::Fail => SpfResult::Fail,
                                s::Qualifier::SoftFail => SpfResult::SoftFail,
                                s::Qualifier::Neutral => SpfResult::Neutral,
                            };

                            return Ok(ResultInfo {
                                result,
                                spf_domain,
                                spf_txt: Some(spf_txt),
                            });
                        },
                        Err(DirectiveError::TempFail) => {
                            return Ok(ResultInfo {
                                result: SpfResult::TempError,
                                spf_domain,
                                spf_txt: Some(spf_txt),
                            })
                        },
                        Err(
                            DirectiveError::PermFail
                            | DirectiveError::SyntaxError(..),
                        ) => {
                            return Ok(ResultInfo {
                                result: SpfResult::PermError,
                                spf_domain,
                                spf_txt: Some(spf_txt),
                            });
                        },
                        Err(DirectiveError::NotReady) => {
                            self.skipped_directive = true;
                        },
                    }
                },
            }
        }

        Err(Some(spf_txt))
    }

    fn eval_directive(
        &mut self,
        ctx: &Context<'_>,
        dns_cache: &mut DnsCache,
        spf_domain: &Rc<DnsName>,
        directive: s::Directive,
    ) -> Result<Option<s::Qualifier>, DirectiveError> {
        if self.eval_mechanism(
            ctx,
            dns_cache,
            spf_domain,
            directive.mechanism,
        )? {
            Ok(Some(directive.qualifier))
        } else {
            Ok(None)
        }
    }

    fn eval_mechanism(
        &mut self,
        ctx: &Context<'_>,
        dns_cache: &mut DnsCache,
        spf_domain: &Rc<DnsName>,
        mechanism: s::Mechanism,
    ) -> Result<bool, DirectiveError> {
        use super::syntax::Mechanism as M;

        match mechanism {
            M::All => Ok(true),
            M::Include(target) => {
                self.eval_include(ctx, dns_cache, spf_domain, target)
            },
            M::A(domain, ipv4_cidr_len, ipv6_cidr_len) => self.eval_a(
                ctx,
                dns_cache,
                spf_domain,
                domain,
                ipv4_cidr_len,
                ipv6_cidr_len,
            ),
            M::Mx(domain, ipv4_cidr_len, ipv6_cidr_len) => self.eval_mx(
                ctx,
                dns_cache,
                spf_domain,
                domain,
                ipv4_cidr_len,
                ipv6_cidr_len,
            ),
            M::Ptr(domain) => self.eval_ptr(ctx, dns_cache, spf_domain, domain),
            M::Ip4(addr, cidr_len) => self.eval_ip4(ctx, addr, cidr_len),
            M::Ip6(addr, cidr_len) => self.eval_ip6(ctx, addr, cidr_len),
            M::Exists(target) => {
                self.eval_exists(ctx, dns_cache, spf_domain, target)
            },
        }
    }

    fn eval_a(
        &mut self,
        ctx: &Context<'_>,
        dns_cache: &mut DnsCache,
        spf_domain: &Rc<DnsName>,
        domain: Option<s::MacroString<'_>>,
        ipv4_cidr_len: Option<u32>,
        ipv6_cidr_len: Option<u32>,
    ) -> Result<bool, DirectiveError> {
        self.incr_dns_directive()?;
        let domain =
            self.expand_and_parse_domain(ctx, dns_cache, spf_domain, domain)?;

        self.eval_a_or_mx_domain(
            ctx,
            &mut dns_cache.a,
            &mut dns_cache.aaaa,
            domain,
            ipv4_cidr_len,
            ipv6_cidr_len,
        )
    }

    fn eval_mx(
        &mut self,
        ctx: &Context<'_>,
        dns_cache: &mut DnsCache,
        spf_domain: &Rc<DnsName>,
        domain: Option<s::MacroString<'_>>,
        ipv4_cidr_len: Option<u32>,
        ipv6_cidr_len: Option<u32>,
    ) -> Result<bool, DirectiveError> {
        self.incr_dns_directive()?;
        let domain =
            self.expand_and_parse_domain(ctx, dns_cache, spf_domain, domain)?;

        let mx_records = top_level_error_map(dns(&mut dns_cache.mx, domain))?
            .map(|v| v.as_slice())
            .unwrap_or_default();

        if mx_records.len() >= MAX_MX_SIZE {
            return Err(DirectiveError::PermFail);
        }

        let mut not_ready = false;
        let mut temp_fail = false;
        for record in mx_records {
            match self.eval_a_or_mx_domain(
                ctx,
                &mut dns_cache.a,
                &mut dns_cache.aaaa,
                Rc::clone(record),
                ipv4_cidr_len,
                ipv6_cidr_len,
            ) {
                Ok(true) => return Ok(true),
                Ok(false) => {},
                // Remember temporary DNS errors but keep looking in case a
                // later record succeeds.
                Err(DirectiveError::TempFail) => temp_fail = true,
                // Keep going if the current one is pending. We do all the
                // lookups in parallel this way.
                Err(DirectiveError::NotReady) => not_ready = true,
                // The other error cases shouldn't happen, but default to
                // passing them through.
                Err(e) => return Err(e),
            }
        }

        if not_ready {
            Err(DirectiveError::NotReady)
        } else if temp_fail {
            Err(DirectiveError::TempFail)
        } else {
            Ok(false)
        }
    }

    fn eval_a_or_mx_domain(
        &self,
        ctx: &Context<'_>,
        dns_cache_a: &mut DnsCacheMap<Vec<Ipv4Addr>>,
        dns_cache_aaaa: &mut DnsCacheMap<Vec<Ipv6Addr>>,
        domain: Rc<DnsName>,
        ipv4_cidr_len: Option<u32>,
        ipv6_cidr_len: Option<u32>,
    ) -> Result<bool, DirectiveError> {
        Ok(match ctx.ip {
            IpAddr::V4(ip) => top_level_error_map(dns(dns_cache_a, domain))?
                .map(|v| v.as_slice())
                .unwrap_or_default()
                .iter()
                .any(|&a| ipv4_addr_matches(ip, a, ipv4_cidr_len)),

            IpAddr::V6(ip) => top_level_error_map(dns(dns_cache_aaaa, domain))?
                .map(|v| v.as_slice())
                .unwrap_or_default()
                .iter()
                .any(|&a| ipv6_addr_matches(ip, a, ipv6_cidr_len)),
        })
    }

    fn eval_ptr(
        &mut self,
        ctx: &Context<'_>,
        dns_cache: &mut DnsCache,
        spf_domain: &Rc<DnsName>,
        domain: Option<s::MacroString<'_>>,
    ) -> Result<bool, DirectiveError> {
        self.incr_dns_directive()?;
        self.has_ptr = true;
        let domain =
            self.expand_and_parse_domain(ctx, dns_cache, spf_domain, domain)?;
        find_validated_name(dns_cache, ctx, &domain).map(|o| o.is_some())
    }

    fn eval_ip4(
        &self,
        ctx: &Context<'_>,
        a: Ipv4Addr,
        cidr_len: Option<u32>,
    ) -> Result<bool, DirectiveError> {
        match ctx.ip {
            IpAddr::V4(v4) => Ok(ipv4_addr_matches(v4, a, cidr_len)),
            IpAddr::V6(_) => Ok(false),
        }
    }

    fn eval_ip6(
        &self,
        ctx: &Context<'_>,
        a: Ipv6Addr,
        cidr_len: Option<u32>,
    ) -> Result<bool, DirectiveError> {
        match ctx.ip {
            IpAddr::V4(_) => Ok(false),
            IpAddr::V6(v6) => Ok(ipv6_addr_matches(v6, a, cidr_len)),
        }
    }

    fn eval_exists(
        &mut self,
        ctx: &Context<'_>,
        dns_cache: &mut DnsCache,
        spf_domain: &Rc<DnsName>,
        domain: s::MacroString<'_>,
    ) -> Result<bool, DirectiveError> {
        self.incr_dns_directive()?;
        let domain = self.expand_and_parse_domain(
            ctx,
            dns_cache,
            spf_domain,
            Some(domain),
        )?;
        Ok(top_level_error_map(dns(&mut dns_cache.a, domain))?
            .map(|v| !v.is_empty())
            .unwrap_or_default())
    }

    fn eval_include(
        &mut self,
        ctx: &Context<'_>,
        dns_cache: &mut DnsCache,
        spf_domain: &Rc<DnsName>,
        domain: s::MacroString<'_>,
    ) -> Result<bool, DirectiveError> {
        // This is the only thing enforcing any kind of recursion limit.
        self.incr_dns_directive()?;
        let domain = self.expand_and_parse_domain(
            ctx,
            dns_cache,
            spf_domain,
            Some(domain),
        )?;

        match self
            .eval_spf_chain(ctx, dns_cache, domain)
            .map(|r| r.result)
        {
            // RFC 7208 § 5.2
            None => Ok(false), // Basically "neutral" (or not known yet)
            Some(SpfResult::Pass) => Ok(true),
            Some(
                SpfResult::Fail | SpfResult::SoftFail | SpfResult::Neutral,
            ) => Ok(false),
            Some(SpfResult::TempError) => Err(DirectiveError::TempFail),
            Some(SpfResult::PermError | SpfResult::None) => {
                Err(DirectiveError::PermFail)
            },
        }
    }

    fn incr_dns_directive(&mut self) -> Result<(), DirectiveError> {
        if self.dns_directives >= MAX_DNS_DIRECTIVES {
            return Err(DirectiveError::PermFail);
        }

        self.dns_directives += 1;
        Ok(())
    }

    fn expand_and_parse_domain(
        &self,
        ctx: &Context<'_>,
        dns_cache: &mut DnsCache,
        spf_domain: &Rc<DnsName>,
        domain: Option<s::MacroString<'_>>,
    ) -> Result<Rc<DnsName>, DirectiveError> {
        match domain {
            None => Ok(Rc::clone(spf_domain)),
            Some(domain) => {
                let domain = self.expand_macro_string(
                    ctx, dns_cache, spf_domain, false, domain,
                )?;
                dns_cache.intern_domain(domain)
            },
        }
    }

    /// Generate the failure explanation from the given SPF record.
    fn explain(
        &self,
        ctx: &Context<'_>,
        dns_cache: &mut DnsCache,
        spf_domain: &DnsName,
        spf_txt: &str,
    ) -> Explanation {
        let Some(explain_domain) =
            spf_txt.split(' ').find_map(|r| match s::Term::parse(r) {
                Ok(s::Term::Modifier(s::Modifier::Explanation(s))) => Some(s),
                _ => None,
            })
        else {
            return Explanation::None;
        };

        let Ok(explain_domain) = self.expand_macro_string(
            ctx,
            dns_cache,
            spf_domain,
            true,
            explain_domain,
        ) else {
            return Explanation::None;
        };

        let Ok(explain_domain) = dns_cache.intern_domain(explain_domain) else {
            return Explanation::None;
        };

        let txt_records = match dns(&mut dns_cache.txt, &explain_domain) {
            Ok(r) => r,
            Err(DnsCacheError::NotFound | DnsCacheError::Error) => {
                return Explanation::None
            },
            Err(DnsCacheError::NotReady) => return Explanation::NotReady,
        };

        let Some(txt_record) = txt_records.first() else {
            return Explanation::None;
        };

        let txt_record = Rc::clone(txt_record);

        // We don't need to consider the possibility of NotReady here, as that
        // can only come from %{p}, but %{p} is always ready if we have a
        // conclusive result.
        let Ok(explanation) = self.expand_macro_string(
            ctx,
            dns_cache,
            spf_domain,
            true,
            s::MacroString::new(&txt_record),
        ) else {
            return Explanation::None;
        };

        Explanation::Some(explanation.into_owned())
    }

    fn expand_macro_string<'s>(
        &self,
        ctx: &'s Context<'s>,
        dns_cache: &mut DnsCache,
        spf_domain: &DnsName,
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
                        ctx, dns_cache, spf_domain, me.kind,
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
        spf_domain: &DnsName,
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
            M::Domain => Cow::Owned(spf_domain.to_ascii()),

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
                    find_validated_name(dns_cache, ctx, spf_domain)?
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
    target_domain: &DnsName,
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
        .find(|n| *target_domain == ***n)
        .into_iter()
        .chain(
            ptr.iter()
                .filter(|n| *target_domain != ***n && target_domain.zone_of(n)),
        )
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

fn intern_domain(
    cache: &mut HashMap<String, Rc<DnsName>>,
    s: Cow<'_, str>,
) -> Result<Rc<DnsName>, DirectiveError> {
    // Work around https://github.com/rust-lang/rust/issues/54663
    if cache.contains_key(&*s) {
        return Ok(Rc::clone(cache.get(&*s).unwrap()));
    }

    let name = DnsName::from_ascii(&s)
        .map(Rc::new)
        .map_err(|_| DirectiveError::PermFail)?;
    cache.insert(s.into_owned(), Rc::clone(&name));
    Ok(name)
}

impl DnsCache {
    fn intern_domain(
        &mut self,
        s: Cow<'_, str>,
    ) -> Result<Rc<DnsName>, DirectiveError> {
        intern_domain(&mut self.name_intern, s)
    }
}

/// Performs the error mapping used for top-level DNS queries.
///
/// Defined by RFC 7208 § 5
fn top_level_error_map<T>(
    r: Result<T, DnsCacheError>,
) -> Result<Option<T>, DirectiveError> {
    match r {
        Ok(t) => Ok(Some(t)),
        Err(DnsCacheError::NotReady) => Err(DirectiveError::NotReady),
        Err(DnsCacheError::Error) => Err(DirectiveError::TempFail),
        Err(DnsCacheError::NotFound) => Ok(None),
    }
}

fn ipv4_addr_matches(a: Ipv4Addr, b: Ipv4Addr, cidr_len: Option<u32>) -> bool {
    if let Some(mask) = cidr_len.and_then(|l| u32::MAX.checked_shl(l)) {
        let a = u32::from_be_bytes(a.octets());
        let b = u32::from_be_bytes(b.octets());
        (a & mask) == (b & mask)
    } else {
        a == b
    }
}

fn ipv6_addr_matches(a: Ipv6Addr, b: Ipv6Addr, cidr_len: Option<u32>) -> bool {
    if let Some(mask) = cidr_len.and_then(|l| u128::MAX.checked_shl(l)) {
        let a = u128::from_be_bytes(a.octets());
        let b = u128::from_be_bytes(b.octets());
        (a & mask) == (b & mask)
    } else {
        a == b
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
            sender_domain_parsed: rdn("email.example.com"),
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
            find_validated_name(
                &mut dns_cache,
                &ctx,
                &ctx.sender_domain_parsed
            ),
        );
        dns_cache.ptr.insert(ctx.ip, DnsEntry::NotFound);
        assert_matches!(
            Ok(None),
            find_validated_name(
                &mut dns_cache,
                &ctx,
                &ctx.sender_domain_parsed
            ),
        );
        dns_cache.ptr.insert(ctx.ip, DnsEntry::Error);
        assert_matches!(
            Ok(None),
            find_validated_name(
                &mut dns_cache,
                &ctx,
                &ctx.sender_domain_parsed
            ),
        );

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
            find_validated_name(
                &mut dns_cache,
                &ctx,
                &ctx.sender_domain_parsed
            ),
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
            find_validated_name(
                &mut dns_cache,
                &ctx,
                &ctx.sender_domain_parsed
            ),
        );

        // Failure => fall through
        put_dns(&mut dns_cache.a, "email.example.com", DnsEntry::NotFound);
        assert_eq!(
            Some(&rdn("sub.email.example.com")),
            find_validated_name(
                &mut dns_cache,
                &ctx,
                &ctx.sender_domain_parsed
            )
            .unwrap(),
        );
        put_dns(&mut dns_cache.a, "email.example.com", DnsEntry::Error);
        assert_eq!(
            Some(&rdn("sub.email.example.com")),
            find_validated_name(
                &mut dns_cache,
                &ctx,
                &ctx.sender_domain_parsed
            )
            .unwrap(),
        );
        // IP address mismatch => fall through
        put_dns(
            &mut dns_cache.a,
            "email.example.com",
            DnsEntry::Ok(vec![Ipv4Addr::new(192, 1, 1, 1)]),
        );
        assert_eq!(
            Some(&rdn("sub.email.example.com")),
            find_validated_name(
                &mut dns_cache,
                &ctx,
                &ctx.sender_domain_parsed
            )
            .unwrap(),
        );
        // We prefer the main site over the subdomain
        put_dns(
            &mut dns_cache.a,
            "email.example.com",
            DnsEntry::Ok(vec![Ipv4Addr::new(192, 0, 2, 3)]),
        );
        assert_eq!(
            Some(&rdn("email.example.com")),
            find_validated_name(
                &mut dns_cache,
                &ctx,
                &ctx.sender_domain_parsed
            )
            .unwrap(),
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
        assert_matches!(
            Ok(None),
            find_validated_name(
                &mut dns_cache,
                &ctx,
                &ctx.sender_domain_parsed
            ),
        );
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
                &rdn("email.example.com"),
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
            eval.expand_macro_string(
                &ctx,
                &mut dns_cache,
                &dn("email.example.com"),
                false,
                ms
            ),
        );

        // With `ptr`, we try to do the lookup.
        eval.has_ptr = true;
        assert_eq!(
            Err(DirectiveError::NotReady),
            eval.expand_macro_string(
                &ctx,
                &mut dns_cache,
                &dn("email.example.com"),
                false,
                ms
            ),
        );
        // Failure => unknown
        dns_cache.ptr.insert(ctx.ip, DnsEntry::NotFound);
        assert_eq!(
            Ok(Cow::Borrowed("unknown")),
            eval.expand_macro_string(
                &ctx,
                &mut dns_cache,
                &dn("email.example.com"),
                false,
                ms
            ),
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
            eval.expand_macro_string(
                &ctx,
                &mut dns_cache,
                &dn("email.example.com"),
                false,
                ms
            ),
        );
        // %{p} uses the SPF domain and not the sender domain, so if we use
        // something else, it fails.
        assert_eq!(
            Ok(Cow::Borrowed("unknown")),
            eval.expand_macro_string(
                &ctx,
                &mut dns_cache,
                &dn("example.net"),
                false,
                ms
            ),
        );
    }

    #[test]
    fn macro_expand_all_simple() {
        let ctx = RefCell::new(Context {
            sender: Some(Cow::Borrowed("john@example.com")),
            sender_local: Some(Cow::Borrowed("john")),
            sender_domain: Cow::Borrowed("example.com"),
            sender_domain_parsed: rdn("example.com"),
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
                &dn("domain.example.org"),
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

    fn parse_a_addrs(addrs: &[&str]) -> Vec<Ipv4Addr> {
        addrs
            .iter()
            .map(|a| a.parse::<Ipv4Addr>().unwrap())
            .collect()
    }

    fn parse_aaaa_addrs(addrs: &[&str]) -> Vec<Ipv6Addr> {
        addrs
            .iter()
            .map(|a| a.parse::<Ipv6Addr>().unwrap())
            .collect()
    }

    fn parse_names(names: &[&str]) -> Vec<Rc<DnsName>> {
        names.iter().map(|s| rdn(s)).collect()
    }

    fn make_txts(txts: &[&str]) -> Vec<Rc<str>> {
        txts.iter().map(|s| Rc::from(s.to_owned())).collect()
    }

    macro_rules! dns_cache {
        ($($domain:expr => {
            $($field:ident : $value:tt,)*
        },)*) => {{
            let mut dns_cache = DnsCache::default();
            $(
                let domain = rdn($domain);
                $(
                    dns_cache!(@$field, dns_cache, domain, $value);
                )*
            )*
            dns_cache
        }};

        (@a, $dns_cache:ident, $domain:ident, NotFound) => {
            $dns_cache.a.push((Rc::clone(&$domain), DnsEntry::NotFound));
        };
        (@a, $dns_cache:ident, $domain:ident, Error) => {
            $dns_cache.a.push((Rc::clone(&$domain), DnsEntry::Error));
        };
        (@a, $dns_cache:ident, $domain:ident, $addrs:expr) => {
            $dns_cache.a.push((Rc::clone(&$domain), DnsEntry::Ok(
                parse_a_addrs(&$addrs),
            )));
        };

        (@aaaa, $dns_cache:ident, $domain:ident, NotFound) => {
            $dns_cache.aaaa.push((Rc::clone(&$domain), DnsEntry::NotFound));
        };
        (@aaaa, $dns_cache:ident, $domain:ident, Error) => {
            $dns_cache.aaaa.push((Rc::clone(&$domain), DnsEntry::Error));
        };
        (@aaaa, $dns_cache:ident, $domain:ident, $addrs:expr) => {
            $dns_cache.aaaa.push((Rc::clone(&$domain), DnsEntry::Ok(
                parse_aaaa_addrs(&$addrs),
            )));
        };

        (@mx, $dns_cache:ident, $domain:ident, NotFound) => {
            $dns_cache.mx.push((Rc::clone(&$domain), DnsEntry::NotFound));
        };
        (@mx, $dns_cache:ident, $domain:ident, Error) => {
            $dns_cache.mx.push((Rc::clone(&$domain), DnsEntry::Error));
        };
        (@mx, $dns_cache:ident, $domain:ident, $addrs:expr) => {
            $dns_cache.mx.push((Rc::clone(&$domain), DnsEntry::Ok(
                parse_names(&$addrs),
            )));
        };

        (@txt, $dns_cache:ident, $domain:ident, NotFound) => {
            $dns_cache.txt.push((Rc::clone(&$domain), DnsEntry::NotFound));
        };
        (@txt, $dns_cache:ident, $domain:ident, Error) => {
            $dns_cache.txt.push((Rc::clone(&$domain), DnsEntry::Error));
        };
        (@txt, $dns_cache:ident, $domain:ident, $txts:expr) => {
            $dns_cache.txt.push((Rc::clone(&$domain), DnsEntry::Ok(
                make_txts(&$txts),
            )));
        };
    }

    fn simple_context(sender_domain: &str, ip: &str) -> Context<'static> {
        Context {
            sender: None,
            sender_local: None,
            sender_domain: Cow::Owned(sender_domain.to_owned()),
            sender_domain_parsed: Rc::new(
                DnsName::from_ascii(sender_domain).unwrap(),
            ),
            helo_domain: Cow::Owned(sender_domain.to_owned()),
            ip: ip.parse().unwrap(),
            receiver_host: Cow::Borrowed("unused"),
            now: DateTime::from_timestamp(0, 0).unwrap(),
        }
    }

    #[test]
    fn eval_no_spf() {
        assert_eq!(
            None,
            eval(
                &simple_context("s.com", "1.2.3.4"),
                &mut DnsCache::default(),
            ),
        );
        assert_eq!(
            Some((SpfResult::None, Explanation::None)),
            eval(
                &simple_context("s.com", "1.2.3.4"),
                &mut dns_cache! {
                    "s.com" => {
                        txt: NotFound,
                    },
                },
            ),
        );
        assert_eq!(
            Some((SpfResult::None, Explanation::None)),
            eval(
                &simple_context("s.com", "1.2.3.4"),
                &mut dns_cache! {
                    "s.com" => {
                        txt: [],
                    },
                },
            ),
        );
        assert_eq!(
            Some((SpfResult::None, Explanation::None)),
            eval(
                &simple_context("s.com", "1.2.3.4"),
                &mut dns_cache! {
                    "s.com" => {
                        txt: ["not-an-spf-record"],
                    },
                },
            ),
        );
        assert_eq!(
            Some((SpfResult::TempError, Explanation::None)),
            eval(
                &simple_context("s.com", "1.2.3.4"),
                &mut dns_cache! {
                    "s.com" => {
                        txt: Error,
                    },
                },
            ),
        );

        assert_eq!(
            Some((SpfResult::Pass, Explanation::None)),
            eval(
                &simple_context("s.com", "1.2.3.4"),
                &mut dns_cache! {
                    "s.com" => {
                        txt: ["v=spf1 all"],
                    },
                },
            ),
        );
        assert_eq!(
            Some((SpfResult::Neutral, Explanation::None)),
            eval(
                &simple_context("s.com", "1.2.3.4"),
                &mut dns_cache! {
                    "s.com" => {
                        txt: ["v=spf1 ?all"],
                    },
                },
            ),
        );
        assert_eq!(
            Some((SpfResult::SoftFail, Explanation::None)),
            eval(
                &simple_context("s.com", "1.2.3.4"),
                &mut dns_cache! {
                    "s.com" => {
                        txt: ["v=spf1 ~all"],
                    },
                },
            ),
        );
        assert_eq!(
            Some((SpfResult::Fail, Explanation::None)),
            eval(
                &simple_context("s.com", "1.2.3.4"),
                &mut dns_cache! {
                    "s.com" => {
                        txt: ["v=spf1 -all"],
                    },
                },
            ),
        );
    }

    #[test]
    fn eval_empty() {
        assert_eq!(
            Some((SpfResult::Neutral, Explanation::None)),
            eval(
                &simple_context("s.com", "1.2.3.4"),
                &mut dns_cache! {
                    "s.com" => {
                        txt: ["v=spf1"],
                    },
                },
            ),
        );
    }

    #[test]
    fn eval_ip_matchers() {
        let mut dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 ip4:1.2.3.4 ip4:2.0.0.0/16 \
                       ip6:dead::beef ip6:cafe:1::/32 -all"],
            },
        };
        assert_eq!(
            Some((SpfResult::Pass, Explanation::None)),
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache),
        );
        assert_eq!(
            Some((SpfResult::Fail, Explanation::None)),
            eval(&simple_context("s.com", "1.2.3.5"), &mut dns_cache),
        );
        assert_eq!(
            Some((SpfResult::Fail, Explanation::None)),
            eval(&simple_context("s.com", "3.2.3.4"), &mut dns_cache),
        );
        assert_eq!(
            Some((SpfResult::Pass, Explanation::None)),
            eval(&simple_context("s.com", "2.0.255.2"), &mut dns_cache),
        );
        assert_eq!(
            Some((SpfResult::Fail, Explanation::None)),
            eval(&simple_context("s.com", "2.1.0.2"), &mut dns_cache),
        );
        assert_eq!(
            Some((SpfResult::Pass, Explanation::None)),
            eval(&simple_context("s.com", "dead::beef"), &mut dns_cache),
        );
        assert_eq!(
            Some((SpfResult::Fail, Explanation::None)),
            eval(&simple_context("s.com", "dead::f00d"), &mut dns_cache),
        );
        assert_eq!(
            Some((SpfResult::Pass, Explanation::None)),
            eval(&simple_context("s.com", "cafe:1::beef"), &mut dns_cache),
        );
        assert_eq!(
            Some((SpfResult::Fail, Explanation::None)),
            eval(&simple_context("s.com", "cafe:2::beef"), &mut dns_cache),
        );
        assert_eq!(
            Some((SpfResult::Fail, Explanation::None)),
            eval(&simple_context("s.com", "beef:2::beef"), &mut dns_cache),
        );
    }

    #[test]
    fn eval_a_matchers() {
        let mut dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 a a:t.com/24/16 ~a/24/16 -all"],
            },
        };
        assert_eq!(
            None,
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );

        dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 a a:t.com/24/16 ~a/24/16 -all"],
                a: NotFound,
                aaaa: Error,
            },
            "t.com" => {
                a: NotFound,
                aaaa: NotFound,
            },
        };
        assert_eq!(
            Some((SpfResult::Fail, Explanation::None)),
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );
        assert_eq!(
            Some((SpfResult::TempError, Explanation::None)),
            eval(&simple_context("s.com", "dead::beef"), &mut dns_cache,),
        );

        dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 a a:t.com/24/16 ~a/24/16 -all"],
                a: ["1.2.3.4", "2.3.4.5"],
                aaaa: ["dead::beef"],
            },
            "t.com" => {
                a: ["4.5.6.7"],
                aaaa: ["cafe::f00d", "f00d::cafe"],
            },
        };
        assert_eq!(
            Some((SpfResult::Pass, Explanation::None)),
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );
        assert_eq!(
            Some((SpfResult::Pass, Explanation::None)),
            eval(&simple_context("s.com", "2.3.4.5"), &mut dns_cache,),
        );
        assert_eq!(
            Some((SpfResult::Pass, Explanation::None)),
            eval(&simple_context("s.com", "4.5.6.255"), &mut dns_cache,),
        );
        assert_eq!(
            Some((SpfResult::SoftFail, Explanation::None)),
            eval(&simple_context("s.com", "1.2.3.255"), &mut dns_cache,),
        );
        assert_eq!(
            Some((SpfResult::Fail, Explanation::None)),
            eval(&simple_context("s.com", "99.88.77.66"), &mut dns_cache,),
        );
        assert_eq!(
            Some((SpfResult::Pass, Explanation::None)),
            eval(&simple_context("s.com", "dead::beef"), &mut dns_cache,),
        );
        assert_eq!(
            Some((SpfResult::Pass, Explanation::None)),
            eval(&simple_context("s.com", "cafe::beef"), &mut dns_cache,),
        );
        assert_eq!(
            Some((SpfResult::Pass, Explanation::None)),
            eval(&simple_context("s.com", "f00d::beef"), &mut dns_cache,),
        );
        assert_eq!(
            Some((SpfResult::SoftFail, Explanation::None)),
            eval(&simple_context("s.com", "dead::cafe"), &mut dns_cache,),
        );
        assert_eq!(
            Some((SpfResult::Fail, Explanation::None)),
            eval(&simple_context("s.com", "baad::cafe"), &mut dns_cache,),
        );
    }

    #[test]
    fn eval_mx_matchers() {
        let mut dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 mx -all"],
            },
        };
        assert_eq!(
            None,
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );

        dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 mx -all"],
                mx: NotFound,
            },
        };
        assert_eq!(
            Some((SpfResult::Fail, Explanation::None)),
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );

        dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 mx -all"],
                mx: Error,
            },
        };
        assert_eq!(
            Some((SpfResult::TempError, Explanation::None)),
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );

        dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 mx -all"],
                mx: ["foo.s.com", "bar.s.com"],
            },
        };
        assert_eq!(
            None,
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );

        dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 mx -all"],
                mx: ["foo.s.com"],
            },
            "foo.s.com" => {
                a: NotFound,
            },
        };
        assert_eq!(
            Some((SpfResult::Fail, Explanation::None)),
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );

        dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 mx -all"],
                mx: ["foo.s.com"],
            },
            "foo.s.com" => {
                a: Error,
            },
        };
        assert_eq!(
            Some((SpfResult::TempError, Explanation::None)),
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );

        dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 mx -all"],
                mx: ["foo.s.com", "bar.s.com"],
            },
        };
        assert_eq!(
            None,
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );

        dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 mx -all"],
                mx: ["foo.s.com", "bar.s.com"],
            },
            "foo.s.com" => {
                a: ["1.2.3.4"],
            },
        };
        assert_eq!(
            Some((SpfResult::Pass, Explanation::None)),
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );
        assert_eq!(
            None,
            eval(&simple_context("s.com", "2.3.4.5"), &mut dns_cache,),
        );

        dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 mx -all"],
                mx: ["foo.s.com", "bar.s.com"],
            },
            "bar.s.com" => {
                a: ["1.2.3.4"],
            },
        };
        assert_eq!(
            Some((SpfResult::Pass, Explanation::None)),
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );
        assert_eq!(
            None,
            eval(&simple_context("s.com", "2.3.4.5"), &mut dns_cache,),
        );

        dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 mx -all"],
                mx: ["foo.s.com", "bar.s.com"],
            },
            "bar.s.com" => {
                a: ["1.2.3.4"],
            },
            "foo.s.com" => {
                a: Error,
            },
        };
        assert_eq!(
            Some((SpfResult::Pass, Explanation::None)),
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );
        assert_eq!(
            Some((SpfResult::TempError, Explanation::None)),
            eval(&simple_context("s.com", "2.3.4.5"), &mut dns_cache,),
        );

        dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 mx mx:t.com/24/16 ~mx/24/16 -all"],
                mx: ["mail.s.com"],
            },
            "mail.s.com" => {
                a: ["1.2.3.4", "2.3.4.5"],
                aaaa: ["dead::beef"],
            },
            "t.com" => {
                mx: ["mx.t.com"],
            },
            "mx.t.com" => {
                a: ["4.5.6.7"],
                aaaa: ["cafe::f00d", "f00d::cafe"],
            },
        };
        assert_eq!(
            Some((SpfResult::Pass, Explanation::None)),
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );
        assert_eq!(
            Some((SpfResult::Pass, Explanation::None)),
            eval(&simple_context("s.com", "2.3.4.5"), &mut dns_cache,),
        );
        assert_eq!(
            Some((SpfResult::Pass, Explanation::None)),
            eval(&simple_context("s.com", "4.5.6.255"), &mut dns_cache,),
        );
        assert_eq!(
            Some((SpfResult::SoftFail, Explanation::None)),
            eval(&simple_context("s.com", "1.2.3.255"), &mut dns_cache,),
        );
        assert_eq!(
            Some((SpfResult::Fail, Explanation::None)),
            eval(&simple_context("s.com", "99.88.77.66"), &mut dns_cache,),
        );
        assert_eq!(
            Some((SpfResult::Pass, Explanation::None)),
            eval(&simple_context("s.com", "dead::beef"), &mut dns_cache,),
        );
        assert_eq!(
            Some((SpfResult::Pass, Explanation::None)),
            eval(&simple_context("s.com", "cafe::beef"), &mut dns_cache,),
        );
        assert_eq!(
            Some((SpfResult::Pass, Explanation::None)),
            eval(&simple_context("s.com", "f00d::beef"), &mut dns_cache,),
        );
        assert_eq!(
            Some((SpfResult::SoftFail, Explanation::None)),
            eval(&simple_context("s.com", "dead::cafe"), &mut dns_cache,),
        );
        assert_eq!(
            Some((SpfResult::Fail, Explanation::None)),
            eval(&simple_context("s.com", "baad::cafe"), &mut dns_cache,),
        );

        dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 mx -all"],
                mx: [
                    "mx1.s.com",
                    "mx2.s.com",
                    "mx3.s.com",
                    "mx4.s.com",
                    "mx5.s.com",
                    "mx6.s.com",
                    "mx7.s.com",
                    "mx8.s.com",
                    "mx9.s.com",
                    "mx10.s.com",
                    "mx11.s.com",
                ],
            },
        };
        assert_eq!(
            Some((SpfResult::PermError, Explanation::None)),
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );
    }

    #[test]
    fn eval_ptr() {
        // The tests for ptr resolution are separate, so this just verifies
        // that the mechanism itself does the right thing.
        let mut dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 ptr -all"],
                a: ["1.2.3.4"],
                aaaa: ["dead::beef"],
            },
        };
        dns_cache.ptr.insert(
            "1.2.3.4".parse::<IpAddr>().unwrap(),
            DnsEntry::Ok(vec![rdn("s.com")]),
        );
        dns_cache.ptr.insert(
            "dead::beef".parse::<IpAddr>().unwrap(),
            DnsEntry::Ok(vec![rdn("s.com")]),
        );

        assert_eq!(
            Some((SpfResult::Pass, Explanation::None)),
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );
        assert_eq!(
            Some((SpfResult::Pass, Explanation::None)),
            eval(&simple_context("s.com", "dead::beef"), &mut dns_cache,),
        );

        assert_eq!(
            None,
            eval(&simple_context("s.com", "5.2.3.4"), &mut dns_cache,),
        );
        assert_eq!(
            None,
            eval(&simple_context("s.com", "baad::beef"), &mut dns_cache,),
        );

        dns_cache.ptr.insert(
            "5.2.3.4".parse::<IpAddr>().unwrap(),
            DnsEntry::Ok(vec![rdn("other.com")]),
        );
        dns_cache.ptr.insert(
            "baad::beef".parse::<IpAddr>().unwrap(),
            DnsEntry::NotFound,
        );
        assert_eq!(
            Some((SpfResult::Fail, Explanation::None)),
            eval(&simple_context("s.com", "5.2.3.4"), &mut dns_cache,),
        );
        assert_eq!(
            Some((SpfResult::Fail, Explanation::None)),
            eval(&simple_context("s.com", "baad::beef"), &mut dns_cache,),
        );
    }

    #[test]
    fn eval_exists() {
        let mut dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 exists:%{i4r}.spf.s.com -all"],
            },
        };
        assert_eq!(
            None,
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );
        assert_eq!(
            None,
            eval(&simple_context("s.com", "dead::beef"), &mut dns_cache,),
        );

        dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 exists:%{i4r}.spf.s.com -all"],
            },
            "4.3.2.1.spf.s.com" => {
                a: ["1.1.1.1"],
            },
            "5.4.3.2.spf.s.com" => {
                a: NotFound,
                aaaa: ["dead::beef"], // never used
            },
            "d.a.e.d.spf.s.com" => {
                a: ["1.1.1.1"],
            },
            "d.a.a.b.spf.s.com" => {
                a: Error,
                aaaa: ["dead::beef"], // never used
            },
        };
        assert_eq!(
            Some((SpfResult::Pass, Explanation::None)),
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );
        assert_eq!(
            Some((SpfResult::Pass, Explanation::None)),
            eval(&simple_context("s.com", "dead::beef"), &mut dns_cache,),
        );
        assert_eq!(
            Some((SpfResult::Fail, Explanation::None)),
            eval(&simple_context("s.com", "2.3.4.5"), &mut dns_cache,),
        );
        assert_eq!(
            Some((SpfResult::TempError, Explanation::None)),
            eval(&simple_context("s.com", "baad::f00d"), &mut dns_cache,),
        );
    }

    #[test]
    fn eval_include() {
        let mut dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 include:t.com -all"],
            },
        };
        assert_eq!(
            None,
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );

        dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 include:t.com -all"],
            },
            "t.com" => {
                txt: Error,
            },
        };
        assert_eq!(
            Some((SpfResult::TempError, Explanation::None)),
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );

        dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 include:t.com -all"],
            },
            "t.com" => {
                txt: NotFound,
            },
        };
        assert_eq!(
            Some((SpfResult::PermError, Explanation::None)),
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );

        dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 include:t.com -all"],
            },
            "t.com" => {
                txt: ["v=spf1 invalid-syntax"],
            },
        };
        assert_eq!(
            Some((SpfResult::PermError, Explanation::None)),
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );

        dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 include:t.com -all"],
            },
            "t.com" => {
                txt: ["v=spf1 a"],
            },
        };
        assert_eq!(
            None,
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );

        dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 include:t.com -all"],
            },
            "t.com" => {
                txt: ["v=spf1 a"],
                a: ["1.2.3.4"],
            },
        };
        assert_eq!(
            Some((SpfResult::Pass, Explanation::None)),
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );

        dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 include:t.com -all"],
            },
            "t.com" => {
                txt: ["v=spf1 a"],
                a: ["5.2.3.4"],
            },
        };
        assert_eq!(
            Some((SpfResult::Fail, Explanation::None)),
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );

        dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 include:t.com ?a -all"],
                a: ["1.2.3.4"],
            },
            "t.com" => {
                txt: ["v=spf1 -all"],
            },
        };
        assert_eq!(
            Some((SpfResult::Neutral, Explanation::None)),
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );

        dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 include:s.com"],
            },
        };
        assert_eq!(
            Some((SpfResult::PermError, Explanation::None)),
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );
    }

    #[test]
    fn eval_redirect() {
        let mut dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 redirect=next.s.com -all"],
            },
        };
        // -all is evaluated before the redirect
        assert_eq!(
            Some((SpfResult::Fail, Explanation::None)),
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );

        dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 ip4:4.4.4.4 redirect=next.s.com"],
            },
        };
        assert_eq!(
            None,
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );

        dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 ip4:4.4.4.4 redirect=next.s.com"],
            },
            "next.s.com" => {
                txt: Error,
            },
        };
        assert_eq!(
            Some((SpfResult::TempError, Explanation::None)),
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );

        dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 ip4:4.4.4.4 redirect=next.s.com"],
            },
            "next.s.com" => {
                txt: NotFound,
            },
        };
        assert_eq!(
            Some((SpfResult::PermError, Explanation::None)),
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );

        dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 ip4:4.4.4.4 redirect=next.s.com"],
            },
            "next.s.com" => {
                txt: ["v=spf1 a -all"],
                a: ["1.2.3.4"],
            },
        };
        assert_eq!(
            Some((SpfResult::Pass, Explanation::None)),
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );
        assert_eq!(
            Some((SpfResult::Fail, Explanation::None)),
            eval(&simple_context("s.com", "5.2.3.4"), &mut dns_cache,),
        );

        dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 redirect=s.com"],
            },
        };
        assert_eq!(
            Some((SpfResult::PermError, Explanation::None)),
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );
    }

    #[test]
    fn eval_exp() {
        let mut dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 exp=exp.s.com -all"],
            },
        };
        assert_eq!(
            Some((SpfResult::Fail, Explanation::NotReady)),
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );

        dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 exp=exp.s.com -all"],
            },
            "exp.s.com" => {
                txt: Error,
            },
        };
        assert_eq!(
            Some((SpfResult::Fail, Explanation::None)),
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );

        dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 exp=exp.s.com -all"],
            },
            "exp.s.com" => {
                txt: NotFound,
            },
        };
        assert_eq!(
            Some((SpfResult::Fail, Explanation::None)),
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );

        dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 exp=exp.s.com -all"],
            },
            "exp.s.com" => {
                txt: ["Nobody sends mail from %{d}!"],
            },
        };
        assert_eq!(
            Some((
                SpfResult::Fail,
                Explanation::Some("Nobody sends mail from s.com!".to_owned())
            )),
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );

        dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 exp=exp.s.com -all"],
            },
            "exp.s.com" => {
                txt: ["Nobody sends mail from %{d"],
            },
        };
        assert_eq!(
            Some((SpfResult::Fail, Explanation::None)),
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );

        dns_cache = dns_cache! {
            "s.com" => {
                txt: ["v=spf1 -ip4:1.2.3.4 exp=exp.s.com redirect=t.com"],
            },
            "exp.s.com" => {
                txt: ["1.2.3.4 is banned"],
            },
            "t.com" => {
                txt: ["v=spf1 ip4:2.3.4.5 -all exp=exp.t.com"],
            },
            "exp.t.com" => {
                txt: ["only 2.3.4.5 is allowed"],
            },
        };
        assert_eq!(
            Some((
                SpfResult::Fail,
                Explanation::Some("1.2.3.4 is banned".to_owned(),)
            )),
            eval(&simple_context("s.com", "1.2.3.4"), &mut dns_cache,),
        );
        assert_eq!(
            Some((
                SpfResult::Fail,
                Explanation::Some("only 2.3.4.5 is allowed".to_owned(),)
            )),
            eval(&simple_context("s.com", "99.2.3.4"), &mut dns_cache,),
        );
        assert_eq!(
            Some((SpfResult::Pass, Explanation::None)),
            eval(&simple_context("s.com", "2.3.4.5"), &mut dns_cache,),
        );
    }
}
