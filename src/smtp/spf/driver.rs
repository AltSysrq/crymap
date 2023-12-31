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

use std::cell::RefCell;
use std::future::Future;
use std::rc::Rc;

use hickory_resolver::Name as DnsName;

use super::eval::{
    eval, Context, DnsCache, DnsCacheMap, DnsEntry, Explanation, SpfResult,
};

pub type DnsResolver = hickory_resolver::AsyncResolver<
    hickory_resolver::name_server::GenericConnector<
        hickory_resolver::name_server::TokioRuntimeProvider,
    >,
>;

/// Runs SPF validation against the given context.
///
/// `dns_cache` will be populated as the function runs. It may be shared with
/// other invocations of `run`, but such concurrent invocations must share the
/// same `dns_notify` handle.
///
/// `run` will exit early at `deadline`.
///
/// DNS lookups are spawned as tasks in the contextual `LocalSet`.
pub async fn run(
    ctx: &Context<'_>,
    dns_cache: Rc<RefCell<DnsCache>>,
    dns_notify: Rc<tokio::sync::Notify>,
    resolver: Rc<DnsResolver>,
    deadline: tokio::time::Instant,
) -> (SpfResult, Explanation) {
    let mut result = (SpfResult::TempError, Explanation::None);

    loop {
        {
            let mut dns_cache_mut = dns_cache.borrow_mut();
            if let Some(r) = eval(ctx, &mut dns_cache_mut) {
                result = r;
                // If we have our result, but the explanation is still pending,
                // keep going until we get our explanation or the deadline
                // expires.
                if !matches!(result.1, Explanation::NotReady) {
                    break;
                }
            }

            spawn_dns_lookups(
                &mut dns_cache_mut,
                &dns_cache,
                &dns_notify,
                &resolver,
            );
        }

        // Wait until the deadline or until we get new DNS information.
        // Critically, there are no await points between the call to eval() and
        // this await, so we know we haven't missed any notifications.
        if tokio::time::timeout_at(deadline, dns_notify.notified())
            .await
            .is_err()
        {
            break;
        }
    }

    result
}

fn spawn_dns_lookups(
    dns_cache_mut: &mut DnsCache,
    dns_cache: &Rc<RefCell<DnsCache>>,
    dns_notify: &Rc<tokio::sync::Notify>,
    resolver: &Rc<DnsResolver>,
) {
    spawn_dns_name_lookups(
        &mut dns_cache_mut.a,
        dns_cache,
        dns_notify,
        resolver,
        |resolver, name| async move {
            resolver
                .ipv4_lookup(name)
                .await
                .map(|r| r.iter().map(|a| a.0).collect::<Vec<_>>())
        },
        |d| &mut d.a,
    );
    spawn_dns_name_lookups(
        &mut dns_cache_mut.aaaa,
        dns_cache,
        dns_notify,
        resolver,
        |resolver, name| async move {
            resolver
                .ipv6_lookup(name)
                .await
                .map(|r| r.iter().map(|a| a.0).collect::<Vec<_>>())
        },
        |d| &mut d.aaaa,
    );
    spawn_dns_name_lookups(
        &mut dns_cache_mut.mx,
        dns_cache,
        dns_notify,
        resolver,
        |resolver, name| async move {
            resolver.mx_lookup(name).await.map(|r| {
                r.iter()
                    .map(|n| Rc::new(n.exchange().clone()))
                    .collect::<Vec<_>>()
            })
        },
        |d| &mut d.mx,
    );
    spawn_dns_name_lookups(
        &mut dns_cache_mut.txt,
        dns_cache,
        dns_notify,
        resolver,
        |resolver, name| async move {
            resolver.txt_lookup(name).await.map(|r| {
                r.iter()
                    .map(|parts| {
                        let len = parts.iter().map(|p| p.len()).sum();
                        let mut combined = Vec::with_capacity(len);
                        for part in parts.iter() {
                            combined.extend_from_slice(part);
                        }

                        match String::from_utf8(combined) {
                            Ok(s) => s,
                            Err(e) => String::from_utf8_lossy(e.as_bytes())
                                .into_owned(),
                        }
                        .into()
                    })
                    .collect::<Vec<_>>()
            })
        },
        |d| &mut d.txt,
    );

    for (&ip, entry) in &mut dns_cache_mut.ptr {
        if !matches!(*entry, DnsEntry::New) {
            continue;
        }

        *entry = DnsEntry::Pending;

        let dns_cache = Rc::clone(dns_cache);
        let dns_notify = Rc::clone(dns_notify);
        let resolver = Rc::clone(resolver);
        tokio::task::spawn_local(async move {
            let new_entry =
                to_dns_entry(resolver.reverse_lookup(ip).await.map(|rev| {
                    rev.iter().map(|n| Rc::new(n.0.clone())).collect::<Vec<_>>()
                }));

            dns_cache.borrow_mut().ptr.insert(ip, new_entry);
            dns_notify.notify_waiters();
        });
    }
}

fn spawn_dns_name_lookups<T, R, F, A>(
    dns_map: &mut DnsCacheMap<T>,
    dns_cache: &Rc<RefCell<DnsCache>>,
    dns_notify: &Rc<tokio::sync::Notify>,
    resolver: &Rc<DnsResolver>,
    run: F,
    access: A,
) where
    R: Future<Output = Result<T, hickory_resolver::error::ResolveError>>
        + 'static,
    F: FnOnce(Rc<DnsResolver>, DnsName) -> R + Clone + 'static,
    A: FnOnce(&mut DnsCache) -> &mut DnsCacheMap<T> + Clone + 'static,
{
    for entry in dns_map {
        if !matches!(entry.1, DnsEntry::New) {
            continue;
        }

        entry.1 = DnsEntry::Pending;

        let run = run.clone();
        let access = access.clone();
        let dns_cache = Rc::clone(dns_cache);
        let dns_notify = Rc::clone(dns_notify);
        let resolver = Rc::clone(resolver);
        let name = Rc::clone(&entry.0);
        tokio::task::spawn_local(async move {
            let mut name_clone = (*name).clone();
            name_clone.set_fqdn(true);
            let new_entry = to_dns_entry(run(resolver, name_clone).await);
            let mut dns_cache = dns_cache.borrow_mut();
            for entry in access(&mut dns_cache) {
                if name == entry.0 {
                    entry.1 = new_entry;
                    break;
                }
            }
            dns_notify.notify_waiters();
        });
    }
}

fn to_dns_entry<T>(
    r: Result<T, hickory_resolver::error::ResolveError>,
) -> DnsEntry<T> {
    use hickory_resolver::error::ResolveErrorKind as Rek;

    match r {
        Ok(v) => DnsEntry::Ok(v),
        Err(e) => match *e.kind() {
            Rek::NoRecordsFound { .. } => DnsEntry::NotFound,
            _ => DnsEntry::Error,
        },
    }
}

#[cfg(all(test, feature = "live-network-tests"))]
mod test {
    use std::borrow::Cow;

    use super::*;

    #[tokio::main(flavor = "current_thread")]
    async fn run_test(domain: &str, ip: &str) -> (SpfResult, Explanation) {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async move {
                let dns_cache = Rc::new(RefCell::new(DnsCache::default()));
                let dns_notify = Rc::new(tokio::sync::Notify::new());
                let resolver = Rc::new(
                    hickory_resolver::AsyncResolver::tokio_from_system_conf()
                        .unwrap(),
                );
                let ctx = Context {
                    sender: None,
                    sender_local: None,
                    sender_domain: Cow::Borrowed(domain),
                    sender_domain_parsed: Rc::new(
                        DnsName::from_ascii(domain).unwrap(),
                    ),
                    helo_domain: Cow::Borrowed(domain),
                    ip: ip.parse().unwrap(),
                    receiver_host: Cow::Borrowed("receiver"),
                    now: chrono::DateTime::from_timestamp(0, 0).unwrap(),
                };
                run(
                    &ctx,
                    dns_cache,
                    dns_notify,
                    resolver,
                    tokio::time::Instant::now()
                        + std::time::Duration::from_secs(20),
                )
                .await
            })
            .await
    }

    #[test]
    fn simple() {
        assert_eq!(
            (SpfResult::Pass, Explanation::None),
            run_test("simple.spftest.lin.gl", "192.0.2.1"),
        );
        assert_eq!(
            (SpfResult::Neutral, Explanation::None),
            run_test("simple.spftest.lin.gl", "192.0.2.2"),
        );
    }

    #[test]
    fn gmail() {
        // SPF snapshot from 2023-12-31
        assert_eq!(
            (SpfResult::Pass, Explanation::None),
            run_test("gmail.com.spftest.lin.gl", "172.217.32.47"),
        );
        assert_eq!(
            (SpfResult::Pass, Explanation::None),
            run_test("gmail.com.spftest.lin.gl", "2800:3f0:4000::1"),
        );
        assert_eq!(
            (SpfResult::SoftFail, Explanation::None),
            run_test("gmail.com.spftest.lin.gl", "1.2.3.4"),
        );
    }

    #[test]
    fn linglptr() {
        // Unfortunately, due to the PTR record, this isn't entirely contained
        // within the spftest zone.
        // This test could fail spuriously if this server is ever moved.
        assert_eq!(
            (SpfResult::Pass, Explanation::None),
            run_test("linglptr.spftest.lin.gl", "104.219.54.11"),
        );
        assert_eq!(
            (SpfResult::Fail, Explanation::None),
            run_test("linglptr.spftest.lin.gl", "104.219.54.12"),
        );
    }

    #[test]
    fn amx() {
        // Matches IPv4 'a'
        assert_eq!(
            (SpfResult::Pass, Explanation::None),
            run_test("amx.spftest.lin.gl", "192.0.2.1"),
        );
        // Matches IPv6 'a'
        assert_eq!(
            (SpfResult::Pass, Explanation::None),
            run_test("amx.spftest.lin.gl", "2001:db8::1"),
        );
        // Matches IPv4 'mx'
        assert_eq!(
            (SpfResult::Pass, Explanation::None),
            run_test("amx.spftest.lin.gl", "192.0.2.2"),
        );
        // Matches IPv6 'mx'
        assert_eq!(
            (SpfResult::Pass, Explanation::None),
            run_test("amx.spftest.lin.gl", "2001:db8::2"),
        );
        assert_eq!(
            (
                SpfResult::Fail,
                Explanation::Some("192.0.2.3 is not allowed!".to_owned(),)
            ),
            run_test("amx.spftest.lin.gl", "192.0.2.3"),
        );
    }
}
