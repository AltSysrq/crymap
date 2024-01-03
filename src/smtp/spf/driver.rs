//-
// Copyright (c) 2023, 2024, Jason Lingle
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
use std::rc::Rc;

use super::eval::{eval, Context, Explanation, SpfResult};
use crate::support::dns;

/// Runs SPF validation against the given context.
///
/// `dns_cache` will be populated as the function runs. It may be shared with
/// other invocations of `run`.
///
/// `run` will exit early at `deadline`.
///
/// DNS lookups are spawned as tasks in the contextual `LocalSet`.
pub async fn run(
    ctx: &Context<'_>,
    dns_cache: Rc<RefCell<dns::Cache>>,
    resolver: Rc<dns::Resolver>,
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
        }
        dns::spawn_lookups(&dns_cache, &resolver);

        // Wait until the deadline or until we get new DNS information.
        // Critically, there are no await points between the call to eval() and
        // this await, so we know we haven't missed any notifications.
        if tokio::time::timeout_at(deadline, dns::wait_for_progress(&dns_cache))
            .await
            .is_err()
        {
            break;
        }
    }

    result
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
                let dns_cache = Rc::new(RefCell::new(dns::Cache::default()));
                let resolver = Rc::new(
                    hickory_resolver::AsyncResolver::tokio_from_system_conf()
                        .unwrap(),
                );
                let ctx = Context {
                    sender: None,
                    sender_local: None,
                    sender_domain: Cow::Borrowed(domain),
                    sender_domain_parsed: Rc::new(
                        dns::Name::from_ascii(domain).unwrap(),
                    ),
                    helo_domain: Cow::Borrowed(domain),
                    ip: ip.parse().unwrap(),
                    receiver_host: Cow::Borrowed("receiver"),
                    now: chrono::DateTime::from_timestamp(0, 0).unwrap(),
                };
                run(
                    &ctx,
                    dns_cache,
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
