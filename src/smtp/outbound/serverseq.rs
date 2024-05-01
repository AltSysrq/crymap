//-
// Copyright (c) 2024, Jason Lingle
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
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;

use rand::seq::SliceRandom;

use super::{transact, transcript::Transcript};
use crate::{
    account::{
        model::ForeignSmtpTlsStatus,
        v2::{Account, SpooledMessageId},
    },
    support::{async_io::ServerIo, buffer::BufferReader, dns},
};

pub struct Results {
    pub success: Vec<String>,
    pub tempfail: Vec<String>,
    pub permfail: Vec<String>,
    pub transcript: io::Result<BufferReader>,
}

pub type TransactResult = Result<transact::Results, transact::Error>;
pub type MockConnect<'a> = &'a dyn Fn(IpAddr) -> TransactResult;

/// Sends the message `message_id` in `account` to the email addresses
/// `destinations` by connecting to mail server(s) for `domain`.
///
/// This call updates the TLS status in the database but does *not* remove
/// successful or permanently failed destinations from the spool.
///
/// If `mock_connect` is `Some`, it invoked for each IP address to be attempted
/// for delivery instead of actually connecting to anything. This is used for
/// testing.
pub async fn execute(
    dns_cache: Rc<RefCell<dns::Cache>>,
    dns_resolver: Option<Rc<dns::Resolver>>,
    account: Rc<RefCell<Account>>,
    message_id: SpooledMessageId,
    domain: Rc<dns::Name>,
    destinations: Vec<String>,
    local_host_name: String,
    mock_connect: Option<MockConnect<'_>>,
) -> Results {
    let mut transcript = Transcript::new(account.borrow().common_paths());
    transcript.line(format_args!("Transcript for messages sent to {domain}"));

    let domain_key = domain.to_ascii();
    let tls_expectations = match account
        .borrow_mut()
        .fetch_foreign_smtp_tls_status(&domain_key)
    {
        Ok(None) => ForeignSmtpTlsStatus {
            domain: domain_key,
            ..ForeignSmtpTlsStatus::default()
        },
        Ok(Some(status)) => status,
        Err(e) => {
            transcript.line(format_args!("Internal error: {e}"));
            return Results {
                success: vec![],
                tempfail: destinations,
                permfail: vec![],
                transcript: transcript.finish(),
            };
        },
    };

    let Ok(mx_records) =
        dns_mx(&mut transcript, &dns_cache, dns_resolver.as_ref(), &domain)
            .await
    else {
        return Results {
            success: vec![],
            tempfail: destinations,
            permfail: vec![],
            transcript: transcript.finish(),
        };
    };

    for mx_domain in mx_records {
        match try_domain(
            &mut transcript,
            &dns_cache,
            dns_resolver.as_ref(),
            &mx_domain,
            &account,
            message_id,
            &destinations,
            &local_host_name,
            &tls_expectations,
            mock_connect,
        )
        .await
        {
            Ok(results) => {
                if let Err(e) = account
                    .borrow_mut()
                    .put_foreign_smtp_tls_status(&results.tls_status)
                {
                    transcript.line(format_args!(
                        "Error updating TLS expectations: {e}",
                    ));
                }
                return Results {
                    success: results.success,
                    tempfail: results.tempfail,
                    permfail: results.permfail,
                    transcript: transcript.finish(),
                };
            },

            Err(transact::Error::TryNextServer) => {},

            Err(transact::Error::TotalFailure) => {
                return Results {
                    success: vec![],
                    tempfail: vec![],
                    permfail: destinations,
                    transcript: transcript.finish(),
                }
            },
        }
    }

    Results {
        success: vec![],
        tempfail: destinations,
        permfail: vec![],
        transcript: transcript.finish(),
    }
}

async fn dns_mx(
    transcript: &mut Transcript,
    dns_cache: &Rc<RefCell<dns::Cache>>,
    dns_resolver: Option<&Rc<dns::Resolver>>,
    domain: &Rc<dns::Name>,
) -> Result<Vec<Rc<dns::Name>>, ()> {
    transcript.line(format_args!(">> DNS MX {domain}"));
    let mx_result = dns::wait_for(dns_cache, dns_resolver, |dns_cache| {
        dns::look_up(&mut dns_cache.mx, domain).cloned()
    })
    .await;

    let mut mx_records = match mx_result {
        Ok(m) if !m.is_empty() => m,
        Ok(_ /* empty */) | Err(dns::CacheError::NotFound) => {
            transcript.line(format_args!(
                "No MX record found, using {domain} \
                 itself as the mail exchange",
            ));
            return Ok(vec![Rc::clone(domain)]);
        },
        Err(dns::CacheError::Error) => {
            transcript.line(format_args!("DNS lookup error"));
            return Err(());
        },
        Err(dns::CacheError::NotReady) => unreachable!(),
    };

    for &(ref name, preference) in &mx_records {
        transcript.line(format_args!("<< {preference} {name}"));
    }

    mx_records.shuffle(&mut rand::thread_rng());
    mx_records.sort_by_key(|&(_, preference)| std::cmp::Reverse(preference));
    Ok(mx_records.into_iter().map(|(name, _)| name).collect())
}

async fn try_domain(
    transcript: &mut Transcript,
    dns_cache: &Rc<RefCell<dns::Cache>>,
    dns_resolver: Option<&Rc<dns::Resolver>>,
    mx_domain: &Rc<dns::Name>,
    account: &RefCell<Account>,
    message_id: SpooledMessageId,
    destinations: &[String],
    local_host_name: &str,
    tls_expectations: &ForeignSmtpTlsStatus,
    mock_connect: Option<MockConnect<'_>>,
) -> TransactResult {
    transcript.line(format_args!("Trying domain {mx_domain}..."));
    let addresses = dns_a(transcript, dns_cache, dns_resolver, mx_domain)
        .await
        .map_err(|_| transact::Error::TryNextServer)?;

    for addr in addresses {
        let addr_result = if let Some(mock_connect) = mock_connect {
            mock_connect(addr)
        } else {
            try_addr(
                transcript,
                mx_domain,
                addr,
                account,
                message_id,
                destinations,
                local_host_name,
                tls_expectations,
            )
            .await
        };

        match addr_result {
            Ok(r) => return Ok(r),
            Err(transact::Error::TotalFailure) => {
                return Err(transact::Error::TotalFailure);
            },
            Err(transact::Error::TryNextServer) => {},
        }
    }

    Err(transact::Error::TryNextServer)
}

async fn dns_a(
    transcript: &mut Transcript,
    dns_cache: &Rc<RefCell<dns::Cache>>,
    dns_resolver: Option<&Rc<dns::Resolver>>,
    domain: &Rc<dns::Name>,
) -> Result<Vec<IpAddr>, ()> {
    let mut results = Vec::<IpAddr>::new();

    transcript.line(format_args!(">> DNS AAAA + A {domain}"));

    let (aaaa_result, a_result) = tokio::join![
        dns::wait_for(dns_cache, dns_resolver, |dns_cache| dns::look_up(
            &mut dns_cache.aaaa,
            domain
        )
        .cloned(),),
        dns::wait_for(dns_cache, dns_resolver, |dns_cache| dns::look_up(
            &mut dns_cache.a,
            domain
        )
        .cloned(),),
    ];

    match aaaa_result {
        Ok(records) => results.extend(records.into_iter().map(IpAddr::V6)),
        Err(dns::CacheError::NotFound) => {},
        Err(_) => transcript.line(format_args!("DNS error on AAAA lookup")),
    }

    match a_result {
        Ok(records) => results.extend(records.into_iter().map(IpAddr::V4)),
        Err(dns::CacheError::NotFound) => {},
        Err(_) => transcript.line(format_args!("DNS error on A lookup")),
    };

    for &addr in &results {
        transcript.line(format_args!("<< {addr}"));
    }

    if results.is_empty() {
        transcript.line(format_args!("No IP addresses found for {domain}"));
        return Err(());
    }

    Ok(results)
}

async fn try_addr(
    transcript: &mut Transcript,
    mx_domain: &Rc<dns::Name>,
    addr: IpAddr,
    account: &RefCell<Account>,
    message_id: SpooledMessageId,
    destinations: &[String],
    local_host_name: &str,
    tls_expectations: &ForeignSmtpTlsStatus,
) -> TransactResult {
    let message = match account.borrow_mut().open_spooled_message(message_id) {
        Ok(message) => message,
        Err(e) => {
            transcript.line(format_args!("Failed to open message: {e}"));
            return Err(transact::Error::TryNextServer);
        },
    };

    let addr = SocketAddr::from((addr, 25));
    transcript.line(format_args!("Connecting to {addr}..."));
    let sock = match tokio::net::TcpStream::connect(addr).await {
        Ok(sock) => sock,
        Err(e) => {
            transcript.line(format_args!("Failed to connect: {e}"));
            return Err(transact::Error::TryNextServer);
        },
    };
    // We need to convert the socket back into a non-async one since we want to
    // manage the low-level tokio stuff ourselves.
    let sock = match sock.into_std() {
        Ok(sock) => sock,
        Err(e) => {
            transcript.line(format_args!("Failed to configure socket: {e}"));
            return Err(transact::Error::TryNextServer);
        },
    };
    let server_io = match ServerIo::new_owned_socket(sock) {
        Ok(server_io) => server_io,
        Err(e) => {
            transcript.line(format_args!("Failed to configure socket: {e}"));
            return Err(transact::Error::TryNextServer);
        },
    };
    transcript.line(format_args!("Connection established"));

    transact::execute(
        server_io,
        transcript,
        message,
        &destinations.iter().map(|s| &**s).collect::<Vec<_>>(),
        tls_expectations,
        mx_domain,
        local_host_name,
    )
    .await
}

#[cfg(test)]
mod test {
    use std::fs;
    use std::io::Read;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::{Arc, Mutex, Weak};

    use chrono::prelude::*;
    use lazy_static::lazy_static;
    use tempfile::TempDir;

    use super::*;
    use crate::{
        account::v2::SmtpTransfer, crypt::master_key::MasterKey,
        support::log_prefix::LogPrefix,
    };

    lazy_static! {
        static ref SYSTEM_DIR: Mutex<Weak<Setup>> = Mutex::new(Weak::new());
    }

    struct Setup {
        system_dir: TempDir,
        master_key: Arc<MasterKey>,
        spooled_message_id: SpooledMessageId,
    }

    fn set_up() -> Arc<Setup> {
        crate::init_test_log();

        let mut lock = SYSTEM_DIR.lock().unwrap();

        if let Some(setup) = lock.upgrade() {
            return setup;
        }

        let setup = Arc::new(set_up_new_root());
        *lock = Arc::downgrade(&setup);
        setup
    }

    fn set_up_new_root() -> Setup {
        let system_dir = TempDir::new().unwrap();
        let master_key = Arc::new(MasterKey::new());
        let user_name = "user";
        let user_dir = system_dir.path().join(user_name);

        fs::create_dir(&user_dir).unwrap();

        let mut account = Account::new(
            LogPrefix::new("initial-setup".to_owned()),
            user_dir,
            Arc::clone(&master_key),
        )
        .unwrap();
        account.provision(b"hunter2").unwrap();

        let buffered_message = account
            .buffer_message(Utc::now().into(), b"message".as_slice())
            .unwrap();
        let spooled_message_id = account
            .spool_message(
                buffered_message,
                SmtpTransfer::SevenBit,
                "zim@irk.com".to_owned(),
                vec![
                    "one@example.com".to_owned(),
                    "two@example.com".to_owned(),
                ],
            )
            .unwrap();

        Setup {
            system_dir,
            master_key,
            spooled_message_id,
        }
    }

    #[tokio::main(flavor = "current_thread")]
    async fn run_test(
        dns: &[(&str, &[&str])],
        connect_results: &[(&str, TransactResult)],
        success: &[&str],
        tempfail: &[&str],
        permfail: &[&str],
    ) {
        let setup = set_up();
        let account = Account::new(
            LogPrefix::new("test".to_owned()),
            setup.system_dir.path().join("user"),
            Arc::clone(&setup.master_key),
        )
        .unwrap();

        let mut dns_cache = dns::Cache::default();
        for &(host, records) in dns {
            let host = Rc::new(dns::Name::from_ascii(host).unwrap());
            let mut a = dns::Entry::<Vec<Ipv4Addr>>::NotFound;
            let mut aaaa = dns::Entry::<Vec<Ipv6Addr>>::NotFound;
            let mut mx = dns::Entry::<Vec<(Rc<dns::Name>, u16)>>::NotFound;

            for &record in records {
                if let Ok(ipv4) = record.parse::<Ipv4Addr>() {
                    match a {
                        dns::Entry::Ok(ref mut v) => v.push(ipv4),
                        ref mut a => *a = dns::Entry::Ok(vec![ipv4]),
                    }
                } else if let Ok(ipv6) = record.parse::<Ipv6Addr>() {
                    match aaaa {
                        dns::Entry::Ok(ref mut v) => v.push(ipv6),
                        ref mut aaaa => *aaaa = dns::Entry::Ok(vec![ipv6]),
                    }
                } else if let Some(mxr) = parse_mx_record(record) {
                    match mx {
                        dns::Entry::Ok(ref mut v) => v.push(mxr),
                        ref mut mx => *mx = dns::Entry::Ok(vec![mxr]),
                    }
                } else if "a-error" == record {
                    a = dns::Entry::Error;
                } else if "aaaa-error" == record {
                    aaaa = dns::Entry::Error;
                } else if "mx-error" == record {
                    mx = dns::Entry::Error;
                } else {
                    panic!("bad DNS entry for {host}: {record}");
                }
            }

            dns_cache.a.push((Rc::clone(&host), a));
            dns_cache.aaaa.push((Rc::clone(&host), aaaa));
            dns_cache.mx.push((host, mx));
        }

        let mock_connect = |actual_ipaddr: IpAddr| {
            for (expected_ip, ref result) in connect_results {
                let expected_ipaddr = expected_ip.parse::<IpAddr>().unwrap();
                if expected_ipaddr == actual_ipaddr {
                    return result.clone();
                }
            }

            panic!("unexpected attempt to connect to {actual_ipaddr}")
        };

        let account = Rc::new(RefCell::new(account));
        let actual_result = execute(
            Rc::new(RefCell::new(dns_cache)),
            None,
            Rc::clone(&account),
            setup.spooled_message_id,
            Rc::new(dns::Name::from_ascii("example.com").unwrap()),
            emails_vec(),
            "localhost".to_owned(),
            Some(&mock_connect),
        )
        .await;

        let mut transcript = String::new();
        actual_result
            .transcript
            .unwrap()
            .read_to_string(&mut transcript)
            .unwrap();
        println!("Transcript:\n{transcript}");

        assert_eq!(
            success
                .into_iter()
                .map(|s| s.to_owned())
                .collect::<Vec<_>>(),
            actual_result.success,
        );
        assert_eq!(
            tempfail
                .into_iter()
                .map(|s| s.to_owned())
                .collect::<Vec<_>>(),
            actual_result.tempfail,
        );
        assert_eq!(
            permfail
                .into_iter()
                .map(|s| s.to_owned())
                .collect::<Vec<_>>(),
            actual_result.permfail,
        );

        if !actual_result.success.is_empty() {
            assert!(
                account
                    .borrow_mut()
                    .fetch_foreign_smtp_tls_status("example.com")
                    .unwrap()
                    .unwrap()
                    .valid_certificate
            );
        }
    }

    fn parse_mx_record(r: &str) -> Option<(Rc<dns::Name>, u16)> {
        let (pref, name) = r.split_once('@')?;
        let pref = pref.parse::<u16>().ok()?;
        let name = dns::Name::from_ascii(name).ok()?;
        Some((Rc::new(name), pref))
    }

    fn emails_vec() -> Vec<String> {
        vec!["one@example.com".to_owned(), "two@example.com".to_owned()]
    }

    fn output_tls_status() -> ForeignSmtpTlsStatus {
        ForeignSmtpTlsStatus {
            domain: "example.com".to_owned(),
            starttls: true,
            tls_version: None,
            valid_certificate: true,
        }
    }

    #[test]
    fn simple_happy_path() {
        run_test(
            &[
                ("example.com", &["10@mx2.example.com", "20@mx1.example.com"]),
                ("mx1.example.com", &["1.2.3.4"]),
            ],
            &[(
                "1.2.3.4",
                Ok(transact::Results {
                    success: emails_vec(),
                    tempfail: vec![],
                    permfail: vec![],
                    tls_status: output_tls_status(),
                }),
            )],
            &["one@example.com", "two@example.com"],
            &[],
            &[],
        );
    }

    #[test]
    fn simple_happy_path_ipv6() {
        run_test(
            &[
                ("example.com", &["10@mx2.example.com", "20@mx1.example.com"]),
                ("mx1.example.com", &["dead::beef"]),
            ],
            &[(
                "dead::beef",
                Ok(transact::Results {
                    success: emails_vec(),
                    tempfail: vec![],
                    permfail: vec![],
                    tls_status: output_tls_status(),
                }),
            )],
            &["one@example.com", "two@example.com"],
            &[],
            &[],
        );
    }

    #[test]
    fn no_mx_fallback() {
        run_test(
            &[("example.com", &["1.2.3.4"])],
            &[(
                "1.2.3.4",
                Ok(transact::Results {
                    success: emails_vec(),
                    tempfail: vec![],
                    permfail: vec![],
                    tls_status: output_tls_status(),
                }),
            )],
            &["one@example.com", "two@example.com"],
            &[],
            &[],
        );
    }

    #[test]
    fn connect_try_next_server_ip_address() {
        run_test(
            &[
                ("example.com", &["10@mx2.example.com", "20@mx1.example.com"]),
                ("mx1.example.com", &["1.2.3.4", "4.5.6.7"]),
            ],
            &[
                ("1.2.3.4", Err(transact::Error::TryNextServer)),
                (
                    "4.5.6.7",
                    Ok(transact::Results {
                        success: emails_vec(),
                        tempfail: vec![],
                        permfail: vec![],
                        tls_status: output_tls_status(),
                    }),
                ),
            ],
            &["one@example.com", "two@example.com"],
            &[],
            &[],
        );
    }

    #[test]
    fn connect_try_next_server_mx_record() {
        run_test(
            &[
                ("example.com", &["10@mx2.example.com", "20@mx1.example.com"]),
                ("mx1.example.com", &["1.2.3.4"]),
                ("mx2.example.com", &["4.5.6.7"]),
            ],
            &[
                ("1.2.3.4", Err(transact::Error::TryNextServer)),
                (
                    "4.5.6.7",
                    Ok(transact::Results {
                        success: emails_vec(),
                        tempfail: vec![],
                        permfail: vec![],
                        tls_status: output_tls_status(),
                    }),
                ),
            ],
            &["one@example.com", "two@example.com"],
            &[],
            &[],
        );
    }

    #[test]
    fn connect_total_failure() {
        run_test(
            &[
                ("example.com", &["10@mx2.example.com", "20@mx1.example.com"]),
                ("mx1.example.com", &["1.2.3.4"]),
                ("mx2.example.com", &["4.5.6.7"]),
            ],
            &[("1.2.3.4", Err(transact::Error::TotalFailure))],
            &[],
            &[],
            &["one@example.com", "two@example.com"],
        );
    }

    #[test]
    fn a_record_error() {
        run_test(
            &[
                ("example.com", &["10@mx2.example.com", "20@mx1.example.com"]),
                ("mx1.example.com", &["a-error"]),
                ("mx2.example.com", &["4.5.6.7"]),
            ],
            &[(
                "4.5.6.7",
                Ok(transact::Results {
                    success: emails_vec(),
                    tempfail: vec![],
                    permfail: vec![],
                    tls_status: output_tls_status(),
                }),
            )],
            &["one@example.com", "two@example.com"],
            &[],
            &[],
        );
    }

    #[test]
    fn a_record_not_found() {
        run_test(
            &[
                ("example.com", &["10@mx2.example.com", "20@mx1.example.com"]),
                ("mx2.example.com", &["4.5.6.7"]),
            ],
            &[(
                "4.5.6.7",
                Ok(transact::Results {
                    success: emails_vec(),
                    tempfail: vec![],
                    permfail: vec![],
                    tls_status: output_tls_status(),
                }),
            )],
            &["one@example.com", "two@example.com"],
            &[],
            &[],
        );
    }

    #[test]
    fn mx_record_error() {
        run_test(
            &[("example.com", &["mx-error"])],
            &[],
            &[],
            &["one@example.com", "two@example.com"],
            &[],
        );
    }

    #[test]
    fn all_servers_tempfail() {
        run_test(
            &[
                ("example.com", &["10@mx2.example.com", "20@mx1.example.com"]),
                ("mx2.example.com", &["a-error", "aaaa-error"]),
            ],
            &[],
            &[],
            &["one@example.com", "two@example.com"],
            &[],
        );
    }
}
