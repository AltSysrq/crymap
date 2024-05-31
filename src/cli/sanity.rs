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

use std::borrow::Cow;
use std::cell::RefCell;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::rc::Rc;
use std::time::{Duration, Instant};

use chrono::prelude::*;

use super::main::*;
use crate::{
    mime::dkim,
    smtp::{dmarc, spf},
    support::{dns, system_config::*},
};

#[tokio::main(flavor = "current_thread")]
pub async fn sanity_check(
    system_config: SystemConfig,
    cmd: SmtpOutSanityCheckSubcommand,
) {
    let local_set = tokio::task::LocalSet::new();
    local_set
        .run_until(sanity_check_impl(system_config, cmd))
        .await;
}

async fn sanity_check_impl(
    system_config: SystemConfig,
    cmd: SmtpOutSanityCheckSubcommand,
) {
    if system_config.smtp.host_name.is_empty() {
        die!(
            EX_CONFIG,
            "smtp.host_name MUST be explicitly configured for outbound SMTP",
        );
    }

    let local_host_name =
        match dns::Name::from_ascii(system_config.smtp.host_name) {
            Ok(n) => n,
            Err(e) => die!(EX_CONFIG, "smtp.host_name is invalid: {e}"),
        };

    let Some((user_name, email_domain)) = cmd.email.split_once('@') else {
        die!(EX_USAGE, "<user> argument must be an email address");
    };

    let email_domain = match dns::Name::from_str_relaxed(email_domain) {
        Ok(n) => n,
        Err(e) => die!(EX_USAGE, "invalid email domain: {e}"),
    };
    let Some(smtp_domain) = system_config
        .smtp
        .domains
        .get(&DomainName(email_domain.clone()))
    else {
        die!(
            EX_CONFIG,
            "server not configured to send mail for {email_domain}"
        );
    };

    let ip_addresses = select_ip_addresses(&cmd);

    let dns_resolver =
        match hickory_resolver::AsyncResolver::tokio_from_system_conf() {
            Ok(r) => Some(Rc::new(r)),
            Err(e) => {
                die!(EX_OSERR, "Failed to initialise DNS resolver: {e}")
            },
        };
    let dns_cache = Rc::new(RefCell::new(dns::Cache::default()));

    domain_report(
        dns_resolver.as_ref(),
        &dns_cache,
        &cmd.email,
        &email_domain,
        smtp_domain,
    )
    .await;

    println!();

    spf_report(
        dns_resolver.as_ref(),
        &dns_cache,
        None,
        None,
        &local_host_name,
        &local_host_name,
        &local_host_name,
        "HELO",
        "v=spf1 a -all",
    )
    .await;
    spf_report(
        dns_resolver.as_ref(),
        &dns_cache,
        Some(&*cmd.email),
        Some(user_name),
        &email_domain,
        &email_domain,
        &local_host_name,
        "MAIL FROM",
        "v=spf1 mx -all",
    )
    .await;

    for ip in ip_addresses {
        println!();
        ip_report(
            dns_resolver.as_ref(),
            &dns_cache,
            &cmd.email,
            user_name,
            &email_domain,
            &local_host_name,
            ip,
        )
        .await;
    }
}

fn select_ip_addresses(cmd: &SmtpOutSanityCheckSubcommand) -> Vec<IpAddr> {
    if let Some(ip) = cmd.ip {
        vec![ip]
    } else {
        let mut addresses = Vec::new();
        let ipv4_addr =
            std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0))
                .and_then(|sock| {
                    sock.connect("8.8.8.8:1000")?;
                    sock.local_addr()
                });
        match ipv4_addr {
            Ok(addr) => addresses.push(addr.ip()),
            Err(e) => println!("Error getting IPv4 address: {e}"),
        }
        let ipv6_addr =
            std::net::UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, 0))
                .and_then(|sock| {
                    sock.connect(
                        "[2606:2800:21f:cb07:6820:80da:af6b:8b2c]:1000",
                    )?;
                    sock.local_addr()
                });
        match ipv6_addr {
            Ok(addr) => addresses.push(addr.ip()),
            Err(e) => println!("Error getting IPv6 address: {e}"),
        }

        if addresses.is_empty() {
            die!(EX_OSERR, "Failed to auto-detect any IP addresses");
        }

        addresses
    }
}

async fn domain_report(
    dns_resolver: Option<&Rc<dns::Resolver>>,
    dns_cache: &Rc<RefCell<dns::Cache>>,
    user_email: &str,
    domain: &dns::Name,
    domain_cfg: &SmtpDomain,
) {
    println!("Checking email domain {domain}...");
    let org_domain = dmarc::organisational_domain(domain);
    if org_domain == *domain {
        println!("\tIs organisational domain? YES");
    } else {
        println!(
            "\
\tIs organisational domain? NO
\t\tOther mail servers will not look for DMARC records at
\t\t\t_dmarc.{domain}
\t\tbut will instead look at
\t\t\t_dmarc.{org_domain}
\t\tThere is nothing you can do to change this. If you are able to set the
\t\tlatter DNS name, you can still make this work, but your DMARC settings
\t\twill need to be less strict than what this tool suggests.",
        );
    }

    check_dmarc_domain(dns_resolver, dns_cache, &org_domain).await;
    check_dkim(dns_resolver, dns_cache, user_email, domain, domain_cfg).await;
}

async fn check_dmarc_domain(
    dns_resolver: Option<&Rc<dns::Resolver>>,
    dns_cache: &Rc<RefCell<dns::Cache>>,
    org_domain: &dns::Name,
) {
    let dmarc_domain = match dns::Name::from_ascii("_dmarc")
        .unwrap()
        .append_domain(org_domain)
    {
        Err(e) => {
            println!(
                "\
\tDMARC: Unusable
\t\tThe domain _dmarc.{org_domain} is not valid: {e}",
            );
            return;
        },
        Ok(dmarc_domain) => dmarc_domain,
    };

    let txt_records =
        match dns::wait_for(dns_cache, dns_resolver, |dns_cache| {
            dns::look_up(&mut dns_cache.txt, &dmarc_domain).cloned()
        })
        .await
        {
            Ok(records) if !records.is_empty() => records,

            Err(dns::CacheError::NotFound) | Ok(_) => {
                println!(
                    "\
\t{dmarc_domain}: NOT FOUND
\t\tYou should create a TXT record here.
\t\tThe below is an valid, very strict record:
\t\t\tv=DMARC1;p=reject;aspf=s;adkim=s",
                );
                return;
            },

            Err(_) => {
                println!(
                    "\
\t{dmarc_domain}: DNS ERROR
\t\tSkipping DMARC checks.",
                );
                return;
            },
        };

    println!("\t{dmarc_domain}:");
    if txt_records.len() > 1 {
        println!(
            "\t\tThere is more than 1 record. Delete the superfluous ones.",
        );
    }
    for record in txt_records {
        print!("\t\t{record:?}: ");
        let record = match dmarc::Record::parse(&record) {
            Ok(r) => r,
            Err(e) => {
                println!("INVALID: {e}");
                println!("\t\t\tFix or delete this entry");
                continue;
            },
        };

        println!("VALID");
        if dmarc::ReceiverPolicy::Reject != record.requested_receiver_policy {
            println!("\t\t\tConsider setting p=reject for better reputation");
        }
        if dmarc::ReceiverPolicy::Reject != record.subdomain_receiver_policy {
            println!(
                "\t\t\tConsider removing the s= \
                      parameter for better reputation",
            );
        }
        if dmarc::AlignmentMode::Strict != record.dkim {
            println!("\t\t\tConsider setting adkim=s for better reputation");
        }
        if dmarc::AlignmentMode::Strict != record.spf {
            println!("\t\t\tConsider setting aspf=s for better reputation");
        }
        if record.percent < 100 {
            println!("\t\t\tConsider removing pct= for better reputation");
        }
    }
}

async fn check_dkim(
    dns_resolver: Option<&Rc<dns::Resolver>>,
    dns_cache: &Rc<RefCell<dns::Cache>>,
    user_email: &str,
    domain: &dns::Name,
    domain_cfg: &SmtpDomain,
) {
    if domain_cfg.dkim.is_empty() {
        println!(
            "\tNo DKIM is defined. DKIM is often required for major email\n\
             \tproviders such as GMail to accept your mail.\n\
             \tConsider setting up DKIM, perhaps with the following details:",
        );
        if let Err(e) = generate_dkim_config(domain) {
            println!("\t\tError generating example: {e}");
        }
        return;
    }

    let unsigned_message_header = format!(
        "From: {user_email}\r\n\
         Subject: This is the subject\r\n",
    );
    let message_body = b"This is the body.\r\n";

    let dkim_keys = domain_cfg
        .dkim
        .iter()
        .map(|(k, v)| (k.clone(), v.0.clone()))
        .collect::<Vec<_>>();
    let mut dkim_signer = dkim::Signer::new(
        &dkim_keys,
        &dkim::Signer::default_template(
            Utc::now(),
            Cow::Owned(domain.to_ascii()),
        ),
    );
    dkim_signer.write_all(message_body).unwrap();
    let dkim_headers = dkim_signer.finish(unsigned_message_header.as_bytes());

    let signed_header_block =
        format!("{dkim_headers}{unsigned_message_header}");
    let mut dkim_verifier = dkim::Verifier::new(signed_header_block.as_bytes());
    let txt_records_futures = dkim_verifier
        .want_txt_records()
        .map(|(selector, sdid)| async move {
            let Ok(domain) =
                dns::Name::from_ascii(format!("{selector}._domainkey.{sdid}"))
            else {
                return None;
            };

            match dns::wait_for(dns_cache, dns_resolver, |dns_cache| {
                dns::look_up(&mut dns_cache.txt, &domain).cloned()
            })
            .await
            {
                Ok(records) if !records.is_empty() => {
                    Some(dkim::TxtRecordEntry {
                        selector: selector.to_owned(),
                        sdid: sdid.to_owned(),
                        txt: Ok(Rc::clone(&records[0])),
                    })
                },

                Err(dns::CacheError::NotFound) | Ok(_) => None,
                Err(_) => Some(dkim::TxtRecordEntry {
                    selector: selector.to_owned(),
                    sdid: sdid.to_owned(),
                    txt: Err(()),
                }),
            }
        })
        .collect::<Vec<_>>();
    let txt_records = futures::future::join_all(txt_records_futures).await;
    let txt_records = txt_records.into_iter().flatten().collect();

    let venv = dkim::VerificationEnvironment {
        now: Utc::now(),
        txt_records,
    };
    dkim_verifier.write_all(message_body).unwrap();

    let mut error = false;
    println!("\tDKIM results:");
    for outcome in dkim_verifier.finish(&venv) {
        let Some(selector) = outcome.selector else {
            continue;
        };
        print!("\t\t{selector}._domainkey.{domain}: ");
        if let Some(e) = outcome.error {
            println!("FAIL: {e}");
            error = true;
        } else {
            println!("PASS");
        }
    }

    if error {
        println!("\tOne or more DKIM keys is improperly configured.");
    } else {
        println!("\tDKIM passes.");
    }
}

fn generate_dkim_config(
    domain: &dns::Name,
) -> Result<(), openssl::error::ErrorStack> {
    fn format_txt(algorithm: &str, pub_key: &[u8]) -> String {
        let raw =
            format!("v=DKIM1;k={algorithm};p={}", base64::encode(pub_key));
        let mut quoted = String::new();
        for start in (0..raw.len()).step_by(255) {
            if !quoted.is_empty() {
                quoted.push(' ');
            }
            quoted.push('"');
            quoted.push_str(&raw[start..(start + 255).min(raw.len())]);
            quoted.push('"');
        }
        quoted
    }

    let rsa = openssl::rsa::Rsa::generate(4096)?;
    let rsa_txt = format_txt("rsa", &rsa.public_key_to_der()?);
    let rsa_cfg = format!("rsa:{}", base64::encode(rsa.private_key_to_der()?));

    let ed25519 = openssl::pkey::PKey::generate_ed25519()?;
    let ed25519_txt = format_txt("ed25519", &ed25519.raw_public_key()?);
    let ed25519_cfg =
        format!("ed25519:{}", base64::encode(ed25519.raw_private_key()?));

    println!(
        "\
\tCreate the following DNS records:
\t\trsa._domainkey.{domain} TXT {rsa_txt}
\t\tzed25519._domainkey.{domain} TXT {ed25519_txt}
\tAnd add the following lines to your Crymap SMTP configuration for {domain}:
\t\tdkim.rsa = \"{rsa_cfg}\"
\t\tdkim.zed25519 = \"{ed25519_cfg}\"
\tYou can rename the \"rsa\" and \"zed25519\" selectors if you like, but keep
\tin mind the signatures will be sent in ascending lexicographical order by
\tselector. As of 2024-05-02, Exchange Online (i.e. outlook.com and friends)
\tonly looks at the first signature even if it doesn't understand it, and it
\tdoes not understand ED25519 signatures, so it will reject your mail as spam
\tif your ED25519 key comes first (hence the 'z' prefix in this suggestion).",
    );

    Ok(())
}

async fn spf_report(
    dns_resolver: Option<&Rc<dns::Resolver>>,
    dns_cache: &Rc<RefCell<dns::Cache>>,
    user_email: Option<&str>,
    user_name: Option<&str>,
    domain: &dns::Name,
    sender_domain: &dns::Name,
    helo_domain: &dns::Name,
    title: &str,
    recommendation: &str,
) {
    print!("{title} SPF for {domain}: ");
    let txt_records =
        match dns::wait_for(dns_cache, dns_resolver, |dns_cache| {
            dns::look_up(&mut dns_cache.txt, domain).cloned()
        })
        .await
        {
            Ok(records) => records,
            Err(dns::CacheError::NotFound) => vec![],
            Err(_) => {
                println!("DNS ERROR");
                return;
            },
        };

    let probable_spf_records = txt_records
        .into_iter()
        .filter(|s| s.starts_with("v=spf1"))
        .collect::<Vec<_>>();
    if probable_spf_records.is_empty() {
        println!("NOT FOUND");
        println!("\tConsider adding the following DNS record:");
        println!("\t\t{domain} TXT \"{recommendation}\"");
        return;
    }

    if probable_spf_records.len() > 1 {
        println!("MULTIPLE RECORDS");
        for record in probable_spf_records {
            println!("\t{record:?}");
            println!("\tRemove all but the one you want to use.");
        }
        return;
    }

    let (result, _) = spf::run(
        &spf::Context {
            sender: user_email.map(Cow::Borrowed),
            sender_local: user_name.map(Cow::Borrowed),
            sender_domain: Cow::Owned(sender_domain.to_ascii()),
            sender_domain_parsed: Rc::new(sender_domain.clone()),
            helo_domain: Cow::Owned(helo_domain.to_ascii()),
            ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
            receiver_host: Cow::Borrowed("undefined"),
            now: Utc::now(),
        },
        dns_cache.clone(),
        dns_resolver.cloned(),
        (Instant::now() + Duration::from_secs(30)).into(),
    )
    .await;

    match result {
        spf::SpfResult::None
        | spf::SpfResult::Neutral
        | spf::SpfResult::SoftFail
        | spf::SpfResult::Pass => {
            println!("TOO LAX: {result:?}");
            println!("\tThe SPF record does not assign hard failure to a test");
            println!("\tIP address which is definitely not yours.");
            println!("\t\t{:?}", probable_spf_records[0]);
            println!("\tEnsure the SPF record ends with \"-all\".");
        },

        spf::SpfResult::Fail => {
            println!("OK");
            println!("\t{:?}", probable_spf_records[0]);
        },

        spf::SpfResult::TempError | spf::SpfResult::PermError => {
            println!("ERROR");
            println!(
                "\tThe SPF record is invalid or references unresolvable \
                 domains.",
            );
            println!("\t\t{:?}", probable_spf_records[0]);
        },
    }
}

async fn ip_report(
    dns_resolver: Option<&Rc<dns::Resolver>>,
    dns_cache: &Rc<RefCell<dns::Cache>>,
    user_email: &str,
    user_name: &str,
    sender_domain: &dns::Name,
    helo_domain: &dns::Name,
    ip: IpAddr,
) {
    println!("Checking IP address {ip}...");

    match ip {
        IpAddr::V4(ip) => {
            print!("\tA record for {helo_domain}: ");
            match dns::wait_for(dns_cache, dns_resolver, |dns_cache| {
                dns::look_up(&mut dns_cache.a, helo_domain).cloned()
            })
            .await
            {
                Ok(records) if !records.is_empty() => {
                    if records.contains(&ip) {
                        println!("OK");
                    } else {
                        println!("MISMATCH");
                        println!(
                            "\t\tThe DNS A record is defined, but does \
                             not include this IP address.",
                        );
                    }
                },

                Ok(_) | Err(dns::CacheError::NotFound) => {
                    println!("NOT FOUND");
                    println!("\t\tYou MUST have the following DNS record:");
                    println!("\t\t{helo_domain} A {ip}");
                },

                Err(_) => {
                    println!("DNS ERROR");
                },
            }
        },

        IpAddr::V6(ip) => {
            print!("\tAAAA record for {helo_domain}: ");
            match dns::wait_for(dns_cache, dns_resolver, |dns_cache| {
                dns::look_up(&mut dns_cache.aaaa, helo_domain).cloned()
            })
            .await
            {
                Ok(records) if !records.is_empty() => {
                    if records.contains(&ip) {
                        println!("OK");
                    } else {
                        println!("MISMATCH");
                        println!(
                            "\t\tThe DNS AAAA record is defined, but does \
                             not include this IP address.",
                        );
                    }
                },

                Ok(_) | Err(dns::CacheError::NotFound) => {
                    println!("NOT FOUND");
                    println!("\t\tYou MUST have the following DNS record:");
                    println!("\t\t{helo_domain} AAAA {ip}");
                },

                Err(_) => {
                    println!("DNS ERROR");
                },
            }
        },
    }

    print!("\tPTR record for {ip}: ");
    match dns::wait_for(dns_cache, dns_resolver, |dns_cache| {
        dns::ptr(&mut dns_cache.ptr, ip).map(|ptr| ptr.to_owned())
    })
    .await
    {
        Ok(records) if !records.is_empty() => {
            if records.iter().any(|r| **r == *helo_domain) {
                println!("OK");
            } else {
                println!("MISMATCH");
                println!(
                    "\t\tThe DNS PTR record is defined, but does not \
                     resolve to {helo_domain}.",
                );
            }
        },

        Ok(_) | Err(dns::CacheError::NotFound) => {
            println!(
                "NOT FOUND
\t\tFor many email providers, particularly those predating DMARC, you MUST
\t\thave a DNS PTR record mapping {ip} to {helo_domain}.",
            );
        },

        Err(_) => println!("DNS ERROR"),
    }

    for (title, domain, have_user) in [
        ("HELO", helo_domain, false),
        ("MAIL FROM", sender_domain, true),
    ] {
        print!("\t{title} SPF for {domain}: ");
        let (result, _) = spf::run(
            &spf::Context {
                sender: have_user.then_some(Cow::Borrowed(user_email)),
                sender_local: have_user.then_some(Cow::Borrowed(user_name)),
                sender_domain: Cow::Owned(domain.to_ascii()),
                sender_domain_parsed: Rc::new(domain.clone()),
                helo_domain: Cow::Owned(helo_domain.to_ascii()),
                ip,
                receiver_host: Cow::Borrowed("undefined"),
                now: Utc::now(),
            },
            dns_cache.clone(),
            dns_resolver.cloned(),
            (Instant::now() + Duration::from_secs(30)).into(),
        )
        .await;
        match result {
            spf::SpfResult::Pass => println!("OK"),
            spf::SpfResult::None | spf::SpfResult::Neutral => {
                println!("NEUTRAL");
                println!(
                    "\t\tThe SPF record at {domain} is missing or too lax.",
                );
            },
            spf::SpfResult::TempError | spf::SpfResult::PermError => {
                println!("ERROR");
                println!(
                    "\t\tThe SPF record at {domain} could not be evaluated.",
                );
            },
            spf::SpfResult::SoftFail | spf::SpfResult::Fail => {
                println!("FAIL");
                println!("\t\tThe SPF record does not permit {ip}.");
            },
        }
    }
}
