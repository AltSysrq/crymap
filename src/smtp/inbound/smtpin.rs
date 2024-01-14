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

#![allow(dead_code)] // TODO Remove

use std::borrow::Cow;
use std::cell::RefCell;
use std::fmt::Write as _;
use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::prelude::*;
use futures::{future::FutureExt, stream::StreamExt};
use itertools::Itertools;
use lazy_static::lazy_static;
use log::{error, warn};
use rand::Rng;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

use super::super::{codes::*, dmarc, spf};
use super::{bridge::*, delivery::*};
use crate::{
    account::model::CommonPaths,
    mime::{dkim, header},
    support::{
        append_limit::APPEND_SIZE_LIMIT,
        buffer::{BufferReader, BufferWriter},
        dns,
        log_prefix::LogPrefix,
        system_config::{self, SystemConfig},
    },
};

const MAX_RECIPIENTS: usize = 50;
const MAX_HEADER_BLOCK_SIZE: usize = 1 << 18;

struct Server {
    log_prefix: LogPrefix,
    config: Arc<SystemConfig>,
    common_paths: Arc<CommonPaths>,
    users_dir: PathBuf,
    request_in: mpsc::Receiver<Request>,
    dns_resolver: Rc<dns::Resolver>,
    dns_cache: Rc<RefCell<dns::Cache>>,

    local_host_name: String,
    peer_ip: IpAddr,

    tls: Option<String>,
    helo_host: String,
    helo_domain: Option<DomainInfo>,
    mail_from_domain: Option<DomainInfo>,
    return_path: String,
}

struct DomainInfo {
    subdomain: Rc<dns::Name>,
    org_domain: Rc<dns::Name>,
    dmarc_domain: Option<Rc<dns::Name>>,
    spf: AsyncValue<(spf::SpfResult, spf::Explanation)>,
}

impl Server {
    async fn run(&mut self) {
        loop {
            let Some(request) = self.request_in.recv().await else {
                return;
            };

            match request.payload {
                RequestPayload::Helo(helo) => {
                    let response = self.req_helo(helo);
                    let _ = request.respond.send(response);
                },

                RequestPayload::Reset => {
                    self.mail_from_domain = None;
                    self.return_path.clear();
                    let _ = request.respond.send(Ok(()));
                },

                RequestPayload::Auth(_)
                | RequestPayload::Recipient(_)
                | RequestPayload::Data(_) => {
                    let _ = request
                        .respond
                        .send(Err(SmtpResponse::internal_sequence_error()));
                },

                RequestPayload::Mail(mail_request) => {
                    let result = self.req_mail(mail_request);
                    let ok = result.is_ok();
                    let _ = request.respond.send(result);
                    if ok {
                        self.handle_mail_transaction().await;
                    } else {
                        warn!(
                            "{} Rejected MAIL FROM due to bad return path",
                            self.log_prefix,
                        );
                    }

                    self.return_path.clear();
                    self.mail_from_domain = None;
                },
            }
        }
    }

    fn req_helo(
        &mut self,
        req: HeloRequest,
    ) -> Result<(), SmtpResponse<'static>> {
        if "LHLO".eq_ignore_ascii_case(&req.command) {
            return Err(SmtpResponse(
                pc::CommandSyntaxError,
                Some((cc::PermFail, sc::WrongProtocolVersion)),
                Cow::Borrowed("This is SMTP, not LMTP"),
            ));
        }

        // Set helo_host first because domain_info() reads it.
        self.helo_host = req.host.clone();
        self.helo_domain = self.domain_info(req.host, true);

        Ok(())
    }

    fn req_mail(
        &mut self,
        req: MailRequest,
    ) -> Result<(), SmtpResponse<'static>> {
        if !req.from.contains('@') {
            return Err(SmtpResponse(
                pc::ActionNotTakenPermanent,
                Some((cc::PermFail, sc::BadSenderMailboxAddressSyntax)),
                Cow::Borrowed("Return path must be an email address"),
            ));
        }

        self.mail_from_domain = self.domain_info(req.from.clone(), true);
        if self.mail_from_domain.is_none() {
            return Err(SmtpResponse(
                pc::ActionNotTakenPermanent,
                Some((cc::PermFail, sc::BadSenderMailboxAddressSyntax)),
                Cow::Borrowed("Return path domain is invalid"),
            ));
        }

        self.return_path = req.from;

        Ok(())
    }

    async fn handle_mail_transaction(&mut self) {
        let mut recipients = Vec::<Recipient>::new();

        let data = loop {
            let Some(request) = self.request_in.recv().await else {
                return;
            };

            match request.payload {
                RequestPayload::Reset => {
                    let _ = request.respond.send(Ok(()));
                    return;
                },

                RequestPayload::Recipient(recipient) => {
                    if recipients.len() >= 50 {
                        let _ = request.respond.send(Err(SmtpResponse(
                            pc::InsufficientStorage,
                            Some((cc::PermFail, sc::TooManyRecipients)),
                            Cow::Borrowed("Too many recipients"),
                        )));
                        continue;
                    }

                    let result = self.accept_recipient(recipient);
                    let result = match result {
                        Ok(r) => {
                            recipients.push(r);
                            Ok(())
                        },
                        Err(r) => Err(r),
                    };

                    let _ = request.respond.send(result);
                },

                RequestPayload::Data(data) => {
                    let _ = request.respond.send(Ok(()));
                    break data;
                },

                RequestPayload::Helo(_)
                | RequestPayload::Auth(_)
                | RequestPayload::Mail(_) => {
                    let _ = request
                        .respond
                        .send(Err(SmtpResponse::internal_sequence_error()));
                },
            }
        };

        let data_result = self.consume_data(data.data).await;
        let Ok(recipient_responses) = data.recipient_responses.await else {
            return;
        };

        let deliverable_message = match data_result {
            Ok(dm) => dm,
            Err(response) => {
                let _ = recipient_responses.send(Err(response)).await;
                return;
            },
        };

        let response = self.deliver_message(recipients, deliverable_message);
        let _ = recipient_responses.send(response).await;
    }

    async fn consume_data(
        &mut self,
        mut data: tokio::io::DuplexStream,
    ) -> Result<DeliverableMessage, SmtpResponse<'static>> {
        lazy_static! {
            static ref END_OF_HEADERS: regex::bytes::Regex =
                regex::bytes::Regex::new("\r?\n\r?\n").unwrap();
        }

        let mut header_buffer_len = 0usize;
        let mut header_buffer = Vec::<u8>::new();

        // We start by collecting data into header_buffer until we find the
        // end of the header block.
        let headers_end = loop {
            header_buffer.resize(header_buffer_len + 1024, 0);
            let nread = match data
                .read(&mut header_buffer[header_buffer_len..])
                .await
            {
                // Should be unreachable
                Err(_) => {
                    return Err(SmtpResponse(
                        pc::TransactionFailed,
                        None,
                        Cow::Borrowed("Internal I/O error"),
                    ))
                },

                Ok(0) => {
                    return Err(SmtpResponse(
                        pc::TransactionFailed,
                        Some((cc::PermFail, sc::OtherMediaError)),
                        Cow::Borrowed("Could not find end of header block"),
                    ))
                },

                Ok(n) => n,
            };

            let search_start = header_buffer_len.saturating_sub(4);
            header_buffer_len += nread;
            if let Some(m) = END_OF_HEADERS
                .find(&header_buffer[search_start..header_buffer_len])
            {
                break m.end();
            }

            if header_buffer_len > MAX_HEADER_BLOCK_SIZE {
                return Err(SmtpResponse(
                    pc::TransactionFailed,
                    Some((cc::PermFail, sc::MessageTooBigForSystem)),
                    Cow::Borrowed("Message header block too large"),
                ));
            }
        };

        // We now have the full header block (and possibly a little extra).
        // Start the validation that depends on that.
        let header_block = &header_buffer[..headers_end];
        let from_header_domain = self.from_header_domain_info(header_block)?;
        let mut dkim_verifier = dkim::Verifier::new(header_block);

        for (selector, sdid) in dkim_verifier.want_txt_records() {
            let mut dns_cache = self.dns_cache.borrow_mut();
            if let Ok(name) = dns_cache
                .intern_domain(Cow::Owned(format!("{selector}._dkim.{sdid}")))
            {
                let _ = dns::look_up(&mut dns_cache.txt, name);
            }
        }
        dns::spawn_lookups(&self.dns_cache, &self.dns_resolver);

        // The various DNS processes have all been queued and will execute as
        // we process the rest of the message.
        let mut data_buffer = BufferWriter::new(Arc::clone(&self.common_paths));
        let io_result = 'yeet: {
            macro_rules! try_or_yeet {
                ($e:expr $(,)*) => {
                    match $e {
                        Ok(v) => v,
                        Err(e) => break 'yeet Err(e),
                    }
                };
            }

            try_or_yeet!(
                data_buffer.write_all(&header_buffer[..header_buffer_len]),
            );
            // The part of header_buffer which is beyond headers_end is part of
            // the body that needs to be verified.
            try_or_yeet!(dkim_verifier
                .write_all(&header_buffer[headers_end..header_buffer_len]));

            let mut buffer = [0u8; 1024];
            loop {
                let nread = try_or_yeet!(data.read(&mut buffer).await);
                if 0 == nread {
                    break;
                }

                try_or_yeet!(data_buffer.write_all(&buffer[..nread]));
                if data_buffer.len() > APPEND_SIZE_LIMIT as u64 {
                    break;
                }
            }

            Ok(())
        };

        if let Err(e) = io_result {
            error!("{} Buffering message failed: {e}", self.log_prefix);
            return Err(SmtpResponse(
                pc::TransactionFailed,
                Some((cc::TempFail, sc::OtherMailSystem)),
                Cow::Borrowed("Internal I/O error"),
            ));
        }

        if data_buffer.len() > APPEND_SIZE_LIMIT as u64 {
            return Err(SmtpResponse(
                pc::TransactionFailed,
                Some((cc::PermFail, sc::MessageLengthExceedsLimit)),
                Cow::Owned(format!(
                    "Maximum message size is {} bytes",
                    APPEND_SIZE_LIMIT,
                )),
            ));
        }

        let (dmarc_txt_records, dkim_txt_records) = self
            .fetch_dmarc_dkim_records(&from_header_domain, &dkim_verifier)
            .await;

        let auth_headers = self
            .authenticate_message(
                from_header_domain,
                dkim_verifier,
                dmarc_txt_records,
                dkim_txt_records,
            )
            .await
            .map_err(|_| {
                SmtpResponse(
                    pc::ActionAborted,
                    Some((cc::PermFail, sc::DeliveryNotAuthorised)),
                    Cow::Borrowed("Message rejected by DMARC policy"),
                )
            })?;

        let data_buffer = data_buffer.flip().map_err(|_| {
            SmtpResponse(
                pc::TransactionFailed,
                Some((cc::TempFail, sc::OtherMailSystem)),
                Cow::Borrowed("Internal I/O error"),
            )
        })?;

        Ok(DeliverableMessage {
            auth_headers,
            data_buffer,
        })
    }

    fn accept_recipient(
        &self,
        req: RecipientRequest,
    ) -> Result<Recipient, SmtpResponse<'static>> {
        if req.to.eq_ignore_ascii_case("postmaster") {
            // RFC 5321 § 4.5 requires "postmaster" (with no domain) to be a
            // special case that bypasses validation.
            return Recipient::normalise_and_validate(
                &self.config.smtp,
                &self.users_dir,
                &req.to,
            );
        }

        let Some((_, domain)) = req.to.rsplit_once('@') else {
            return Err(SmtpResponse(
                pc::ActionNotTakenPermanent,
                Some((cc::PermFail, sc::BadDestinationMailboxAddressSyntax)),
                Cow::Borrowed(
                    "no such user - specifying the domain is mandatory",
                ),
            ));
        };

        let Ok(domain) = dns::Name::from_str_relaxed(domain) else {
            return Err(SmtpResponse(
                pc::ActionNotTakenPermanent,
                Some((cc::PermFail, sc::BadDestinationMailboxAddressSyntax)),
                Cow::Borrowed("no such user - domain is invalid"),
            ));
        };

        let domain = system_config::DomainName(domain);
        if !self.config.smtp.domains.contains_key(&domain) {
            return Err(SmtpResponse(
                pc::UserNotLocal,
                Some((cc::PermFail, sc::DeliveryNotAuthorised)),
                Cow::Borrowed("Relay not permitted"),
            ));
        }

        Recipient::normalise_and_validate(
            &self.config.smtp,
            &self.users_dir,
            &req.to,
        )
    }

    fn domain_info(&self, s: String, run_spf: bool) -> Option<DomainInfo> {
        let domain_str = s.rsplit_once('@').map_or(s.as_str(), |rs| rs.1);
        let subdomain = Rc::new(dns::Name::from_str_relaxed(domain_str).ok()?);
        let org_domain = Rc::new(dmarc::organisational_domain(&subdomain));
        let spf_deadline = Instant::now() + Duration::from_secs(20);

        let helo_domain = self.helo_host.clone();
        let sender_domain_parsed = Rc::clone(&subdomain);
        let ip = self.peer_ip;
        let receiver_host = self.local_host_name.clone();
        let dns_cache = Rc::clone(&self.dns_cache);
        let dns_resolver = Rc::clone(&self.dns_resolver);
        let spf_task = if run_spf {
            Some(tokio::task::spawn_local(async move {
                let s_split = s.rsplit_once('@');
                let ctx = spf::Context {
                    sender: if s_split.is_some() {
                        Some(Cow::Borrowed(&s))
                    } else {
                        None
                    },
                    sender_local: s
                        .rsplit_once('@')
                        .map(|rs| Cow::Borrowed(rs.0)),
                    sender_domain: Cow::Borrowed(
                        s_split.map_or(s.as_str(), |rs| rs.1),
                    ),
                    sender_domain_parsed,

                    helo_domain: Cow::Owned(helo_domain),
                    ip,
                    receiver_host: Cow::Owned(receiver_host),
                    now: Utc::now(),
                };

                spf::run(&ctx, dns_cache, dns_resolver, spf_deadline.into())
                    .await
            }))
        } else {
            None
        };

        // Speculatively prepare to fetch the DMARC record for the
        // organisational domain.
        let dmarc_domain = dns::Name::from_ascii("_dmarc")
            .unwrap()
            .append_domain(&org_domain)
            .ok()
            .map(Rc::new);
        if let Some(ref dmarc_domain) = dmarc_domain {
            let _ = dns::look_up(
                &mut self.dns_cache.borrow_mut().txt,
                dmarc_domain,
            );
            dns::spawn_lookups(&self.dns_cache, &self.dns_resolver);
        }

        Some(DomainInfo {
            subdomain,
            org_domain,
            dmarc_domain,
            spf: spf_task.map(Into::into).unwrap_or_else(|| {
                (spf::SpfResult::None, spf::Explanation::None).into()
            }),
        })
    }

    #[allow(clippy::wrong_self_convention)] // not that sort of "from"
    fn from_header_domain_info(
        &self,
        header_block: &[u8],
    ) -> Result<Option<DomainInfo>, SmtpResponse<'static>> {
        // RFC 7489 § 6.6.1 provides guidance on pathological cases.

        // If there's not exactly one From header, the message is invalid and
        // must be rejected.
        let from_header = header::FULL_HEADER_LINE
            .captures_iter(header_block)
            .filter(|m| {
                std::str::from_utf8(m.get(2).unwrap().as_bytes())
                    .ok()
                    .is_some_and(|n| "From".eq_ignore_ascii_case(n))
            })
            .map(|m| m.get(3).unwrap().as_bytes())
            .exactly_one()
            .map_err(|e| {
                SmtpResponse(
                    pc::TransactionFailed,
                    Some((cc::PermFail, sc::OtherMediaError)),
                    Cow::Borrowed(if e.count() > 1 {
                        "Message has multiple From headers"
                    } else {
                        "Message has no From header"
                    }),
                )
            })?;

        let from_addresses =
            header::parse_address_list(from_header).ok_or(SmtpResponse(
                pc::TransactionFailed,
                Some((cc::PermFail, sc::OtherMediaError)),
                Cow::Borrowed("Message From header is invalid"),
            ))?;

        if from_addresses.is_empty() {
            return Err(SmtpResponse(
                pc::TransactionFailed,
                Some((cc::PermFail, sc::OtherMediaError)),
                Cow::Borrowed("Message From header has no addresses"),
            ));
        }

        // If there's more than one From address, we can't do any verification.
        // (RFC 7489 says to reject "because the sorts of mail normally protected by
        // DMARC do not use this format", but we can't evaluate whether DMARC
        // is in effect without evaluating all of them.)
        if from_addresses.len() > 1 {
            return Ok(None);
        }

        let &header::Address::Mailbox(ref mailbox) = &from_addresses[0] else {
            // RFC 7489 says to do no validation if From is a group.
            return Ok(None);
        };

        let mut local = String::new();
        for part in &mailbox.addr.local {
            if !local.is_empty() {
                local.push('.');
            }
            local.push_str(&String::from_utf8_lossy(part));
        }

        let mut domain = String::new();
        for part in &mailbox.addr.domain {
            if !domain.is_empty() {
                domain.push('.');
            }
            domain.push_str(&String::from_utf8_lossy(part));
        }

        if domain.is_empty() {
            return Ok(None);
        }

        let sender = format!("{local}@{domain}");
        let Some(domain_info) = self.domain_info(sender, false) else {
            return Err(SmtpResponse(
                pc::TransactionFailed,
                Some((cc::PermFail, sc::OtherMediaError)),
                Cow::Borrowed("Message From address has invalid domain"),
            ));
        };

        Ok(Some(domain_info))
    }

    async fn fetch_dmarc_dkim_records(
        &self,
        from_header_domain: &Option<DomainInfo>,
        dkim_verifier: &dkim::Verifier<'_>,
    ) -> (
        Result<Vec<Rc<str>>, dns::CacheError>,
        Vec<dkim::TxtRecordEntry>,
    ) {
        let dns_deadline = Instant::now() + Duration::from_secs(20);
        let dkim_txt_records = dkim_verifier
            .want_txt_records()
            .filter_map(|(selector, sdid)| {
                let selector = selector.to_owned();
                let sdid = sdid.to_owned();
                let name = self
                    .dns_cache
                    .borrow_mut()
                    .intern_domain(Cow::Owned(format!(
                        "{selector}._dkim.{sdid}"
                    )))
                    .ok()?;
                let dns_cache = &self.dns_cache;
                let dns_resolver = &self.dns_resolver;
                Some(async move {
                    let result = tokio::time::timeout_at(
                        dns_deadline.into(),
                        dns::wait_for(dns_cache, dns_resolver, |cache| {
                            dns::look_up(&mut cache.txt, &name).cloned()
                        }),
                    )
                    .await
                    .unwrap_or(Err(dns::CacheError::Error));

                    match result {
                        Ok(results) => results
                            .into_iter()
                            .map(|txt| dkim::TxtRecordEntry {
                                selector: selector.clone(),
                                sdid: sdid.clone(),
                                txt: Ok(txt),
                            })
                            .collect::<Vec<_>>(),
                        Err(_) => vec![dkim::TxtRecordEntry {
                            selector,
                            sdid,
                            txt: Err(()),
                        }],
                    }
                })
            })
            .collect::<futures::stream::FuturesUnordered<_>>()
            .flat_map(futures::stream::iter)
            .collect::<Vec<_>>();

        let dmarc_txt_record =
            tokio::time::timeout_at(dns_deadline.into(), async {
                if let Some(dmarc_domain) = from_header_domain
                    .as_ref()
                    .and_then(|di| di.dmarc_domain.as_ref())
                {
                    dns::wait_for(
                        &self.dns_cache,
                        &self.dns_resolver,
                        |cache| {
                            dns::look_up(&mut cache.txt, dmarc_domain).cloned()
                        },
                    )
                    .await
                } else {
                    Err(dns::CacheError::NotFound)
                }
            })
            .map(|r| r.unwrap_or(Err(dns::CacheError::Error)));

        tokio::join!(dmarc_txt_record, dkim_txt_records)
    }

    async fn authenticate_message(
        &mut self,
        from_header_domain: Option<DomainInfo>,
        dkim_verifier: dkim::Verifier<'_>,
        dmarc_records: Result<Vec<Rc<str>>, dns::CacheError>,
        dkim_records: Vec<dkim::TxtRecordEntry>,
    ) -> Result<String, ()> {
        let mut headers = String::new();

        let spf_result = if let Some(ref mut domain) = self.mail_from_domain {
            Some((
                "envelope-from",
                Rc::clone(&domain.subdomain),
                domain.spf.get().await,
            ))
        } else if let Some(ref mut domain) = self.helo_domain {
            Some(("helo", Rc::clone(&domain.subdomain), domain.spf.get().await))
        } else {
            None
        };

        let dmarc_record = dmarc_records.as_ref().and_then(|txts| {
            txts.first()
                .ok_or(&dns::CacheError::NotFound)
                .map(|t| dmarc::Record::parse(t))
        });
        let fallback_dmarc_record = dmarc::Record {
            version: "DMARC1",
            dkim: Default::default(),
            spf: Default::default(),
            failure_reporting: Default::default(),
            requested_receiver_policy: Default::default(),
            subdomain_receiver_policy: Default::default(),
            percent: 0,
            report_format: "",
            report_interval: 0,
            aggregate_report_addresses: None,
            message_report_addresses: None,
        };
        let effective_dmarc_policy = match dmarc_record {
            Ok(Ok(ref record)) => record,
            _ => &fallback_dmarc_record,
        };

        // RFC 7001
        let mut reject = if let Some(ref domain) = from_header_domain {
            let _ = write!(
                headers,
                "Authentication-Results: {receiver};\r\n",
                receiver = self.local_host_name,
            );

            let effective_dmarc_spf_result = match spf_result {
                None => {
                    let _ = write!(
                        headers,
                        "\tspf=none reason=\"no domain in HELO or \
                         MAIL FROM\";\r\n",
                    );
                    spf::SpfResult::None
                },
                Some((_, ref spf_domain, (mut r, _))) => {
                    let _ = write!(headers, "\tspf={r}");
                    if !domain.org_domain.zone_of(spf_domain) {
                        let _ =
                            write!(headers, " (but from an unrelated domain)");
                        r = spf::SpfResult::Fail;
                    } else if dmarc::AlignmentMode::Strict
                        == effective_dmarc_policy.spf
                    {
                        let _ = write!(
                            headers,
                            " (from a subdomain, but DMARC has aspf=strict)",
                        );
                        r = spf::SpfResult::Fail;
                    }
                    let _ = write!(headers, ";\r\n");
                    r
                },
            };

            let dkim_venv = dkim::VerificationEnvironment {
                now: Utc::now(),
                txt_records: dkim_records,
            };
            let dkim_result = consolidate_dkim_results(
                &domain.org_domain,
                dmarc::AlignmentMode::Relaxed == effective_dmarc_policy.dkim,
                dkim_verifier.finish(&dkim_venv),
            );

            let _ = write!(
                headers,
                "\tdkim={} (\r\n{}\t);\r\n",
                dkim_result.result, dkim_result.comments,
            );

            let (dmarc_accept, dmarc_result) = match (
                effective_dmarc_spf_result,
                dkim_result.pass,
                dmarc_record,
            ) {
                (_, _, Err(&dns::CacheError::NotFound)) => (true, "none"),

                (
                    _,
                    _,
                    Err(&dns::CacheError::NotReady | &dns::CacheError::Error),
                ) => (true, "temperror"),

                (_, _, Ok(Err(_))) => (true, "permerror"),

                (spf::SpfResult::Fail | spf::SpfResult::None, _, _)
                | (_, Some(false), _) => (false, "fail"),

                (spf::SpfResult::TempError, _, _) | (_, None, _) => {
                    (true, "temperror")
                },

                (spf::SpfResult::Pass, Some(true), _) => (true, "pass"),

                _ => (true, "neutral"),
            };

            let _ = write!(
                headers,
                "\tdmarc={dmarc_result} header.from={hf}\r\n",
                hf = domain.subdomain,
            );

            let receiver_policy = if domain.org_domain == domain.subdomain {
                effective_dmarc_policy.requested_receiver_policy
            } else {
                effective_dmarc_policy.subdomain_receiver_policy
            };

            !dmarc_accept && dmarc::ReceiverPolicy::Reject == receiver_policy
        } else {
            let _ = write!(
                headers,
                "Authentication-Results: {receiver}; none\r\n\
                 \t(no single organisational domain is responsible \
                 for this message)\r\n",
                receiver = self.local_host_name,
            );
            false
        };

        if let Some((identifier, domain, result)) = spf_result {
            format_spf_header(
                &mut headers,
                &self.local_host_name,
                self.peer_ip,
                identifier,
                &domain,
                result,
            );
        }

        reject &= rand::rngs::OsRng.gen_range(0u32..99)
            < effective_dmarc_policy.percent;
        reject &= self.config.smtp.reject_dmarc_failures;

        if reject {
            Err(())
        } else {
            Ok(headers)
        }
    }

    fn deliver_message(
        &mut self,
        recipients: Vec<Recipient>,
        mut message: DeliverableMessage,
    ) -> Result<(), SmtpResponse<'static>> {
        let now = Utc::now();
        let smtp_date = now.to_rfc2822();
        let mut message_prefix = message.auth_headers;
        let _ = write!(message_prefix, "Return-Path: {}\r\n", self.return_path);
        let message_prefix_base = message_prefix.len();

        // We don't have anywhere to hold partially-failed transactions, nor do
        // we have the ability to indicate partially-failed transactions to the
        // other side. However, partial failures here are also quite
        // exceptional. We thus use this system:
        // - We return success if any recipient succeeds.
        // - If all recipients fail, we return the first failure. In most
        //   cases, if all recipients fail, they failed for the same reason.
        // - If some fail, we log the partial failures and drop those messages
        //   on the floor.
        let mut has_success = false;
        let mut error = None::<(Recipient, SmtpResponse<'static>)>;

        for recipient in recipients {
            message_prefix.truncate(message_prefix_base);
            format_received_header(
                &mut message_prefix,
                &self.local_host_name,
                self.tls.as_deref(),
                self.helo_domain.as_ref().map(|di| &*di.subdomain),
                self.peer_ip,
                &recipient,
                &smtp_date,
            );

            let result = deliver_local(
                &self.log_prefix,
                &self.config,
                &self.users_dir,
                &recipient,
                &mut message.data_buffer,
                &message_prefix,
            );

            match result {
                Ok(()) => {
                    has_success = true;
                    if let Some((failed_recipient, failed_response)) =
                        error.take()
                    {
                        error!(
                            "{} Dropped inbound message for <{}>: {:?}",
                            self.log_prefix,
                            failed_recipient.normalised,
                            failed_response,
                        );
                    }
                },

                Err(response) => {
                    if has_success {
                        error!(
                            "{} Dropped inbound message for <{}>: {:?}",
                            self.log_prefix, recipient.normalised, response,
                        );
                    } else if error.is_none() {
                        error = Some((recipient, response));
                    }
                },
            }
        }

        match error {
            None => Ok(()),
            Some((_, response)) => Err(response),
        }
    }
}

enum AsyncValue<T> {
    Ready(T),
    Pending(tokio::task::JoinHandle<T>),
}

impl<T> Drop for AsyncValue<T> {
    fn drop(&mut self) {
        if let Self::Pending(ref task) = *self {
            task.abort();
        }
    }
}

impl<T> From<T> for AsyncValue<T> {
    fn from(inner: T) -> Self {
        Self::Ready(inner)
    }
}

impl<T> From<tokio::task::JoinHandle<T>> for AsyncValue<T> {
    fn from(task: tokio::task::JoinHandle<T>) -> Self {
        Self::Pending(task)
    }
}

impl<T: Clone> AsyncValue<T> {
    async fn get(&mut self) -> T {
        let task = match *self {
            Self::Ready(ref v) => return v.clone(),
            Self::Pending(ref mut task) => task,
        };

        let value = Pin::new(task).await.unwrap();
        *self = Self::Ready(value.clone());
        value
    }
}

struct DeliverableMessage {
    data_buffer: BufferReader,
    auth_headers: String,
}

fn format_spf_header(
    s: &mut String,
    receiver: &str,
    client_ip: IpAddr,
    identity: &str,
    domain: &dns::Name,
    result: (spf::SpfResult, spf::Explanation),
) {
    // RFC 7208 § 9.1
    let _ = write!(
        s,
        // We don't add the "SHOULD" boilerplate comment as it's entirely
        // redundant with the structured results.
        "Received-SPF: {result_str} {explanation}\r\n\
         \tidentity={identity}; client-ip={client_ip};\r\n\
         \treceiver=\"{receiver}\"; {identity}=\"{domain}\"\r\n",
        result_str = result.0,
        explanation = if let spf::Explanation::Some(ref explanation) = result.1
        {
            format!(
                "(foreign explanation: {})",
                make_header_comment_safe(explanation)
            )
        } else {
            String::new()
        },
    );
}

fn format_received_header(
    s: &mut String,
    local_host_name: &str,
    tls: Option<&str>,
    helo_domain: Option<&dns::Name>,
    peer_ip: IpAddr,
    recipient: &Recipient,
    smtp_date: &str,
) {
    // RFC 5321 § 4.4
    let _ = write!(s, "Received: from ");
    if let Some(helo_domain) = helo_domain {
        let _ = write!(s, "{} ({})", helo_domain.to_ascii(), peer_ip);
    } else {
        let _ = write!(s, "{peer_ip}");
    }
    let _ = write!(
        s,
        "\r\n\tby {local_host_name} ({svc} {vmaj}.{vmin}.{vpat})\r\n\
         \tvia TCP with {protocol}\r\n\
         \tfor <{recipient}>;\r\n\
         \t{smtp_date}\r\n",
        svc = env!("CARGO_PKG_NAME"),
        vmaj = env!("CARGO_PKG_VERSION_MAJOR"),
        vmin = env!("CARGO_PKG_VERSION_MINOR"),
        vpat = env!("CARGO_PKG_VERSION_PATCH"),
        protocol = if let Some(tls) = tls {
            format!("ESMTPS ({tls})")
        } else {
            "ESMTP".to_owned()
        },
        recipient = recipient.smtp,
    );
}

fn make_header_comment_safe(s: &str) -> Cow<'_, str> {
    const MAX_LEN: usize = 200;

    fn acceptable_char(c: char) -> bool {
        matches!(
            c, 'A'..='Z' | 'a'..='z' | '0'..='9' | ' '..='\'' | '*'..='/' |
            ':'..='?' | '_' | '@')
    }

    if s.len() <= MAX_LEN && s.chars().all(acceptable_char) {
        Cow::Borrowed(s)
    } else {
        let mut s = s.to_owned();
        s.retain(acceptable_char);
        if s.len() > MAX_LEN {
            // Won't panic since we've already filtered to ASCII
            s.truncate(MAX_LEN);
        }

        Cow::Owned(s)
    }
}

struct DkimResult {
    comments: String,
    result: &'static str,
    pass: Option<bool>,
}

fn consolidate_dkim_results(
    org_domain: &dns::Name,
    allow_subdomains: bool,
    dkim_results: impl Iterator<Item = dkim::Outcome>,
) -> DkimResult {
    let mut has_relevant_temperror = false;
    let mut has_relevant_permerror = false;
    let mut has_relevant_neutral = false;
    let mut has_relevant_pass = false;
    let mut has_relevant_fail = false;
    let mut has_relevant_policy = false;

    let mut comments = String::new();
    for outcome in dkim_results {
        let _ = write!(
            comments,
            "\t\t{domain}/{selector}: ",
            domain = outcome
                .sdid
                .as_ref()
                .map(|d| d.to_string())
                .unwrap_or("?".to_owned()),
            selector = make_header_comment_safe(
                outcome.selector.as_deref().unwrap_or("?")
            ),
        );

        let Some(sdid) = outcome.sdid else {
            match outcome.error {
                None => {
                    // Should never happen
                    let _ = write!(comments, "unknown");
                },

                Some(e) => {
                    let _ = write!(
                        comments,
                        "{}",
                        make_header_comment_safe(&e.to_string()),
                    );
                },
            }
            let _ = write!(comments, "\r\n");

            continue;
        };

        let relevant = if allow_subdomains {
            org_domain.zone_of(&sdid)
        } else {
            *org_domain == sdid
        };

        if let Some(e) = outcome.error {
            use crate::mime::dkim::Failure as F;

            let _ = write!(
                comments,
                "{}\r\n",
                make_header_comment_safe(&e.to_string()),
            );

            match e {
                dkim::Error::Io(_) | dkim::Error::Ssl(_) => {
                    has_relevant_temperror |= relevant
                },

                dkim::Error::Fail(f) => match f {
                    F::HeaderParse(..)
                    | F::DnsTxtParse(..)
                    | F::DnsTxtNotFound(..)
                    | F::UnsupportedVersion
                    | F::InvalidPublicKey
                    | F::InvalidSdid
                    | F::InvalidAuid => {
                        has_relevant_permerror |= relevant;
                    },

                    F::DnsTxtError(..) => has_relevant_temperror |= relevant,

                    F::RsaKeyTooBig => has_relevant_policy |= relevant,

                    F::TestMode(..) => has_relevant_neutral |= relevant,

                    F::WeakHashFunction
                    | F::WeakKey
                    | F::BodyTruncated
                    | F::BodyHashMismatch
                    | F::SignatureMismatch
                    | F::PublicKeyRevoked
                    | F::FromFieldUnsigned
                    | F::UnacceptableHashAlgorithm
                    | F::SignatureAlgorithmMismatch
                    | F::InvalidHashSignatureCombination
                    | F::ExpiredSignature
                    | F::FutureSignature
                    | F::AuidOutsideSdid
                    | F::AuidSdidMismatch => {
                        has_relevant_fail |= relevant;
                    },
                },
            }

            continue;
        }

        if !relevant {
            let _ = write!(comments, "valid signature, but irrelevant\r\n");
        } else {
            has_relevant_pass = true;
            let _ = write!(comments, "pass\r\n");
        }
    }

    if comments.is_empty() {
        comments.push_str("\t\tno DKIM signatures found\r\n");
    }

    let (pass, result) = if has_relevant_pass {
        (Some(true), "pass")
    } else if has_relevant_temperror {
        (None, "temperror")
    } else if has_relevant_neutral {
        (None, "neutral")
    } else if has_relevant_fail {
        (Some(false), "fail")
    } else if has_relevant_policy {
        (Some(false), "policy")
    } else if has_relevant_permerror {
        (Some(false), "permerror")
    } else {
        (Some(false), "none")
    };

    DkimResult {
        comments,
        pass,
        result,
    }
}
