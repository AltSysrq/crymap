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
        self.helo_domain = self.domain_info(req.host);

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

        self.mail_from_domain = self.domain_info(req.from.clone());
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

        let _data_result = self.consume_data(data.data).await;
        let Ok(_recipient_responses) = data.recipient_responses.await else {
            return;
        };

        todo!()
    }

    async fn consume_data(
        &self,
        mut data: tokio::io::DuplexStream,
    ) -> Result<DeliverableMessage, SmtpResponse> {
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

        let (_dmarc_txt_records, _dkim_txt_records) = self
            .fetch_dmarc_dkim_records(&from_header_domain, &dkim_verifier)
            .await;

        todo!()
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

    fn domain_info(&self, s: String) -> Option<DomainInfo> {
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
        let spf_task = tokio::task::spawn_local(async move {
            let s_split = s.rsplit_once('@');
            let ctx = spf::Context {
                sender: if s_split.is_some() {
                    Some(Cow::Borrowed(&s))
                } else {
                    None
                },
                sender_local: s.rsplit_once('@').map(|rs| Cow::Borrowed(rs.0)),
                sender_domain: Cow::Borrowed(
                    s_split.map_or(s.as_str(), |rs| rs.1),
                ),
                sender_domain_parsed,

                helo_domain: Cow::Owned(helo_domain),
                ip,
                receiver_host: Cow::Owned(receiver_host),
                now: Utc::now(),
            };

            spf::run(&ctx, dns_cache, dns_resolver, spf_deadline.into()).await
        });

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
            spf: spf_task.into(),
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
        let Some(domain_info) = self.domain_info(sender) else {
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
