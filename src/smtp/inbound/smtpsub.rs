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
use std::collections::HashSet;
use std::fmt::Write as _;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;

use chrono::prelude::*;
use itertools::Itertools;
use log::error;
use tokio::{io::AsyncReadExt, sync::mpsc};

use super::super::codes::*;
use super::{bridge::*, delivery::*};
use crate::{
    account::v2::{Account, LogInError, SmtpTransfer, SpooledMessageId},
    mime::{dkim, header},
    support::{
        append_limit::APPEND_SIZE_LIMIT,
        buffer::{BufferReader, BufferWriter},
        dns,
        error::Error,
        log_prefix::LogPrefix,
        system_config::{self, SystemConfig},
    },
};

const MAX_RECIPIENTS: usize = 50;
const MAX_HEADER_BLOCK_SIZE: usize = 1 << 18;

pub async fn serve_smtpsub(
    io: crate::support::async_io::ServerIo,
    config: Arc<SystemConfig>,
    log_prefix: LogPrefix,
    ssl_acceptor: openssl::ssl::SslAcceptor,
    data_root: PathBuf,
    local_host_name: String,
    spool_out: mpsc::Sender<SpooledMessageId>,
) -> Result<(), crate::support::error::Error> {
    let tls = io.ssl_string();
    let (request_tx, request_rx) = mpsc::channel(1);
    let server_service = super::server::Service {
        lmtp: false,
        offer_binarymime: false,
        auth: true,
        send_request: request_tx,
    };

    let mut service = SmtpsubService {
        log_prefix: log_prefix.clone(),
        config,
        data_root,
        request_in: request_rx,
        spool_out,

        account: None,
        authed_user_names: Default::default(),
        local_host_name: local_host_name.clone(),

        tls,
        return_path: Default::default(),
    };

    tokio::join![
        super::server::run(
            io,
            log_prefix,
            ssl_acceptor,
            server_service,
            local_host_name
        ),
        service.run(),
    ]
    .0
}

struct SmtpsubService {
    log_prefix: LogPrefix,
    config: Arc<SystemConfig>,
    data_root: PathBuf,
    request_in: mpsc::Receiver<Request>,
    spool_out: mpsc::Sender<SpooledMessageId>,

    account: Option<Account>,
    authed_user_names: HashSet<String>,
    local_host_name: String,

    tls: Option<String>,
    return_path: String,
}

impl SmtpsubService {
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
                    self.return_path.clear();
                    let _ = request.respond.send(Ok(()));
                },

                RequestPayload::Auth(req) => {
                    let response = self.req_auth(req);
                    let _ = request.respond.send(response);
                },

                RequestPayload::Recipient(_) | RequestPayload::Data(_) => {
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
                    }

                    self.return_path.clear();
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

        self.tls = req.tls;
        Ok(())
    }

    fn req_auth(
        &mut self,
        req: AuthRequest,
    ) -> Result<(), SmtpResponse<'static>> {
        let (account, aliases) = Account::log_in(
            self.log_prefix.clone(),
            &self.config,
            &self.data_root,
            &req.userid,
            &req.password,
        )
        .map_err(|e| match e {
            LogInError::IllegalUserId | LogInError::InvalidCredentials => {
                SmtpResponse(
                    pc::AuthenticationCredentialsInvalid,
                    Some((cc::PermFail, sc::AuthenticationCredentialsInvalid)),
                    Cow::Owned(e.to_string()),
                )
            },

            LogInError::ConfigError => SmtpResponse(
                pc::ServiceNotAvailableClosing,
                Some((cc::TempFail, sc::SystemIncorrectlyConfigured)),
                Cow::Owned(e.to_string()),
            ),

            LogInError::SetupError => SmtpResponse(
                pc::TemporaryAuthenticationFailure,
                Some((cc::TempFail, sc::SystemIncorrectlyConfigured)),
                Cow::Owned(e.to_string()),
            ),
        })?;

        self.account = Some(account);
        self.authed_user_names = aliases;
        Ok(())
    }

    fn req_mail(
        &mut self,
        req: MailRequest,
    ) -> Result<(), SmtpResponse<'static>> {
        if self.account.is_none() {
            return Err(SmtpResponse(
                pc::BadSequenceOfCommands,
                Some((cc::PermFail, sc::DeliveryNotAuthorised)),
                Cow::Borrowed("Must log in before sending mail"),
            ));
        }

        if !req.from.is_empty() {
            self.require_authed_return_path(&req.from)?;
        }
        self.return_path = req.from;
        Ok(())
    }

    async fn handle_mail_transaction(&mut self) {
        let mut recipients = Vec::<String>::new();

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
                    if recipients.len() >= MAX_RECIPIENTS {
                        let _ = request.respond.send(Err(SmtpResponse(
                            pc::InsufficientStorage,
                            Some((cc::PermFail, sc::TooManyRecipients)),
                            Cow::Borrowed("Too many recipients"),
                        )));
                        continue;
                    }

                    let Some((_, domain)) = recipient.to.rsplit_once('@')
                    else {
                        let _ = request.respond.send(Err(SmtpResponse(
                            pc::ActionNotTakenPermanent,
                            Some((
                                cc::PermFail,
                                sc::BadDestinationMailboxAddressSyntax,
                            )),
                            Cow::Borrowed(
                                "Recipient must be a full email address",
                            ),
                        )));
                        continue;
                    };

                    if dns::Name::from_str_relaxed(domain).is_err() {
                        let _ = request.respond.send(Err(SmtpResponse(
                            pc::ActionNotTakenPermanent,
                            Some((
                                cc::PermFail,
                                sc::BadDestinationMailboxAddressSyntax,
                            )),
                            Cow::Borrowed("Invalid recipient domain"),
                        )));
                        continue;
                    }

                    // Silently ignore attempts to add duplicate recipients.
                    if !recipients.contains(&recipient.to) {
                        recipients.push(recipient.to);
                    }
                    let _ = request.respond.send(Ok(()));
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
                    return;
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

        if let Err(e) =
            self.spool_message(recipients, deliverable_message).await
        {
            error!(
                "{} Failed to spool message for delivery: {e}",
                self.log_prefix,
            );
            let _ = recipient_responses
                .send(Err(SmtpResponse(
                    pc::TransactionFailed,
                    Some((cc::TempFail, sc::OtherMailSystem)),
                    Cow::Borrowed("Internal error spooling message"),
                )))
                .await;
            return;
        }

        let _ = recipient_responses.send(Ok(())).await;
    }

    async fn consume_data(
        &mut self,
        mut data: tokio::io::DuplexStream,
    ) -> Result<DeliverableMessage, SmtpResponse<'static>> {
        let (header_buffer, headers_end) =
            super::smtpin::buffer_headers(&mut data).await?;
        let header_block = &header_buffer[..headers_end];
        let now = Utc::now();
        let smtp_date = now.to_rfc2822();
        let mut transfer_detector = SmtpTransferDetector::new();

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

        if from_addresses.len() > 1 {
            return Err(SmtpResponse(
                pc::TransactionFailed,
                Some((cc::PermFail, sc::OtherMediaError)),
                Cow::Borrowed(
                    "Sending mail with multiple From addresses \
                     is not supported",
                ),
            ));
        }

        let &header::Address::Mailbox(ref mailbox) = &from_addresses[0] else {
            return Err(SmtpResponse(
                pc::TransactionFailed,
                Some((cc::PermFail, sc::OtherMediaError)),
                Cow::Borrowed(
                    "Sending mail with a mailing list in the From header \
                     is not supported",
                ),
            ));
        };

        let mailbox_addr = mailbox.addr.to_string();
        // Implicitly set the return path to the From address if the client
        // didn't suggest otherwise.
        if self.return_path.is_empty() {
            self.return_path = mailbox_addr.clone();
        }
        let (dkim_ssid, smtp_domain_cfg) =
            self.require_authed_return_path(&mailbox_addr)?;

        let dkim_key_pairs = smtp_domain_cfg
            .dkim
            .iter()
            .map(|(k, v)| (k.clone(), v.0.clone()))
            .collect::<Vec<_>>();
        let mut dkim_signer = dkim::Signer::new(
            &dkim_key_pairs,
            &dkim::Signer::default_template(
                now,
                Cow::Owned(dkim_ssid.to_ascii()),
            ),
        );

        let mut data_buffer =
            BufferWriter::new(self.account.as_ref().unwrap().common_paths());
        let io_result = 'yeet: {
            macro_rules! try_or_yeet {
                ($e:expr $(,)*) => {
                    match $e {
                        Ok(v) => v,
                        Err(e) => break 'yeet Err(e),
                    }
                };
            }

            try_or_yeet!(data_buffer.write_all(&header_buffer));
            try_or_yeet!(dkim_signer.write_all(&header_buffer[headers_end..]));
            transfer_detector.write(&header_buffer);

            let mut buffer = [0u8; 1024];
            loop {
                let nread = try_or_yeet!(data.read(&mut buffer).await);
                if 0 == nread {
                    break;
                }

                try_or_yeet!(data_buffer.write_all(&buffer[..nread]));
                try_or_yeet!(dkim_signer.write_all(&buffer[..nread]));
                transfer_detector.write(&buffer[..nread]);
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

        let mut trace_headers = dkim_signer.finish(header_block);
        let _ =
            write!(trace_headers, "Return-Path: <{}>\r\n", self.return_path);
        super::smtpin::format_received_header(
            &mut trace_headers,
            &self.local_host_name,
            self.tls.as_deref(),
            // We include no details about the point of origin since it is not
            // legitimately useful for the receiver (i.e. the user's device is
            // not a mail server) and we don't want to unnecessarily leak
            // personal information.
            None,
            None,
            // Don't include the recipient so that we don't need a separate
            // message for each destination.
            None,
            &smtp_date,
        );

        let data_buffer = data_buffer.flip().map_err(|_| {
            SmtpResponse(
                pc::TransactionFailed,
                Some((cc::TempFail, sc::OtherMailSystem)),
                Cow::Borrowed("Internal I/O error"),
            )
        })?;

        // This is out-of-order, but it doesn't matter since the trace headers
        // will always start with a non-special 7-bit character.
        transfer_detector.write(trace_headers.as_bytes());

        Ok(DeliverableMessage {
            trace_headers,
            data_buffer,
            transfer: transfer_detector.finish(),
        })
    }

    async fn spool_message(
        &mut self,
        recipients: Vec<String>,
        message: DeliverableMessage,
    ) -> Result<(), Error> {
        let account = self.account.as_mut().unwrap();
        let buffered = account.buffer_message(
            Utc::now().into(),
            io::Read::chain(
                message.trace_headers.as_bytes(),
                message.data_buffer,
            ),
        )?;
        let spooled = account.spool_message(
            buffered,
            message.transfer,
            self.return_path.clone(),
            recipients,
        )?;
        let _ = self.spool_out.send(spooled).await;
        Ok(())
    }

    fn require_authed_return_path(
        &self,
        return_path: &str,
    ) -> Result<(dns::Name, &system_config::SmtpDomain), SmtpResponse<'static>>
    {
        let Some(recipient) =
            Recipient::normalise(&self.config.smtp, return_path.to_owned())
        else {
            return Err(SmtpResponse(
                pc::ParameterSyntaxError,
                Some((cc::PermFail, sc::BadSenderMailboxAddressSyntax)),
                Cow::Borrowed("Invalid MAIL FROM or From: email address"),
            ));
        };

        if !self.authed_user_names.contains(&recipient.normalised) {
            return Err(SmtpResponse(
                pc::ActionNotTakenPermanent,
                Some((cc::PermFail, sc::DeliveryNotAuthorised)),
                Cow::Owned(format!(
                    "User not authorised to send mail for {}",
                    recipient.smtp,
                )),
            ));
        }

        let Some((_, domain)) = return_path.rsplit_once('@') else {
            return Err(SmtpResponse(
                pc::ParameterSyntaxError,
                Some((cc::PermFail, sc::BadSenderMailboxAddressSyntax)),
                Cow::Borrowed("Invalid MAIL FROM or From: email address"),
            ));
        };

        let Ok(domain) = dns::Name::from_str_relaxed(domain) else {
            return Err(SmtpResponse(
                pc::ParameterSyntaxError,
                Some((cc::PermFail, sc::BadSenderMailboxAddressSyntax)),
                Cow::Borrowed("Invalid MAIL FROM or From: domain"),
            ));
        };

        let domain = system_config::DomainName(domain);
        let Some(smtp_domain) = self.config.smtp.domains.get(&domain) else {
            return Err(SmtpResponse(
                pc::UserNotLocal,
                Some((cc::PermFail, sc::DeliveryNotAuthorised)),
                Cow::Owned(format!(
                    "Server not configured to send mail from {}",
                    domain.0.to_ascii(),
                )),
            ));
        };

        Ok((domain.0, smtp_domain))
    }
}

struct DeliverableMessage {
    data_buffer: BufferReader,
    trace_headers: String,
    transfer: SmtpTransfer,
}

struct SmtpTransferDetector {
    transfer: SmtpTransfer,
    // Whether the last buffer ended with \r
    has_trailing_cr: bool,
}

impl SmtpTransferDetector {
    fn new() -> Self {
        Self {
            transfer: SmtpTransfer::SevenBit,
            has_trailing_cr: false,
        }
    }

    fn write(&mut self, mut data: &[u8]) {
        if self.has_trailing_cr && Some(b'\n') == data.first().copied() {
            self.has_trailing_cr = false;
            data = &data[1..];
        }

        if data.is_empty() {
            return;
        }

        if self.has_trailing_cr {
            // \r not followed by \n forces binary
            self.transfer = SmtpTransfer::Binary;
            self.has_trailing_cr = false;
        }

        for triplet in std::iter::once(None::<u8>)
            .chain(data.iter().copied().map(Some))
            .chain(std::iter::once(None))
            .tuple_windows()
        {
            match triplet {
                // NUL forces binary transfer
                (_, Some(0), _) => self.transfer = SmtpTransfer::Binary,

                // Ignore DOS line endings
                (Some(b'\r'), Some(b'\n'), _) => {},
                (_, Some(b'\r'), Some(b'\n')) => {},

                // Isolated CR or LF forces binary transfer
                (_, Some(b'\n'), _) | (_, Some(b'\r'), Some(_)) => {
                    self.transfer = SmtpTransfer::Binary;
                },

                (_, Some(b'\r'), None) => {
                    self.has_trailing_cr = true;
                },

                // 8-bit values force at least 8BITMIME
                (_, Some(v), _) if v >= 128 => {
                    self.transfer = self.transfer.max(SmtpTransfer::EightBit);
                },

                // Anything else is uninteresting
                _ => {},
            }
        }
    }

    fn finish(self) -> SmtpTransfer {
        if self.has_trailing_cr {
            // Trailing CR forces binary transfer
            SmtpTransfer::Binary
        } else {
            self.transfer
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn detect_transfer(buffers: &[&[u8]]) -> SmtpTransfer {
        let mut detector = SmtpTransferDetector::new();
        for &buffer in buffers {
            detector.write(buffer);
        }
        detector.finish()
    }

    #[test]
    fn detect_smtp_transfer() {
        assert_eq!(SmtpTransfer::SevenBit, detect_transfer(&[b"hello world"]));
        assert_eq!(
            SmtpTransfer::SevenBit,
            detect_transfer(&[b"\r\nhello\r\nworld\r", b"\nfoo\r\n",]),
        );
        assert_eq!(
            SmtpTransfer::SevenBit,
            detect_transfer(&[b"\r", b"\n", b"foo"]),
        );
        assert_eq!(
            SmtpTransfer::SevenBit,
            detect_transfer(&[b"\r", b"", b"\n", b"foo"]),
        );
        assert_eq!(SmtpTransfer::Binary, detect_transfer(&[b"foo\r"]),);
        assert_eq!(SmtpTransfer::Binary, detect_transfer(&[b"foo\r", b"bar"]),);
        assert_eq!(SmtpTransfer::Binary, detect_transfer(&[b"foo\r", b""]),);
        assert_eq!(
            SmtpTransfer::Binary,
            detect_transfer(&[b"foo\r", b"\n", b"\nbar"]),
        );
        assert_eq!(SmtpTransfer::Binary, detect_transfer(&[b"foo\0bar"]),);
        assert_eq!(SmtpTransfer::EightBit, detect_transfer(&[b"f\x80\x80"]));
        assert_eq!(SmtpTransfer::Binary, detect_transfer(&[b"\nf\x80\x80"]));
        assert_eq!(SmtpTransfer::Binary, detect_transfer(&[b"f\x80\x80\n"]));
    }
}
