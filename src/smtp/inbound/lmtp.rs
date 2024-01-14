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
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use chrono::prelude::*;
use log::error;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

use super::super::codes::*;
use super::{bridge::*, delivery::*};
use crate::{
    account::model::CommonPaths,
    support::{
        buffer::BufferWriter, log_prefix::LogPrefix,
        system_config::SystemConfig,
    },
};

pub async fn serve_lmtp(
    io: crate::support::async_io::ServerIo,
    config: Arc<SystemConfig>,
    log_prefix: LogPrefix,
    ssl_acceptor: openssl::ssl::SslAcceptor,
    users_dir: PathBuf,
    local_host_name: String,
    peer_name: String,
) -> Result<(), crate::support::error::Error> {
    let common_paths = Arc::new(CommonPaths {
        tmp: std::env::temp_dir(),
        garbage: std::env::temp_dir(),
    });

    let (request_tx, request_rx) = mpsc::channel(1);
    let server_service = super::server::Service {
        lmtp: true,
        offer_binarymime: true,
        send_request: request_tx,
    };

    let mut service = LmtpService {
        log_prefix: log_prefix.clone(),
        config,
        common_paths,
        users_dir,
        local_host_name: local_host_name.clone(),
        peer_name,
        request_in: request_rx,

        tls: None,
        helo_host: String::new(),
        return_path: String::new(),
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

struct LmtpService {
    log_prefix: LogPrefix,
    config: Arc<SystemConfig>,
    common_paths: Arc<CommonPaths>,
    users_dir: PathBuf,
    request_in: mpsc::Receiver<Request>,

    local_host_name: String,
    peer_name: String,

    tls: Option<String>,
    helo_host: String,
    return_path: String,
}

impl LmtpService {
    async fn run(&mut self) {
        loop {
            let Some(request) = self.request_in.recv().await else {
                return;
            };

            match request.payload {
                RequestPayload::Helo(helo) => {
                    if !"LHLO".eq_ignore_ascii_case(&helo.command) {
                        let _ = request.respond.send(Err(SmtpResponse(
                            pc::CommandSyntaxError,
                            Some((cc::PermFail, sc::WrongProtocolVersion)),
                            Cow::Borrowed("This is LMTP, not SMTP"),
                        )));
                    } else {
                        self.helo_host = helo.host;
                        self.tls = helo.tls;
                        let _ = request.respond.send(Ok(()));
                    }
                },

                RequestPayload::Reset => {
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
                    self.return_path = mail_request.from;
                    let _ = request.respond.send(Ok(()));
                    self.handle_mail_transaction().await;
                },
            }
        }
    }

    async fn handle_mail_transaction(&mut self) {
        let mut recipients = Vec::<Recipient>::new();
        let mut data_buffer = BufferWriter::new(Arc::clone(&self.common_paths));

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
                    let result = match Recipient::normalise_and_validate(
                        &self.config.smtp,
                        &self.users_dir,
                        &recipient.to,
                    ) {
                        Ok(r) => {
                            recipients.push(r);
                            Ok(())
                        },

                        Err(response) => Err(response),
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

        let DataRequest {
            data,
            recipient_responses,
        } = data;
        let copy_result = {
            // Move `data` into here so it gets dropped at the end of this
            // scope.
            let mut data = data;
            let mut buffer = [0u8; 4096];
            loop {
                let nread = match data.read(&mut buffer).await {
                    Ok(0) => break data_buffer.flip(),
                    Err(e) => break Err(e),
                    Ok(n) => n,
                };

                match data_buffer.write_all(&buffer[..nread]) {
                    Ok(_) => {},
                    Err(e) => break Err(e),
                }
            }
        };

        let Ok(recipient_responses) = recipient_responses.await else {
            return;
        };

        let mut buffer_reader = match copy_result {
            Ok(r) => r,
            Err(e) => {
                error!("{} buffering message failed: {e}", self.log_prefix);
                let response = SmtpResponse(
                    pc::TransactionFailed,
                    Some((cc::TempFail, sc::OtherMailSystem)),
                    Cow::Borrowed("internal I/O error"),
                );

                for _ in 0..recipients.len() {
                    if recipient_responses
                        .send(Err(response.clone()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }

                return;
            },
        };

        let now = Utc::now();
        let smtp_date = now.to_rfc2822();

        for recipient in recipients {
            // This only resembles the SMTP standard format for this header.
            // The biggest difference is that we just report the raw
            // representation of the peer address since we can't really conform
            // to the formal syntax (usually it's a UNIX socket path and not an
            // IP address).
            let message_prefix = format!(
                "Received: from {} ({})\r\n\
                 \tby {} ({} {}.{}.{}) via {}\r\n\
                 \tfor <{}>;\r\n\
                 \t{}\r\n",
                self.helo_host,
                self.peer_name,
                self.local_host_name,
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION_MAJOR"),
                env!("CARGO_PKG_VERSION_MINOR"),
                env!("CARGO_PKG_VERSION_PATCH"),
                match self.tls {
                    None => "LMTP".to_owned(),
                    Some(ref tls) => format!("LMTP+TLS ({tls})"),
                },
                recipient.smtp,
                smtp_date,
            );

            let _ = recipient_responses
                .send(deliver_local(
                    &self.log_prefix,
                    &self.config,
                    &self.users_dir,
                    &recipient,
                    &mut buffer_reader,
                    &message_prefix,
                ))
                .await;
        }
    }
}
