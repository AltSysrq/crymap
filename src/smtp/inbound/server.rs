//-
// Copyright (c) 2020, 2023, 2024, 2025 Jason Lingle
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
use std::io;
use std::pin::Pin;
use std::str;
use std::task;
use std::time::{Duration, Instant};

use log::{error, info, warn};
use openssl::ssl::SslAcceptor;
use tokio::io::{
    AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufStream, DuplexStream,
};
use tokio::sync::{mpsc, oneshot};

use super::super::{codes::*, syntax::*};
use super::bridge::*;
use crate::support::{
    append_limit::APPEND_SIZE_LIMIT, async_io::ServerIo, error::Error,
    log_prefix::LogPrefix,
};

pub(super) struct Service {
    pub(super) lmtp: bool,
    /// Whether the `BINARYMIME` extension is offered.
    ///
    /// We don't offer it on outbound SMTP because we don't support downgrading
    /// binary messages to non-binary and it is reasonably expectable that some
    /// implementations that don't offer `BINARYMIME` will in fact have issues
    /// with binary messages. (We also don't support downgrading `8BITMIME` or
    /// `SMTPUTF8`, but systems not supporting 8-bit are extinct; all that
    /// remain are systems that fail to declare their functional support for
    /// these extensions.)
    pub(super) offer_binarymime: bool,
    /// Whether authentication is in use.
    ///
    /// If true, no mail commands can be issued without authentication. If
    /// false, authentication is not permitted.
    pub(super) auth: bool,
    pub(super) send_request: mpsc::Sender<Request>,
}

struct Server {
    io: BufStream<ServerIo>,
    log_prefix: LogPrefix,
    ssl_acceptor: Option<SslAcceptor>,
    service: Service,
    local_host_name: String,

    ineffective_commands: u32,
    deadline_tx: mpsc::Sender<Instant>,
    quit: bool,
    has_helo: bool,
    has_mail_from: bool,
    has_auth: bool,
    recipients: u32,
    sending_data: Option<SendData>,

    /// Whether any UNIX newlines have been seen in commands.
    unix_newlines: bool,
}

pub(super) async fn run(
    io: ServerIo,
    log_prefix: LogPrefix,
    ssl_acceptor: Option<SslAcceptor>,
    service: Service,
    local_host_name: String,
) -> Result<(), Error> {
    let (deadline_tx, deadline_rx) = mpsc::channel(1);

    let mut server = Server {
        io: BufStream::new(io),
        log_prefix,
        ssl_acceptor,
        service,
        local_host_name,

        ineffective_commands: 0,
        deadline_tx,
        quit: false,
        has_helo: false,
        has_mail_from: false,
        has_auth: false,
        recipients: 0,
        sending_data: None,
        unix_newlines: false,
    };

    tokio::select! {
        r = server.run() => r,
        _ = idle_timer(deadline_rx) => {
            Err(Error::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "Connection idle timer expired",
            )))
        },
    }
}

struct SendData {
    stream: DuplexStream,
    recipient_responses:
        oneshot::Sender<mpsc::Sender<Result<(), SmtpResponse<'static>>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseKind {
    /// The last in a series of responses.
    ///
    /// Indicates no continuation and forces a flush.
    Final,
    /// A non-final response which needs to be sent immediately.
    ///
    /// Forces a flush, but also indicates continuation.
    Urgent,
    /// A non-final response that is safe to buffer.
    Delayable,
}

impl ResponseKind {
    fn or_final(self, phinal: bool) -> Self {
        if phinal {
            ResponseKind::Final
        } else {
            self
        }
    }

    fn indicator(self) -> char {
        match self {
            Final => ' ',
            Urgent | Delayable => '-',
        }
    }
}

use self::ResponseKind::*;

macro_rules! require {
    ($this:expr, $($fns:ident = $arg:expr,)* @else $el:block) => {
        $(if let Some(r) = $this.$fns($arg).await { $el; return r; })*
    };
    ($this:expr, $($fns:ident = $arg:expr),*) => {
        require!($this, $($fns = $arg,)* @else {})
    };
}

const MAX_LINE: usize = 1024;

static EXTENSIONS: &[&str] = &[
    "8BITMIME", // RFC 6152
    "AUTH PLAIN",
    "BINARYMIME",          // RFC 3030
    "CHUNKING",            // RFC 3030
    "ENHANCEDSTATUSCODES", // RFC 5248
    "PIPELINING",
    concat_appendlimit!("SIZE "),
    "SMTPUTF8", // RFC 6531
    "STARTTLS",
    "HELP", // The final item must be unconditional
];

impl Server {
    pub(super) async fn run(&mut self) -> Result<(), Error> {
        self.send_greeting().await?;

        let mut buffer = Vec::new();
        while !self.quit {
            self.run_command(&mut buffer).await?;
        }

        Ok(())
    }

    async fn run_command(&mut self, buffer: &mut Vec<u8>) -> Result<(), Error> {
        let _ = self
            .deadline_tx
            .send(Instant::now() + Duration::from_secs(60))
            .await;
        buffer.clear();

        (&mut self.io)
            .take(MAX_LINE as u64)
            .read_until(b'\n', buffer)
            .await?;
        if buffer.is_empty() {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF reached at start of command",
            )));
        }

        if !buffer.ends_with(b"\n") {
            if buffer.len() >= MAX_LINE {
                self.send_response(
                    Final,
                    pc::CommandSyntaxError,
                    Some((cc::PermFail, sc::OtherProtocolStatus)),
                    Cow::Borrowed("Command line too long"),
                )
                .await?;

                // Skip the rest of the line
                while !buffer.is_empty() && !buffer.ends_with(b"\n") {
                    buffer.clear();
                    (&mut self.io)
                        .take(MAX_LINE as u64)
                        .read_until(b'\n', buffer)
                        .await?;
                }

                return Ok(());
            } else {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "EOF reached within command",
                )));
            }
        }

        self.ineffective_commands += 1;
        if self.ineffective_commands > 30 {
            warn!(
                "{} Terminating connection after too many non-mail commands",
                self.log_prefix,
            );
            self.send_response(
                Final,
                pc::ServiceClosing,
                None,
                Cow::Borrowed("Too many commands issued without sending mail"),
            )
            .await?;
            self.quit = true;
            return Ok(());
        }

        let line_ending_len = if buffer.ends_with(b"\r\n") {
            2
        } else {
            self.unix_newlines = true;
            1
        };

        let command_line = &buffer[..buffer.len() - line_ending_len];
        if command_line.contains(&0) {
            warn!(
                "{} Remote is speaking binary, closing connection",
                self.log_prefix,
            );
            self.quit = true;
            return Ok(());
        }

        let command_line = match str::from_utf8(command_line) {
            Ok(s) => s,
            Err(_) => {
                warn!("{} Non-UTF-8 command received", self.log_prefix);
                self.send_response(
                    Final,
                    pc::CommandSyntaxError,
                    Some((cc::PermFail, sc::OtherProtocolStatus)),
                    Cow::Borrowed("Malformed UTF-8"),
                )
                .await?;
                return Ok(());
            },
        };

        let command = match command_line.parse::<Command>() {
            Ok(c) => c,
            Err(_) => {
                let mut debug_line = command_line;
                if let Some((truncate_len, _)) =
                    debug_line.char_indices().nth(64)
                {
                    debug_line = &debug_line[..truncate_len];
                }

                warn!(
                    "{} Received bad command {debug_line:?}",
                    self.log_prefix
                );

                if looks_like_known_command(command_line) {
                    self.send_response(
                        Final,
                        pc::ParameterSyntaxError,
                        Some((cc::PermFail, sc::InvalidCommandArguments)),
                        Cow::Borrowed("Unknown command syntax"),
                    )
                    .await?;
                } else {
                    self.send_response(
                        Final,
                        pc::CommandSyntaxError,
                        Some((cc::PermFail, sc::InvalidCommand)),
                        Cow::Borrowed("Unrecognised command"),
                    )
                    .await?;
                }

                return Ok(());
            },
        };

        match command {
            Command::Helo(command, origin) => {
                self.cmd_helo(command, origin).await
            },
            Command::Auth(mechanism, data) => {
                self.cmd_auth(mechanism, data).await
            },
            Command::MailFrom(email, size, warnings) => {
                for warning in warnings {
                    warn!("{} {}", self.log_prefix, warning);
                }
                self.cmd_mail_from(email, size).await
            },
            Command::Recipient(email, warnings) => {
                for warning in warnings {
                    warn!("{} {}", self.log_prefix, warning);
                }
                self.cmd_recipient(email).await
            },
            Command::Data => self.cmd_data().await,
            Command::BinaryData(len, last) => {
                self.cmd_binary_data(len, last).await
            },
            Command::Reset => self.cmd_reset().await,
            Command::Verify => self.cmd_verify().await,
            Command::Expand => self.cmd_expand().await,
            Command::Help => self.cmd_help().await,
            Command::Noop => self.cmd_noop().await,
            Command::Quit => self.cmd_quit().await,
            Command::StartTls => self.cmd_start_tls().await,
        }
    }

    async fn cmd_helo(
        &mut self,
        command: String,
        origin: String,
    ) -> Result<(), Error> {
        require!(self, need_helo = false);

        let extended = !"HELO".eq_ignore_ascii_case(&command);
        self.log_prefix.set_helo(origin.clone());
        info!("{} SMTP {command}", self.log_prefix);

        if !self
            .service_request(RequestPayload::Helo(HeloRequest {
                command,
                host: origin.clone(),
                tls: self.io.get_ref().ssl_string(),
            }))
            .await?
        {
            return Ok(());
        }

        self.send_response(
            Delayable.or_final(!extended),
            pc::Ok,
            None,
            Cow::Owned(format!(
                "{} salutations, {}",
                self.local_host_name, origin
            )),
        )
        .await?;
        self.has_helo = true;

        if extended {
            for (ix, &ext) in EXTENSIONS.iter().enumerate() {
                // RFC 3207 requires not sending STARTTLS after TLS has been
                // negotiated.
                if "STARTTLS" == ext
                    && (self.io.get_ref().is_ssl()
                        || self.ssl_acceptor.is_none())
                {
                    continue;
                }

                if "BINARYMIME" == ext && !self.service.offer_binarymime {
                    continue;
                }

                if ext.starts_with("AUTH ")
                    && (!self.service.auth || !self.io.get_ref().is_ssl())
                {
                    continue;
                }

                self.send_response(
                    Delayable.or_final(ix + 1 == EXTENSIONS.len()),
                    pc::Ok,
                    None,
                    Cow::Borrowed(ext),
                )
                .await?;
            }
        }

        Ok(())
    }

    async fn cmd_auth(
        &mut self,
        mechanism: String,
        data: Option<String>,
    ) -> Result<(), Error> {
        require!(self, need_helo = true, need_mail_from = false);

        if !self.io.get_ref().is_ssl() {
            warn!("{} Rejected attempt to AUTH without TLS", self.log_prefix);
            return self.send_response(
                Final,
                pc::EncryptionRequiredForRequestedAuthenticationMechanism,
                Some((cc::PermFail, sc::EncryptionRequiredForRequestedAuthenticationMechanism)),
                Cow::Borrowed("Have you no shame?"),
            ).await;
        }

        if !self.service.auth {
            warn!(
                "{} Rejected attempt to AUTH on an unauthenticated service",
                self.log_prefix,
            );
            return self
                .send_response(
                    Final,
                    pc::CommandNotImplemented,
                    Some((cc::PermFail, sc::SecurityFeaturesNotSupported)),
                    Cow::Borrowed("Authentication is not supported here"),
                )
                .await;
        }

        if self.has_auth {
            return self
                .send_response(
                    Final,
                    pc::BadSequenceOfCommands,
                    None,
                    Cow::Borrowed("Already authenticated"),
                )
                .await;
        }

        if !mechanism.eq_ignore_ascii_case("PLAIN") {
            warn!(
                "{} Rejected attempt to auth with method {mechanism:?}",
                self.log_prefix,
            );
            return self
                .send_response(
                    Final,
                    pc::CommandParameterNotImplemented,
                    // The obvious thing is to return SecurityFeaturesNotSupported,
                    // but RFC 4954 requires InvalidCommandArguments instead.
                    Some((cc::PermFail, sc::InvalidCommandArguments)),
                    Cow::Borrowed("Unsupported AUTH mechanism"),
                )
                .await;
        }

        let data = match data {
            Some(data) if data != "=" => data,
            _ => {
                self.send_response(
                    Final,
                    pc::ServerChallenge,
                    None,
                    Cow::Borrowed(""),
                )
                .await?;

                let mut buffer = Vec::new();
                (&mut self.io)
                    .take(MAX_LINE as u64)
                    .read_until(b'\n', &mut buffer)
                    .await?;

                if !buffer.ends_with(b"\n") {
                    self.send_response(
                        Final,
                        pc::CommandSyntaxError,
                        Some((
                            cc::PermFail,
                            sc::AuthenticationExchangeLineTooLong,
                        )),
                        Cow::Borrowed("Line too long"),
                    )
                    .await?;
                    return Err(Error::Io(io::Error::new(
                        io::ErrorKind::Other,
                        "Authentication line too long",
                    )));
                }

                let _ = buffer.pop();
                if Some(&b'\r') == buffer.last() {
                    let _ = buffer.pop();
                }

                String::from_utf8_lossy(&buffer).into_owned()
            },
        };

        if data.is_empty() || data == "=" {
            return self
                .send_response(
                    Final,
                    pc::ParameterSyntaxError,
                    Some((cc::PermFail, sc::SyntaxError)),
                    Cow::Borrowed("The empty string is not valid for PLAIN"),
                )
                .await;
        }

        if data == "*" {
            return self
                .send_response(
                    Final,
                    pc::ParameterSyntaxError,
                    None,
                    Cow::Borrowed("SASL aborted"),
                )
                .await;
        }

        let Some(data) = base64::decode(&data)
            .ok()
            .and_then(|d| String::from_utf8(d).ok())
        else {
            return self
                .send_response(
                    Final,
                    pc::CommandSyntaxError,
                    Some((cc::PermFail, sc::SyntaxError)),
                    Cow::Borrowed("Invalid base64"),
                )
                .await;
        };

        // All we currently support is RFC 2595 PLAIN
        // Format is <authorise-id>NUL<authenticate-id<NUL>password
        // <authorise-id> is optional if it is the same as <authenticate-id>.
        let mut parts = data.split('\x00');
        let (Some(authorise), Some(authenticate), Some(password), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return self
                .send_response(
                    Final,
                    pc::CommandSyntaxError,
                    Some((cc::PermFail, sc::SyntaxError)),
                    Cow::Borrowed("Invalid auth syntax"),
                )
                .await;
        };

        if !authorise.is_empty() && authorise != authenticate {
            return self
                .send_response(
                    Final,
                    pc::AuthenticationCredentialsInvalid,
                    Some((cc::PermFail, sc::AuthenticationCredentialsInvalid)),
                    Cow::Borrowed("authorise-id must match authenticate-id"),
                )
                .await;
        }

        if self
            .service_request(RequestPayload::Auth(AuthRequest {
                userid: authenticate.to_owned(),
                password: password.to_owned(),
            }))
            .await?
        {
            self.has_auth = true;

            self.send_response(
                Final,
                pc::AuthenticationSucceeded,
                Some((cc::Success, sc::OtherSecurity)),
                Cow::Borrowed("OK"),
            )
            .await?;
        }

        Ok(())
    }

    async fn cmd_mail_from(
        &mut self,
        return_path: String,
        approx_size: Option<u64>,
    ) -> Result<(), Error> {
        require!(self, need_helo = true, need_mail_from = false);
        if self.service.auth && !self.has_auth {
            return self
                .send_response(
                    Final,
                    pc::AuthenticationRequired,
                    Some((cc::PermFail, sc::DeliveryNotAuthorised)),
                    Cow::Borrowed("Authentication required"),
                )
                .await;
        }

        if approx_size.unwrap_or(0) > APPEND_SIZE_LIMIT as u64 {
            return self
                .send_response(
                    Final,
                    pc::ExceededStorageAllocation,
                    Some((cc::PermFail, sc::MessageLengthExceedsLimit)),
                    Cow::Owned(format!(
                        "Maximum message size is {} bytes",
                        APPEND_SIZE_LIMIT
                    )),
                )
                .await;
        }

        if !self
            .service_request(RequestPayload::Mail(MailRequest {
                from: return_path,
            }))
            .await?
        {
            return Ok(());
        }

        info!("{} Start mail transaction", self.log_prefix);
        self.ineffective_commands = 0;
        self.has_mail_from = true;
        self.send_response(
            Final,
            pc::Ok,
            Some((cc::Success, sc::Undefined)),
            Cow::Borrowed("OK"),
        )
        .await
    }

    async fn cmd_recipient(
        &mut self,
        forward_path: String,
    ) -> Result<(), Error> {
        require!(
            self,
            need_helo = true,
            need_mail_from = true,
            need_data = false
        );

        if !self
            .service_request(RequestPayload::Recipient(RecipientRequest {
                to: forward_path,
            }))
            .await?
        {
            return Ok(());
        }

        self.ineffective_commands = 0;
        self.recipients += 1;
        self.send_response(
            Final,
            pc::Ok,
            Some((cc::Success, sc::DestinationAddressValid)),
            Cow::Borrowed("OK"),
        )
        .await
    }

    /// Initiates a data transfer.
    ///
    /// A `Data` request will be executed against the service. If it accepts,
    /// `sending_data` is initialised and this returns `true`. If the transfer
    /// is rejected, `false` is returned.
    async fn start_data_transfer(&mut self) -> Result<bool, Error> {
        let (data_in, data_out) = tokio::io::duplex(4096);
        let (recipients_tx, recipients_rx) = oneshot::channel();
        if !self
            .service_request(RequestPayload::Data(DataRequest {
                data: data_in,
                recipient_responses: recipients_rx,
            }))
            .await?
        {
            return Ok(false);
        }

        self.sending_data = Some(SendData {
            stream: data_out,
            recipient_responses: recipients_tx,
        });
        Ok(true)
    }

    /// Completes a data transfer.
    ///
    /// The data stream to the service is severed, then the responses for each
    /// recipient (LMTP) or singular response (SMTP) are retrieved and sent.
    /// The mail delivery state is reset.
    async fn complete_data_transfer(&mut self) -> Result<(), Error> {
        let sending_data = self.sending_data.take().unwrap();
        drop(sending_data.stream);

        let (recipients_tx, mut recipients_rx) = mpsc::channel(1);
        // If this fails, `recipients_rx` will be a broken channel, and we'll
        // log when we try to get the responses out.
        let _ = sending_data.recipient_responses.send(recipients_tx);

        let need_responses = if self.service.lmtp {
            self.recipients
        } else {
            1
        };

        let mut success = false;
        for i in 0..need_responses {
            let response = recipients_rx
                .recv()
                .await
                .unwrap_or_else(|| {
                    error!(
                    "{} [BUG] Service worker disappeared during data transfer",
                    self.log_prefix,
                );
                    Err(SmtpResponse(
                        pc::TransactionFailed,
                        Some((cc::TempFail, sc::OtherMailSystem)),
                        Cow::Borrowed("Internal server error"),
                    ))
                })
                .err()
                .unwrap_or(SmtpResponse(
                    pc::Ok,
                    Some((cc::Success, sc::Undefined)),
                    Cow::Borrowed("OK"),
                ));
            success |= (200..=299).contains(&(response.0 as i32));
            self.send_response(
                Urgent.or_final(i + 1 == need_responses),
                response.0,
                response.1,
                response.2,
            )
            .await?;
        }

        info!(
            "{} Completed data transfer {}",
            self.log_prefix,
            if success {
                "successfully"
            } else {
                "unsuccessfully"
            },
        );

        self.recipients = 0;
        self.has_mail_from = false;
        Ok(())
    }

    async fn cmd_data(&mut self) -> Result<(), Error> {
        require!(
            self,
            need_helo = true,
            need_mail_from = true,
            need_recipients = true,
            need_data = false
        );

        if !self.start_data_transfer().await? {
            return Ok(());
        }

        self.ineffective_commands = 0;
        self.send_response(
            Final,
            pc::StartMailInput,
            None,
            Cow::Borrowed("Go ahead"),
        )
        .await?;

        info!("{} Begin legacy-format data transfer", self.log_prefix);

        let _ = self
            .deadline_tx
            .send(Instant::now() + Duration::from_secs(1800))
            .await;
        {
            let sending_data = self.sending_data.as_mut().unwrap();
            copy_with_dot_stuffing(
                Pin::new(&mut DiscardOnError(&mut sending_data.stream)),
                Pin::new(&mut self.io),
                // If we've seen the client speaking SMTP with UNIX newlines,
                // assume the message may be UNIX, or may at least be
                // terminated with a UNIX-delimited '.'.
                self.unix_newlines,
                // Automatically detect line endings.
                true,
            )
            .await?;
        }

        self.complete_data_transfer().await
    }

    async fn cmd_binary_data(
        &mut self,
        len: u64,
        last: bool,
    ) -> Result<(), Error> {
        // Extend the deadline to account for a 32kbps transfer rate.
        let _ = self
            .deadline_tx
            .send(Instant::now() + Duration::from_secs(30 + len / 4000))
            .await;

        let mut consumed = false;
        let result = self.cmd_binary_data_impl(&mut consumed, len, last).await;
        if !consumed {
            tokio::io::copy(
                &mut (&mut self.io).take(len),
                &mut tokio::io::sink(),
            )
            .await?;
        }

        result
    }

    async fn cmd_binary_data_impl(
        &mut self,
        consumed: &mut bool,
        len: u64,
        last: bool,
    ) -> Result<(), Error> {
        require!(
            self,
            need_helo = true,
            need_mail_from = true,
            need_recipients = true
        );

        self.ineffective_commands = 0;
        if self.sending_data.is_none() {
            if !self.start_data_transfer().await? {
                return Ok(());
            }

            info!("{} Begin binary data transfer", self.log_prefix);
        }

        let abort = {
            let mut src = (&mut self.io).take(len);
            let sending_data = self.sending_data.as_mut().unwrap();
            let result =
                tokio::io::copy(&mut src, &mut sending_data.stream).await;
            // Ensure we actually consume the whole blob
            let _ = tokio::io::copy(&mut src, &mut tokio::io::sink()).await;
            *consumed = true;

            match result {
                Ok(_) => false,
                // BrokenPipe => sending_data.stream is broken
                Err(e) if io::ErrorKind::BrokenPipe == e.kind() => true,
                // Any other error => the server input failed
                Err(e) => return Err(Error::Io(e)),
            }
        };

        if last || abort {
            self.complete_data_transfer().await
        } else {
            self.send_response(
                Final,
                pc::Ok,
                Some((cc::Success, sc::Undefined)),
                Cow::Borrowed("OK"),
            )
            .await
        }
    }

    async fn cmd_reset(&mut self) -> Result<(), Error> {
        self.has_mail_from = false;
        self.recipients = 0;
        self.sending_data = None;
        if self.service_request(RequestPayload::Reset).await? {
            self.send_response(
                Final,
                pc::Ok,
                Some((cc::Success, sc::Undefined)),
                Cow::Borrowed("OK"),
            )
            .await?;
        }

        Ok(())
    }

    async fn cmd_verify(&mut self) -> Result<(), Error> {
        info!("{} Rejected attempt to use VRFY", self.log_prefix);
        self.send_response(
            Final,
            pc::CannotVerify,
            Some((cc::Success, sc::OtherSecurity)),
            Cow::Borrowed("VRFY not supported"),
        )
        .await
    }

    async fn cmd_expand(&mut self) -> Result<(), Error> {
        self.send_response(
            Final,
            pc::ActionNotTakenPermanent,
            Some((cc::PermFail, sc::SystemNotCapableOfSelectedFeatures)),
            Cow::Borrowed("There are no mailing lists here"),
        )
        .await
    }

    async fn cmd_help(&mut self) -> Result<(), Error> {
        self.send_response(
            Delayable,
            pc::HelpMessage,
            Some((cc::Success, sc::Undefined)),
            Cow::Borrowed("You asked me for help"),
        )
        .await?;
        self.send_response(
            Delayable,
            pc::HelpMessage,
            Some((cc::Success, sc::Undefined)),
            Cow::Borrowed("An SMTP server!"),
        )
        .await?;
        self.send_response(
            Delayable,
            pc::HelpMessage,
            Some((cc::Success, sc::Undefined)),
            Cow::Borrowed("What a strange life choice"),
        )
        .await?;
        self.send_response(
            Delayable,
            pc::HelpMessage,
            Some((cc::Success, sc::Undefined)),
            Cow::Borrowed("This is the Crymap SMTP server."),
        )
        .await?;
        self.send_response(
            Final,
            pc::HelpMessage,
            Some((cc::Success, sc::Undefined)),
            Cow::Borrowed("End of HELP"),
        )
        .await
    }

    async fn cmd_noop(&mut self) -> Result<(), Error> {
        self.send_response(
            Final,
            pc::Ok,
            Some((cc::Success, sc::Undefined)),
            Cow::Borrowed("OK"),
        )
        .await
    }

    async fn cmd_quit(&mut self) -> Result<(), Error> {
        self.quit = true;
        let _ = self
            .send_response(
                Final,
                pc::ServiceClosing,
                Some((cc::Success, sc::Undefined)),
                Cow::Borrowed("Bye"),
            )
            .await;
        Ok(())
    }

    async fn cmd_start_tls(&mut self) -> Result<(), Error> {
        require!(
            self,
            need_helo = true,
            need_tls = false,
            need_mail_from = false,
            need_recipients = false,
            need_data = false
        );

        if self.ssl_acceptor.is_none() {
            self.send_response(
                Final,
                pc::ActionNotTakenPermanent,
                None,
                Cow::Borrowed("TLS not configured"),
            )
            .await?;
            return Ok(());
        }

        self.send_response(
            Final,
            pc::ServiceReady,
            Some((cc::Success, sc::Undefined)),
            Cow::Borrowed("Switching to TLS"),
        )
        .await?;

        info!("{} Start TLS handshake", self.log_prefix);

        self.has_helo = false;
        self.io
            .get_mut()
            .ssl_accept(&self.ssl_acceptor.take().unwrap())
            .await?;

        info!("{} TLS handshake completed", self.log_prefix);

        Ok(())
    }

    async fn need_helo(&mut self, present: bool) -> Option<Result<(), Error>> {
        self.check_need(
            self.has_helo,
            present,
            "Already got HELO",
            "Still waiting for HELO",
        )
        .await
    }

    async fn need_mail_from(
        &mut self,
        present: bool,
    ) -> Option<Result<(), Error>> {
        self.check_need(
            self.has_mail_from,
            present,
            "Already got MAIL FROM",
            "Still waiting for MAIL FROM",
        )
        .await
    }

    async fn need_recipients(
        &mut self,
        present: bool,
    ) -> Option<Result<(), Error>> {
        self.check_need(
            self.recipients > 0,
            present,
            "Already have recipients",
            "No recipients",
        )
        .await
    }

    async fn need_data(&mut self, present: bool) -> Option<Result<(), Error>> {
        self.check_need(
            self.sending_data.is_some(),
            present,
            "Already transferring data",
            "Not currently transferring data",
        )
        .await
    }

    async fn need_tls(&mut self, present: bool) -> Option<Result<(), Error>> {
        self.check_need(
            self.sending_data.is_some(),
            present,
            "Already using TLS",
            "Not using TLS",
        )
        .await
    }

    async fn check_need(
        &mut self,
        current_status: bool,
        desired_status: bool,
        message_if_already_present: &str,
        message_if_missing: &str,
    ) -> Option<Result<(), Error>> {
        if current_status != desired_status {
            Some(
                self.send_response(
                    Final,
                    pc::BadSequenceOfCommands,
                    Some((cc::PermFail, sc::InvalidCommand)),
                    Cow::Borrowed(if current_status {
                        message_if_already_present
                    } else {
                        message_if_missing
                    }),
                )
                .await,
            )
        } else {
            None
        }
    }

    async fn send_greeting(&mut self) -> Result<(), Error> {
        self.send_response(
            Final,
            pc::ServiceReady,
            None,
            Cow::Owned(format!(
                "{} {} {} {}.{}.{} ready",
                self.local_host_name,
                match (self.service.lmtp, self.io.get_ref().is_ssl()) {
                    (false, false) => "ESMTP",
                    (false, true) => "ESMTPS",
                    (true, false) => "LMTP",
                    (true, true) => "LMTPS",
                },
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION_MAJOR"),
                env!("CARGO_PKG_VERSION_MINOR"),
                env!("CARGO_PKG_VERSION_PATCH"),
            )),
        )
        .await
    }

    async fn send_response(
        &mut self,
        kind: ResponseKind,
        primary_code: PrimaryCode,
        secondary_code: Option<(ClassCode, SubjectCode)>,
        quip: Cow<'_, str>,
    ) -> Result<(), Error> {
        use std::fmt::Write as _;

        if primary_code == pc::ServiceClosing
            || primary_code == pc::ServiceNotAvailableClosing
        {
            self.quit = true;
        }

        let mut s = String::new();
        let _ = write!(s, "{}{}", primary_code as u16, kind.indicator());
        if let Some((class, subject)) = secondary_code {
            let subject = subject as u16;
            let split = if subject >= 100 { 100 } else { 10 };

            let _ = write!(
                s,
                "{}.{}.{} ",
                class as u8,
                subject / split,
                subject % split
            );
        }

        let _ = write!(s, "{}\r\n", quip);

        self.io.write_all(s.as_bytes()).await?;
        match kind {
            Final | Urgent => self.io.flush().await?,
            Delayable => (),
        }

        Ok(())
    }

    /// Send `payload` as a request to the service, and waits for the service's
    /// response.
    ///
    /// If an error occurs or the service rejects the request, the response
    /// produced by the service is sent and `false` is returned. Otherwise,
    /// nothing is sent to the client and `true` is returned.
    async fn service_request(
        &mut self,
        payload: RequestPayload,
    ) -> Result<bool, Error> {
        let (response_tx, response_rx) = oneshot::channel();
        if self
            .service
            .send_request
            .send(Request {
                payload,
                respond: response_tx,
            })
            .await
            .is_err()
        {
            error!("{} [BUG] Service worker disappeared", self.log_prefix);
            self.send_response(
                Final,
                pc::ServiceNotAvailableClosing,
                Some((cc::TempFail, sc::OtherMailSystem)),
                Cow::Borrowed("Internal server error"),
            )
            .await?;
            return Ok(false);
        }

        let Ok(result) = response_rx.await else {
            error!("{} [BUG] Service worker disappeared", self.log_prefix);
            self.send_response(
                Final,
                pc::ServiceNotAvailableClosing,
                Some((cc::TempFail, sc::OtherMailSystem)),
                Cow::Borrowed("Internal server error"),
            )
            .await?;
            return Ok(false);
        };

        if let Err(e) = result {
            self.send_response(Final, e.0, e.1, e.2).await?;
            return Ok(false);
        }

        Ok(true)
    }
}

/// Wraps `DuplexStream` to silently succeed and consume all data on any error.
struct DiscardOnError<'a>(&'a mut DuplexStream);

impl tokio::io::AsyncWrite for DiscardOnError<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        ctx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> task::Poll<io::Result<usize>> {
        match Pin::new(&mut *self.get_mut().0).poll_write(ctx, buf) {
            task::Poll::Ready(Err(_)) => task::Poll::Ready(Ok(buf.len())),
            poll => poll,
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        ctx: &mut task::Context<'_>,
    ) -> task::Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().0).poll_flush(ctx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        ctx: &mut task::Context<'_>,
    ) -> task::Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().0).poll_shutdown(ctx)
    }
}

/// Copies `src` to `dst`, stripping dot stuffing, consuming up to and
/// including the line with just `.`.
///
/// UNIX line endings will be understood by default and converted to DOS
/// newlines if `unix_lines` is `true`. `unix_lines` will be forced to true if
/// an LF is encountered before a CR unless `detect_line_endings` is false.
///
/// As long as `unix_lines` is false, this implementation requires strict
/// conformance to the use of DOS newlines in exchange for being able to
/// preserve arbitrary binary content exactly.
async fn copy_with_dot_stuffing(
    mut dst: Pin<&mut impl AsyncWriteExt>,
    mut src: Pin<&mut impl AsyncBufReadExt>,
    mut unix_lines: bool,
    mut detect_line_endings: bool,
) -> io::Result<()> {
    /// Write `data` to `dst`, possibly performing line-ending conversion.
    ///
    /// `data` must either be a partial line or the end of a line, including
    /// the input that was read.
    ///
    /// `has_trailing_cr` is set to whether the previous write ended with a
    /// bare CR. `unix_lines` indicates whether conversion is enabled.
    async fn write_with_line_conversion(
        mut dst: Pin<&mut impl AsyncWriteExt>,
        data: &[u8],
        has_trailing_cr: bool,
        unix_lines: bool,
    ) -> io::Result<()> {
        if unix_lines
            && data.ends_with(b"\n")
            && !data.ends_with(b"\r\n")
            && (!has_trailing_cr || b"\n" != data)
        {
            dst.as_mut().write_all(&data[..data.len() - 1]).await?;
            dst.as_mut().write_all(b"\r\n").await?;
        } else {
            // No conversion, no line ending, or it already ends with a DOS
            // line ending.
            dst.write_all(data).await?;
        }

        Ok(())
    }

    // Copy src to dst until a line which is just ".\r\n" is encountered. If a
    // line which is not ".\r\n" is found which begins with '.', the first '.'
    // on the line is removed. The "\r\n" before ".\r\n" is part of the
    // content.
    //
    // To be binary-safe, we need to handle CRLFs strictly, and not treat just
    // any LF as a line ending. E.g., the sequence "\n.\n" may occur by itself
    // in the input and should be part of the message.

    // Whether the next read is reading from the start of the line; i.e., true
    // at the beginning of text and after each CRLF.
    let mut start_of_line = true;
    // Whether the last read ended with CR. This means that if the next read is
    // just \n, we still treat it as a line ending.
    let mut has_trailing_cr = false;

    loop {
        let mut src_buffer = src.as_mut();
        let mut buffer = src_buffer.fill_buf().await?;

        if buffer.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF encountered in DATA payload",
            ));
        }

        if let Some(eol) = memchr::memchr(b'\n', buffer) {
            buffer = &buffer[..=eol];

            if detect_line_endings {
                // This is our first line-ending. If it's not a DOS newline,
                // perform conversion for the rest of the message.
                if !buffer.ends_with(b"\r\n") && !has_trailing_cr {
                    unix_lines = true;
                }

                detect_line_endings = false;
            }
        }

        let buffer_len = buffer.len();

        if start_of_line {
            // The case of ".\n" at the start of a line is illegal when
            // `!unix_lines`. Assume it's supposed to be the end of the text.
            // In the case of `unix_lines`, it *is* the normal end of text.
            if b".\r\n" == buffer || b".\n" == buffer {
                // End of content
                src.as_mut().consume(buffer_len);
                break;
            }

            if b".\r" == buffer {
                // Maybe end of content, if we can get a \n next.
                src.as_mut().consume(buffer_len);

                let mut extra = [0u8; 1];
                src.as_mut().read_exact(&mut extra).await?;
                if b'\n' == extra[0] {
                    // End of content
                    break;
                }

                // Nope, keep going. The isolated . at the start of the line is
                // illegal, so whether or not we include it is moot.
                dst.write_all(b"\r").await?;
                dst.write_all(&extra).await?;
                has_trailing_cr = b'\r' == extra[0];
                start_of_line = false;
                continue;
            }

            if b"." == buffer {
                // Could be end of content or a stuffed dot.
                src.as_mut().consume(buffer_len);

                let mut extra = [0u8; 2];
                src.as_mut().read_exact(&mut extra[..1]).await?;

                if b'\n' == extra[0] {
                    // ".\n" is illegal with !unix_lines, but is the end of
                    // content with unix_lines, so this is the end of content.
                    break;
                }

                src.as_mut().read_exact(&mut extra[1..]).await?;

                if b"\r\n" == &extra {
                    // End of content
                    break;
                }

                // Nope, keep going. The isolated '.' at the start of the line
                // either is part of dot-stuffing (if extra[0] is '.') or
                // illegal, so just drop it.
                //
                // We know that extra[0] is not '\n', so the only possible line
                // ending is at the end of `extra`.
                write_with_line_conversion(
                    dst.as_mut(),
                    &extra,
                    false, // There was a '.' since the last has_trailing_cr write
                    unix_lines,
                )
                .await?;
                has_trailing_cr = extra.ends_with(b"\r");
                start_of_line = unix_lines && extra.ends_with(b"\n");
                continue;
            }
        }

        // Else, everything inside buffer is content, except possibly a leading
        // '.'.
        let line_contents = if b'.' == buffer[0] && start_of_line {
            &buffer[1..]
        } else {
            buffer
        };
        write_with_line_conversion(
            dst.as_mut(),
            line_contents,
            has_trailing_cr,
            unix_lines,
        )
        .await?;

        start_of_line = buffer.ends_with(b"\r\n")
            || (b"\n" == buffer && has_trailing_cr)
            || (unix_lines && buffer.ends_with(b"\n"));
        has_trailing_cr = buffer.ends_with(b"\r");
        src.as_mut().consume(buffer_len);
    }

    Ok(())
}

// Runs until either the deadline channel is closed or the current deadline has
// expired. Used to force-close idle connections.
async fn idle_timer(mut deadline_rx: mpsc::Receiver<Instant>) {
    let mut deadline = Instant::now() + Duration::from_secs(30);

    loop {
        match tokio::time::timeout_at(deadline.into(), deadline_rx.recv()).await
        {
            Err(_) => return,   // Timed out
            Ok(None) => return, // Done
            Ok(Some(d)) => deadline = d,
        }
    }
}

#[cfg(test)]
mod test {
    use proptest::prelude::*;

    use super::*;

    fn copy_with_dot_stuffing_sync(
        stuffed: &[u8],
        buffer_size: usize,
        unix_lines: bool,
        detect_line_endings: bool,
    ) -> Vec<u8> {
        let mut decoded_bytes = Vec::<u8>::new();
        let mut reader =
            tokio::io::BufReader::with_capacity(buffer_size, stuffed);
        futures::executor::block_on(copy_with_dot_stuffing(
            Pin::new(&mut decoded_bytes),
            Pin::new(&mut reader),
            unix_lines,
            detect_line_endings,
        ))
        .unwrap();

        decoded_bytes
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 4096,
            ..ProptestConfig::default()
        })]

        #[test]
        fn binary_dot_stuffing_decodes_properly(
            content in "[x.\r\n]{0,100}\r\n",
            buffer_size in 1usize..=32,
        ) {
            let mut stuffed = content.replace("\r\n.", "\r\n..");
            if stuffed.starts_with(".") {
                stuffed = format!(".{}", stuffed);
            }
            stuffed.push_str(".\r\n");

            let decoded_bytes = copy_with_dot_stuffing_sync(
                stuffed.as_bytes(),
                buffer_size,
                // For this test, never do line ending conversion.
                false,
                false,
            );

            assert_eq!(content, str::from_utf8(&decoded_bytes).unwrap());
        }

        #[test]
        fn text_dot_stuffing_decodes_properly(
            content in "[x.\r\n]{0,100}\r\n",
            buffer_size in 1usize..=32,
        ) {
            let mut stuffed = content.replace("\n.", "\n..");
            if stuffed.starts_with(".") {
                stuffed = format!(".{}", stuffed);
            }
            stuffed.push_str(".\n");

            let decoded_bytes = copy_with_dot_stuffing_sync(
                stuffed.as_bytes(),
                buffer_size,
                // For this test, always do line ending conversion.
                true,
                false,
            );

            let converted_content = content.replace("\r\n", "\n")
                .replace("\n", "\r\n");
            assert_eq!(
                converted_content,
                str::from_utf8(&decoded_bytes).unwrap(),
            );
        }
    }

    #[test]
    fn dot_stuffing_line_ending_detection() {
        assert_eq!(
            b"foo\r\nbar\n.\r\n".to_vec(),
            copy_with_dot_stuffing_sync(
                b"foo\r\nbar\n.\r\n.\r\n",
                64,
                false,
                true,
            ),
        );
        assert_eq!(
            b"foo\r\nbar\r\nbaz\r\n".to_vec(),
            copy_with_dot_stuffing_sync(
                b"foo\nbar\r\nbaz\n.\n",
                64,
                false,
                true,
            ),
        );
    }
}
