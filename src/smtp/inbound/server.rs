//-
// Copyright (c) 2020, 2023, 2024 Jason Lingle
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

use log::{error, warn};
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
    pub(super) send_request: mpsc::Sender<Request>,
}

struct Server {
    io: BufStream<ServerIo>,
    log_prefix: LogPrefix,
    ssl_acceptor: SslAcceptor,
    service: Service,
    local_host_name: String,

    ineffective_commands: u32,
    quit: bool,
    has_helo: bool,
    has_mail_from: bool,
    recipients: u32,
    sending_data: Option<SendData>,
}

pub(super) async fn run(
    io: ServerIo,
    log_prefix: LogPrefix,
    ssl_acceptor: SslAcceptor,
    service: Service,
    local_host_name: String,
) -> Result<(), Error> {
    let mut server = Server {
        io: BufStream::new(io),
        log_prefix,
        ssl_acceptor,
        service,
        local_host_name,

        ineffective_commands: 0,
        quit: false,
        has_helo: false,
        has_mail_from: false,
        recipients: 0,
        sending_data: None,
    };
    server.run().await
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
    "8BITMIME",
    "BINARYMIME",
    "CHUNKING",
    "ENHANCEDSTATUSCODES",
    "PIPELINING",
    "SMTPUTF8",
    concat_appendlimit!("SIZE="),
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

        if !buffer.ends_with(b"\r\n") {
            self.send_response(
                Final,
                pc::CommandSyntaxError,
                Some((cc::PermFail, sc::SyntaxError)),
                Cow::Borrowed("Sadly we cannot allow UNIX newlines here"),
            )
            .await?;
            return Ok(());
        }

        let command_line = match str::from_utf8(&buffer[..buffer.len() - 2]) {
            Ok(s) => s,
            Err(_) => {
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
            Command::MailFrom(email, size) => {
                self.cmd_mail_from(email, size).await
            },
            Command::Recipient(email) => self.cmd_recipient(email).await,
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
            if extended { Delayable } else { Final },
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
                if "STARTTLS" == ext && self.io.get_ref().is_ssl() {
                    continue;
                }

                if "BINARYMIME" == ext && !self.service.offer_binarymime {
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

    async fn cmd_mail_from(
        &mut self,
        return_path: String,
        approx_size: Option<u64>,
    ) -> Result<(), Error> {
        require!(self, need_helo = true, need_mail_from = false);

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
            self.send_response(
                Urgent.or_final(i + 1 == need_responses),
                response.0,
                response.1,
                response.2,
            )
            .await?;
        }

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

        {
            let sending_data = self.sending_data.as_mut().unwrap();
            copy_with_dot_stuffing(
                Pin::new(&mut DiscardOnError(&mut sending_data.stream)),
                Pin::new(&mut self.io),
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
            Cow::Borrowed("You have asked me for help"),
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
        self.send_response(
            Final,
            pc::ServiceReady,
            Some((cc::Success, sc::Undefined)),
            Cow::Borrowed("Switching to TLS"),
        )
        .await?;

        self.has_helo = false;
        self.io.get_mut().ssl_accept(&self.ssl_acceptor).await?;
        self.send_greeting().await
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

        let mut s = String::new();
        let _ = write!(s, "{}{}", primary_code as u16, kind.indicator());
        if let Some((class, subject)) = secondary_code {
            let subject = subject as u8;
            let _ =
                write!(s, "{}.{}.{} ", class as u8, subject / 10, subject % 10);
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

async fn copy_with_dot_stuffing(
    mut dst: Pin<&mut impl AsyncWriteExt>,
    mut src: Pin<&mut impl AsyncBufReadExt>,
) -> io::Result<()> {
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

    let mut buffer = Vec::new();

    loop {
        buffer.clear();
        src.read_until(b'\n', &mut buffer).await?;

        if buffer.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF encountered in DATA payload",
            ));
        }

        if b".\r\n" == &buffer[..] && start_of_line {
            // End of content
            break;
        }

        // Else, everything inside buffer is content, except possibly a leading
        // '.'.
        if b'.' == buffer[0] && start_of_line {
            dst.write_all(&buffer[1..]).await?;
        } else {
            dst.write_all(&buffer).await?;
        }

        start_of_line = buffer.ends_with(b"\r\n")
            || (b"\n" == &buffer[..] && has_trailing_cr);
        has_trailing_cr = buffer.ends_with(b"\r");
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 4096,
            ..ProptestConfig::default()
        })]

        #[test]
        fn dot_stuffing_decodes_properly(
            content in "[x.\r\n]{0,100}\r\n",
            buffer_size in 1usize..=32,
        ) {
            let mut stuffed = content.replace("\r\n.", "\r\n..");
            if stuffed.starts_with(".") {
                stuffed = format!(".{}", stuffed);
            }
            stuffed.push_str(".\r\n");

            let mut decoded_bytes = Vec::<u8>::new();
            let mut reader = tokio::io::BufReader::with_capacity(
                buffer_size, stuffed.as_bytes());
            futures::executor::block_on(copy_with_dot_stuffing(
                Pin::new(&mut decoded_bytes),
                Pin::new(&mut reader))).unwrap();

            assert_eq!(content, str::from_utf8(&decoded_bytes).unwrap());
        }
    }
}
