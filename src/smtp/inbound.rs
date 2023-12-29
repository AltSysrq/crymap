//-
// Copyright (c) 2020, 2023, Jason Lingle
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
use std::io::{self, Write};
use std::mem;
use std::path::PathBuf;
use std::pin::Pin;
use std::str;
use std::sync::Arc;

use chrono::prelude::*;
use log::{error, info, warn};
use openssl::ssl::SslAcceptor;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufStream};

use super::codes::*;
use super::syntax::*;
use crate::account::model::CommonPaths;
use crate::account::v2::DeliveryAccount;
use crate::support::{
    append_limit::APPEND_SIZE_LIMIT,
    async_io::ServerIo,
    buffer::BufferWriter,
    error::Error,
    log_prefix::LogPrefix,
    safe_name::is_safe_name,
    system_config::{LmtpConfig, SystemConfig},
    unix_privileges,
};

pub async fn serve_lmtp(
    io: ServerIo,
    config: Arc<SystemConfig>,
    log_prefix: LogPrefix,
    ssl_acceptor: SslAcceptor,
    users_dir: PathBuf,
    host_name: String,
    peer_name: String,
) {
    let mut server = Server::new(
        io,
        config,
        log_prefix.clone(),
        ssl_acceptor,
        users_dir,
        host_name,
        peer_name,
    );
    match server.run().await {
        Ok(_) => info!("{} Normal client disconnect", log_prefix),
        Err(e) => warn!("{} Abnormal client disconnect: {}", log_prefix, e),
    }
}

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
    // STARTTLS must not be the last item in this list since it is included
    // conditionally.
    "STARTTLS",
    "8BITMIME",
    "BINARYMIME",
    "CHUNKING",
    "ENHANCEDSTATUSCODES",
    "HELP",
    "PIPELINING",
    concat_appendlimit!("SIZE="),
    "SMTPUTF8",
];

pub(super) struct Server {
    io: BufStream<ServerIo>,
    config: Arc<SystemConfig>,
    log_prefix: LogPrefix,
    ssl_acceptor: SslAcceptor,

    users_dir: PathBuf,
    common_paths: Arc<CommonPaths>,

    /// The name we report as our host name.
    host_name: String,
    /// The name of the peer as reported by `getpeername()`.
    peer_name: String,
    /// The self-reported name of the peer given in LHLO.
    peer_id: Option<String>,

    started_tls: bool,
    quit: bool,

    return_path: Option<String>,
    recipients: Vec<Recipient>,
    data_buffer: BufferWriter,
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

impl Server {
    pub(super) fn new(
        io: ServerIo,
        config: Arc<SystemConfig>,
        log_prefix: LogPrefix,
        ssl_acceptor: SslAcceptor,
        users_dir: PathBuf,
        host_name: String,
        peer_name: String,
    ) -> Self {
        let common_paths = Arc::new(CommonPaths {
            tmp: std::env::temp_dir(),
            garbage: std::env::temp_dir(),
        });

        Server {
            data_buffer: BufferWriter::new(Arc::clone(&common_paths)),
            io: BufStream::new(io),
            config,
            log_prefix,
            ssl_acceptor,
            users_dir,
            common_paths,
            host_name,
            peer_name,
            peer_id: None,
            started_tls: false,
            quit: false,
            return_path: None,
            recipients: Vec::new(),
        }
    }

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
                } else if looks_like_smtp_helo(command_line) {
                    self.send_response(
                        Final,
                        pc::CommandSyntaxError,
                        Some((cc::PermFail, sc::WrongProtocolVersion)),
                        Cow::Borrowed("This is LMTP, not SMTP"),
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
            Command::Lhlo(origin) => self.cmd_lhlo(origin).await,
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

    async fn cmd_lhlo(&mut self, origin: String) -> Result<(), Error> {
        require!(self, need_lhlo = false);

        self.send_response(
            Delayable,
            pc::Ok,
            None,
            Cow::Owned(format!("{} salutations, {}", self.host_name, origin)),
        )
        .await?;
        self.peer_id = Some(origin);

        for (ix, &ext) in EXTENSIONS.iter().enumerate() {
            // RFC 3207 requires not sending STARTTLS after TLS has been
            // negotiated.
            if "STARTTLS" == ext && self.started_tls {
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

        Ok(())
    }

    async fn cmd_mail_from(
        &mut self,
        return_path: String,
        approx_size: Option<u64>,
    ) -> Result<(), Error> {
        require!(self, need_lhlo = true, need_return_path = false);

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

        // Ensure there is no buffered data (or anything else).
        // This can happen due to an out-of-sequence BDAT chunk.
        self.reset();

        self.return_path = Some(return_path);
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
            need_lhlo = true,
            need_return_path = true,
            need_data = false
        );

        match Recipient::normalise(&self.config.lmtp, forward_path.clone()) {
            None => {
                self.send_response(
                    Final,
                    pc::ActionNotTakenPermanent,
                    Some((cc::PermFail, sc::BadDestinationMailboxAddress)),
                    // The "no such user - " prefix has significance with some
                    // agents according to RFC 5321
                    Cow::Owned(format!(
                        "no such user - {} (disallowed name)",
                        forward_path
                    )),
                )
                .await
            },

            Some(recipient) => {
                if self.users_dir.join(&recipient.normalised).is_dir() {
                    self.recipients.push(recipient);
                    self.send_response(
                        Final,
                        pc::Ok,
                        Some((cc::Success, sc::DestinationAddressValid)),
                        Cow::Borrowed("OK"),
                    )
                    .await
                } else {
                    self.send_response(
                        Final,
                        pc::ActionNotTakenPermanent,
                        Some((cc::PermFail, sc::BadDestinationMailboxAddress)),
                        Cow::Owned(format!("no such user - {}", forward_path)),
                    )
                    .await
                }
            },
        }
    }

    async fn cmd_data(&mut self) -> Result<(), Error> {
        require!(
            self,
            need_lhlo = true,
            need_return_path = true,
            need_recipients = true,
            need_data = false
        );

        self.send_response(
            Final,
            pc::StartMailInput,
            None,
            Cow::Borrowed("Go ahead"),
        )
        .await?;
        copy_with_dot_stuffing(&mut self.data_buffer, Pin::new(&mut self.io))
            .await?;
        self.deliver().await
    }

    async fn cmd_binary_data(
        &mut self,
        len: u64,
        last: bool,
    ) -> Result<(), Error> {
        require!(
            self,
            need_lhlo = true,
            need_return_path = true,
            need_recipients = true,
            @else {
                // Discard the chunk
                let nread =
                    tokio::io::copy(&mut (&mut self.io).take(len), &mut tokio::io::sink()).await?;
                if nread != len {
                    return Err(Error::Io(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "EOF before end of BDAT",
                    )));
                }
            }
        );

        {
            let mut buf = [0u8; 4096];
            let mut remaining = len;
            while remaining > 0 {
                let max = usize::try_from(remaining)
                    .unwrap_or(buf.len())
                    .min(buf.len());
                let nread = self.io.read(&mut buf[..max]).await?;
                if 0 == nread {
                    return Err(Error::Io(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "EOF before end of BDAT",
                    )));
                }

                remaining -= nread as u64;
                self.data_buffer.write_all(&buf[..nread])?;
            }
        }

        if last {
            self.deliver().await
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
        self.reset();
        self.send_response(
            Final,
            pc::Ok,
            Some((cc::Success, sc::Undefined)),
            Cow::Borrowed("OK"),
        )
        .await
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
            Cow::Borrowed("An LMTP server!"),
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
            Cow::Borrowed("This is the Crymap LMTP server."),
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
        require!(self, need_tls = false);
        self.started_tls = true;
        self.send_response(
            Final,
            pc::ServiceReady,
            Some((cc::Success, sc::Undefined)),
            Cow::Borrowed("Switching to TLS"),
        )
        .await?;

        self.io.get_mut().ssl_accept(&self.ssl_acceptor).await?;
        self.reset();
        self.peer_id = None;
        self.send_greeting().await
    }

    async fn need_lhlo(&mut self, present: bool) -> Option<Result<(), Error>> {
        self.check_need(
            self.peer_id.is_some(),
            present,
            "Already got LHLO",
            "Still waiting for LHLO",
        )
        .await
    }

    async fn need_return_path(
        &mut self,
        present: bool,
    ) -> Option<Result<(), Error>> {
        self.check_need(
            self.return_path.is_some(),
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
            !self.recipients.is_empty(),
            present,
            "Already have recipients",
            "No recipients",
        )
        .await
    }

    async fn need_data(&mut self, present: bool) -> Option<Result<(), Error>> {
        self.check_need(
            self.data_buffer.len() > 0,
            present,
            "Already have data buffered",
            "No data buffered",
        )
        .await
    }

    async fn need_tls(&mut self, present: bool) -> Option<Result<(), Error>> {
        self.check_need(
            self.started_tls,
            present,
            "TLS already started",
            "TLS not started",
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

    fn reset(&mut self) {
        self.return_path = None;
        self.recipients.clear();
        self.data_buffer = BufferWriter::new(Arc::clone(&self.common_paths));
    }

    async fn deliver(&mut self) -> Result<(), Error> {
        struct RestoreUidGid;
        impl Drop for RestoreUidGid {
            fn drop(&mut self) {
                let _ = nix::unistd::seteuid(nix::unistd::getuid());
                let _ = nix::unistd::setegid(nix::unistd::getgid());
            }
        }

        let now = Utc::now();
        let smtp_date = now.to_rfc2822();
        let mut data_buffer = mem::replace(
            &mut self.data_buffer,
            BufferWriter::new(Arc::clone(&self.common_paths)),
        )
        .flip()?;

        // NB The main difference between LMTP and SMTP is that we emit one
        // response *per recipient* instead of one response for the whole
        // transaction.
        let num_recipients = self.recipients.len();
        for (ix, recipient) in
            mem::take(&mut self.recipients).into_iter().enumerate()
        {
            let response_kind = Urgent.or_final(ix + 1 == num_recipients);

            if data_buffer.len() > APPEND_SIZE_LIMIT as u64 {
                self.send_response(
                    response_kind,
                    pc::ExceededStorageAllocation,
                    Some((cc::PermFail, sc::MessageLengthExceedsLimit)),
                    Cow::Owned(format!(
                        "Maximum message size is {} bytes",
                        APPEND_SIZE_LIMIT
                    )),
                )
                .await?;
                continue;
            }

            data_buffer.rewind()?;

            let mut user_dir = self.users_dir.join(&recipient.normalised);

            let _restore_uid_gid = RestoreUidGid;

            if unix_privileges::assume_user_privileges(
                &self.log_prefix.to_string(),
                self.config.security.chroot_system,
                &mut user_dir,
                true,
            )
            .is_err()
            {
                self.send_response(
                    response_kind,
                    pc::ActionNotTakenTemporary,
                    Some((
                        cc::TempFail,
                        if user_dir.is_dir() {
                            sc::SystemIncorrectlyConfigured
                        } else {
                            sc::OtherMailboxStatus
                        },
                    )),
                    Cow::Borrowed("Problem with mailbox permissions"),
                )
                .await?;
                continue;
            }

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
                self.peer_id.as_ref().unwrap(),
                self.peer_name,
                self.host_name,
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION_MAJOR"),
                env!("CARGO_PKG_VERSION_MINOR"),
                env!("CARGO_PKG_VERSION_PATCH"),
                if self.started_tls { "LMTP+TLS" } else { "LMTP" },
                recipient.smtp,
                smtp_date
            );

            let sub_log_prefix = self.log_prefix.deep_clone();
            sub_log_prefix.set_user(recipient.normalised.clone());
            let result = DeliveryAccount::new(sub_log_prefix, user_dir)
                .and_then(|mut account| {
                    account.deliver(
                        "INBOX",
                        &[],
                        io::Read::chain(
                            message_prefix.as_bytes(),
                            &mut data_buffer,
                        ),
                    )
                });

            match result {
                Ok(_) => {
                    self.send_response(
                        response_kind,
                        pc::Ok,
                        Some((cc::Success, sc::Undefined)),
                        Cow::Borrowed("OK"),
                    )
                    .await?;
                },

                Err(e) => {
                    // NB In the one test that (normally) gets to this path,
                    // it's because the user was deliberately deleted.
                    error!(
                        "{} Unexpected error delivering to {}: {}",
                        self.log_prefix, recipient.normalised, e
                    );
                    self.send_response(
                        response_kind,
                        pc::ActionNotTakenTemporary,
                        Some((cc::TempFail, sc::OtherMailboxStatus)),
                        Cow::Borrowed(
                            "Unexpected problem accessing INBOX; \
                             see LMTP server logs for details",
                        ),
                    )
                    .await?;
                },
            }
        }

        self.reset();

        Ok(())
    }

    async fn send_greeting(&mut self) -> Result<(), Error> {
        self.send_response(
            Final,
            pc::ServiceReady,
            None,
            Cow::Owned(format!(
                "{} {} {}.{}.{} LMTP{} ready",
                self.host_name,
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION_MAJOR"),
                env!("CARGO_PKG_VERSION_MINOR"),
                env!("CARGO_PKG_VERSION_PATCH"),
                if self.started_tls { "+TLS" } else { "" }
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
}

#[derive(Debug, Clone)]
struct Recipient {
    normalised: String,
    smtp: String,
}

impl Recipient {
    pub fn normalise(config: &LmtpConfig, smtp: String) -> Option<Self> {
        let mut split = smtp.split('@');
        let (mut local, domain) =
            match (split.next(), split.next(), split.next()) {
                (Some(l), None, _) => (l.to_owned(), None),
                (Some(l), Some(d), None) => {
                    (l.to_owned(), Some(d.to_lowercase()))
                },
                _ => return None,
            };

        if !config.verbatim_user_names {
            local = local.to_lowercase();
            let mut has_plus = false;
            local.retain(|c| {
                has_plus |= '+' == c;
                !has_plus && c != '.'
            });
        }

        let normalised = match (config.keep_recipient_domain, domain) {
            (false, _) | (_, None) => local,
            (true, Some(domain)) => format!("{}@{}", local, domain),
        };

        if !is_safe_name(&normalised) {
            return None;
        }

        Some(Recipient { smtp, normalised })
    }
}

async fn copy_with_dot_stuffing(
    mut dst: impl Write,
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
            dst.write_all(&buffer[1..])?;
        } else {
            dst.write_all(&buffer)?;
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

    #[test]
    fn user_normalisation() {
        fn normalise(smtp: &str, keep_domain: bool, verbatim: bool) -> String {
            Recipient::normalise(
                &LmtpConfig {
                    keep_recipient_domain: keep_domain,
                    verbatim_user_names: verbatim,
                    ..LmtpConfig::default()
                },
                smtp.to_owned(),
            )
            .map(|r| r.normalised)
            .unwrap_or_else(|| "<None>".to_owned())
        }

        assert_eq!("foobar", normalise("foobar", false, false));
        assert_eq!("foobar", normalise("foobar", false, true));
        assert_eq!("foobar", normalise("foobar", true, false));
        assert_eq!("foobar", normalise("foobar", true, true));

        assert_eq!("foobar", normalise("Foo.Bar", false, false));
        assert_eq!("Foo.Bar", normalise("Foo.Bar", false, true));
        assert_eq!("foobar", normalise("Foo.Bar", true, false));
        assert_eq!("Foo.Bar", normalise("Foo.Bar", true, true));

        assert_eq!("foo", normalise("foo+bar", false, false));
        assert_eq!("foo+bar", normalise("foo+bar", false, true));
        assert_eq!("foo", normalise("foo+bar", true, false));
        assert_eq!("foo+bar", normalise("foo+bar", true, true));

        assert_eq!("foo", normalise("foo@bar.com", false, false));
        assert_eq!("foo", normalise("foo@bar.com", false, true));
        assert_eq!("foo@bar.com", normalise("foo@bar.com", true, false));
        assert_eq!("foo@bar.com", normalise("foo@bar.com", true, true));

        assert_eq!("foo", normalise("foo@BAR.COM", false, false));
        assert_eq!("foo", normalise("foo@BAR.COM", false, true));
        assert_eq!("foo@bar.com", normalise("foo@BAR.COM", true, false));
        assert_eq!("foo@bar.com", normalise("foo@BAR.COM", true, true));

        assert_eq!("föö", normalise("FÖ.Ö+bar@Baz.Com", false, false));
        assert_eq!("FÖ.Ö+bar", normalise("FÖ.Ö+bar@Baz.Com", false, true));
        assert_eq!("föö@baz.com", normalise("FÖ.Ö+bar@Baz.Com", true, false));
        assert_eq!(
            "FÖ.Ö+bar@baz.com",
            normalise("FÖ.Ö+bar@Baz.Com", true, true)
        );

        assert_eq!("<None>", normalise("foo@bar@baz", false, false));
        assert_eq!("<None>", normalise("foo/bar@baz.com", false, false));
        assert_eq!("<None>", normalise("@foo.com", false, false));
    }

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
                &mut decoded_bytes,
                Pin::new(&mut reader))).unwrap();

            assert_eq!(content, str::from_utf8(&decoded_bytes).unwrap());
        }
    }
}
