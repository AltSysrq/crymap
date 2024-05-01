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
use std::fmt::Write as _;
use std::io;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use log::error;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::transcript::Transcript;
use crate::{
    account::{
        model::{ForeignSmtpTlsStatus, TlsVersion},
        v2::{SmtpTransfer, SpooledMessage},
    },
    support::{async_io::ServerIo, dns},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The transaction on this connection failed entirely, but it's worth
    /// trying the next server.
    TryNextServer,
    /// The transaction on this connection failed entirely and trying another
    /// server (or ever retrying) is futile.
    TotalFailure,
}

#[derive(Debug, Clone)]
pub struct Results {
    /// The listed email addresses succeeded.
    pub success: Vec<String>,
    /// The listed email addresses failed temporarily.
    pub tempfail: Vec<String>,
    /// The listed email addresses failed permanently.
    pub permfail: Vec<String>,
    /// The updated foreign SMTP TLS status.
    pub tls_status: ForeignSmtpTlsStatus,
}

/// Executes an SMTP transaction against an established connection.
///
/// `message` will be delivered to each recipient in `destinations` via `cxn`.
pub async fn execute(
    cxn: ServerIo,
    transcript: &mut Transcript,
    message: SpooledMessage,
    destinations: &[&str],
    tls_expectations: &ForeignSmtpTlsStatus,
    mx_domain: &dns::Name,
    local_host_name: &str,
) -> Result<Results, Error> {
    let tx = Transaction {
        cxn,
        transcript,
        message,
        destinations,
        tls_expectations,
        mx_domain,
        local_host_name,

        line_buffer: [0u8; MAX_LINE],
        line_buffer_len: 0,
        command_deadline: Instant::now() + COMMAND_TIMEOUT,
    };
    tx.run().await
}

const MAX_LINE: usize = 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

struct Transaction<'a, 'b> {
    cxn: ServerIo,
    transcript: &'a mut Transcript,
    message: SpooledMessage,
    destinations: &'b [&'b str],
    tls_expectations: &'b ForeignSmtpTlsStatus,
    mx_domain: &'b dns::Name,
    local_host_name: &'b str,

    line_buffer: [u8; MAX_LINE],
    line_buffer_len: usize,
    command_deadline: Instant,
}

#[derive(Clone, Copy, Default)]
struct Capabilities {
    starttls: bool,
    binary: bool,
    chunking: bool,
    eight_bit: bool,
    size: bool,
    max_size: Option<u64>,
}

impl Transaction<'_, '_> {
    async fn run(mut self) -> Result<Results, Error> {
        // Process greeting
        self.read_status_as_server().await?;

        let capabilities = self.execute_helo().await?;
        let (tls_status, capabilities) =
            self.negotiate_tls(capabilities).await?;
        if let Some(max_size) = capabilities.max_size {
            if u64::from(self.message.size) > max_size {
                self.transcript.line(format_args!(
                    "Server reports maximum size of {}, which is \
                     less than the message size of {}",
                    max_size, self.message.size,
                ));
                return Err(Error::TotalFailure);
            }
        }

        self.start_transaction(&capabilities).await?;
        let recipient_result = self.send_recipients(tls_status).await?;

        if !recipient_result.success.is_empty() {
            if capabilities.chunking {
                self.send_message_via_bdat().await?;
            } else {
                self.send_message_via_data().await?;
            }
        }

        // The message has been sent. Do the mostly superfluous QUIT command,
        // but we don't care what actually happens.
        if self.send_command("QUIT").await.is_ok() {
            let _ = self.read_status().await;
        }

        Ok(recipient_result)
    }

    async fn execute_helo(&mut self) -> Result<Capabilities, Error> {
        let mut capabilities = Capabilities::default();
        self.send_command(&format!("EHLO {}", self.local_host_name))
            .await?;
        let ehlo_status = self
            .read_responses(|line| {
                if "STARTTLS".eq_ignore_ascii_case(line.comment) {
                    capabilities.starttls = true;
                } else if "BINARYMIME".eq_ignore_ascii_case(line.comment) {
                    capabilities.binary = true;
                } else if "CHUNKING".eq_ignore_ascii_case(line.comment) {
                    capabilities.chunking = true;
                } else if "8BITMIME".eq_ignore_ascii_case(line.comment) {
                    capabilities.eight_bit = true;
                } else if "SIZE".eq_ignore_ascii_case(line.comment) {
                    capabilities.size = true;
                } else if line
                    .comment
                    .get(..5)
                    .unwrap_or("")
                    .eq_ignore_ascii_case("SIZE ")
                {
                    capabilities.size = true;
                    capabilities.max_size = line.comment[5..]
                        .parse::<u64>()
                        .ok()
                        // 0 means "no limit".
                        .filter(|&s| s > 0);
                }
            })
            .await?;

        match ehlo_status {
            200..=299 => return Ok(capabilities),
            500..=504 | 550 => (), // Retry with HELO
            _ => self.handle_status_as_server(ehlo_status)?,
        }

        // EHLO apparently not supported; retry legacy HELO
        self.send_command(&format!("HELO {}", self.local_host_name))
            .await?;
        self.read_status_as_server().await?;
        Ok(Capabilities::default())
    }

    async fn negotiate_tls(
        &mut self,
        capabilities: Capabilities,
    ) -> Result<(ForeignSmtpTlsStatus, Capabilities), Error> {
        let mut new_status = ForeignSmtpTlsStatus {
            domain: self.tls_expectations.domain.clone(),
            ..Default::default()
        };

        if !capabilities.starttls {
            if self.tls_expectations.starttls {
                self.transcript.line(format_args!(
                    "SECURITY VIOLATION: Server claims it does not support \
                     STARTTLS, but we've seen it in the past.",
                ));
                return Err(Error::TryNextServer);
            }

            self.transcript.line(format_args!(
                "WARNING: Conducting this transaction in cleartext!",
            ));
            return Ok((new_status, capabilities));
        }

        new_status.starttls = true;
        self.send_command("STARTTLS").await?;
        self.read_status_as_server().await?;
        self.transcript.line(format_args!(
            "<> Performing TLS handshake; expecting {} \
             certificate and version ≥ {:?}",
            if self.tls_expectations.valid_certificate {
                "valid"
            } else {
                "any"
            },
            self.tls_expectations.tls_version.unwrap_or_default(),
        ));

        let mut connector_builder =
            SslConnector::builder(SslMethod::tls_client())
                .map_err(unexpected_ssl_error)?;
        let valid_certificate = Arc::new(AtomicBool::new(false));
        connector_builder.set_verify_callback(
            if self.tls_expectations.valid_certificate {
                SslVerifyMode::PEER
            } else {
                SslVerifyMode::NONE
            },
            {
                let valid_certificate = Arc::clone(&valid_certificate);
                move |valid, _| {
                    valid_certificate.store(valid, Ordering::Relaxed);
                    valid
                }
            },
        );
        connector_builder
            .set_min_proto_version(
                match self.tls_expectations.tls_version.unwrap_or_default() {
                    TlsVersion::Ssl3 => None,
                    TlsVersion::Tls10 => Some(SslVersion::TLS1),
                    TlsVersion::Tls11 => Some(SslVersion::TLS1_1),
                    TlsVersion::Tls12 => Some(SslVersion::TLS1_2),
                    TlsVersion::Tls13 => Some(SslVersion::TLS1_3),
                },
            )
            .map_err(unexpected_ssl_error)?;

        let mx_domain_str = self.mx_domain.to_ascii();
        let ssl_result = tokio::time::timeout_at(
            self.command_deadline.into(),
            self.cxn.ssl_connect(
                mx_domain_str.strip_suffix('.').unwrap_or(&*mx_domain_str),
                &connector_builder.build(),
            ),
        )
        .await;

        match ssl_result {
            Ok(Ok(())) => {},
            Err(_) => {
                self.transcript
                    .line(format_args!("<> TLS handshake timed out"));
                return Err(Error::TryNextServer);
            },
            Ok(Err(e)) => {
                self.transcript
                    .line(format_args!("<> TLS handshake failed: {e}"));
                return Err(Error::TryNextServer);
            },
        }

        new_status.valid_certificate =
            valid_certificate.load(Ordering::Relaxed);

        let tls_version = match self.cxn.ssl_version() {
            None | Some(SslVersion::SSL3) => TlsVersion::Ssl3,
            Some(SslVersion::TLS1) => TlsVersion::Tls10,
            Some(SslVersion::TLS1_1) => TlsVersion::Tls11,
            Some(SslVersion::TLS1_2) => TlsVersion::Tls12,
            Some(SslVersion::TLS1_3) => TlsVersion::Tls13,
            v => {
                error!("Unhandled TLS version: {v:?}");
                TlsVersion::Ssl3
            },
        };
        new_status.tls_version = Some(tls_version);

        self.transcript.line(format_args!(
            "<> TLS handshake succeeded with {} certificate and version {:?}",
            if new_status.valid_certificate {
                "valid"
            } else {
                "invalid"
            },
            tls_version,
        ));

        let new_capabilities = self.execute_helo().await?;
        Ok((new_status, new_capabilities))
    }

    async fn start_transaction(
        &mut self,
        capabilities: &Capabilities,
    ) -> Result<(), Error> {
        let mut command = format!("MAIL FROM:<{}>", self.message.mail_from);
        if capabilities.size {
            let _ = write!(command, " SIZE={}", self.message.size);
        }

        match self.message.transfer {
            SmtpTransfer::Binary
                if capabilities.binary && capabilities.chunking =>
            {
                command.push_str(" BODY=BINARYMIME");
            },

            SmtpTransfer::Binary | SmtpTransfer::EightBit
                if capabilities.eight_bit =>
            {
                command.push_str(" BODY=8BITMIME");
            },

            _ => {},
        }

        self.send_command(&command).await?;
        self.read_status_as_mail().await?;
        Ok(())
    }

    async fn send_recipients(
        &mut self,
        tls_status: ForeignSmtpTlsStatus,
    ) -> Result<Results, Error> {
        let mut results = Results {
            success: Vec::new(),
            tempfail: Vec::new(),
            permfail: Vec::new(),
            tls_status,
        };

        for &recipient in self.destinations {
            self.send_command(&format!("RCPT TO:<{}>", recipient))
                .await?;
            match self.read_status().await? {
                200..=299 => results.success.push(recipient.to_owned()),
                400..=499 => results.tempfail.push(recipient.to_owned()),
                500..=599 => results.permfail.push(recipient.to_owned()),
                code => {
                    self.transcript.line(format_args!(
                        "Unexpected result for RCPT TO: {code}"
                    ));
                    results.tempfail.push(recipient.to_owned());
                },
            }
        }

        Ok(results)
    }

    async fn send_message_via_data(&mut self) -> Result<(), Error> {
        self.send_command("DATA").await?;
        match self.read_status().await? {
            // 2XX status codes are undefined, but OpenSMTPD treats them the
            // same as 354 here, presumably with good reason.
            200..=299 | 354 => {},

            code => {
                self.handle_status_as_server(code)?;
                error!("BUG: Improperly handled code {code} from DATA command",);
                return Err(Error::TryNextServer);
            },
        }

        self.extend_command_deadline_for_transfer(u64::from(self.message.size));
        let result = tokio::time::timeout_at(
            self.command_deadline.into(),
            copy_with_dot_stuffing(&mut self.cxn, &mut self.message.data),
        )
        .await;

        match result {
            Err(_timeout) => {
                self.transcript
                    .line(format_args!("<< DATA transfer timed out"));
                return Err(Error::TryNextServer);
            },

            Ok(Err(io)) => {
                self.transcript.line(format_args!("I/O error: {io}"));
                return Err(Error::TryNextServer);
            },

            Ok(Ok(())) => {},
        }

        self.transcript.line(format_args!(
            "<< [{} bytes, dot-stuffed]",
            self.message.size
        ));
        self.read_status_as_mail().await?;

        Ok(())
    }

    async fn send_message_via_bdat(&mut self) -> Result<(), Error> {
        const CHUNK_SIZE: u64 = 256 * 1024;
        let mut buf = vec![0u8; CHUNK_SIZE as usize];
        let mut data_left = u64::from(self.message.size);

        while data_left > 0 {
            let chunk_size = data_left.min(CHUNK_SIZE);
            if let Err(e) = self
                .message
                .data
                .read_exact(&mut buf[..chunk_size as usize])
            {
                self.transcript
                    .line(format_args!("I/O error reading message: {e}"));
                return Err(Error::TotalFailure);
            }

            data_left -= chunk_size;

            let mut command = format!("BDAT {chunk_size}");
            if 0 == data_left {
                command.push_str(" LAST");
            }

            self.send_command(&command).await?;
            self.extend_command_deadline_for_transfer(chunk_size);
            let send_result =
                tokio::time::timeout_at(self.command_deadline.into(), async {
                    self.cxn.write_all(&buf[..chunk_size as usize]).await?;
                    self.cxn.flush().await?;
                    io::Result::Ok(())
                })
                .await;
            match send_result {
                Ok(Ok(_)) => {},

                Ok(Err(io)) => {
                    self.transcript
                        .line(format_args!("I/O error sending data: {io}"));
                    return Err(Error::TryNextServer);
                },

                Err(_timeout) => {
                    self.transcript.line(format_args!("Timeout sending data"));
                    return Err(Error::TryNextServer);
                },
            }

            self.transcript
                .line(format_args!("<< [{chunk_size} bytes]"));

            self.read_status_as_mail().await?;
        }

        Ok(())
    }

    /// Send the given command (which does not include the line ending) to the
    /// server.
    ///
    /// The command deadline is reset to the current time plus the standard
    /// command timeout.
    async fn send_command(&mut self, command: &str) -> Result<(), Error> {
        self.command_deadline = Instant::now() + COMMAND_TIMEOUT;
        let io = async {
            self.cxn.write_all(command.as_bytes()).await?;
            self.cxn.write_all(b"\r\n").await?;
            self.cxn.flush().await?;
            io::Result::Ok(())
        };

        self.transcript.line(format_args!("<< {command}"));
        match tokio::time::timeout_at(self.command_deadline.into(), io).await {
            Ok(Ok(())) => {},
            Ok(Err(e)) => {
                self.transcript.line(format_args!(
                    "I/O error sending command to server: {e}"
                ));
                return Err(Error::TryNextServer);
            },
            Err(_) => {
                self.transcript
                    .line(format_args!("Timeout sending command to server"));
                return Err(Error::TryNextServer);
            },
        }

        Ok(())
    }

    /// Read a command status and interpret according as pertaining to this
    /// particular server.
    async fn read_status_as_server(&mut self) -> Result<(), Error> {
        let status = self.read_status().await?;
        self.handle_status_as_server(status)
    }

    /// Interpret a command status as pertaining to the server itself.
    fn handle_status_as_server(&mut self, status: u32) -> Result<(), Error> {
        match status {
            200..=299 => Ok(()),
            400..=499 => {
                self.transcript.line(format_args!(
                    "Server appears temporarily unavailable",
                ));
                Err(Error::TryNextServer)
            },
            500..=599 => {
                self.transcript.line(format_args!(
                    "Server suggests it is permanently unavailable",
                ));
                Err(Error::TryNextServer)
            },
            _ => {
                self.transcript
                    .line(format_args!("Unexpected response code; giving up"));
                Err(Error::TryNextServer)
            },
        }
    }

    /// Read a command status and interpret according as pertaining to this
    /// particular email message.
    async fn read_status_as_mail(&mut self) -> Result<(), Error> {
        let status = self.read_status().await?;
        self.handle_status_as_mail(status)
    }

    /// Interpret a command status as pertaining to the email message.
    fn handle_status_as_mail(&mut self, status: u32) -> Result<(), Error> {
        match status {
            200..=299 => Ok(()),
            400..=499 => {
                self.transcript
                    .line(format_args!("Mail failed temporarily"));
                Err(Error::TryNextServer)
            },
            500..=599 => {
                self.transcript.line(format_args!("Mail rejected"));
                Err(Error::TotalFailure)
            },
            _ => {
                self.transcript
                    .line(format_args!("Unexpected response code; giving up"));
                Err(Error::TryNextServer)
            },
        }
    }

    /// Discard all responses until the next final response, and return the
    /// code on that response.
    async fn read_status(&mut self) -> Result<u32, Error> {
        self.read_responses(|_| ()).await
    }

    /// Read response lines up to and including the final one, returning the
    /// final status code.
    ///
    /// `on_line` is invoked for each parsed line.
    async fn read_responses(
        &mut self,
        mut on_line: impl FnMut(&ParsedLine<'_>),
    ) -> Result<u32, Error> {
        for _ in 0..1000 {
            let line = self.read_line().await?;
            let len = line.len();
            let parsed = parse_line(&line);
            if let Some(ref parsed) = parsed {
                on_line(parsed);
            }
            let parsed = parsed.map(|l| (l.status, l.last));
            self.consume_line(len);

            let Some((status, last)) = parsed else {
                self.transcript.line(format_args!("Bad SMTP response"));
                return Err(Error::TryNextServer);
            };

            if last {
                return Ok(status);
            }
        }

        self.transcript
            .line(format_args!("Too many responses; giving up"));
        Err(Error::TryNextServer)
    }

    /// Read data from the server until `line_buffer` contains a line ending.
    /// On success, return the line that was read, including the line ending.
    async fn read_line(&mut self) -> Result<Cow<'_, str>, Error> {
        loop {
            if let Some(ix) =
                memchr::memchr(b'\n', &self.line_buffer[..self.line_buffer_len])
            {
                let s = String::from_utf8_lossy(&self.line_buffer[..ix]);
                self.transcript.line(format_args!(">> {:?}", &*s));
                return Ok(s);
            }

            if self.line_buffer_len >= MAX_LINE {
                self.transcript
                    .line(format_args!("Server response line too long"));
                return Err(Error::TryNextServer);
            }

            match tokio::time::timeout_at(
                self.command_deadline.into(),
                self.cxn.read(&mut self.line_buffer[self.line_buffer_len..]),
            )
            .await
            {
                Err(_timeout) => {
                    self.transcript.line(format_args!(
                        "Timed out reading line from server"
                    ));
                    return Err(Error::TryNextServer);
                },

                Ok(Err(e)) => {
                    self.transcript.line(format_args!(
                        "I/O error reading line from server: {e}"
                    ));
                    return Err(Error::TryNextServer);
                },

                Ok(Ok(0)) => {
                    self.transcript
                        .line(format_args!("EOF reading line from server"));
                    return Err(Error::TryNextServer);
                },

                Ok(Ok(n)) => {
                    self.line_buffer_len += n;
                },
            }
        }
    }

    fn consume_line(&mut self, n: usize) {
        debug_assert!(n < self.line_buffer_len);
        debug_assert!(b'\n' == self.line_buffer[n]);

        self.line_buffer.copy_within(n + 1..self.line_buffer_len, 0);
        self.line_buffer_len -= n + 1;
    }

    fn extend_command_deadline_for_transfer(&mut self, size: u64) {
        // Extend the deadline to account for a 32kbps transfer rate.
        self.command_deadline += Duration::from_millis(size / 4);
    }
}

struct ParsedLine<'a> {
    status: u32,
    last: bool,
    comment: &'a str,
}

fn parse_line(s: &str) -> Option<ParsedLine<'_>> {
    let s = s.trim_end_matches(['\r', '\n']);
    let status = s.get(0..3)?;
    let last = s.get(3..4)?;
    let comment = s.get(4..)?;

    let status: u32 = status.parse().ok()?;
    let last = match last {
        " " => true,
        "-" => false,
        _ => return None,
    };

    Some(ParsedLine {
        status,
        last,
        comment,
    })
}

fn unexpected_ssl_error(err: openssl::error::ErrorStack) -> Error {
    error!("unexpected SSL error: {err}");
    Error::TotalFailure
}

/// Copy `src` into `dst`, applying CRLF-strict dot stuffing. The copy includes
/// the terminating ".\r\n".
async fn copy_with_dot_stuffing(
    dst: &mut (impl tokio::io::AsyncWrite + Unpin),
    src: &mut impl io::BufRead,
) -> io::Result<()> {
    let mut dst = tokio::io::BufWriter::new(dst);
    let mut start_of_line = true;
    let mut prev_end = 0u8;

    loop {
        let mut buffer = src.fill_buf()?;
        if buffer.is_empty() {
            break;
        }

        if let Some(eol) = memchr::memchr(b'\n', buffer) {
            buffer = &buffer[..eol + 1];
        }

        if start_of_line && Some(b'.') == buffer.first().copied() {
            dst.write_all(b".").await?;
        }
        dst.write_all(buffer).await?;

        let last = buffer
            .last()
            .copied()
            .expect("buffer is definitely non-empty");
        let prev = buffer
            .get(buffer.len().wrapping_sub(2))
            .copied()
            .unwrap_or(prev_end);
        start_of_line = b'\r' == prev && b'\n' == last;
        prev_end = last;

        let buffer_len = buffer.len();
        src.consume(buffer_len);
    }

    if !start_of_line {
        dst.write_all(b"\r\n").await?;
    }
    dst.write_all(b".\r\n").await?;
    dst.flush().await?;

    Ok(())
}

#[cfg(test)]
mod test {
    use std::os::unix::net::UnixStream;

    use itertools::Itertools;
    use openssl::ssl::SslAcceptor;
    use proptest::prelude::*;

    use super::super::super::codes::*;
    use super::*;
    use crate::{
        account::model::CommonPaths,
        test_data::{CERTIFICATE, CERTIFICATE_PRIVATE_KEY},
    };

    fn copy_with_dot_stuffing_sync(
        content: &[u8],
        buffer_size: usize,
    ) -> Vec<u8> {
        // We box content into a trait object to ensure the buffer behaviour
        // can never be specialised away.
        let mut reader = io::BufReader::with_capacity(
            buffer_size,
            Box::new(content) as Box<dyn io::Read>,
        );
        let mut decoded_bytes = Vec::<u8>::new();
        futures::executor::block_on(copy_with_dot_stuffing(
            &mut decoded_bytes,
            &mut reader,
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
        fn binary_dot_stuffing_encodes_properly(
            content in "[x.\r\n]{1,100}",
            buffer_size in 1usize..=32,
        ) {
            let mut stuffed = content.replace("\r\n.", "\r\n..");
            if stuffed.starts_with(".") {
                stuffed = format!(".{}", stuffed);
            }
            if !stuffed.ends_with("\r\n") {
                stuffed.push_str("\r\n");
            }
            stuffed.push_str(".\r\n");

            let actual = String::from_utf8(
                copy_with_dot_stuffing_sync(content.as_bytes(), buffer_size))
                .unwrap();
            assert_eq!(stuffed, actual);
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum SessionStep {
        Command(&'static str),
        Response(PrimaryCode, &'static str),
        RawResponseData(&'static str),
        InfiniteResponse,
        StartTls(bool),
        DotStuffedData,
        Bdats,
    }

    use self::SessionStep::{
        Bdats, Command as C, DotStuffedData, RawResponseData, Response as R,
        StartTls,
    };

    struct SessionParms {
        local_host_name: &'static str,
        tls_version: Option<SslVersion>,
        mail_from: &'static str,
        destinations: &'static [&'static str],
        message_data: Vec<u8>,
        transfer: SmtpTransfer,
        unix_lines: bool,
        tls_expectations: ForeignSmtpTlsStatus,
    }

    impl Default for SessionParms {
        fn default() -> Self {
            Self {
                local_host_name: "mx.earth.com",
                tls_version: None,
                mail_from: "zim@earth.com",
                destinations: &["tallest@irk.com"],
                message_data: b"this is the message data\r\n".to_vec(),
                transfer: SmtpTransfer::SevenBit,
                unix_lines: false,
                tls_expectations: ForeignSmtpTlsStatus {
                    domain: "mail.irk.com".to_owned(),
                    ..ForeignSmtpTlsStatus::default()
                },
            }
        }
    }

    #[tokio::main(flavor = "current_thread")]
    async fn run_session(
        parms: &SessionParms,
        steps: &[SessionStep],
    ) -> Result<Results, Error> {
        let common_paths = Arc::new(CommonPaths {
            tmp: std::env::temp_dir(),
            garbage: std::env::temp_dir(),
        });
        let (server_io, client_io) = UnixStream::pair().unwrap();
        let server_io = ServerIo::new_owned_socket(server_io).unwrap();
        let client_io = ServerIo::new_owned_socket(client_io).unwrap();
        let server_future = run_server(server_io, parms, steps);
        let mut transcript = Transcript::new(common_paths);
        let message = SpooledMessage {
            id: crate::account::v2::SpooledMessageId::DUMMY,
            transfer: parms.transfer,
            expires: Default::default(),
            mail_from: parms.mail_from.to_owned(),
            destinations: vec![],
            size: parms.message_data.len() as u32,
            data: Box::new(io::Cursor::new(parms.message_data.clone())),
        };
        let mx_domain = dns::Name::from_ascii("unused.com").unwrap();
        let client_future = execute(
            client_io,
            &mut transcript,
            message,
            parms.destinations,
            &parms.tls_expectations,
            &mx_domain,
            parms.local_host_name,
        );
        let (ret, server_result) = tokio::join![client_future, server_future];

        let mut transcript_text = String::new();
        let mut transcript_reader = transcript.finish().unwrap();
        io::Read::read_to_string(&mut transcript_reader, &mut transcript_text)
            .unwrap();
        println!("Transcript:\n{}", transcript_text);

        if let Some(err) = server_result.expect("server I/O error") {
            panic!("server returned test failure: {err}");
        }

        ret
    }

    async fn run_server(
        mut cxn: ServerIo,
        parms: &SessionParms,
        steps: &[SessionStep],
    ) -> io::Result<Option<String>> {
        async fn read_line(
            cxn: &mut ServerIo,
            buf: &mut [u8],
            buf_len: &mut usize,
        ) -> io::Result<Result<String, String>> {
            let len = loop {
                if let Some(eol) = memchr::memchr(b'\n', &buf[..*buf_len]) {
                    break eol + 1;
                }

                if *buf_len >= buf.len() {
                    return Ok(Err("Over-long command line".to_owned()));
                }

                *buf_len += cxn.read(&mut buf[*buf_len..]).await?;
            };

            let Ok(mut s) =
                std::str::from_utf8(&buf[..len]).map(|s| s.to_owned())
            else {
                return Ok(Err("Non-UTF8 command line".to_owned()));
            };

            if !s.ends_with("\r\n") {
                return Ok(Err(format!("Improperly terminated line: {s:?}")));
            }

            buf.copy_within(s.len()..*buf_len, 0);
            *buf_len -= s.len();

            s.truncate(s.len() - 2);
            Ok(Ok(s))
        }

        let mut ssl_acceptor_builder =
            SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
                .unwrap();
        ssl_acceptor_builder
            .set_private_key(&CERTIFICATE_PRIVATE_KEY)
            .unwrap();
        ssl_acceptor_builder.set_certificate(&CERTIFICATE).unwrap();
        ssl_acceptor_builder
            .set_min_proto_version(parms.tls_version)
            .unwrap();
        ssl_acceptor_builder
            .set_max_proto_version(parms.tls_version)
            .unwrap();
        let ssl_acceptor = ssl_acceptor_builder.build();

        let mut buf = [0u8; 256];
        let mut buf_len = 0usize;

        let line_ending = if parms.unix_lines { "\n" } else { "\r\n" };

        for (step, next_step) in steps
            .iter()
            .copied()
            .chain(std::iter::once(SessionStep::Command("unreachable")))
            .tuple_windows()
        {
            match step {
                SessionStep::Command(expected_line) => {
                    let actual_line =
                        match read_line(&mut cxn, &mut buf, &mut buf_len)
                            .await?
                        {
                            Ok(line) => line,
                            Err(err) => return Ok(Some(err)),
                        };

                    if actual_line != expected_line {
                        return Ok(Some(format!(
                            "expected command {expected_line:?}, \
                             got {actual_line:?}",
                        )));
                    }
                },

                SessionStep::Response(code, message) => {
                    let line = format!(
                        "{}{}{message}{}",
                        code as u32,
                        if matches!(next_step, SessionStep::Response(..)) {
                            "-"
                        } else {
                            " "
                        },
                        line_ending,
                    );
                    cxn.write_all(line.as_bytes()).await?;
                    cxn.flush().await?;
                },

                SessionStep::RawResponseData(s) => {
                    cxn.write_all(s.as_bytes()).await?;
                    cxn.flush().await?;
                },

                SessionStep::InfiniteResponse => {
                    while cxn.write_all(b"250 ").await.is_ok() {}
                },

                SessionStep::StartTls(success) => {
                    match cxn.ssl_accept(&ssl_acceptor).await {
                        Ok(()) => {
                            if !success {
                                return Ok(Some(
                                    "TLS handshake succeeded unexpectedly"
                                        .to_owned(),
                                ));
                            }
                        },
                        Err(crate::support::error::Error::Io(e)) => {
                            return Err(e)
                        },
                        Err(e) => {
                            if success {
                                return Ok(Some(format!(
                                    "TLS handshake failed unexpectedly: {e}",
                                )));
                            } else {
                                println!(
                                    "expected server TLS handshake failure: {e}",
                                );
                            }
                        },
                    }
                },

                SessionStep::DotStuffedData => {
                    let mut size = 0usize;
                    loop {
                        let line =
                            match read_line(&mut cxn, &mut buf, &mut buf_len)
                                .await?
                            {
                                Ok(line) => line,
                                Err(err) => return Ok(Some(err)),
                            };

                        if "." == line {
                            break;
                        }

                        size += line.len() + 2;
                        if line.starts_with(".") {
                            size -= 1;
                        }
                    }

                    if size != parms.message_data.len() {
                        return Ok(Some(format!(
                            "expected message with {} bytes, but got {} bytes",
                            parms.message_data.len(),
                            size,
                        )));
                    }
                },

                SessionStep::Bdats => {
                    let mut size = 0usize;
                    let mut done = false;
                    while !done {
                        let line =
                            match read_line(&mut cxn, &mut buf, &mut buf_len)
                                .await?
                            {
                                Ok(line) => line,
                                Err(err) => return Ok(Some(err)),
                            };

                        if !line.starts_with("BDAT ") {
                            return Ok(Some(format!(
                                "expected BDAT, got {line:?}",
                            )));
                        }

                        let mut payload_size = &line[5..];
                        done = if line.ends_with(" LAST") {
                            payload_size =
                                &payload_size[..payload_size.len() - 5];
                            true
                        } else {
                            false
                        };

                        let Ok(payload_size) = payload_size.parse::<usize>()
                        else {
                            return Ok(Some(format!(
                                "bad BDAT line: {line:?}"
                            )));
                        };

                        size += payload_size;

                        let already_buffered = buf_len.min(payload_size);
                        buf.copy_within(already_buffered..buf_len, 0);
                        buf_len -= already_buffered;

                        if already_buffered < payload_size {
                            tokio::io::copy(
                                &mut (&mut cxn).take(
                                    (payload_size - already_buffered) as u64,
                                ),
                                &mut tokio::io::sink(),
                            )
                            .await?;
                        }

                        if !done {
                            let response = format!("250 MOAR!{line_ending}");
                            cxn.write_all(response.as_bytes()).await?;
                        }
                    }

                    if size != parms.message_data.len() {
                        return Ok(Some(format!(
                            "expected message with {} bytes, but got {} bytes",
                            parms.message_data.len(),
                            size,
                        )));
                    }
                },
            }
        }

        // Ensure the client actually hangs up and isn't trying to talk to us
        // more or waiting for us to say something.
        let mut more = [0u8];
        match tokio::time::timeout(Duration::from_secs(5), cxn.read(&mut more))
            .await
        {
            Err(_timeout) => {
                return Ok(Some("client never hung up".to_owned()))
            },
            Ok(Err(e)) => match e.kind() {
                io::ErrorKind::UnexpectedEof
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::ConnectionReset => {},
                _ => return Err(e),
            },
            Ok(Ok(0)) => {},
            Ok(Ok(_)) => return Ok(Some("client wrote more data".to_owned())),
        }

        Ok(None)
    }

    fn all_succeed(parms: &SessionParms, steps: &[SessionStep]) -> Results {
        let results = run_session(parms, steps).unwrap();

        for &d in parms.destinations {
            assert!(
                results.success.iter().any(|success| success == d),
                "destination {d} was not successful",
            );
        }
        assert_eq!(results.success.len(), parms.destinations.len());
        assert!(results.tempfail.is_empty());
        assert!(results.permfail.is_empty());

        results
    }

    fn try_next_server(parms: &SessionParms, steps: &[SessionStep]) {
        let result = run_session(parms, steps);
        match result {
            Ok(_) => panic!("succeeded unexpectedly"),
            Err(e) => assert_eq!(Error::TryNextServer, e),
        }
    }

    fn total_failure(parms: &SessionParms, steps: &[SessionStep]) {
        let result = run_session(parms, steps);
        match result {
            Ok(_) => panic!("succeeded unexpectedly"),
            Err(e) => assert_eq!(Error::TotalFailure, e),
        }
    }

    #[test]
    fn minimal_success() {
        all_succeed(
            &SessionParms::default(),
            &[
                R(pc::Ok, "Greeting"),
                C("EHLO mx.earth.com"),
                R(pc::Ok, "No extensions supported"),
                C("MAIL FROM:<zim@earth.com>"),
                R(pc::Ok, "OK"),
                C("RCPT TO:<tallest@irk.com>"),
                R(pc::Ok, "OK"),
                C("DATA"),
                R(pc::StartMailInput, "OK"),
                DotStuffedData,
                R(pc::Ok, "OK"),
                C("QUIT"),
                R(pc::ServiceClosing, "Bye"),
            ],
        );
    }

    #[test]
    fn unix_newlines() {
        all_succeed(
            &SessionParms {
                unix_lines: true,
                ..SessionParms::default()
            },
            &[
                R(pc::Ok, "Greeting"),
                C("EHLO mx.earth.com"),
                R(pc::Ok, "No extensions supported"),
                C("MAIL FROM:<zim@earth.com>"),
                R(pc::Ok, "OK"),
                C("RCPT TO:<tallest@irk.com>"),
                R(pc::Ok, "OK"),
                C("DATA"),
                R(pc::StartMailInput, "OK"),
                DotStuffedData,
                R(pc::Ok, "OK"),
                C("QUIT"),
                R(pc::ServiceClosing, "Bye"),
            ],
        );
    }

    #[test]
    fn data_two_hundred() {
        all_succeed(
            &SessionParms::default(),
            &[
                R(pc::Ok, "Greeting"),
                C("EHLO mx.earth.com"),
                R(pc::Ok, "No extensions supported"),
                C("MAIL FROM:<zim@earth.com>"),
                R(pc::Ok, "OK"),
                C("RCPT TO:<tallest@irk.com>"),
                R(pc::Ok, "OK"),
                C("DATA"),
                R(pc::Ok, "Not 354 for some reason..."),
                DotStuffedData,
                R(pc::Ok, "OK"),
                C("QUIT"),
                R(pc::ServiceClosing, "Bye"),
            ],
        );
    }

    #[test]
    fn helo_fallback() {
        all_succeed(
            &SessionParms::default(),
            &[
                R(pc::Ok, "How do you do?"),
                C("EHLO mx.earth.com"),
                R(
                    pc::CommandSyntaxError,
                    "Gee willikers, I don't know what EHLO means",
                ),
                C("HELO mx.earth.com"),
                R(pc::Ok, "OK"),
                C("MAIL FROM:<zim@earth.com>"),
                R(pc::Ok, "OK"),
                C("RCPT TO:<tallest@irk.com>"),
                R(pc::Ok, "OK"),
                C("DATA"),
                R(pc::StartMailInput, "OK"),
                DotStuffedData,
                R(pc::Ok, "OK"),
                C("QUIT"),
                R(pc::ServiceClosing, "Bye"),
            ],
        );
    }

    #[test]
    fn first_time_starttls() {
        let results = all_succeed(
            &SessionParms {
                tls_version: Some(SslVersion::TLS1_3),
                ..SessionParms::default()
            },
            &[
                R(pc::Ok, "Greeting"),
                C("EHLO mx.earth.com"),
                R(pc::Ok, "Ok"),
                R(pc::Ok, "StartTLS"),
                C("STARTTLS"),
                R(pc::Ok, "Ok"),
                StartTls(true),
                C("EHLO mx.earth.com"),
                R(pc::Ok, "Ok"),
                C("MAIL FROM:<zim@earth.com>"),
                R(pc::Ok, "OK"),
                C("RCPT TO:<tallest@irk.com>"),
                R(pc::Ok, "OK"),
                C("DATA"),
                R(pc::StartMailInput, "OK"),
                DotStuffedData,
                R(pc::Ok, "OK"),
                C("QUIT"),
                R(pc::ServiceClosing, "Bye"),
            ],
        );

        assert!(results.tls_status.starttls);
        assert!(!results.tls_status.valid_certificate);
        assert_eq!(Some(TlsVersion::Tls13), results.tls_status.tls_version);
    }

    #[test]
    fn strip_tls_attack() {
        try_next_server(
            &SessionParms {
                tls_expectations: ForeignSmtpTlsStatus {
                    domain: "mail.irk.com".to_owned(),
                    starttls: true,
                    ..Default::default()
                },
                ..Default::default()
            },
            &[
                R(pc::Ok, "Greeting"),
                C("EHLO mx.earth.com"),
                R(pc::Ok, "Ok"),
                R(pc::Ok, "NO STARTTLS HERE!"),
            ],
        );
    }

    #[test]
    fn certificate_downgrade_attack() {
        try_next_server(
            &SessionParms {
                tls_expectations: ForeignSmtpTlsStatus {
                    domain: "mail.irk.com".to_owned(),
                    starttls: true,
                    valid_certificate: true,
                    tls_version: Some(TlsVersion::Tls13),
                },
                ..Default::default()
            },
            &[
                R(pc::Ok, "Greeting, I have MITM'ed you!"),
                C("EHLO mx.earth.com"),
                R(pc::Ok, "Ok"),
                R(pc::Ok, "STARTTLS"),
                C("STARTTLS"),
                R(pc::Ok, "Ok"),
                StartTls(false),
            ],
        );
    }

    #[test]
    fn tls_version_downgrade_attack() {
        try_next_server(
            &SessionParms {
                tls_expectations: ForeignSmtpTlsStatus {
                    domain: "mail.irk.com".to_owned(),
                    starttls: true,
                    valid_certificate: false,
                    tls_version: Some(TlsVersion::Tls13),
                },
                tls_version: Some(SslVersion::TLS1_2),
                ..Default::default()
            },
            &[
                R(pc::Ok, "Greeting, I have MITM'ed you!"),
                C("EHLO mx.earth.com"),
                R(pc::Ok, "Ok"),
                R(pc::Ok, "STARTTLS"),
                C("STARTTLS"),
                R(pc::Ok, "Ok"),
                StartTls(false),
            ],
        );
    }

    #[test]
    fn tls_version_upgrade() {
        let results = all_succeed(
            &SessionParms {
                tls_expectations: ForeignSmtpTlsStatus {
                    domain: "mail.irk.com".to_owned(),
                    starttls: true,
                    valid_certificate: false,
                    tls_version: Some(TlsVersion::Tls12),
                },
                tls_version: Some(SslVersion::TLS1_3),
                ..SessionParms::default()
            },
            &[
                R(pc::Ok, "Greeting"),
                C("EHLO mx.earth.com"),
                R(pc::Ok, "Ok"),
                R(pc::Ok, "StartTLS"),
                C("STARTTLS"),
                R(pc::Ok, "Ok"),
                StartTls(true),
                C("EHLO mx.earth.com"),
                R(pc::Ok, "Ok"),
                C("MAIL FROM:<zim@earth.com>"),
                R(pc::Ok, "OK"),
                C("RCPT TO:<tallest@irk.com>"),
                R(pc::Ok, "OK"),
                C("DATA"),
                R(pc::StartMailInput, "OK"),
                DotStuffedData,
                R(pc::Ok, "OK"),
                C("QUIT"),
                R(pc::ServiceClosing, "Bye"),
            ],
        );

        assert!(results.tls_status.starttls);
        assert!(!results.tls_status.valid_certificate);
        assert_eq!(Some(TlsVersion::Tls13), results.tls_status.tls_version);
    }

    #[test]
    fn starttls_rejected() {
        try_next_server(
            &SessionParms::default(),
            &[
                R(pc::Ok, "Greeting, I have MITM'ed you!"),
                C("EHLO mx.earth.com"),
                R(pc::Ok, "Ok"),
                R(pc::Ok, "STARTTLS"),
                C("STARTTLS"),
                R(pc::ActionNotTakenTemporary, "No TLS for you!"),
            ],
        );
    }

    #[test]
    fn greeting_reject_permanent() {
        try_next_server(
            &SessionParms::default(),
            &[R(pc::ActionNotTakenPermanent, "No SMTP here")],
        );
    }

    #[test]
    fn greeting_reject_temporary() {
        try_next_server(
            &SessionParms::default(),
            &[R(pc::ActionNotTakenPermanent, "No SMTP here")],
        );
    }

    #[test]
    fn mail_reject_permanent() {
        total_failure(
            &SessionParms::default(),
            &[
                R(pc::Ok, "Greeting"),
                C("EHLO mx.earth.com"),
                R(pc::Ok, "Ok"),
                C("MAIL FROM:<zim@earth.com>"),
                R(pc::ActionNotTakenPermanent, "Not welcome here"),
            ],
        );
    }

    #[test]
    fn mail_reject_temporary() {
        try_next_server(
            &SessionParms::default(),
            &[
                R(pc::Ok, "Greeting"),
                C("EHLO mx.earth.com"),
                R(pc::Ok, "Ok"),
                C("MAIL FROM:<zim@earth.com>"),
                R(pc::ActionNotTakenTemporary, "Server error"),
            ],
        );
    }

    #[test]
    fn one_recipient_rejected_temporarily() {
        let results = run_session(
            &SessionParms {
                destinations: &["tallest@irk.com", "gir@irk.com"],
                ..Default::default()
            },
            &[
                R(pc::Ok, "Greeting"),
                C("EHLO mx.earth.com"),
                R(pc::Ok, "Ok"),
                C("MAIL FROM:<zim@earth.com>"),
                R(pc::Ok, "Ok"),
                C("RCPT TO:<tallest@irk.com>"),
                R(pc::Ok, "Ok"),
                C("RCPT TO:<gir@irk.com>"),
                R(pc::InsufficientStorage, "Mailbox full"),
                C("DATA"),
                R(pc::StartMailInput, "Ok"),
                DotStuffedData,
                R(pc::Ok, "Ok"),
                C("QUIT"),
                R(pc::ServiceClosing, "Bye"),
            ],
        )
        .unwrap();

        assert_eq!(vec!["tallest@irk.com".to_owned()], results.success);
        assert_eq!(vec!["gir@irk.com".to_owned()], results.tempfail);
    }

    #[test]
    fn one_recipient_rejected_permanently() {
        let results = run_session(
            &SessionParms {
                destinations: &["tallest@irk.com", "gir@irk.com"],
                ..Default::default()
            },
            &[
                R(pc::Ok, "Greeting"),
                C("EHLO mx.earth.com"),
                R(pc::Ok, "Ok"),
                C("MAIL FROM:<zim@earth.com>"),
                R(pc::Ok, "Ok"),
                C("RCPT TO:<tallest@irk.com>"),
                R(pc::Ok, "Ok"),
                C("RCPT TO:<gir@irk.com>"),
                R(pc::UserNotLocal, "User reassigned to Earth"),
                C("DATA"),
                R(pc::StartMailInput, "Ok"),
                DotStuffedData,
                R(pc::Ok, "Ok"),
                C("QUIT"),
                R(pc::ServiceClosing, "Bye"),
            ],
        )
        .unwrap();

        assert_eq!(vec!["tallest@irk.com".to_owned()], results.success);
        assert_eq!(vec!["gir@irk.com".to_owned()], results.permfail);
    }

    #[test]
    fn all_recipients_rejected() {
        let results = run_session(
            &SessionParms {
                destinations: &["tallest@irk.com", "gir@irk.com"],
                ..Default::default()
            },
            &[
                R(pc::Ok, "Greeting"),
                C("EHLO mx.earth.com"),
                R(pc::Ok, "Ok"),
                C("MAIL FROM:<zim@earth.com>"),
                R(pc::Ok, "Ok"),
                C("RCPT TO:<tallest@irk.com>"),
                R(pc::InsufficientStorage, "Mailbox full"),
                C("RCPT TO:<gir@irk.com>"),
                R(pc::UserNotLocal, "User reassigned to Earth"),
                C("QUIT"),
                R(pc::ServiceClosing, "Bye"),
            ],
        )
        .unwrap();

        assert_eq!(vec!["tallest@irk.com".to_owned()], results.tempfail);
        assert_eq!(vec!["gir@irk.com".to_owned()], results.permfail);
    }

    #[test]
    fn post_data_tempfail() {
        try_next_server(
            &SessionParms::default(),
            &[
                R(pc::Ok, "Greeting"),
                C("EHLO mx.earth.com"),
                R(pc::Ok, "Ok"),
                C("MAIL FROM:<zim@earth.com>"),
                R(pc::Ok, "Ok"),
                C("RCPT TO:<tallest@irk.com>"),
                R(pc::Ok, "Ok"),
                C("DATA"),
                R(pc::StartMailInput, "Ok"),
                DotStuffedData,
                R(pc::ActionNotTakenTemporary, "Server error"),
            ],
        );
    }

    #[test]
    fn post_data_permfail() {
        total_failure(
            &SessionParms::default(),
            &[
                R(pc::Ok, "Greeting"),
                C("EHLO mx.earth.com"),
                R(pc::Ok, "Ok"),
                C("MAIL FROM:<zim@earth.com>"),
                R(pc::Ok, "Ok"),
                C("RCPT TO:<tallest@irk.com>"),
                R(pc::Ok, "Ok"),
                C("DATA"),
                R(pc::StartMailInput, "Ok"),
                DotStuffedData,
                R(pc::ActionNotTakenPermanent, "Mail rejected"),
            ],
        );
    }

    #[test]
    fn bdat_small() {
        all_succeed(
            &SessionParms::default(),
            &[
                R(pc::Ok, "Greeting"),
                C("EHLO mx.earth.com"),
                R(pc::Ok, "Ok"),
                R(pc::Ok, "ChUnKiNg"),
                C("MAIL FROM:<zim@earth.com>"),
                R(pc::Ok, "Ok"),
                C("RCPT TO:<tallest@irk.com>"),
                R(pc::Ok, "Ok"),
                Bdats,
                R(pc::Ok, "Ok"),
                C("QUIT"),
                R(pc::Ok, "Ok"),
            ],
        );
    }

    #[test]
    fn bdat_large() {
        let message = "This is a long message.\r\n".repeat(1_000_000);
        all_succeed(
            &SessionParms {
                message_data: message.into(),
                ..SessionParms::default()
            },
            &[
                R(pc::Ok, "Greeting"),
                C("EHLO mx.earth.com"),
                R(pc::Ok, "Ok"),
                R(pc::Ok, "ChUnKiNg"),
                C("MAIL FROM:<zim@earth.com>"),
                R(pc::Ok, "Ok"),
                C("RCPT TO:<tallest@irk.com>"),
                R(pc::Ok, "Ok"),
                Bdats,
                R(pc::Ok, "Ok"),
                C("QUIT"),
                R(pc::Ok, "Ok"),
            ],
        );
    }

    #[test]
    fn post_bdat_tempfail() {
        try_next_server(
            &SessionParms::default(),
            &[
                R(pc::Ok, "Greeting"),
                C("EHLO mx.earth.com"),
                R(pc::Ok, "Ok"),
                R(pc::Ok, "CHUNKING"),
                C("MAIL FROM:<zim@earth.com>"),
                R(pc::Ok, "Ok"),
                C("RCPT TO:<tallest@irk.com>"),
                R(pc::Ok, "Ok"),
                Bdats,
                R(pc::ActionNotTakenTemporary, "Server error"),
            ],
        );
    }

    #[test]
    fn post_bdat_permfail() {
        total_failure(
            &SessionParms::default(),
            &[
                R(pc::Ok, "Greeting"),
                C("EHLO mx.earth.com"),
                R(pc::Ok, "Ok"),
                R(pc::Ok, "CHUNKING"),
                C("MAIL FROM:<zim@earth.com>"),
                R(pc::Ok, "Ok"),
                C("RCPT TO:<tallest@irk.com>"),
                R(pc::Ok, "Ok"),
                Bdats,
                R(pc::ActionNotTakenPermanent, "Mail rejected"),
            ],
        );
    }

    #[test]
    fn size_no_argument() {
        all_succeed(
            &SessionParms::default(),
            &[
                R(pc::Ok, "Greeting"),
                C("EHLO mx.earth.com"),
                R(pc::Ok, "Ok"),
                R(pc::Ok, "SiZe"),
                C("MAIL FROM:<zim@earth.com> SIZE=26"),
                R(pc::Ok, "Ok"),
                C("RCPT TO:<tallest@irk.com>"),
                R(pc::Ok, "Ok"),
                C("DATA"),
                R(pc::StartMailInput, "Ok"),
                DotStuffedData,
                R(pc::Ok, "Ok"),
                C("QUIT"),
                R(pc::Ok, "Bye"),
            ],
        );
    }

    #[test]
    fn size_zero_argument() {
        all_succeed(
            &SessionParms::default(),
            &[
                R(pc::Ok, "Greeting"),
                C("EHLO mx.earth.com"),
                R(pc::Ok, "Ok"),
                R(pc::Ok, "SiZe 0"),
                C("MAIL FROM:<zim@earth.com> SIZE=26"),
                R(pc::Ok, "Ok"),
                C("RCPT TO:<tallest@irk.com>"),
                R(pc::Ok, "Ok"),
                C("DATA"),
                R(pc::StartMailInput, "Ok"),
                DotStuffedData,
                R(pc::Ok, "Ok"),
                C("QUIT"),
                R(pc::Ok, "Bye"),
            ],
        );
    }

    #[test]
    fn size_just_big_enough() {
        all_succeed(
            &SessionParms::default(),
            &[
                R(pc::Ok, "Greeting"),
                C("EHLO mx.earth.com"),
                R(pc::Ok, "Ok"),
                R(pc::Ok, "SiZe 26"),
                C("MAIL FROM:<zim@earth.com> SIZE=26"),
                R(pc::Ok, "Ok"),
                C("RCPT TO:<tallest@irk.com>"),
                R(pc::Ok, "Ok"),
                C("DATA"),
                R(pc::StartMailInput, "Ok"),
                DotStuffedData,
                R(pc::Ok, "Ok"),
                C("QUIT"),
                R(pc::Ok, "Bye"),
            ],
        );
    }

    #[test]
    fn size_too_small() {
        total_failure(
            &SessionParms::default(),
            &[
                R(pc::Ok, "Greeting"),
                C("EHLO mx.earth.com"),
                R(pc::Ok, "Ok"),
                R(pc::Ok, "SiZe 13"),
            ],
        );
    }

    #[test]
    fn binary_payload_to_binary_server() {
        all_succeed(
            &SessionParms {
                transfer: SmtpTransfer::Binary,
                ..SessionParms::default()
            },
            &[
                R(pc::Ok, "Greeting"),
                C("EHLO mx.earth.com"),
                R(pc::Ok, "Ok"),
                R(pc::Ok, "ChUnKiNg"),
                R(pc::Ok, "BiNaRyMiMe"),
                R(pc::Ok, "8bItMiMe"),
                C("MAIL FROM:<zim@earth.com> BODY=BINARYMIME"),
                R(pc::Ok, "OK"),
                C("RCPT TO:<tallest@irk.com>"),
                R(pc::Ok, "OK"),
                Bdats,
                R(pc::Ok, "OK"),
                C("QUIT"),
                R(pc::ServiceClosing, "Bye"),
            ],
        );
    }

    #[test]
    fn eightbit_payload_to_binary_server() {
        all_succeed(
            &SessionParms {
                transfer: SmtpTransfer::EightBit,
                ..SessionParms::default()
            },
            &[
                R(pc::Ok, "Greeting"),
                C("EHLO mx.earth.com"),
                R(pc::Ok, "Ok"),
                R(pc::Ok, "ChUnKiNg"),
                R(pc::Ok, "BiNaRyMiMe"),
                R(pc::Ok, "8bItMiMe"),
                C("MAIL FROM:<zim@earth.com> BODY=8BITMIME"),
                R(pc::Ok, "OK"),
                C("RCPT TO:<tallest@irk.com>"),
                R(pc::Ok, "OK"),
                Bdats,
                R(pc::Ok, "OK"),
                C("QUIT"),
                R(pc::ServiceClosing, "Bye"),
            ],
        );
    }

    #[test]
    fn sevenbit_payload_to_binary_server() {
        all_succeed(
            &SessionParms {
                transfer: SmtpTransfer::SevenBit,
                ..SessionParms::default()
            },
            &[
                R(pc::Ok, "Greeting"),
                C("EHLO mx.earth.com"),
                R(pc::Ok, "Ok"),
                R(pc::Ok, "ChUnKiNg"),
                R(pc::Ok, "BiNaRyMiMe"),
                R(pc::Ok, "8bItMiMe"),
                C("MAIL FROM:<zim@earth.com>"),
                R(pc::Ok, "OK"),
                C("RCPT TO:<tallest@irk.com>"),
                R(pc::Ok, "OK"),
                Bdats,
                R(pc::Ok, "OK"),
                C("QUIT"),
                R(pc::ServiceClosing, "Bye"),
            ],
        );
    }

    #[test]
    fn binary_payload_to_eightbit_server() {
        all_succeed(
            &SessionParms {
                transfer: SmtpTransfer::Binary,
                ..SessionParms::default()
            },
            &[
                R(pc::Ok, "Greeting"),
                C("EHLO mx.earth.com"),
                R(pc::Ok, "Ok"),
                R(pc::Ok, "ChUnKiNg"),
                R(pc::Ok, "8bItMiMe"),
                C("MAIL FROM:<zim@earth.com> BODY=8BITMIME"),
                R(pc::Ok, "OK"),
                C("RCPT TO:<tallest@irk.com>"),
                R(pc::Ok, "OK"),
                Bdats,
                R(pc::Ok, "OK"),
                C("QUIT"),
                R(pc::ServiceClosing, "Bye"),
            ],
        );
    }

    #[test]
    fn eightbit_payload_to_eightbit_server() {
        all_succeed(
            &SessionParms {
                transfer: SmtpTransfer::EightBit,
                ..SessionParms::default()
            },
            &[
                R(pc::Ok, "Greeting"),
                C("EHLO mx.earth.com"),
                R(pc::Ok, "Ok"),
                R(pc::Ok, "ChUnKiNg"),
                R(pc::Ok, "8bItMiMe"),
                C("MAIL FROM:<zim@earth.com> BODY=8BITMIME"),
                R(pc::Ok, "OK"),
                C("RCPT TO:<tallest@irk.com>"),
                R(pc::Ok, "OK"),
                Bdats,
                R(pc::Ok, "OK"),
                C("QUIT"),
                R(pc::ServiceClosing, "Bye"),
            ],
        );
    }

    #[test]
    fn sevenbit_payload_to_eightbit_server() {
        all_succeed(
            &SessionParms {
                transfer: SmtpTransfer::SevenBit,
                ..SessionParms::default()
            },
            &[
                R(pc::Ok, "Greeting"),
                C("EHLO mx.earth.com"),
                R(pc::Ok, "Ok"),
                R(pc::Ok, "ChUnKiNg"),
                R(pc::Ok, "8bItMiMe"),
                C("MAIL FROM:<zim@earth.com>"),
                R(pc::Ok, "OK"),
                C("RCPT TO:<tallest@irk.com>"),
                R(pc::Ok, "OK"),
                Bdats,
                R(pc::Ok, "OK"),
                C("QUIT"),
                R(pc::ServiceClosing, "Bye"),
            ],
        );
    }

    #[test]
    fn binary_payload_to_sevenbit_server() {
        all_succeed(
            &SessionParms {
                transfer: SmtpTransfer::Binary,
                ..SessionParms::default()
            },
            &[
                R(pc::Ok, "Greeting"),
                C("EHLO mx.earth.com"),
                R(pc::Ok, "Ok"),
                R(pc::Ok, "ChUnKiNg"),
                C("MAIL FROM:<zim@earth.com>"),
                R(pc::Ok, "OK"),
                C("RCPT TO:<tallest@irk.com>"),
                R(pc::Ok, "OK"),
                Bdats,
                R(pc::Ok, "OK"),
                C("QUIT"),
                R(pc::ServiceClosing, "Bye"),
            ],
        );
    }

    #[test]
    fn eightbit_payload_to_sevenbit_server() {
        all_succeed(
            &SessionParms {
                transfer: SmtpTransfer::EightBit,
                ..SessionParms::default()
            },
            &[
                R(pc::Ok, "Greeting"),
                C("EHLO mx.earth.com"),
                R(pc::Ok, "Ok"),
                R(pc::Ok, "ChUnKiNg"),
                C("MAIL FROM:<zim@earth.com>"),
                R(pc::Ok, "OK"),
                C("RCPT TO:<tallest@irk.com>"),
                R(pc::Ok, "OK"),
                Bdats,
                R(pc::Ok, "OK"),
                C("QUIT"),
                R(pc::ServiceClosing, "Bye"),
            ],
        );
    }

    #[test]
    fn size_extension_bad_integer() {
        all_succeed(
            &SessionParms::default(),
            &[
                R(pc::Ok, "Greeting"),
                C("EHLO mx.earth.com"),
                R(pc::Ok, "Ok"),
                R(pc::Ok, "CHUNKING"),
                R(pc::Ok, "SIZE FORTY-TWO"),
                C("MAIL FROM:<zim@earth.com> SIZE=26"),
                R(pc::Ok, "OK"),
                C("RCPT TO:<tallest@irk.com>"),
                R(pc::Ok, "OK"),
                Bdats,
                R(pc::Ok, "OK"),
                C("QUIT"),
                R(pc::ServiceClosing, "Bye"),
            ],
        );
    }

    #[test]
    fn bad_status_line() {
        try_next_server(
            &SessionParms::default(),
            &[RawResponseData("HTTP/1.1 400 Bad Request\r\n")],
        );
    }

    #[test]
    fn overlong_response_line() {
        try_next_server(
            &SessionParms::default(),
            &[SessionStep::InfiniteResponse],
        );
    }
}
