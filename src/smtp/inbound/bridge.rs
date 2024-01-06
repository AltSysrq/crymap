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

//! The "bridge" between the common SMTP/LMTP inbound server and the specific
//! service implementations.
//!
//! The common server and the service are modelled as separate actors to permit
//! a simple implementation of each service as a single async function, which
//! gives flexibility in streaming the delivered message body.
//!
//! Data passed from the common server to the service are "requests", and data
//! passed the other way are "responses".

use std::borrow::Cow;

use tokio::sync::{mpsc, oneshot};

use super::super::codes::*;
use crate::account::v2::Account;

/// An SMTP response, excluding the continuation/final distinction.
#[derive(Clone, Debug)]
pub struct SmtpResponse<'a>(
    pub PrimaryCode,
    pub Option<(ClassCode, SubjectCode)>,
    pub Cow<'a, str>,
);

impl SmtpResponse<'static> {
    /// Generates a response for a sequence error which the server should have
    /// prevented.
    #[cfg(not(test))]
    pub fn internal_sequence_error() -> Self {
        Self(
            pc::BadSequenceOfCommands,
            Some((cc::PermFail, sc::InvalidCommand)),
            Cow::Borrowed("Unexpected command"),
        )
    }

    #[cfg(test)]
    pub fn internal_sequence_error() -> Self {
        panic!("Unexpected command")
    }
}

pub struct Request {
    pub payload: RequestPayload,
    /// The channel on which the primary response is sent.
    pub respond: oneshot::Sender<Result<(), SmtpResponse<'static>>>,
}

pub enum RequestPayload {
    Helo(HeloRequest),
    #[allow(dead_code)] // TODO Remove
    Auth(AuthRequest),
    Mail(MailRequest),
    Recipient(RecipientRequest),
    Data(DataRequest),
    Reset,
}

/// The HELO/EHLO/LHLO commands.
///
/// This will occur twice on a connection where the remote host uses STARTTLS.
pub struct HeloRequest {
    pub command: String,
    pub host: String,
    pub tls: Option<String>,
}

/// A successful AUTH command.
pub struct AuthRequest {
    pub account: Account,
}

/// A `MAIL FROM` command.
pub struct MailRequest {
    pub from: String,
}

/// An `RCPT TO` command.
pub struct RecipientRequest {
    pub to: String,
}

/// The start of the message data.
///
/// Upon receiving `DataRequest`, the service will immediately indicate whether
/// it wishes to accept the data on the request's `respond` channel.
///
/// It then consumes `data` until EOF or it encounters an error, at which point
/// it drops `data`. Once `data` is dropped, it reads the value out of
/// `recipient_responses`. If that channel is closed, the server aborted the
/// transfer and the buffered message must be discarded. Otherwise, the server
/// is expecting the delivery to proceed.
///
/// The channel received from `recipient_responses` is used to send each
/// response required after delivery. For SMTP, this will be only one response.
/// For LMTP, it will be one response for each successful `RecipientRequest`
/// since the last reset.
pub struct DataRequest {
    pub data: tokio::io::DuplexStream,
    pub recipient_responses:
        oneshot::Receiver<mpsc::Sender<Result<(), SmtpResponse<'static>>>>,
}
