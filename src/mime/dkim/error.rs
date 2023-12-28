//-
// Copyright (c) 2023, Jason Lingle
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

use thiserror::Error;

/// Reasons a DKIM signature could not be validated.
#[derive(Error, Debug)]
pub enum Error {
    /// No pass/fail status could be ascribed to a signature. This includes
    /// transient network errors, signatures with unsupported algorithms, and
    /// unexpected errors.
    ///
    /// This does not correspond to "TEMPFAIL" from RFC 6376. While it includes
    /// all temporary failures, it also includes permanent failures which don't
    /// indicate a problem with the message.
    #[error(transparent)]
    Ambivalent(#[from] Ambivalence),
    /// The signature is objectively invalid.
    #[error(transparent)]
    Fail(#[from] Failure),
}

#[derive(Error, Debug)]
pub enum Ambivalence {
    #[error("unexpected OpenSSL error: {0}")]
    Ssl(openssl::error::ErrorStack),
    #[error("unexpected I/O error: {0}")]
    Io(std::io::Error),
    #[error("can't parse DKIM-Signature header: {0}")]
    HeaderParse(String),
    #[error("can't parse TXT record {0}: {1}")]
    DnsTxtParse(String, String),
    #[error("can't find TXT record {0}, or it is not DKIM1")]
    DnsTxtNotFound(String),
    #[error("verification failed, but the selector is in test mode: {0}")]
    TestMode(Failure),
}

#[derive(Error, Debug)]
pub enum Failure {
    #[error("body is shorter than the l= tag indicates")]
    BodyTruncated,
    #[error("the computed body hash does not match the bh= tag")]
    BodyHashMismatch,
    #[error("the computed message hash does not match the signature")]
    SignatureMismatch,
    #[error("the public key was revoked")]
    PublicKeyRevoked,
}
