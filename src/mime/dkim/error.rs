//-
// Copyright (c) 2023, 2024, Jason Lingle
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
    #[error("unexpected OpenSSL error: {0}")]
    Ssl(openssl::error::ErrorStack),
    #[error("unexpected I/O error: {0}")]
    Io(std::io::Error),
    #[error(transparent)]
    Fail(#[from] Failure),
}

impl std::cmp::PartialEq for Error {
    fn eq(&self, rhs: &Self) -> bool {
        match (self, rhs) {
            (&Self::Ssl(..) | &Self::Io(..), _) => false,
            (&Self::Fail(ref l), &Self::Fail(ref r)) => l == r,
            (&Self::Fail(..), _) => false,
        }
    }
}

#[derive(Error, PartialEq, Debug)]
pub enum Failure {
    #[error("can't parse DKIM-Signature header: {0}")]
    HeaderParse(String),
    #[error("can't parse TXT record {0}: {1}")]
    DnsTxtParse(String, String),
    #[error("can't find TXT record {0}, or it is not DKIM1")]
    DnsTxtNotFound(String),
    #[error("DNS error fetching TXT record {0}")]
    DnsTxtError(String),
    #[error("unsupported DKIM version")]
    UnsupportedVersion,
    #[error("RSA key is too big to validate")]
    RsaKeyTooBig,
    #[error("valid signature, but hash function is weak")]
    WeakHashFunction,
    #[error("valid signature, but signing key is weak")]
    WeakKey,
    #[error("verification failed, but the selector is in test mode: {0}")]
    TestMode(Box<Failure>),
    #[error("body is shorter than the l= tag indicates")]
    BodyTruncated,
    #[error("the computed body hash does not match the bh= tag")]
    BodyHashMismatch,
    #[error("the computed message hash does not match the signature")]
    SignatureMismatch,
    #[error("the public key was revoked")]
    PublicKeyRevoked,
    #[error("'From' field not signed")]
    FromFieldUnsigned,
    #[error("DKIM-Signature hash algorithm not allowed by TXT record")]
    UnacceptableHashAlgorithm,
    #[error("DKIM-Signature signature algorithm disagrees with TXT record")]
    SignatureAlgorithmMismatch,
    #[error("valid signature, but it has expired")]
    ExpiredSignature,
    #[error("valid signature, but the timestamp is in the future")]
    FutureSignature,
    #[error("public key is invalid")]
    InvalidPublicKey,
    #[error("invalid hash + signature algorithm combination")]
    InvalidHashSignatureCombination,
    #[error("SDID is not a valid domain")]
    InvalidSdid,
    #[error("AUID carries an invalid domain")]
    InvalidAuid,
    #[error("AUID is not within SDID zone")]
    AuidOutsideSdid,
    #[error("AUID is not the same as SDID, but the strict flag is set")]
    AuidSdidMismatch,
}
