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
#[derive(Error, PartialEq, Debug)]
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
    TestMode(Failure),
}

impl std::cmp::PartialEq for Ambivalence {
    fn eq(&self, rhs: &Self) -> bool {
        match (self, rhs) {
            (&Self::Ssl(..) | &Self::Io(..), _) => false,

            (&Self::HeaderParse(ref a), &Self::HeaderParse(ref b)) => a == b,
            (&Self::HeaderParse(..), _) => false,

            (
                &Self::DnsTxtParse(ref a, ref b),
                &Self::DnsTxtParse(ref c, ref d),
            ) => (a, b) == (c, d),
            (&Self::DnsTxtParse(..), _) => false,

            (&Self::DnsTxtNotFound(ref a), &Self::DnsTxtNotFound(ref b)) => {
                a == b
            },
            (&Self::DnsTxtNotFound(..), _) => false,

            (&Self::DnsTxtError(ref a), &Self::DnsTxtError(ref b)) => a == b,
            (&Self::DnsTxtError(..), _) => false,

            (&Self::UnsupportedVersion, &Self::UnsupportedVersion) => true,
            (&Self::UnsupportedVersion, _) => false,

            (&Self::RsaKeyTooBig, &Self::RsaKeyTooBig) => true,
            (&Self::RsaKeyTooBig, _) => false,

            (&Self::WeakHashFunction, &Self::WeakHashFunction) => true,
            (&Self::WeakHashFunction, _) => false,

            (&Self::WeakKey, &Self::WeakKey) => true,
            (&Self::WeakKey, _) => false,

            (&Self::TestMode(ref a), &Self::TestMode(ref b)) => a == b,
            (&Self::TestMode(..), _) => false,
        }
    }
}

#[derive(Error, PartialEq, Debug)]
pub enum Failure {
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
