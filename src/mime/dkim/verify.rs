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

use std::fmt::Write as _;
use std::io::{self, Write};

use chrono::prelude::*;

use super::{
    hash, Ambivalence, Error, Failure, HashAlgorithm, Header,
    SignatureAlgorithm, TxtRecord, HEADER_NAME,
};
use crate::mime::header::FULL_HEADER_LINE;

const MAX_SIGNATURES: usize = 8;
const MAX_RSA_BITS: u32 = 16384;

/// The final result of DKIM verification.
///
/// This is ordered such that a lesser outcome of a sub-verification takes
/// priority over a greater one.
///
/// RFC 5451 § 2.4.1
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum OutcomeKind {
    Pass,
    Fail,
    Policy,
    Neutral,
    TempError,
    PermError,
    None,
}

#[derive(Clone, Debug)]
pub struct Outcome {
    /// The summary of the outcome.
    pub kind: OutcomeKind,
    /// Human-readable text describing the results of each key, or otherwise
    /// explaining the outcome.
    pub comment: String,
}

/// Environmental information passed in to the verifier.
#[derive(Clone, Debug)]
pub struct VerificationEnvironment {
    /// The current time.
    pub now: DateTime<Utc>,
    /// The claimed host name of the sender.
    pub sender: hickory_resolver::Name,
    /// The TXT records that were actually fetched.
    pub txt_records: Vec<TxtRecordEntry>,
}

/// Raw results for TXT entries fetched from DNS.
#[derive(Clone, Debug)]
pub struct TxtRecordEntry {
    pub selector: String,
    pub sdid: String,
    pub txt: String,
}

/// Processes DKIM verification on an inbound message.
pub struct Verifier<'a> {
    header_block: &'a [u8],
    subs: Vec<Result<SubVerifier<'a>, String>>,
}

struct SubVerifier<'a> {
    header: Header<'a>,
    hasher: hash::BodyHasher,
}

pub(super) trait Captures<U> {}
impl<T: ?Sized, U> Captures<U> for T {}

impl<'a> Verifier<'a> {
    /// Creates a verifier for a message beginning with the given header block.
    ///
    /// This identifies all the signatures that will be subject to verification
    /// and prepares to collect their results.
    pub fn new(header_block: &'a [u8]) -> Self {
        let subs = FULL_HEADER_LINE
            .captures_iter(header_block)
            .filter(|m| {
                std::str::from_utf8(m.get(2).unwrap().as_bytes())
                    .ok()
                    .is_some_and(|n| HEADER_NAME == n)
            })
            .filter_map(|m| {
                std::str::from_utf8(m.get(1).unwrap().as_bytes()).ok()
            })
            .take(MAX_SIGNATURES)
            .map(|signature| {
                Header::parse(signature).map(|header| SubVerifier {
                    hasher: hash::BodyHasher::new(&header),
                    header,
                })
            })
            .collect();

        Self { header_block, subs }
    }

    /// Returns the TXT records that this verifier wants.
    ///
    /// Each item is a `(selector, domain)` pair, such that the TXT record will
    /// be found at `${selector}._domainkey.${domain}.` after normalisation.
    /// The verifier does not know about DNS normalisation and expects to
    /// receive these exact strings back in the final step.
    pub fn want_txt_records(&self) -> impl Iterator<Item = (&str, &str)> + '_ {
        self.subs
            .iter()
            .filter_map(|s| s.as_ref().ok())
            .map(|s| (&*s.header.selector, &*s.header.sdid))
    }

    /// Completes the verification process.
    pub fn finish(self, env: &VerificationEnvironment) -> Outcome {
        let mut outcome = OutcomeKind::None;
        let mut comment = String::new();

        for sub_result in self.finish_raw(env) {
            if !comment.is_empty() {
                comment.push_str("; ");
            }
            match sub_result {
                Ok(()) => comment.push_str("pass"),
                Err(ref e) => {
                    let _ = write!(comment, "{e}");
                },
            }

            let sub_outcome = OutcomeKind::from(sub_result);
            if sub_outcome < outcome {
                outcome = sub_outcome;
            }
        }

        if comment.is_empty() {
            comment.push_str("no DKIM signatures");
        }

        Outcome {
            kind: outcome,
            comment,
        }
    }

    pub(super) fn finish_raw<'e>(
        self,
        env: &'e VerificationEnvironment,
    ) -> impl Iterator<Item = Result<(), Error>> + Captures<(&'a (), &'e ())>
    {
        self.subs.into_iter().map(move |sub| match sub {
            Err(syntax_error) => {
                Err(Error::Ambivalent(Ambivalence::HeaderParse(syntax_error)))
            },

            Ok(sub) => sub.finish(self.header_block, env),
        })
    }
}

/// Writing to the `Verifier` feeds body data into the verification process.
impl Write for Verifier<'_> {
    fn write(&mut self, src: &[u8]) -> io::Result<usize> {
        for sub in &mut self.subs {
            if let Ok(ref mut sub) = *sub {
                sub.hasher.write_all(src)?;
            }
        }

        Ok(src.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        for sub in &mut self.subs {
            if let Ok(ref mut sub) = *sub {
                sub.hasher.flush()?;
            }
        }

        Ok(())
    }
}

impl SubVerifier<'_> {
    fn finish(
        self,
        header_block: &[u8],
        env: &VerificationEnvironment,
    ) -> Result<(), Error> {
        // RFC 6376 § 6

        // TODO Should we also be verifying that `d` has some relationship with
        // the SMTP sender?

        // § 6.1.1
        // TODO We're required to validate the `i` tag if present.

        if 1 != self.header.version {
            return Err(Ambivalence::UnsupportedVersion.into());
        }

        if !self
            .header
            .signed_headers
            .iter()
            .any(|h| h.eq_ignore_ascii_case("From"))
        {
            return Err(Failure::FromFieldUnsigned.into());
        }

        // § 6.1.2

        // Steps 1--5

        // Test all the TXT records for the domain to find one which is
        // parsable and has the correct version. If we can't parse any of them,
        // remember the first syntax error we saw.
        let mut txt_parse_error = None::<String>;
        let mut txt_record = None::<TxtRecord<'_>>;
        for record in &env.txt_records {
            if record.selector != *self.header.selector
                || record.sdid != *self.header.sdid
            {
                continue;
            }

            match TxtRecord::parse(&record.txt) {
                Ok(r) => {
                    if "DKIM1" == r.version {
                        txt_record = Some(r);
                        break;
                    }
                },

                Err(e) if txt_parse_error.is_none() => {
                    txt_parse_error = Some(e);
                },

                Err(_) => (),
            }
        }

        let Some(txt_record) = txt_record else {
            return Err(txt_parse_error
                .map(|e| Ambivalence::DnsTxtParse(self.format_selector(), e))
                .unwrap_or_else(|| {
                    Ambivalence::DnsTxtNotFound(self.format_selector())
                })
                .into());
        };

        let is_test = txt_record.flags.test;
        self.finish_with_txt_record(header_block, env, txt_record)
            .map_err(|e| match e {
                Error::Fail(f) if is_test => {
                    Error::Ambivalent(Ambivalence::TestMode(f))
                },
                e => e,
            })
    }

    // This is conceptually a continuation of the above function, but is
    // subject to test mode filtering on the result.
    fn finish_with_txt_record(
        self,
        header_block: &[u8],
        env: &VerificationEnvironment,
        txt_record: TxtRecord<'_>,
    ) -> Result<(), Error> {
        // Still in § 6.1.2

        // Step 6
        if txt_record
            .acceptable_hash_algorithms
            .as_ref()
            .is_some_and(|aha| !aha.contains(&self.header.algorithm.hash))
        {
            return Err(Failure::UnacceptableHashAlgorithm.into());
        }

        // Step 7
        if txt_record.public_key.is_empty() {
            return Err(Failure::PublicKeyRevoked.into());
        }

        // Step 8
        if txt_record.key_type != self.header.algorithm.signature {
            return Err(Failure::SignatureAlgorithmMismatch.into());
        }

        // § 6.1.3

        // Steps 2 & 3
        let body_hash = self.hasher.finish(&self.header)?;
        if body_hash != self.header.body_hash {
            return Err(Failure::BodyHashMismatch.into());
        }

        // Steps 1 & 4
        let (public_key, acceptable_strength) = match txt_record.key_type {
            SignatureAlgorithm::Rsa => {
                let k = openssl::rsa::Rsa::public_key_from_der(
                    &txt_record.public_key,
                )
                .map_err(|_| Failure::InvalidPublicKey)?;
                let pk = openssl::pkey::PKey::from_rsa(k)
                    .map_err(|_| Failure::InvalidPublicKey)?;
                // RFC 8301
                let acceptable_strength = pk.bits() >= 1024;
                if pk.bits() > MAX_RSA_BITS {
                    return Err(Ambivalence::RsaKeyTooBig.into());
                }
                (pk, acceptable_strength)
            },

            SignatureAlgorithm::Ed25519 => {
                // RFC 8463
                // Ed25519 keys are always the same size, so there's no key
                // strength to test.
                let k = openssl::pkey::PKey::public_key_from_raw_bytes(
                    &txt_record.public_key,
                    openssl::pkey::Id::ED25519,
                )
                .map_err(|_| Failure::InvalidPublicKey)?;

                (k, true)
            },
        };

        let header_data = hash::header_hash_data(&self.header, header_block);
        let mut verifier = match self.header.algorithm.signature {
            SignatureAlgorithm::Rsa => openssl::sign::Verifier::new(
                self.header.algorithm.hash.message_digest(),
                &public_key,
            ),
            SignatureAlgorithm::Ed25519 => {
                // Only SHA-256 is possible.
                if self.header.algorithm.hash != HashAlgorithm::Sha256 {
                    return Err(Failure::InvalidHashSignatureCombination.into());
                }
                // OpenSSL rejects explicit configuration of the digest.
                openssl::sign::Verifier::new_without_digest(&public_key)
            },
        }
        .map_err(Ambivalence::Ssl)?;
        let valid = verifier
            .verify_oneshot(&self.header.signature, &header_data)
            .map_err(Ambivalence::Ssl)?;
        if !valid {
            return Err(Failure::SignatureMismatch.into());
        }

        // RFC 8301
        if HashAlgorithm::Sha1 == self.header.algorithm.hash {
            return Err(Ambivalence::WeakHashFunction.into());
        }

        if !acceptable_strength {
            return Err(Ambivalence::WeakKey.into());
        }

        // RFC 6376 forgets to talk about timestamps in its verification
        // procedure.
        if self
            .header
            .signature_expiration
            .is_some_and(|x| x < env.now)
        {
            return Err(Failure::ExpiredSignature.into());
        }

        if self
            .header
            .signature_timestamp
            .is_some_and(|x| x > env.now + chrono::Duration::days(1))
        {
            return Err(Failure::FutureSignature.into());
        }

        Ok(())
    }

    fn format_selector(&self) -> String {
        format!("{}._domainkey.{}", self.header.selector, self.header.sdid)
    }
}

impl From<Result<(), Error>> for OutcomeKind {
    fn from(r: Result<(), Error>) -> Self {
        use super::error::Ambivalence as A;

        match r {
            Ok(()) => Self::Pass,

            // NB "PERMFAIL" in RFC 6376 is entirely different from "PERMERROR"
            // in RFC 5451; this is the latter.
            Err(Error::Ambivalent(e)) => match e {
                A::Ssl(..) => Self::PermError,
                A::Io(..) => Self::TempError,
                A::HeaderParse(..) => Self::Neutral,
                A::DnsTxtParse(..) => Self::Neutral,
                A::DnsTxtNotFound(..) => Self::TempError,
                A::TestMode(..) => Self::Neutral,
                A::UnsupportedVersion => Self::Neutral,
                A::RsaKeyTooBig => Self::Policy,
                A::WeakHashFunction => Self::Policy,
                A::WeakKey => Self::Policy,
            },

            Err(Error::Fail(_)) => Self::Fail,
        }
    }
}

#[cfg(test)]
mod test {
    use super::super::{split_message, test_domain_keys};
    use super::*;
    use crate::test_data::*;

    fn run_verifier(
        message: &[u8],
        sender: &str,
        now_unix: i64,
        txt_records: Vec<TxtRecordEntry>,
    ) -> Vec<Result<(), Error>> {
        let (header_block, body) = split_message(message);
        let mut verifier = Verifier::new(header_block);
        verifier.write_all(body).unwrap();

        let env = VerificationEnvironment {
            sender: hickory_resolver::Name::from_str_relaxed(sender).unwrap(),
            now: DateTime::from_timestamp(now_unix, 0).unwrap(),
            txt_records,
        };
        verifier.finish_raw(&env).collect()
    }

    #[test]
    fn verify_amazoncojp_2x_rsa_sha256() {
        let txt_records = vec![TxtRecordEntry {
            selector: "hsbnp7p3ensaochzwyq5wwmceodymuwv".to_owned(),
            sdid: "amazonses.com".to_owned(),
            txt: test_domain_keys::HSG_AMAZONSES_COM.to_owned(),
        }];

        let not_found = || {
            Err::<(), _>(Error::Ambivalent(Ambivalence::DnsTxtNotFound(
                "55v6dsnbko3asrylf5mgtqv5mgll5any._domainkey.amazon.co.jp"
                    .to_owned(),
            )))
        };

        assert_eq!(
            vec![not_found(), Ok(())],
            run_verifier(
                DKIM_AMAZONCOJP_RSA_SHA256,
                "amazonses.com",
                1694481247,
                txt_records.clone(),
            ),
        );
        assert_eq!(
            vec![not_found(), Err(Error::Fail(Failure::FutureSignature))],
            run_verifier(
                DKIM_AMAZONCOJP_RSA_SHA256,
                "amazonses.com",
                1594481246,
                txt_records.clone(),
            ),
        );
    }

    // TODO More tests
}
