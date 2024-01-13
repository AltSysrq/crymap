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

use std::borrow::Cow;
use std::io::{self, Write};

use chrono::prelude::*;

use super::{
    hash, Algorithm, Ambivalence, BodyCanonicalisation, Canonicalisation,
    Error, HashAlgorithm, Header, HeaderCanonicalisation, SignatureAlgorithm,
};

pub type KeyPair = openssl::pkey::PKey<openssl::pkey::Private>;

/// Generates DKIM signatures for a message.
pub struct Signer<'a> {
    subs: Vec<SubSigner<'a>>,
}

struct SubSigner<'a> {
    header: Header<'a>,
    hasher: hash::BodyHasher,
    key: &'a KeyPair,
}

impl<'a> Signer<'a> {
    /// Starts a new signer with the given keys and header template.
    ///
    /// The fields specific to each signature of the template are implicitly
    /// cleared. For each key, a signature will be generated, using the
    /// selector name given. The header signature algorithm is automatically
    /// set based on the key type.
    pub fn new(keys: &'a [(String, KeyPair)], template: &Header<'a>) -> Self {
        Self {
            subs: keys
                .iter()
                .map(|&(ref selector, ref key)| {
                    let mut header = template.to_owned();
                    header.raw = None;
                    header.body_hash.clear();
                    header.signature.clear();
                    header.selector = Cow::Borrowed(selector);
                    header.algorithm.signature = match key.id() {
                        openssl::pkey::Id::RSA => SignatureAlgorithm::Rsa,
                        openssl::pkey::Id::ED25519 => {
                            SignatureAlgorithm::Ed25519
                        },
                        id => panic!("unexpected key type: {id:?}"),
                    };

                    let hasher = hash::BodyHasher::new(&header);

                    SubSigner {
                        header,
                        hasher,
                        key,
                    }
                })
                .collect(),
        }
    }

    /// Generates the header template Crymap uses for production use.
    pub fn default_template(
        now: DateTime<Utc>,
        sdid: Cow<'_, str>,
    ) -> Header<'_> {
        Header {
            raw: None,
            version: 1,
            algorithm: Algorithm {
                hash: HashAlgorithm::Sha256,
                // Gets overwritten per key
                signature: SignatureAlgorithm::Ed25519,
            },
            signature: Vec::new(),
            body_hash: Vec::new(),
            canonicalisation: Canonicalisation {
                // Arguably Simple would be preferable, but I couldn't find any
                // examples of it in real use in the wild, so do what everyone
                // else does.
                header: HeaderCanonicalisation::Relaxed,
                // Simple is required to pass binary content reliably.
                body: BodyCanonicalisation::Simple,
            },
            sdid,
            signed_headers: vec![
                Cow::Borrowed("CC"),
                Cow::Borrowed("Content-Type"),
                Cow::Borrowed("Date"),
                Cow::Borrowed("From"),
                Cow::Borrowed("In-Reply-To"),
                Cow::Borrowed("Message-ID"),
                Cow::Borrowed("References"),
                Cow::Borrowed("Reply-To"),
                Cow::Borrowed("Subject"),
                Cow::Borrowed("To"),
            ],
            auid: None,
            body_length: None,
            dns_txt: true,
            selector: Cow::Borrowed(""),
            signature_timestamp: Some(now),
            signature_expiration: Some(now + chrono::Duration::days(7)),
        }
    }

    /// Completes the signing process.
    ///
    /// Returns the header line(s) to prepend to the message.
    pub fn finish(self, header_block: &[u8]) -> String {
        let mut prepend = String::new();
        for sub in self.subs {
            match sub.finish(header_block) {
                Ok(header) => {
                    prepend.push_str(&header);
                    prepend.push_str("\r\n");
                },

                #[cfg(test)]
                Err(e) => {
                    panic!("DKIM signature failed: {e}");
                },

                #[cfg(not(test))]
                Err(e) => {
                    log::error!("DKIM signature failed: {e}");
                },
            }
        }

        prepend
    }
}

/// Writing to a `Signer` feeds the body data into it.
impl Write for Signer<'_> {
    fn write(&mut self, src: &[u8]) -> io::Result<usize> {
        for sub in &mut self.subs {
            sub.hasher.write_all(src)?;
        }

        Ok(src.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        for sub in &mut self.subs {
            sub.hasher.flush()?;
        }

        Ok(())
    }
}

impl SubSigner<'_> {
    fn finish(mut self, header_block: &[u8]) -> Result<String, Error> {
        self.header.body_hash = self.hasher.finish(&self.header)?;
        let hash_data = hash::header_hash_data(&self.header, header_block);
        let mut signer = match self.header.algorithm.signature {
            SignatureAlgorithm::Rsa => openssl::sign::Signer::new(
                self.header.algorithm.hash.message_digest(),
                self.key,
            ),
            SignatureAlgorithm::Ed25519 => {
                // OpenSSL rejects explicit configuration of the digest
                openssl::sign::Signer::new_without_digest(self.key)
            },
        }
        .map_err(Ambivalence::Ssl)?;
        self.header.signature = signer
            .sign_oneshot_to_vec(&hash_data)
            .map_err(Ambivalence::Ssl)?;

        Ok(self.header.raw().into_owned().text.into_owned())
    }
}

#[cfg(test)]
mod test {
    use super::super::{
        split_message, TxtRecordEntry, VerificationEnvironment, Verifier,
    };
    use super::*;
    use crate::test_data::*;

    #[test]
    fn test_sign_and_verify() {
        let (original_headers, body) = split_message(CHRISTMAS_TREE);

        let rsa_pair = openssl::rsa::Rsa::generate(1024).unwrap();

        let keys = [
            (
                "ed".to_owned(),
                openssl::pkey::PKey::generate_ed25519().unwrap(),
            ),
            (
                "rsa".to_owned(),
                openssl::pkey::PKey::from_rsa(rsa_pair).unwrap(),
            ),
        ];
        let mut signer = Signer::new(
            &keys,
            &Signer::default_template(Utc::now(), Cow::Borrowed("example.com")),
        );
        signer.write_all(body).unwrap();
        let signed_headers = signer.finish(original_headers);

        let ver_env = VerificationEnvironment {
            now: Utc::now(),
            txt_records: vec![
                TxtRecordEntry {
                    sdid: "example.com".to_owned(),
                    selector: "ed".to_owned(),
                    txt: format!(
                        "k=ed25519;p={}",
                        base64::encode(&keys[0].1.raw_public_key().unwrap()),
                    )
                    .into(),
                },
                TxtRecordEntry {
                    sdid: "example.com".to_owned(),
                    selector: "rsa".to_owned(),
                    txt: format!(
                        "k=rsa;p={}",
                        base64::encode(&keys[1].1.public_key_to_der().unwrap()),
                    )
                    .into(),
                },
            ],
        };

        let mut combined_headers = signed_headers.as_bytes().to_vec();
        combined_headers.extend_from_slice(&original_headers);

        let mut verifier = Verifier::new(&combined_headers);
        verifier.write_all(body).unwrap();
        let results = verifier.finish_raw(&ver_env).collect::<Vec<_>>();
        assert_eq!(vec![Ok::<_, Error>(()), Ok(())], results);
    }
}
