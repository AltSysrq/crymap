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

use std::io::{self, Write};

use openssl::hash::MessageDigest;

use super::{
    Ambivalence, BodyCanonicaliser, Error, Failure, HashAlgorithm, Header,
};

/// Computes the hash of the message body.
pub(super) struct BodyHasher {
    body_hash: BodyCanonicaliser<DigestWriter>,
}

impl BodyHasher {
    /// Starts a new `BodyHasher` with the configuration from the given header.
    pub fn new(header: &Header<'_>) -> Self {
        Self {
            body_hash: BodyCanonicaliser::new(
                DigestWriter {
                    digest: openssl::hash::Hasher::new(
                        match header.algorithm.hash {
                            HashAlgorithm::Sha1 => MessageDigest::sha1(),
                            HashAlgorithm::Sha256 => MessageDigest::sha256(),
                        },
                    ),
                    limit: header.body_length.unwrap_or(u64::MAX),
                    bytes_written: 0,
                },
                header.canonicalisation.body,
            ),
        }
    }

    /// Finishes computing the hash for this header.
    ///
    /// This *does not* validate that the hash matches the hash in the header,
    /// as this function is used both in the signing and verification
    /// processes.
    pub fn finish(self, header: &Header<'_>) -> Result<Vec<u8>, Error> {
        let body_hash = self
            .body_hash
            .finish()
            // Should never fail
            .map_err(Ambivalence::Io)?;

        let hash = body_hash
            .digest
            .and_then(|mut h| h.finish())
            // We don't expect hashing to ever fail
            .map_err(Ambivalence::Ssl)?
            .to_vec();

        // We don't strictly need to validate that body_hash.bytes_written ==
        // header.body_length. If the body was truncated, the hash will be
        // different anyway. However, this gives us better error messages. `l`
        // is not allowed to be longer than the actual bytes processed, so
        // there shouldn't be any false errors here.
        if let Some(body_length) = header.body_length {
            if body_hash.bytes_written < body_length {
                return Err(Error::Fail(Failure::BodyTruncated));
            }
        }

        Ok(hash)
    }
}

impl Write for BodyHasher {
    fn write(&mut self, src: &[u8]) -> io::Result<usize> {
        self.body_hash.write(src)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.body_hash.flush()
    }
}

/// Implements `Write` with a size limit into an OpenSSL hasher. The `write`
/// implementation itself always succeeds; if an error occurs, it is stored
/// internally.
///
/// Note that the body size is determined *after* canonicalisation, so the size
/// limit needs to be here (within the `BodyCanonicaliser`) and not at a higher
/// level.
struct DigestWriter {
    digest: Result<openssl::hash::Hasher, openssl::error::ErrorStack>,
    limit: u64,
    bytes_written: u64,
}

impl Write for DigestWriter {
    fn write(&mut self, src: &[u8]) -> io::Result<usize> {
        let bytes_to_hash = usize::try_from(self.limit - self.bytes_written)
            .unwrap_or(usize::MAX)
            .min(src.len());

        if bytes_to_hash > 0 {
            let result = match self.digest {
                Ok(ref mut digest) => digest.update(src),
                Err(_) => Ok(()),
            };

            if let Err(e) = result {
                self.digest = Err(e);
            }
            self.bytes_written += bytes_to_hash as u64;
        }

        Ok(src.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::super::HEADER_NAME;
    use super::*;
    use crate::{mime::header::FULL_HEADER_LINE, test_data::*};

    fn validate_body_hash(message: &[u8]) {
        let blank_line = memchr::memmem::find(message, b"\r\n\r\n")
            .expect("no CRLF-CRLF in message");
        let header = FULL_HEADER_LINE
            .captures_iter(&message[..blank_line])
            .find(|m| {
                std::str::from_utf8(m.get(2).unwrap().as_bytes())
                    .unwrap()
                    .eq_ignore_ascii_case(HEADER_NAME)
            })
            .map(|m| {
                Header::parse(
                    std::str::from_utf8(m.get(1).unwrap().as_bytes()).unwrap(),
                )
                .unwrap()
            })
            .expect("couldn't find DKIM-Signature header");

        let mut hasher = BodyHasher::new(&header);
        hasher.write_all(&message[blank_line + 4..]).unwrap();
        let hash = hasher.finish(&header).unwrap();
        assert_eq!(header.body_hash, hash);
    }

    #[test]
    fn test_body_hash_lingl_rsa_sha1() {
        validate_body_hash(DKIM_LINGL_RSA_SHA1);
    }

    #[test]
    fn test_body_hash_amazoncojp_2x_rsa_sha256() {
        validate_body_hash(DKIM_AMAZONCOJP_RSA_SHA256);
    }

    #[test]
    fn test_body_hash_yahoo_rsa_sha256() {
        validate_body_hash(DKIM_YAHOO_RSA_SHA256);
    }

    #[test]
    fn test_body_hash_limited_length() {
        // No examples found in the wild; test by hand.
        let header = Header::parse(
            "DKIM-Signature: v=1;a=rsa-sha256;b=;\
             bh=Nsx3H8hrN69TdEBLtV66Rt2u82rLWvpdZQpUyTcsqE4=;\
             c=relaxed/relaxed;d=example.com;h=from:date;l=7;\
             s=selector",
        )
        .unwrap();
        let mut hasher = BodyHasher::new(&header);
        // Canonicalises to `foo\r\nbar\r\n`, so 7 chars is `foo\r\nba`.
        hasher.write_all(b"foo \t\r\nbar").unwrap();
        let hash = hasher.finish(&header).unwrap();
        assert_eq!(header.body_hash, hash);
    }

    #[test]
    fn test_body_hash_truncated() {
        let header = Header::parse(
            "DKIM-Signature: v=1;a=rsa-sha256;b=;\
             bh=Nsx3H8hrN69TdEBLtV66Rt2u82rLWvpdZQpUyTcsqE4=;\
             c=relaxed/relaxed;d=example.com;h=from:date;l=7;\
             s=selector",
        )
        .unwrap();
        let mut hasher = BodyHasher::new(&header);
        hasher.write_all(b"foo").unwrap();
        assert_matches!(
            Err(Error::Fail(Failure::BodyTruncated)),
            hasher.finish(&header),
        );
    }
}
