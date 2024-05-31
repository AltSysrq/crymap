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
use std::mem;

use super::{BodyCanonicaliser, Error, Failure, Header};
use crate::mime::header::FULL_HEADER_LINE;

/// Generates the header hash data into a byte vec.
///
/// This generates a whole `Vec<u8>` instead of writing to a writer because
/// OpenSSL's Ed25519 implementation requires being presented all the data at
/// once.
pub(super) fn header_hash_data(
    header: &Header<'_>,
    header_block: &[u8],
) -> Vec<u8> {
    let mut out = Vec::<u8>::with_capacity(header_block.len() / 4);
    let mut resolved_headers: Vec<&str> = vec![""; header.signed_headers.len()];
    // Find which message header lines correspond to each `signed_headers`
    // value. A single occurrence in `signed_headers` matches the final
    // occurrence of that header in the message. On repeated values in
    // `signed_headers`, the Nth occurrence `signed_header` matches the
    // Nth-from-last occurrence of the header in the header block.
    //
    // This implementation works by checking each header line against each
    // `signed_headers` value. If it matches, that `resolved_headers` value is
    // set to the new message header, and the old value from `resolved_headers`
    // is carried into the next occurrence of the same header name, and so on.
    //
    // There's nominally special cases around references to other
    // DKIM-Signature blocks. However, the standard requires that signers only
    // daisy-chain them if they actually exist at the point of signing, so no
    // compliant signer will produce a case we'd need to handle differently,
    // and when we sign ourselves, we don't reference DKIM-Signature.
    for m in FULL_HEADER_LINE.captures_iter(header_block) {
        // Header values are always supposed to be UTF-8 if they are 8-bit at
        // all, so we just skip past anything that isn't UTF-8.
        let Ok(header_name) = std::str::from_utf8(m.get(2).unwrap().as_bytes())
        else {
            continue;
        };

        let Ok(mut header_line) =
            std::str::from_utf8(m.get(1).unwrap().as_bytes())
        else {
            continue;
        };

        for (resolved, target_name) in
            resolved_headers.iter_mut().zip(&header.signed_headers)
        {
            if target_name.eq_ignore_ascii_case(header_name) {
                mem::swap(&mut header_line, resolved);
            }
        }
    }

    // RFC 6376 § 3.7, "hash step 2".
    // The standard contradicts itself here. In prose, it says that the hash
    // inputs are:
    //
    // > 1. The header fields specified by the "h=" tag [...].
    // > 2. The DKIM-Signature header field [...].
    // (there is no 3.)
    //
    // However, it goes on to present this pseudocode, which implies that the
    // body hash is redundantly passed in after the DKIM-Signature header
    // field.
    //
    // > body-hash    =  hash-alg (canon-body, l-param)
    // > data-hash    =  hash-alg (h-headers, D-SIG, body-hash)
    // > signature    =  sig-alg (d-domain, selector, data-hash)
    //
    // The implementation here is the one that successfully validates
    // known-good third-party implementations.

    for h in resolved_headers {
        // If the header is entirely missing, we skip it entirely, rather than
        // adding an implicit \r\n. This is curious, as it allows an attacker
        // to shuffle header data around without breaking the signature.
        if h.is_empty() {
            continue;
        }

        header
            .canonicalisation
            .header
            .write(&mut out, h, "")
            .expect("writing to a vec never fails");
        out.extend_from_slice(b"\r\n");
    }

    let header_raw = header.raw();
    header
        .canonicalisation
        .header
        .write(
            &mut out,
            &header_raw.text[..header_raw.b.start],
            &header_raw.text[header_raw.b.end..],
        )
        .expect("writing to a vec never fails");
    // No \r\n after the DKIM-Signature header

    out
}

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
                        header.algorithm.hash.message_digest(),
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
            .map_err(Error::Io)?;

        let hash = body_hash
            .digest
            .and_then(|mut h| h.finish())
            // We don't expect hashing to ever fail
            .map_err(Error::Ssl)?
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
    use std::borrow::Cow;

    use chrono::prelude::*;

    use super::super::{
        split_message, test_domain_keys, Algorithm, BodyCanonicalisation,
        Canonicalisation, HashAlgorithm, HeaderCanonicalisation,
        SignatureAlgorithm, TxtRecord, HEADER_NAME,
    };
    use super::*;
    use crate::test_data::*;

    fn extract_nth_dkim_header(header_block: &[u8], n: usize) -> Header<'_> {
        FULL_HEADER_LINE
            .captures_iter(header_block)
            .filter(|m| {
                std::str::from_utf8(m.get(2).unwrap().as_bytes())
                    .unwrap()
                    .eq_ignore_ascii_case(HEADER_NAME)
            })
            .skip(n)
            .next()
            .map(|m| {
                Header::parse(
                    std::str::from_utf8(m.get(1).unwrap().as_bytes()).unwrap(),
                )
                .unwrap()
            })
            .expect("couldn't find DKIM-Signature header")
    }

    fn validate_body_hash(message: &[u8]) {
        let (header_block, body) = split_message(message);
        let header = extract_nth_dkim_header(header_block, 0);

        let mut hasher = BodyHasher::new(&header);
        hasher.write_all(body).unwrap();
        let hash = hasher.finish(&header).unwrap();
        assert_eq!(header.body_hash, hash);
    }

    fn collect_header_hash_data(message: &[u8], n: usize) -> String {
        let (header_block, _) = split_message(message);
        let header = extract_nth_dkim_header(header_block, n);

        let out = header_hash_data(&header, header_block);
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn test_header_hash_data() {
        // relaxed
        assert_eq!(
            "message-id:<10d8b2e8-acd3-98d9-5312-6e2a9c900286@lin.gl>\r\n\
             date:Mon, 8 May 2023 20:19:29 +0000\r\n\
             mime-version:1.0\r\n\
             to:lindotgl@gmail.com\r\n\
             from:Jason Lingle <jason@lin.gl>\r\n\
             subject:Test email\r\n\
             content-type:text/plain; charset=UTF-8; format=flowed\r\n\
             content-transfer-encoding:7bit\r\n\
             dkim-signature:v=1; a=rsa-sha1; c=relaxed; d=lin.gl; h=message-id:date \
               :mime-version:to:from:subject:content-type \
               :content-transfer-encoding; s=selector1; bh=rnQpHRF2D2lVmnkKkePd \
               zkry2F8=; b=",
            collect_header_hash_data(DKIM_LINGL_RSA_SHA1, 0),
        );
        // relaxed
        assert_eq!(
            "date:Tue, 12 Sep 2023 01:14:07 +0000\r\n\
             from:\"Amazon.co.jp\" <store-news@amazon.co.jp>\r\n\
             to:jason@lin.gl\r\n\
             message-id:<0101018a86f3ed7f-fe8d791b-adcd-4244-\
               8b46-fa7d227050bc-000000@us-west-2.amazonses.com>\r\n\
             subject:=?UTF-8?B?6LOt44Kx44Kw44Or44Kk5Y+MKDE0KSAo44Ks44Oz44Ks44Oz?= \
               =?UTF-8?B?44Kz44Of44OD44Kv44K5Sk9LRVIp44Gq44Gp44GK55+l44KJ44Gb?=\r\n\
             mime-version:1.0\r\n\
             content-type:multipart/alternative; \
               boundary=\"----=_Part_375994_2040052076.1694481247599\"\r\n\
             dkim-signature:v=1; a=rsa-sha256; q=dns/txt; c=relaxed/simple; \
               s=55v6dsnbko3asrylf5mgtqv5mgll5any; d=amazon.co.jp; t=1694481247; \
               h=Date:From:To:Message-ID:Subject:MIME-Version:Content-Type; \
               bh=HcKSAdwhXQ1MiHCZKbdFHJoJhb1uuMH9sTy0jsyxiew=; \
               b=",
            collect_header_hash_data(DKIM_AMAZONCOJP_RSA_SHA256, 0),
        );
        assert_eq!(
            "date:Tue, 12 Sep 2023 01:14:07 +0000\r\n\
             from:\"Amazon.co.jp\" <store-news@amazon.co.jp>\r\n\
             to:jason@lin.gl\r\n\
             message-id:<0101018a86f3ed7f-fe8d791b-adcd-4244-\
               8b46-fa7d227050bc-000000@us-west-2.amazonses.com>\r\n\
             subject:=?UTF-8?B?6LOt44Kx44Kw44Or44Kk5Y+MKDE0KSAo44Ks44Oz44Ks44Oz?= \
               =?UTF-8?B?44Kz44Of44OD44Kv44K5Sk9LRVIp44Gq44Gp44GK55+l44KJ44Gb?=\r\n\
             mime-version:1.0\r\n\
             content-type:multipart/alternative; \
               boundary=\"----=_Part_375994_2040052076.1694481247599\"\r\n\
             feedback-id:1.us-west-2.Ci45k5OkUuH90u7dO0Ory1StkcbFm601BtN95yGGkr4=:AmazonSES\r\n\
             dkim-signature:v=1; a=rsa-sha256; q=dns/txt; c=relaxed/simple; \
               s=hsbnp7p3ensaochzwyq5wwmceodymuwv; d=amazonses.com; t=1694481247; \
               h=Date:From:To:Message-ID:Subject:MIME-Version:Content-Type:Feedback-ID; \
               bh=HcKSAdwhXQ1MiHCZKbdFHJoJhb1uuMH9sTy0jsyxiew=; \
               b=",
            collect_header_hash_data(DKIM_AMAZONCOJP_RSA_SHA256, 1),
        );

        // Signing example. This also tests the edge cases around multiple
        // headers, etc.
        fn utc(ts: i64) -> DateTime<Utc> {
            DateTime::from_timestamp(ts, 0).unwrap()
        }
        let signing_header = Header {
            raw: None,
            version: 1,
            algorithm: Algorithm {
                signature: SignatureAlgorithm::Ed25519,
                hash: HashAlgorithm::Sha256,
            },
            signature: b"\xb2\x28\x27\x6a\xdb\xab\x79\xe7\x9e".to_vec(),
            body_hash: b"\x6e\x87\x72\x85\xab\x21".to_vec(),
            canonicalisation: Canonicalisation {
                body: BodyCanonicalisation::Simple,
                header: HeaderCanonicalisation::Simple,
            },
            sdid: Cow::Borrowed("example.com"),
            auid: Some(Cow::Borrowed("@example.com")),
            signed_headers: vec![
                Cow::Borrowed("From"),
                Cow::Borrowed("To"),
                Cow::Borrowed("From"),
                Cow::Borrowed("Content-Location"),
                Cow::Borrowed("Content-Transfer-Encoding"),
                Cow::Borrowed("Subject"),
            ],
            body_length: None,
            dns_txt: true,
            selector: Cow::Borrowed("selector0"),
            signature_timestamp: Some(utc(42)),
            signature_expiration: Some(utc(54)),
        };
        let out = header_hash_data(
            &signing_header,
            b"FrOm: first from header\r\n\
              To: to header\r\n\
              from: second from header\r\n\
              foo: bar\r\n\
              FROM: third from header\r\n",
        );
        assert_eq!(
            "FROM: third from header\r\n\
             To: to header\r\n\
             from: second from header\r\n\
             DKIM-Signature: v=1;a=ed25519-sha256;c=simple/simple;d=example.com;\r\n\
             \x20i=@example.com;h=From:To:From:Content-Location:Content-Transfer-Encoding:\r\n\
             \x20Subject;s=selector0;t=42;x=54;bh=bodyhash;b=",
            String::from_utf8(out).unwrap(),
        );
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

    // Verifies a DKIM signature primitively. This is testing that we're
    // hashing everything correctly. It only supports RSA.
    fn primitive_dkim_verify(message: &[u8], dns_txt: &str, n: usize) {
        let (header_block, body) = split_message(message);
        let header = extract_nth_dkim_header(header_block, n);
        assert_eq!(SignatureAlgorithm::Rsa, header.algorithm.signature);
        let dns_txt = TxtRecord::parse(dns_txt).unwrap();
        assert_eq!(SignatureAlgorithm::Rsa, dns_txt.key_type);

        let public_key =
            openssl::rsa::Rsa::public_key_from_der(&dns_txt.public_key)
                .unwrap();
        let public_key = openssl::pkey::PKey::from_rsa(public_key).unwrap();
        let mut verifier = openssl::sign::Verifier::new(
            header.algorithm.hash.message_digest(),
            &public_key,
        )
        .unwrap();

        // Superfluous for this test, but sanity check the body hash anyway.
        let mut hasher = BodyHasher::new(&header);
        hasher.write_all(body).unwrap();
        let body_hash = hasher.finish(&header).unwrap();
        assert_eq!(header.body_hash, body_hash);

        let header_data = header_hash_data(&header, header_block);
        assert!(
            verifier
                .verify_oneshot(&header.signature, &header_data)
                .unwrap(),
            "verification failed",
        );
    }

    #[test]
    fn test_signature_lingl_rsa_sha1() {
        primitive_dkim_verify(
            DKIM_LINGL_RSA_SHA1,
            test_domain_keys::SELECTOR1_LIN_GL,
            0,
        );
    }

    #[test]
    fn test_signature_amazoncojp_rsa_sha256() {
        // The key for the d=amazon.co.jp entry (index 0) has been revoked and
        // lost, so we can only verify the second entry.
        primitive_dkim_verify(
            DKIM_AMAZONCOJP_RSA_SHA256,
            test_domain_keys::HSG_AMAZONSES_COM,
            1,
        );
    }

    #[test]
    fn test_signature_yahoo_rsa256() {
        primitive_dkim_verify(
            DKIM_YAHOO_RSA_SHA256,
            test_domain_keys::S2048_YAHOO_COM,
            0,
        );
    }
}
