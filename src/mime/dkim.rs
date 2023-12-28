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

#![allow(dead_code)]

use std::borrow::Cow;
use std::ops::Range;

use chrono::prelude::*;

use crate::support::chronox::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum HashAlgorithm {
    /// RFC 6376, obsoleted by RFC 8301
    Sha1,
    /// RFC 6376
    Sha256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// RFC 6376
    Rsa,
    /// RFC 8463
    Ed25519,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum BodyCanonicalisation {
    /// RFC 6376
    #[default]
    Simple,
    /// RFC 6376
    Relaxed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum HeaderCanonicalisation {
    /// RFC 6376
    #[default]
    Simple,
    /// RFC 6376
    Relaxed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawHeader<'a> {
    /// The full DKIM header, starting at the first byte of the
    /// `DKIM-Signature` header line and extending to but not including the
    /// (CR)LF which terminates the whole header.
    pub text: Cow<'a, str>,
    /// The range in `text` of the value of the `b` field, starting with the
    /// first byte after the `=` and ending on the `;` or the end of `text`.
    /// I.e., this is the portion of `text` which is *NOT* used as input to the
    /// final message hash.
    pub b: Range<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header<'a> {
    /// If this header was parsed from pre-existing text, that text content
    /// exactly as it was encountered.
    pub raw: Option<RawHeader<'a>>,
    /// The `v` field.
    pub version: u32,
    /// The `a` field.
    pub algorithm: Algorithm,
    /// The `b` field, decoded.
    pub signature: Vec<u8>,
    /// The `bh` field, decoded.
    pub body_hash: Vec<u8>,
    /// The `c` field.
    pub canonicalisation: Canonicalisation,
    /// The `d` field, still in punycode.
    pub sdid: Cow<'a, str>,
    /// The `h` field, decoded.
    pub signed_headers: Vec<Cow<'a, str>>,
    // The `i` field. is not used by this implementation.
    /// The `l` field.
    pub body_length: Option<u64>,
    /// Is `dns/txt` included in the `q` field?
    pub dns_txt: bool,
    /// The `s` field, still in punycode.
    pub selector: Cow<'a, str>,
    /// The `t` field.
    pub signature_timestamp: Option<DateTime<Utc>>,
    /// The `x` field.
    pub signature_expiration: Option<DateTime<Utc>>,
    // The `z` field is not used by this implementation.
}

impl<'a> Header<'a> {
    #[cfg(test)]
    fn without_raw(self) -> Self {
        Self { raw: None, ..self }
    }

    /// Parses the given string.
    ///
    /// The string must include the `DKIM-Header:` prefix and must not contain
    /// the final line ending.
    pub fn parse(whole_header: &'a str) -> Result<Self, String> {
        let Some((header_name, s)) = whole_header.split_once(':') else {
            return Err("DKIM header didn't have :".to_owned());
        };

        let header_text_offset = header_name.len() + 1;

        debug_assert!(!s.ends_with('\n'));

        let mut version = None::<u32>;
        let mut algorithm = None::<Algorithm>;
        let mut signature = None::<(Vec<u8>, Range<usize>)>;
        let mut body_hash = None::<Vec<u8>>;
        let mut canonicalisation = None::<Canonicalisation>;
        let mut sdid = None::<Cow<'a, str>>;
        let mut signed_headers = None::<Vec<Cow<'a, str>>>;
        let mut body_length = None::<u64>;
        let mut dns_txt = None::<bool>;
        let mut selector = None::<Cow<'a, str>>;
        let mut signature_timestamp = None::<DateTime<Utc>>;
        let mut signature_expiration = None::<DateTime<Utc>>;

        for (k, v, v_range) in split_kv_pairs(s) {
            let v_range = v_range.start + header_text_offset
                ..v_range.end + header_text_offset;

            match k {
                "v" => {
                    set_opt(
                        k,
                        &mut version,
                        v.parse().map_err(|_| format!("unparsable v={v}"))?,
                    )?;
                },

                "a" => set_opt(k, &mut algorithm, Algorithm::parse(v)?)?,
                "b" => set_opt(k, &mut signature, (decode_base64(v), v_range))?,
                "bh" => set_opt(k, &mut body_hash, decode_base64(v))?,
                "c" => {
                    set_opt(
                        k,
                        &mut canonicalisation,
                        Canonicalisation::parse(v)?,
                    )?;
                },
                "d" => set_opt(k, &mut sdid, Cow::Borrowed(v))?,
                "h" => set_opt(
                    k,
                    &mut signed_headers,
                    v.split(':')
                        .map(|s| Cow::Borrowed(s.trim_matches(FWS)))
                        .collect(),
                )?,
                "l" => {
                    set_opt(
                        k,
                        &mut body_length,
                        v.parse().map_err(|_| format!("unparsable l={v}"))?,
                    )?;
                },
                "q" => {
                    set_opt(
                        k,
                        &mut dns_txt,
                        v.split(':')
                            .map(|s| s.trim_matches(FWS))
                            .any(|s| "dns/txt" == s),
                    )?;
                },
                "s" => set_opt(k, &mut selector, Cow::Borrowed(v))?,
                "t" => {
                    set_opt(k, &mut signature_timestamp, decode_timestamp(v)?)?
                },
                "x" => {
                    set_opt(k, &mut signature_expiration, decode_timestamp(v)?)?
                },
                _ => {},
            }
        }

        let (signature, signature_range) = signature.ok_or("missing b= tag")?;
        Ok(Self {
            raw: Some(RawHeader {
                text: Cow::Borrowed(whole_header),
                b: signature_range,
            }),
            version: version.ok_or("missing v= tag")?,
            algorithm: algorithm.ok_or("missing a= tag")?,
            signature,
            body_hash: body_hash.ok_or("missing bh= tag")?,
            canonicalisation: canonicalisation.unwrap_or_default(),
            sdid: sdid.ok_or("missing d= tag")?,
            signed_headers: signed_headers.ok_or("missing h= tag")?,
            body_length,
            dns_txt: dns_txt.unwrap_or(true),
            selector: selector.ok_or("missing s= tag")?,
            signature_timestamp,
            signature_expiration,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Algorithm {
    pub signature: SignatureAlgorithm,
    pub hash: HashAlgorithm,
}

impl SignatureAlgorithm {
    fn parse(signature: &str) -> Result<Self, String> {
        match signature {
            "rsa" => Ok(Self::Rsa),
            "ed25519" => Ok(Self::Ed25519),
            s => Err(format!("unknown signature algorithm: {s}")),
        }
    }
}

impl HashAlgorithm {
    fn parse(hash: &str) -> Result<Self, String> {
        match hash {
            "sha1" => Ok(Self::Sha1),
            "sha256" => Ok(Self::Sha256),
            h => Err(format!("unknown hash algorithm: {h}")),
        }
    }
}

impl Algorithm {
    fn parse(s: &str) -> Result<Self, String> {
        let Some((signature, hash)) = s.split_once('-') else {
            return Err(format!("couldn't parse a={s}"));
        };

        let signature = SignatureAlgorithm::parse(signature)?;
        let hash = HashAlgorithm::parse(hash)?;

        Ok(Self { signature, hash })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Canonicalisation {
    pub header: HeaderCanonicalisation,
    pub body: BodyCanonicalisation,
}

impl Canonicalisation {
    fn parse(s: &str) -> Result<Self, String> {
        let (header, body) = s.split_once('/').unwrap_or((s, "simple"));

        let header = match header {
            "simple" => HeaderCanonicalisation::Simple,
            "relaxed" => HeaderCanonicalisation::Relaxed,
            h => return Err(format!("unknown header canonicalisation: {h}")),
        };
        let body = match body {
            "simple" => BodyCanonicalisation::Simple,
            "relaxed" => BodyCanonicalisation::Relaxed,
            b => return Err(format!("unknown body canonicalisation: {b}")),
        };

        Ok(Self { header, body })
    }
}

/// A parsed representation of a DKIM TXT record stored in DNS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxtRecord<'a> {
    /// The `v` field.
    pub version: Cow<'a, str>,
    /// The `h` field.
    ///
    /// Unknown algorithms are dropped at parse time and the whole vec is
    /// deduplicated.
    pub acceptable_hash_algorithms: Option<Vec<HashAlgorithm>>,
    /// The `k` field.
    pub key_type: SignatureAlgorithm,
    // The `n` field is unused by this algorithm.
    /// The `p` field, decoded.
    pub public_key: Vec<u8>,
    /// Whether the `s` field includes `email`.
    pub is_email: bool,
    /// The flags set in the `t` field.
    pub flags: TxtFlags,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct TxtFlags {
    /// Whether `y` is set in `t`.
    pub test: bool,
    /// Whether `s` is set in `t`.
    pub strict: bool,
}

impl<'a> TxtRecord<'a> {
    pub fn parse(s: &'a str) -> Result<Self, String> {
        let mut version = None::<Cow<'a, str>>;
        let mut acceptable_hash_algorithms = None::<Vec<HashAlgorithm>>;
        let mut key_type = None::<SignatureAlgorithm>;
        let mut public_key = None::<Vec<u8>>;
        let mut is_email = None::<bool>;
        let mut flags = None::<TxtFlags>;

        for (k, v, _) in split_kv_pairs(s) {
            match k {
                "v" => set_opt(k, &mut version, Cow::Borrowed(v))?,
                "h" => {
                    let mut algorithms = v
                        .split(':')
                        .filter_map(|s| {
                            HashAlgorithm::parse(s.trim_matches(FWS)).ok()
                        })
                        .collect::<Vec<_>>();
                    algorithms.sort_unstable();
                    algorithms.dedup();
                    set_opt(k, &mut acceptable_hash_algorithms, algorithms)?;
                },
                "k" => {
                    set_opt(k, &mut key_type, SignatureAlgorithm::parse(v)?)?
                },
                "p" => set_opt(k, &mut public_key, decode_base64(v))?,
                "s" => {
                    set_opt(
                        k,
                        &mut is_email,
                        v.split(':').any(|s| {
                            let s = s.trim_matches(FWS);
                            "*" == s || "email" == s
                        }),
                    )?;
                },
                "t" => {
                    let mut parsed_flags = TxtFlags::default();
                    for flag in v.split(':') {
                        match flag.trim_matches(FWS) {
                            "y" => parsed_flags.test = true,
                            "s" => parsed_flags.strict = true,
                            _ => {},
                        }
                    }
                    set_opt(k, &mut flags, parsed_flags)?;
                },
                _ => {},
            }
        }

        Ok(Self {
            version: version.unwrap_or(Cow::Borrowed("DKIM1")),
            acceptable_hash_algorithms,
            key_type: key_type.unwrap_or(SignatureAlgorithm::Rsa),
            public_key: public_key.ok_or("missing p= tag")?,
            is_email: is_email.unwrap_or(true),
            flags: flags.unwrap_or_default(),
        })
    }
}

const HEADER_NAME: &str = "DKIM-Signature";
const FWS: &[char] = &[' ', '\t', '\r', '\n'];

/// Splits the given string into key-value pairs as per RFC 6376 § 3.2. Keys
/// and values are not decoded but are fully trimmed. The range associated with
/// each item is the range of the value *before* trimming; this is used to
/// determine the `b` field of `RawHeader`.
fn split_kv_pairs(
    s: &str,
) -> impl Iterator<Item = (&str, &str, Range<usize>)> + '_ {
    let mut offset = 0usize;
    s.split(';')
        .map(move |group| {
            let start = offset;
            offset += group.len() + 1;
            (group, start)
        })
        .filter_map(|(group, offset)| {
            group.split_once('=').map(|(k, v)| {
                let v_start = offset + k.len() + 1;
                let v_end = v_start + v.len();
                let k = k.trim_matches(FWS);
                let v = v.trim_matches(FWS);
                (k, v, v_start..v_end)
            })
        })
}

/// Decode RFC 6376 DKIM-Quoted-Printable-encoded text.
///
/// This is only used by the `z` field, which we currently don't even decode,
/// but I didn't realise that until after implementing it.
#[allow(dead_code)]
fn decode_qp(s: &str) -> Cow<'_, str> {
    // QP decoding essentially works by deleting whitespace characters and
    // decoding =XX codes. We can trim the exterior whitespace away, and if
    // there are no whitespace or '=' characters inside after doing so, we know
    // there's nothing to decode.
    let s = s.trim_matches(FWS);
    if s.find(FWS).is_none() && s.find('=').is_none() {
        return Cow::Borrowed(s);
    }

    let mut out = Vec::<u8>::with_capacity(s.len());
    let mut it = s
        .as_bytes()
        .iter()
        .copied()
        .filter(|&ch| !matches!(ch, b' ' | b'\t' | b'\r' | b'\n'));
    while let Some(ch) = it.next() {
        match ch {
            b'=' => {
                let Some(a) = it.next() else {
                    break;
                };
                let Some(b) = it.next() else {
                    break;
                };

                if let (Some(a), Some(b)) =
                    ((a as char).to_digit(16), (b as char).to_digit(16))
                {
                    out.push((a << 4 | b) as u8);
                }
            },
            ch => out.push(ch),
        }
    }

    match String::from_utf8(out) {
        Ok(s) => Cow::Owned(s),
        Err(e) => {
            Cow::Owned(String::from_utf8_lossy(e.as_bytes()).into_owned())
        },
    }
}

/// Decode RFC 6376 base64 with embedded folding whitespace.
fn decode_base64(s: &str) -> Vec<u8> {
    fn is_base64_char(ch: char) -> bool {
        matches!(ch, '0'..='9' | 'a'..='z' | 'A'..='Z' | '+' | '/' | '=')
    }

    // Manually strip out any non-base64 chars since the base64 crate can't be
    // configured to ignore such characters (even in the latest version with
    // the over-engineered API).
    let mut s = Cow::Borrowed(s.trim_matches(|c| !is_base64_char(c)));
    if s.find(|c| !is_base64_char(c)).is_some() {
        s = Cow::Owned(s.chars().filter(|&c| is_base64_char(c)).collect());
    }

    base64::decode_config(
        s.as_bytes(),
        base64::Config::new(base64::CharacterSet::Standard, true)
            .decode_allow_trailing_bits(true),
    )
    .unwrap_or_else(|_| Vec::new())
}

fn set_opt<T>(k: &str, opt: &mut Option<T>, v: T) -> Result<(), String> {
    if opt.is_some() {
        return Err(format!("duplicate {k}= tag"));
    }

    *opt = Some(v);
    Ok(())
}

fn decode_timestamp(s: &str) -> Result<DateTime<Utc>, String> {
    // We require `s` to be parsable as an integer, but silently clamp
    // the date to a representable range.
    let seconds = s
        .parse::<i64>()
        .map_err(|_| format!("unparsable timestamp: {s}"))?
        .max(0);
    Ok(
        DateTime::<Utc>::from_timestamp(seconds, 0).unwrap_or_else(|| {
            NaiveDate::from_ymdx(9999, 12, 31).and_hmsx_utc(23, 59, 59)
        }),
    )
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_split_kv_pairs() {
        let input = "foo = bar; baz = \r\n\
                     \tquux ;a=b = c;invalid;x=y";
        let output = split_kv_pairs(input).collect::<Vec<_>>();
        assert_eq!(
            vec![
                ("foo", "bar", 5..9),
                ("baz", "quux", 16..25),
                ("a", "b = c", 28..33),
                ("x", "y", 44..45),
            ],
            output,
        );
    }

    #[test]
    fn test_decode_qp() {
        assert_eq!("foo", &*decode_qp("foo"));
        assert_eq!("foo", &*decode_qp(" \t\r\nfoo\n\r\t "));
        assert_eq!("foo", &*decode_qp(" f\to\r\no "));
        assert_eq!("föö", &*decode_qp("f=C3= b 6 ö "));
        assert_eq!("f�o", &*decode_qp("f=C3o"));
    }

    #[test]
    fn test_decode_base64() {
        assert_eq!(b"foo\n".to_vec(), decode_base64("Zm9vCg=="),);
        assert_eq!(b"foo\n".to_vec(), decode_base64("Zm9vCg"),);
        assert_eq!(b"foo\n".to_vec(), decode_base64(" Zm9\r\n\tvCg=="),);
        assert_eq!(b"".to_vec(), decode_base64("!"),);
    }

    #[test]
    fn test_parse_dkim_header() {
        macro_rules! signed_headers {
            ($($h:expr),* $(,)*) => {
                vec![$(Cow::Borrowed($h),)*]
            }
        }

        fn utc(ts: i64) -> DateTime<Utc> {
            DateTime::from_timestamp(ts, 0).unwrap()
        }

        assert_eq!(
            Header {
                raw: None,
                version: 1,
                algorithm: Algorithm {
                    signature: SignatureAlgorithm::Rsa,
                    hash: HashAlgorithm::Sha256,
                },
                signature: include_bytes!("dkim-test-data/amazon-b.dat")
                    .to_vec(),
                body_hash: include_bytes!("dkim-test-data/amazon-bh.dat")
                    .to_vec(),
                canonicalisation: Canonicalisation {
                    header: HeaderCanonicalisation::Relaxed,
                    body: BodyCanonicalisation::Simple,
                },
                sdid: Cow::Borrowed("amazon.com"),
                signed_headers: signed_headers![
                    "Date",
                    "From",
                    "Reply-To",
                    "To",
                    "Message-ID",
                    "Subject",
                    "MIME-Version",
                    "Content-Type",
                ],
                body_length: None,
                dns_txt: true,
                selector: Cow::Borrowed("yg4mwqurec7fkhzutopddd3ytuaqrvuz"),
                signature_timestamp: Some(utc(1702483030)),
                signature_expiration: None,
            },
            // Amazon SES, circa 2023-12.
            Header::parse(
                "\
DKIM-Signature: v=1; a=rsa-sha256; q=dns/txt; c=relaxed/simple;
\ts=yg4mwqurec7fkhzutopddd3ytuaqrvuz; d=amazon.com; t=1702483030;
\th=Date:From:Reply-To:To:Message-ID:Subject:MIME-Version:Content-Type;
\tbh=jSubcFfoY5PufRsPiY2av8nT07eomDmnPkIRbeTFRBk=;
\tb=VGfAECANIUoGP05kazP5l0RlanbyeTVz+M1qS6m3QwBw256D2tmn3mC/PxX3UMBE
\tK18keZA2lWsjALPQasI0nDjJXKPoZeoy7hmz83cSyCt59Kh24cb8xMqbbX3UvyEL2h8
\tQvdZD9L6Qilqdy7ZzvKZvD5WYE8CKmPr/4jJcJtA=",
            )
            .unwrap()
            .without_raw(),
        );
        assert_eq!(
            Header {
                raw: None,
                version: 1,
                algorithm: Algorithm {
                    signature: SignatureAlgorithm::Rsa,
                    hash: HashAlgorithm::Sha256,
                },
                signature: include_bytes!("dkim-test-data/google-b.dat")
                    .to_vec(),
                body_hash: include_bytes!("dkim-test-data/google-bh.dat")
                    .to_vec(),
                canonicalisation: Canonicalisation {
                    header: HeaderCanonicalisation::Relaxed,
                    body: BodyCanonicalisation::Relaxed,
                },
                sdid: Cow::Borrowed("gmail.com"),
                signed_headers: signed_headers![
                    "to",
                    "subject",
                    "message-id",
                    "date",
                    "from",
                    "mime-version",
                    "from",
                    "to",
                    "cc",
                    "subject",
                    "date",
                    "message-id",
                    "reply-to",
                ],
                body_length: None,
                dns_txt: true,
                selector: Cow::Borrowed("20230601"),
                signature_timestamp: Some(utc(1702265476)),
                signature_expiration: Some(utc(1702870276)),
            },
            // gmail.com personal mail, circa 2023-12
            Header::parse(
                "\
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1702265476; x=1702870276; darn=lin.gl;
        h=to:subject:message-id:date:from:mime-version:from:to:cc:subject
         :date:message-id:reply-to;
        bh=0HSnqiLGPQgqEHPjncsz6eneQIh6uCmew9b4eBI1sEQ=;
        b=ZL9RDgSe+ARbYahAWXMlRv0sNyDqloirtgr/vqPY0Gcb2NXifE2UgHgVyq/h+LHvGV
         aDUZvYOUlXaq+2oC3I/sh5+kBV/HgWuUW85uf9i29w97+fhLnhUP4LqCV3you597xbbS
         PWy9pmuOkgNpgUuCm7nL7e708EsyPmqBz4m15CL6x6yO9i70QFGTT+/EtXgmEQ+NlZwx
         HacrTTroLhklPoH6RWEmyM4bXbsdH+mOTVSGGjhxaEyFNjAWYINrApvFcarbZqPID+xF
         Q8pvsIB2fmAAsUTwhZ/51Doz7injzAUc+S7eGPlHiwXYsSHdc4zP5VngMHVJHye57y9l
         wABQ==",
            )
            .unwrap()
            .without_raw(),
        );

        assert_eq!(
            Header {
                raw: None,
                version: 1,
                algorithm: Algorithm {
                    signature: SignatureAlgorithm::Rsa,
                    hash: HashAlgorithm::Sha256,
                },
                signature: include_bytes!("dkim-test-data/yahoo-b.dat")
                    .to_vec(),
                body_hash: include_bytes!("dkim-test-data/yahoo-bh.dat")
                    .to_vec(),
                canonicalisation: Canonicalisation {
                    header: HeaderCanonicalisation::Relaxed,
                    body: BodyCanonicalisation::Relaxed,
                },
                sdid: Cow::Borrowed("yahoo.com"),
                signed_headers: signed_headers![
                    "Date",
                    "From",
                    "To",
                    "Subject",
                    "References",
                    "From",
                    "Subject",
                    "Reply-To",
                ],
                body_length: None,
                dns_txt: true,
                selector: Cow::Borrowed("s2048"),
                signature_timestamp: Some(utc(1682347998)),
                signature_expiration: None,
            },
            // Yahoo.com personal email, circa 2023-04
            Header::parse(
                // Yahoo!'s DKIM implementation doesn't care about the
                // 80-character line limit apparently,
                "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=yah\
                 oo.com; s=s2048; t=1682347998; bh=p8cdqs66pBqQszjnyvAcAvXuE\
                 bmIa/Xf0lO3Ln2eVZk=; h=Date:From:To:Subject:References:From\
                 :Subject:Reply-To; b=uHZNI+P6MgL/RMwAjMpxy/zVCl2bl4KLwrEN1X\
                 qFnnjpfq7m626c8i0HvODK/908i/SnurxoT5vy9A3TUHRm0iVUHikl/uXOX\
                 GWgTnV6HX3BwbEOZT6W2cL+ZeIz8dHyx9S5XTPNqv3Buo3mekl/+KFfT5z9\
                 8+Qt3Xk1s9F8CG7hEyFHsPSrzWI8GYeVaGw+HsmAWJgN+SBvQJ0FAgyEtG4\
                 Q2VaC/qCNBfkZBLPcRBXi6kuk9Vnu81g+HmOxJKrSpv+SggR4H7yH3q+Kq0\
                 k+Z0dDU/87Iypzyfu1f9wtKqIImsHBT5hIGtN1I6rEMf645QE0a6iTAJpkE\
                 CQUxuekCQ==",
            )
            .unwrap()
            .without_raw(),
        );

        assert_eq!(
            Header {
                raw: None,
                version: 1,
                algorithm: Algorithm {
                    signature: SignatureAlgorithm::Rsa,
                    hash: HashAlgorithm::Sha1,
                },
                signature: include_bytes!("dkim-test-data/dkimproxy-b.dat")
                    .to_vec(),
                body_hash: include_bytes!("dkim-test-data/dkimproxy-bh.dat")
                    .to_vec(),
                canonicalisation: Canonicalisation {
                    header: HeaderCanonicalisation::Relaxed,
                    body: BodyCanonicalisation::Simple,
                },
                sdid: Cow::Borrowed("lin.gl"),
                signed_headers: signed_headers![
                    "message-id",
                    "date",
                    "mime-version",
                    "to",
                    "from",
                    "subject",
                    "content-type",
                    "content-transfer-encoding",
                ],
                body_length: None,
                dns_txt: true,
                selector: Cow::Borrowed("selector1"),
                signature_timestamp: None,
                signature_expiration: None,
            },
            // dkimproxy 1.4.1 output
            Header::parse(
                // Er, yes, my mail server was still using SHA-1 in 2023...
                "\
DKIM-Signature: v=1; a=rsa-sha1; c=relaxed; d=lin.gl; h=message-id:date
\t:mime-version:to:from:subject:content-type
\t:content-transfer-encoding; s=selector1; bh=rnQpHRF2D2lVmnkKkePd
\tzkry2F8=; b=IWB9g5DqRp1bujI0mN3a65F6UuVDi/mqUrT8oXd+SLvjqbuqayMN
\tBCJdd/HgoZd4rJlgruqsavTMZriKi4xFgnUqLg+0EcqNStNu+9Ny1AFpEInX1Np1
\t0f80Iktwlu7v7nLbGQnEHGtjgWAxiit25l0TSqcApYs3W/tskqqVCbwl9D/gdk9c
\t++oz0WNPDHcK0uxcm6FQFNLYrGjwmU6/E4et/1MiyzM1CQgUKHpqb+T//Kg+zDgJ
\t1Yo5bMnipPFc0gvPM8Z8ln+mIb+MKkRjCRYbE/zJMdjN6giLE9n0wgAxfKXx/Hrd
\tW5mabxTTXMXi9m1LeBxuO63x0TJ9pP/b+yZb0PviVnOv80QTmvYZSsT+IKn3gcVx
\tvv9wx0a7YY6M1fHdsyJYLq1FoIr5Ca9+WBJIofAqJhioI8dBIy59K9osWh/YyPjb
\tOWjvolfTA0EhTaMcZNoGL8DZrXbXvDjI2+hQLP7nAP4rMH8y54miBojjY96F4jTC
\t/x7JJFVqYuRs8nrlYQl2iq6Rtu8utuzzAObMHhs2jst8Q1p/xiQ4eGkBvV1O9TLH
\tPbDSvS0nzWF6+f5XM/J3ELYMqWJ1LU03kgnQ2y6yQnBVrWW+kH+HRYIGYzktoftP
\tAidn5MwXR8J60IGVee4Eg/A0u5FYzLvQ5w9+iJCaowz/rKM7irnXbPU=",
            )
            .unwrap()
            .without_raw(),
        );

        assert_eq!(
            Header {
                raw: None,
                version: 2,
                algorithm: Algorithm {
                    signature: SignatureAlgorithm::Ed25519,
                    hash: HashAlgorithm::Sha1,
                },
                signature: vec![],
                body_hash: vec![],
                canonicalisation: Canonicalisation {
                    header: HeaderCanonicalisation::Simple,
                    body: BodyCanonicalisation::Relaxed,
                },
                sdid: Cow::Borrowed("example.com"),
                signed_headers: signed_headers!["from", "date"],
                body_length: Some(400),
                dns_txt: false,
                selector: Cow::Borrowed("selector"),
                signature_timestamp: None,
                signature_expiration: Some(utc(42)),
            },
            Header::parse(
                // Hand-written case to test more exotic options
                "DKIM-Signature: v = 2; a = ed25519-sha1
\t; b=; bh=; c=simple/relaxed;d=example.com;h=from
\t:
\tdate
\t;l= 400 ;q=divination/tea-leaves;s= selector ; x=42",
            )
            .unwrap()
            .without_raw(),
        );

        // Verify that `raw.b` has the correct text.
        let header = Header::parse(
            "DKIM-Signature: v=1;a=rsa-sha1;b=food;bh=;c=simple;\
             d=example.com;h=from;s=selector",
        )
        .unwrap();
        let raw = header.raw.unwrap();
        assert!(raw.text.starts_with("DKIM-Signature: "));
        assert_eq!("food", &raw.text[raw.b.clone()]);

        let header = Header::parse(
            "DkIm-SiGnAtUrE   :    v=1;a=rsa-sha1;b=  \r\n\
             \t food  \r\n\
             ;bh=;c=simple;\
             d=example.com;h=from;s=selector",
        )
        .unwrap();
        let raw = header.raw.unwrap();
        assert!(raw.text.starts_with("DkIm-SiGnAtUrE   :   "));
        assert_eq!("  \r\n\t food  \r\n", &raw.text[raw.b.clone()]);

        let header = Header::parse(
            "DKIM-Signature: v=1;a=rsa-sha1;bh=;c=simple;\
             d=example.com;h=from;s=selector;b = food",
        )
        .unwrap();
        let raw = header.raw.unwrap();
        assert_eq!(" food", &raw.text[raw.b.clone()]);
    }

    #[test]
    fn test_parse_dkim_txt_record() {
        assert_eq!(
            TxtRecord {
                version: Cow::Borrowed("DKIM1"),
                acceptable_hash_algorithms: None,
                key_type: SignatureAlgorithm::Rsa,
                public_key: include_bytes!(
                    "dkim-test-data/selector1._domainkey.lin.gl.dat"
                )
                .to_vec(),
                is_email: true,
                flags: TxtFlags {
                    test: false,
                    strict: true,
                },
            },
            // selector1._domainkey.lin.gl, 2023-12-27
            TxtRecord::parse(
                "v=DKIM1;p=MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxCRVe\
                 M0ctOIvf0NRKs2bcYE3gXjfE9G0s+IY1Iw8cE/XAhisgUraQg5Vzv0d4La+\
                 SgQIJEm5XtkTeHFUgWIJM7ZXCI+WOi33+BRn9lwNe9TvoX+zYMCvTLFkEUF\
                 /tXihfg/8VcKMC1pc2Ik9bMh020XQUpPJkA/tduYJpq762n1gML0XhxaXHW\
                 41Qzkxh2TlATzbBv4V0Lcm4/JXFS9psUB8Sm6TB8N5G5g1zpCQbsA9jFyt3\
                 G8VkzUJ4gFJpAqE9czME7BPtVEKHDOSVqA+sztfrUsVjxHoqRXEQR6nj99/\
                 uIPprEvjdJ1PyZQKaj9mWqnX7XZor0nGl1tNW+rmfKgIhSh+cRvt2hRbtTF\
                 nXL+q6efqK+CwfN5j8pyLkox+S7WITdGrTTXoqPiPSDkjfaJhNi9Uhd/Mbk\
                 xF854vDeAm8ZYIIsjwt1p+XIscDP8X7niUOrRuWcpElX+CRtqc2qi2atqAJ\
                 hMySZQbh8NW8XVI+EPDYbWA5/JFA5lrf16TuCoyN5uwfaiYTBzTXxlQHWUm\
                 sZN/tXkpbO6fHAmc7bvBZfKGMYpmDvKhNZMhmeQjDLkOaSb47AEQf7+weMi\
                 qsZEIUhKoQf0En6KNhVWBjezH8022dy7GkxP3Hek+ESxvbwSJHH5mby+TGS\
                 U6a+mRausK4Ji72JhXH4PvnEvtimECAwEAAQ==;s=email;t=s",
            )
            .unwrap(),
        );
        assert_eq!(
            TxtRecord {
                version: Cow::Borrowed("DKIM1"),
                acceptable_hash_algorithms: None,
                key_type: SignatureAlgorithm::Rsa,
                public_key: include_bytes!(
                    "dkim-test-data/s2048._domainkey.yahoo.com.dat"
                )
                .to_vec(),
                is_email: true,
                flags: TxtFlags::default(),
            },
            // s2048._domainkey.yahoo.com, 2023-12-27
            TxtRecord::parse(
                "k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuoWufg\
                 bWw58MczUGbMv176RaxdZGOMkQmn8OOJ/HGoQ6dalSMWiLaj8IMcHC1cubJ\
                 x2gziAPQHVPtFYayyLA4ayJUSNk10/uqfByiU8qiPCE4JSFrpxflhMIKV4b\
                 t+g1uHw7wLzguCf4YAoR6XxUKRsAoHuoF7M+v6bMZ/X1G+viWHkBl4UfgJQ\
                 6O8F1ckKKoZ5KqUkJH5pDaqbgs+F3PpyiAUQfB6EEzOA1KMPRWJGpzgPtKo\
                 ukDcQuKUw9GAul7kSIyEcizqrbaUKNLGAmz0elkqRnzIsVpz6jdT1/YV5Ri\
                 6YUOQ5sN5bqNzZ8TxoQlkbVRy6eKOjUnoSSTmSAhwIDAQAB;",
            )
            .unwrap(),
        );
        assert_eq!(
            TxtRecord {
                version: Cow::Borrowed("DKIM1"),
                acceptable_hash_algorithms: None,
                key_type: SignatureAlgorithm::Rsa,
                public_key: include_bytes!(
                    "dkim-test-data/\
                     yg4mwqurec7fkhzutopddd3ytuaqrvuz.\
                     _domainkey.amazon.com.dat",
                )
                .to_vec(),
                is_email: true,
                flags: TxtFlags::default(),
            },
            // yg4mwqurec7fkhzutopddd3ytuaqrvuz._domainkey.amazon.com, 2023-12-27
            TxtRecord::parse(
                "p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC5bK96ORNNFosbAaVNZ\
                 U/gVzhANHyd00o1O7qbEeMNLKPNpS8/TYwdlrVnQ7JtJHjIR9EPj61jgtS6\
                 04XpAltDMYvic2I40AaKgSfr4dDlRcALRtlVqmG7U5MdLiMyabxXPl2s/oq\
                 kevALySg0sr/defHC+qAhmdot9Ii/ZQ3YcQIDAQAB",
            )
            .unwrap(),
        );
        assert_eq!(
            TxtRecord {
                version: Cow::Borrowed("DKIM1"),
                acceptable_hash_algorithms: None,
                key_type: SignatureAlgorithm::Rsa,
                public_key: include_bytes!(
                    "dkim-test-data/20230601._domainkey.gmail.com.dat",
                )
                .to_vec(),
                is_email: true,
                flags: TxtFlags::default(),
            },
            // 20230601._domainkey.gmail.com, 2023-12-27
            TxtRecord::parse(
                "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCA\
                 QEAntvSKT1hkqhKe0xcaZ0x+QbouDsJuBfby/S82jxsoC/SodmfmVs2D1KA\
                 H3mi1AqdMdU12h2VfETeOJkgGYq5ljd996AJ7ud2SyOLQmlhaNHH7Lx+Mda\
                 b8/zDN1SdxPARDgcM7AsRECHwQ15R20FaKUABGu4NTbR2fDKnYwiq5jQyBk\
                 LWP+LgGOgfUF4T4HZb2PY2bQtEP6QeqOtcW4rrsH24L7XhD+HSZb1hsitrE\
                 0VPbhJzxDwI4JF815XMnSVjZgYUXP8CxI1Y0FONlqtQYgsorZ9apoW1KPQe\
                 8brSSlRsi9sXB/tu56LmG7tEDNmrZ5XUwQYUUADBOu7t1niwXwIDAQAB",
            )
            .unwrap(),
        );
        assert_eq!(
            TxtRecord {
                version: Cow::Borrowed("DKIM2"),
                acceptable_hash_algorithms: Some(vec![HashAlgorithm::Sha256]),
                key_type: SignatureAlgorithm::Ed25519,
                public_key: vec![],
                is_email: false,
                flags: TxtFlags {
                    test: true,
                    strict: false,
                },
            },
            // Hand-written exotic example
            TxtRecord::parse(
                "v= DKIM2 ; k= ed25519 ; h= sha256 : sha3 ; \
                 t= y : x ; s = snail-mail ; foo=bar; p=",
            )
            .unwrap(),
        );
    }
}
