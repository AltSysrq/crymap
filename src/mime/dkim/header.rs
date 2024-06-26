use std::borrow::Cow;
use std::fmt;
use std::ops::Range;

use chrono::prelude::*;

use super::Canonicalisation;
use crate::support::chronox::*;

pub const HEADER_NAME: &str = "DKIM-Signature";
pub(super) const FWS: &[char] = &[' ', '\t', '\r', '\n'];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum HashAlgorithm {
    /// RFC 6376, obsoleted by RFC 8301
    Sha1,
    /// RFC 6376
    Sha256,
}

impl HashAlgorithm {
    pub fn message_digest(self) -> openssl::hash::MessageDigest {
        match self {
            Self::Sha1 => openssl::hash::MessageDigest::sha1(),
            Self::Sha256 => openssl::hash::MessageDigest::sha256(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// RFC 6376
    Rsa,
    /// RFC 8463
    Ed25519,
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
    /// The `i` field, still in punycode and its not-quite-email-address
    /// format.
    pub auid: Option<Cow<'a, str>>,
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

    /// If this `Header` has a raw representation, returns it. Otherwise, it
    /// generates the one Crymap uses when signing.
    pub fn raw(&self) -> Cow<'_, RawHeader<'a>> {
        use std::fmt::Write as _;

        const MAX_LINE: usize = 76;

        fn reserve_space(
            dst: &mut String,
            line_length: &mut usize,
            required: usize,
        ) {
            if *line_length + required > MAX_LINE {
                dst.push_str("\r\n ");
                *line_length = 1;
            }

            *line_length += required;
        }

        fn append_field(
            dst: &mut String,
            line_length: &mut usize,
            tag: &str,
            value: &str,
        ) {
            let size = tag.len() + value.len() + 2;
            reserve_space(dst, line_length, size);
            let _ = write!(dst, "{}={};", tag, value);
        }

        fn append_base64(
            dst: &mut String,
            line_length: &mut usize,
            tag: &str,
            mut data: &[u8],
            last: bool,
        ) -> usize {
            reserve_space(dst, line_length, tag.len() + 1);
            let _ = write!(dst, "{}=", tag);
            let start = dst.len();
            while !data.is_empty() {
                let mut avail = MAX_LINE.saturating_sub(*line_length) / 4 * 3;
                if 0 == avail {
                    dst.push_str("\r\n ");
                    *line_length = 1;
                    avail = (MAX_LINE - 1) / 4 * 3;
                }

                let len = avail.min(data.len());
                let old_str_len = dst.len();
                // This only produces padding if len is not a multiple of 3,
                // which only happens when we hit the end of `data`.
                base64::encode_config_buf(&data[..len], base64::STANDARD, dst);

                data = &data[len..];
                *line_length += dst.len() - old_str_len;
            }

            if !last {
                reserve_space(dst, line_length, 1);
                dst.push(';');
            }

            start
        }

        if let Some(ref raw) = self.raw {
            return Cow::Borrowed(raw);
        }

        let mut text = String::with_capacity(256);
        let _ = write!(
            text,
            "{HEADER_NAME}: v={version};a={algorithm};c={canon};",
            version = self.version,
            algorithm = self.algorithm,
            canon = self.canonicalisation,
        );
        let mut line_length = text.len();
        append_field(&mut text, &mut line_length, "d", &self.sdid);
        if let Some(ref auid) = self.auid {
            // This isn't strictly correct, as auid could contain characters
            // that need QP encoding. However, production use does not generate
            // this field, so this is good enough for testing. (And even if the
            // production use case changes, there's never any actual reason to
            // put something to the left of the '@', much less anything that
            // needs QP.)
            append_field(&mut text, &mut line_length, "i", auid);
        }
        reserve_space(&mut text, &mut line_length, 2);
        text.push_str("h=");
        for (ix, h) in self.signed_headers.iter().enumerate() {
            reserve_space(&mut text, &mut line_length, h.len() + 1);
            text.push_str(h);
            text.push(if ix + 1 == self.signed_headers.len() {
                ';'
            } else {
                ':'
            });
        }
        if self.signed_headers.is_empty() {
            // Shouldn't happen, but at least make something syntactically
            // valid.
            text.push(';');
            line_length += 1;
        }
        if let Some(body_length) = self.body_length {
            append_field(
                &mut text,
                &mut line_length,
                "l",
                &body_length.to_string(),
            );
        }
        append_field(&mut text, &mut line_length, "s", &self.selector);
        if let Some(ts) = self.signature_timestamp {
            append_field(
                &mut text,
                &mut line_length,
                "t",
                &ts.timestamp().to_string(),
            );
        }
        if let Some(ts) = self.signature_expiration {
            append_field(
                &mut text,
                &mut line_length,
                "x",
                &ts.timestamp().to_string(),
            );
        }
        append_base64(
            &mut text,
            &mut line_length,
            "bh",
            &self.body_hash,
            false,
        );
        let b_start = append_base64(
            &mut text,
            &mut line_length,
            "b",
            &self.signature,
            true,
        );

        Cow::Owned(RawHeader {
            b: b_start..text.len(),
            text: Cow::Owned(text),
        })
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
        let mut auid = None::<Cow<'a, str>>;
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
                "i" => set_opt(k, &mut auid, decode_qp(v))?,
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
            auid,
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

impl fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Rsa => write!(f, "rsa"),
            Self::Ed25519 => write!(f, "ed25519"),
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

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Sha1 => write!(f, "sha1"),
            Self::Sha256 => write!(f, "sha256"),
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}-{}", self.signature, self.hash)
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
    use super::super::{
        test_domain_keys, BodyCanonicalisation, HeaderCanonicalisation,
    };
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
                signature: include_bytes!("test-data/amazon-b.dat").to_vec(),
                body_hash: include_bytes!("test-data/amazon-bh.dat").to_vec(),
                canonicalisation: Canonicalisation {
                    header: HeaderCanonicalisation::Relaxed,
                    body: BodyCanonicalisation::Simple,
                },
                sdid: Cow::Borrowed("amazon.com"),
                auid: None,
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
                signature: include_bytes!("test-data/google-b.dat").to_vec(),
                body_hash: include_bytes!("test-data/google-bh.dat").to_vec(),
                canonicalisation: Canonicalisation {
                    header: HeaderCanonicalisation::Relaxed,
                    body: BodyCanonicalisation::Relaxed,
                },
                sdid: Cow::Borrowed("gmail.com"),
                auid: None,
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
                signature: include_bytes!("test-data/yahoo-b.dat").to_vec(),
                body_hash: include_bytes!("test-data/yahoo-bh.dat").to_vec(),
                canonicalisation: Canonicalisation {
                    header: HeaderCanonicalisation::Relaxed,
                    body: BodyCanonicalisation::Relaxed,
                },
                sdid: Cow::Borrowed("yahoo.com"),
                auid: None,
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
                signature: include_bytes!("test-data/dkimproxy-b.dat").to_vec(),
                body_hash: include_bytes!("test-data/dkimproxy-bh.dat")
                    .to_vec(),
                canonicalisation: Canonicalisation {
                    header: HeaderCanonicalisation::Relaxed,
                    body: BodyCanonicalisation::Simple,
                },
                sdid: Cow::Borrowed("lin.gl"),
                auid: None,
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
                auid: Some(Cow::Borrowed(
                    "\"Jöhn Smïth\"@subdomain.example.com"
                )),
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
\t; i==22J=C3=B6hn=20Sm=C3=A
Fth=22@subdomain.example.com;
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
                    "test-data/selector1._domainkey.lin.gl.dat"
                )
                .to_vec(),
                is_email: true,
                flags: TxtFlags {
                    test: false,
                    strict: true,
                },
            },
            TxtRecord::parse(test_domain_keys::SELECTOR1_LIN_GL).unwrap(),
        );
        assert_eq!(
            TxtRecord {
                version: Cow::Borrowed("DKIM1"),
                acceptable_hash_algorithms: None,
                key_type: SignatureAlgorithm::Rsa,
                public_key: include_bytes!(
                    "test-data/s2048._domainkey.yahoo.com.dat"
                )
                .to_vec(),
                is_email: true,
                flags: TxtFlags::default(),
            },
            TxtRecord::parse(test_domain_keys::S2048_YAHOO_COM).unwrap(),
        );
        assert_eq!(
            TxtRecord {
                version: Cow::Borrowed("DKIM1"),
                acceptable_hash_algorithms: None,
                key_type: SignatureAlgorithm::Rsa,
                public_key: include_bytes!(
                    "test-data/\
                     yg4mwqurec7fkhzutopddd3ytuaqrvuz.\
                     _domainkey.amazon.com.dat",
                )
                .to_vec(),
                is_email: true,
                flags: TxtFlags::default(),
            },
            TxtRecord::parse(test_domain_keys::YG4_AMAZON_COM).unwrap(),
        );
        assert_eq!(
            TxtRecord {
                version: Cow::Borrowed("DKIM1"),
                acceptable_hash_algorithms: None,
                key_type: SignatureAlgorithm::Rsa,
                public_key: include_bytes!(
                    "test-data/20230601._domainkey.gmail.com.dat",
                )
                .to_vec(),
                is_email: true,
                flags: TxtFlags::default(),
            },
            TxtRecord::parse(test_domain_keys::K20230601_GMAIL_COM).unwrap(),
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
