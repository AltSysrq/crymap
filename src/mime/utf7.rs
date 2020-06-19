//-
// Copyright (c) 2020, Jason Lingle
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
use std::str;

/// A configuration of UTF-7.
#[derive(Clone, Copy, Debug)]
pub struct Utf7 {
    shift_in: u8,
    shift_in_escaped: &'static str,
    base64: base64::Config,
    ch_63: u8,
    indirect: &'static [u8],
}

/// Standard UTF-7, as set by RFC 2152.
pub const STD: Utf7 = Utf7 {
    shift_in: b'+',
    shift_in_escaped: "+-",
    base64: base64::STANDARD_NO_PAD,
    ch_63: b'/',
    indirect: b"~\\+",
};

/// IMAP's "modified UTF-7", as set by RFC 3501
pub const IMAP: Utf7 = Utf7 {
    shift_in: b'&',
    shift_in_escaped: "&-",
    base64: base64::IMAP_MUTF7,
    ch_63: b',',
    indirect: b"&",
};

impl Utf7 {
    /// Decode the given string from UTF-7.
    ///
    /// This assumes that the string is a complete unit. This is suitable for
    /// IMAP strings and the transfer encoding for UTF-7 required by RFC 2152,
    /// where the transcoding can be done on a line-for-line basis.
    ///
    /// Decoding is extremely permissive. 8-bit characters and other non-direct
    /// characters are passed through. Direct characters which should not be
    /// encoded are still accepted in their encoded form. Unnecessary shift
    /// sequences are permitted. The shift-out character is not required at the
    /// end or before a non-base-64 character.
    ///
    /// Note that RFC 3501 discourages this permissiveness in mailbox names,
    /// but does not outright forbid it. Since we ultimately store all mailbox
    /// names as UTF-8 and re-encode out the door, thee distinction is mostly
    /// moot.
    pub fn decode<'a>(&self, s: &'a str) -> Cow<'a, str> {
        let bytes = s.as_bytes();
        let mut transformed = String::new();
        let mut utf16 = Vec::new();
        let mut utf16_ne = Vec::new();

        // Find delimiters where base64 encoding starts.
        //
        // We can't just use split() because the standard UTF-7 encoding can
        // include its own shift-in character in base64.
        let mut split_points = bytes
            .iter()
            .copied()
            .enumerate()
            .scan(false, |in_encoded, (ix, ch)| {
                if *in_encoded {
                    *in_encoded = self.is_base64_char(ch);
                    Some((ix, false))
                } else {
                    if self.shift_in == ch {
                        *in_encoded = true;
                        Some((ix, true))
                    } else {
                        Some((ix, false))
                    }
                }
            })
            .filter(|&(_, is_start)| is_start)
            .map(|(ix, _)| ix)
            .chain(std::iter::once(s.len()));

        let mut split_start = split_points.next().unwrap();
        let mut prefix = Some(&bytes[..split_start]);

        for split_end in split_points {
            let chunk = &bytes[split_start + 1..split_end];
            split_start = split_end;

            if let Some(prefix) = prefix.take() {
                transformed.push_str(
                    str::from_utf8(prefix).expect("Invalidated UTF-8?"),
                );
            }

            let base64_end = chunk
                .iter()
                .copied()
                .enumerate()
                .filter(|&(_, ch)| !self.is_base64_char(ch))
                .next();

            let (base64_end, unencoded_start) = match base64_end {
                None => (chunk.len(), chunk.len()),
                Some((ix, b'-')) => (ix, ix + 1),
                Some((ix, _)) => (ix, ix),
            };

            if 0 == base64_end {
                transformed.push(self.shift_in.into());
            } else {
                utf16.clear();
                if base64::decode_config_buf(
                    &chunk[..base64_end],
                    self.base64.decode_allow_trailing_bits(true),
                    &mut utf16,
                )
                .is_err()
                {
                    // Just push the whole thing un-encoded
                    transformed.push(self.shift_in.into());
                    transformed.push_str(
                        str::from_utf8(chunk).expect("Invalidated UTF-8?"),
                    );
                    continue;
                }

                utf16_ne.clear();
                utf16_ne.extend(
                    utf16
                        .chunks(2)
                        // If there's a spurious trailing byte, drop it
                        .filter(|chunk| 2 == chunk.len())
                        .map(|c| u16::from_be_bytes([c[0], c[1]])),
                );

                transformed.push_str(&String::from_utf16_lossy(&utf16_ne));
            }

            transformed.push_str(
                str::from_utf8(&chunk[unencoded_start..])
                    .expect("Invalidated UTF-8?"),
            );
        }

        if transformed.is_empty() {
            Cow::Borrowed(s)
        } else {
            Cow::Owned(transformed)
        }
    }

    /// Encode the given string into UTF-7.
    ///
    /// The encoded string is minimal (i.e., contains no unnecessary shift
    /// sequences) and normalised (never encodes a direct character and only
    /// uses the special escape sequence for the shift-in character, all
    /// encoded sequences have an explicit shift-out).
    ///
    /// Currently, this is only thoroughly tested for IMAP since that is the
    /// only context where we need to *encode* this awful encoding.
    pub fn encode<'a>(&self, s: &'a str) -> Cow<'a, str> {
        let mut transformed = String::new();

        let mut direct_start = 0;
        let mut direct_end = 0;
        for (ix, byte) in s.as_bytes().iter().copied().enumerate() {
            if self.is_direct(byte) {
                if ix != direct_end {
                    self.encode_group(
                        &mut transformed,
                        s,
                        direct_start,
                        direct_end,
                        ix,
                    );
                    direct_start = ix;
                }
                direct_end = ix + 1;
            } else if self.shift_in == byte {
                self.encode_group(
                    &mut transformed,
                    s,
                    direct_start,
                    direct_end,
                    ix,
                );
                transformed.push_str(self.shift_in_escaped);
                direct_start = ix + 1;
                direct_end = ix + 1;
            }
        }

        if transformed.is_empty() && direct_end == s.len() {
            Cow::Borrowed(s)
        } else {
            self.encode_group(
                &mut transformed,
                s,
                direct_start,
                direct_end,
                s.len(),
            );
            Cow::Owned(transformed)
        }
    }

    fn encode_group(
        &self,
        dst: &mut String,
        src: &str,
        direct_start: usize,
        direct_end: usize,
        indirect_end: usize,
    ) {
        dst.push_str(&src[direct_start..direct_end]);

        if direct_end < indirect_end {
            let mut buf =
                Vec::<u8>::with_capacity((indirect_end - direct_end) * 2);
            for unit in src[direct_end..indirect_end].encode_utf16() {
                buf.extend_from_slice(&unit.to_be_bytes());
            }

            dst.push(self.shift_in.into());
            dst.push_str(&base64::encode_config(&buf, self.base64));
            dst.push('-');
        }
    }

    fn is_direct(&self, byte: u8) -> bool {
        byte >= b' ' && byte < 0x7F && !self.indirect.contains(&byte)
    }

    fn is_base64_char(&self, ch: u8) -> bool {
        (ch >= b'a' && ch <= b'z')
            || (ch >= b'A' && ch <= b'Z')
            || (ch >= b'0' && ch <= b'9')
            || ch == b'+'
            || ch == self.ch_63
    }
}

#[cfg(test)]
mod test {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn imap_encode() {
        assert_eq!("INBOX", IMAP.encode("INBOX"));
        assert_eq!("Lost &- Found", IMAP.encode("Lost & Found"));
        // Examples from RFC 3501
        assert_eq!(
            "~peter/mail/&U,BTFw-/&ZeVnLIqe-",
            IMAP.encode("~peter/mail/台北/日本語")
        );
        assert_eq!("&Jjo-!", IMAP.encode("☺!"));
        assert_eq!("&U,BTF2XlZyyKng-", IMAP.encode("台北日本語"));
        // Misc
        assert_eq!("&AADYANwA,+AAoQCh-", IMAP.encode("\x00𐀀￠¡¡"));
    }

    #[test]
    fn imap_decode() {
        assert_eq!("INBOX", IMAP.decode("INBOX"));
        assert_eq!("Lost & Found", IMAP.decode("Lost &- Found"));
        // Examples from RFC 3501
        assert_eq!(
            "~peter/mail/台北/日本語",
            IMAP.decode("~peter/mail/&U,BTFw-/&ZeVnLIqe-")
        );
        assert_eq!("☺!", IMAP.decode("&Jjo-!"));
        assert_eq!("台北日本語", IMAP.decode("&U,BTF2XlZyyKng-"));
        // Misc
        assert_eq!("\x00𐀀￠¡¡", IMAP.decode("&AADYANwA,+AAoQCh-"));
    }

    #[test]
    fn std_encode() {
        assert_eq!("hello world", STD.encode("hello world"));
        assert_eq!(
            "+AH4-peter+AFw-lost+-found",
            STD.encode("~peter\\lost+found")
        );
        // Examples from RFC 2152
        assert_eq!("Hi Mom +Jjo-!", STD.encode("Hi Mom ☺!"));
        assert_eq!("+ZeVnLIqe-", STD.encode("日本語"));
        assert_eq!("A+ImIDkQ-.", STD.encode("A≢Α.")); // -
        assert_eq!("Item 3 is +AKM-1.", STD.encode("Item 3 is £1."));
        // Misc
        assert_eq!("+AADYANwA/+AAoQCh-", STD.encode("\x00𐀀￠¡¡"));
    }

    #[test]
    fn std_decode() {
        assert_eq!("hello world", STD.decode("hello world"));
        assert_eq!(
            "~peter\\lost+found",
            STD.decode("+AH4-peter+AFw-lost+-found")
        );
        // Examples from RFC 2152
        assert_eq!("Hi Mom ☺!", STD.decode("Hi Mom +Jjo-!"));
        assert_eq!("日本語", STD.decode("+ZeVnLIqe-"));
        assert_eq!("A≢Α.", STD.decode("A+ImIDkQ."));
        assert_eq!("Item 3 is £1.", STD.decode("Item 3 is +AKM-1."));
        // Misc
        assert_eq!("\x00𐀀￠¡¡", STD.decode("+AADYANwA/+AAoQCh-"));
    }

    #[test]
    fn decode_pathological() {
        assert_eq!("hello+", STD.decode("hello+"));
        assert_eq!("hello+.", STD.decode("hello+."));
        assert_eq!("hello+ä", STD.decode("hello+ä"));
        assert_eq!("hello~", STD.decode("hello+AH4"));
        assert_eq!("¡", IMAP.decode("&AA¡"));
    }

    proptest! {
        #[test]
        fn encoding_is_reversible(s in ".*") {
            assert_eq!(s, STD.decode(&STD.encode(&s)));
            assert_eq!(s, IMAP.decode(&IMAP.encode(&s)));
        }

        #[test]
        fn decoding_never_fails(s in ".*") {
            STD.decode(&s);
            IMAP.decode(&s);
        }
    }
}
