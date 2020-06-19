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

use encoding_rs::*;
use lazy_static::lazy_static;
use regex::Regex;

use super::quoted_printable::qp_decode;
use super::utf7;

lazy_static! {
    static ref ENCODED_WORD: Regex =
        Regex::new(r"^=\?([!->@-~]*)\?([!->@-~]*)\?([!->@-~]*)\?=$").unwrap();
}

/// Test if `word` (in its entirety) is an RFC 2047 "encoded word".
///
/// If it is, decode it and return its decoded value.
///
/// Returns `None` if it is not an encoded word or if it could not be decoded.
///
/// This returns an `Option` instead of returning the input unchanged in cases
/// where it is not an encoded word because the distinction is significant:
/// whitespace is supposed to be deleted between adjacent encoded words, but
/// must be left alone in all other cases.
pub fn ew_decode(word: &str) -> Option<Cow<str>> {
    // RFC 2047 specifies the maximum length of an encoded word as 75
    // characters. However, there are agents that produce longer encoded words,
    // and Thunderbird at least will interpret them. For example, one email I
    // have received has the subject (name of the innocent removed, wrapped for
    // clarity):
    //
    // =?windows-1252?Q?The_Jade_Scorpion_Commands_You_To_Meet_With_Colorado_
    // School_Of_Mines_Prof._Xxxxx_X._Xxxxx_from_The_United_States?=
    //
    // The main motivation for the length limit is to limit look-ahead, which
    // isn't really a problem for us, so we follow Thunderbird's lead and allow
    // arbitrary-length encoded words.
    //
    // (For those curious about the subject, it was part of a spam campaign by
    // a J.P. Morgan, who, among other things, fancies himself the president of
    // the solar system in 2210.)

    let captures = ENCODED_WORD.captures(word)?;

    let charset = captures.get(1).unwrap().as_str();
    let transfer_encoding = captures.get(2).unwrap().as_str();
    let mut content =
        Cow::Borrowed(captures.get(3).unwrap().as_str().as_bytes());

    // _ in the content (before transfer decoding) stands for ASCII space
    // regardless of charset
    if content.contains(&b'_') {
        for b in content.to_mut() {
            if *b == b'_' {
                *b = b' ';
            }
        }
    }

    // These match blocks let us keep borrowing as much as possible. Basically,
    // if the cow becomes owned at any stage, it needs to stay owned the whole
    // way through so that the borrowed case only ever borrows from `word`.
    let content = match content {
        Cow::Owned(content) => decode_xfer(transfer_encoding, &content)
            .map(Cow::into_owned)
            .map(Cow::Owned),
        Cow::Borrowed(content) => decode_xfer(transfer_encoding, content),
    }?;

    match content {
        Cow::Owned(content) => decode_charset(charset, &content)
            .map(Cow::into_owned)
            .map(Cow::Owned),
        Cow::Borrowed(content) => decode_charset(charset, content),
    }
}

fn decode_xfer<'a>(xfer: &str, content: &'a [u8]) -> Option<Cow<'a, [u8]>> {
    match xfer {
        "q" | "Q" => Some(qp_decode(&content).0),
        "b" | "B" => base64::decode(&content).ok().map(Cow::Owned),
        _ => None,
    }
}

fn decode_charset<'a>(
    charset: &str,
    content: &'a [u8],
) -> Option<Cow<'a, str>> {
    // encoding-rs doesn't do UTF-7...
    if "utf-7".eq_ignore_ascii_case(charset) {
        Some(utf7::STD.decode(str::from_utf8(&content).ok()?))
    } else {
        // ... but it does everything else (at least everything else that
        // Thunderbird supports)
        Some(
            Encoding::for_label_no_replacement(charset.as_bytes())?
                .decode_with_bom_removal(&content)
                .0,
        )
    }
}

#[cfg(test)]
mod test {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn test_ew_decode() {
        assert_eq!(None, ew_decode("hello world"));

        // Examples from RFC 2047
        assert_eq!(
            "Keith Moore",
            ew_decode("=?US-ASCII?Q?Keith_Moore?=").unwrap()
        );
        assert_eq!(
            "Keld Jørn Simonsen",
            ew_decode("=?ISO-8859-1?Q?Keld_J=F8rn_Simonsen?=").unwrap()
        );
        assert_eq!("André", ew_decode("=?ISO-8859-1?Q?Andr=E9?=").unwrap());
        assert_eq!(
            "If you can read this yo",
            ew_decode("=?ISO-8859-1?B?SWYgeW91IGNhbiByZWFkIHRoaXMgeW8=?=")
                .unwrap()
        );
        assert_eq!(
            "u understand the example.",
            ew_decode("=?ISO-8859-2?B?dSB1bmRlcnN0YW5kIHRoZSBleGFtcGxlLg==?=")
                .unwrap()
        );
        assert_eq!(
            "םולש ןב ילטפנ",
            ew_decode("=?iso-8859-8?b?7eXs+SDv4SDp7Oj08A==?=").unwrap()
        );
    }

    proptest! {
        #[test]
        fn ew_decode_never_panics(s in r"=\?.*\?.*\?.*\?=") {
            ew_decode(&s);
        }
    }
}
