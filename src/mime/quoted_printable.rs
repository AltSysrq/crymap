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

/// Decodes quoted-printable encoding, as described by RFC 2045.
///
/// Encoded bytes and soft line endings are both handled, the latter by
/// discarding. UNIX line endings are handled as well as DOS line endings.
///
/// This never fails. Invalid sequences are passed through untransformed.
/// Certain restrictions, such as not having trailing whitespace on a line, are
/// not enforced, and are passed through. 8-bit characters are passed through,
/// including invalid UTF-8.
///
/// Returns the decoded text, as well as a possible "dangling" slice, which
/// represents a QP escape sequence that is not yet complete.
pub fn qp_decode(s: &[u8]) -> (Cow<[u8]>, &[u8]) {
    let mut transformed = Vec::new();
    let mut dangling: Option<&[u8]> = None;

    let mut split = s.split(|&b| b'=' == b);
    let mut prefix = split.next();

    for element in split {
        if let Some(prefix) = prefix.take() {
            transformed.extend_from_slice(prefix);
        }

        if let Some(dangling) = dangling.take() {
            transformed.push(b'=');
            transformed.extend_from_slice(dangling);
        }

        if element.is_empty() {
            dangling = Some(element);
            continue;
        }

        if b'\n' == element[0] {
            // Soft line break with UNIX ending, discard
            transformed.extend_from_slice(&element[1..]);
            continue;
        }

        // All other = sequences are two bytes long
        if element.len() < 2 {
            dangling = Some(element);
            continue;
        }

        let encoded = &element[..2];
        let tail = &element[2..];
        if b"\r\n" == encoded {
            // Soft line break with DOS ending, discard
            transformed.extend_from_slice(tail);
            continue;
        }

        if let Some(ch) = str::from_utf8(encoded)
            .ok()
            .and_then(|e| u8::from_str_radix(e, 16).ok())
        {
            // Valid encoded byte
            transformed.push(ch);
            transformed.extend_from_slice(tail);
        } else {
            // Invalid encoding, just push the whole string verbatim
            transformed.push(b'=');
            transformed.extend_from_slice(element);
        }
    }

    if transformed.is_empty() {
        (Cow::Borrowed(s), &[])
    } else {
        (
            Cow::Owned(transformed),
            dangling.map(|d| &s[s.len() - d.len() - 1..]).unwrap_or(&[]),
        )
    }
}

#[cfg(test)]
mod test {
    use proptest::prelude::*;

    use super::*;

    fn assert_qp(expected: &[u8], expected_dangling: &[u8], input: &[u8]) {
        let (actual, actual_dangling) = qp_decode(input);
        assert_eq!(expected, &actual[..]);
        assert_eq!(expected_dangling, actual_dangling);
    }

    #[test]
    fn test_qp_decode() {
        assert_qp(b"hello world", b"", b"hello world");
        assert_qp(b"\xabfoo", b"", b"=ABfoo");
        assert_qp(b"fo\xabo", b"", b"fo=ABo");
        assert_qp(b"foo\xab", b"", b"foo=AB");

        assert_qp(b"foo\xab\xcd", b"", b"foo=AB=CD");
        assert_qp(b"foo\xabbar\xcd", b"", b"foo=ABbar=CD");

        assert_qp(b"foo", b"", b"foo=\n");
        assert_qp(b"foobar", b"", b"foo=\nbar");
        assert_qp(b"foo", b"", b"foo=\r\n");
        assert_qp(b"foobar", b"", b"foo=\r\nbar");

        assert_qp(b"foo=()bar", b"", b"foo=()bar");
        assert_qp(b"foo=\xabbar", b"", b"foo==ABbar");
        assert_qp(b"foo=A\xabbar", b"", b"foo=A=ABbar");
        assert_qp("foo=ゑbar".as_bytes(), b"", "foo=ゑbar".as_bytes());
        assert_qp(b"foo=\x80\x80bar", b"", b"foo=\x80\x80bar");

        assert_qp(b"foo", b"=", b"foo=");
        assert_qp(b"foo", b"=A", b"foo=A");
        assert_qp(b"foo", b"=\r", b"foo=\r");
    }

    proptest! {
        #[test]
        fn qp_decode_never_fails_for_str(s in ".*") {
            qp_decode(s.as_bytes());
        }

        #[test]
        fn qp_decode_never_fails_for_bytes(
            s in prop::collection::vec(prop::num::u8::ANY, 0..20)
        ) {
            qp_decode(&s);
        }
    }
}
