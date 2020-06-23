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

use crate::mime::encoded_word;

fn to_utf8(cow: Cow<[u8]>) -> Cow<str> {
    match cow {
        Cow::Owned(owned) => Cow::Owned(match String::from_utf8(owned) {
            Ok(s) => s,
            Err(e) => String::from_utf8_lossy(&e.as_bytes()).into_owned(),
        }),
        Cow::Borrowed(borrowed) => String::from_utf8_lossy(borrowed),
    }
}

pub fn decode_atom(atom: Cow<[u8]>) -> String {
    // TODO Had intended to do encoded_word handling here, but that's not sound
    // --- it's only allowed for RFC 822 "word" items and unstructured text.
    to_utf8(atom).into_owned()
}

pub fn decode_phrase(phrase: Vec<Cow<[u8]>>) -> String {
    decode_sequence(phrase, b' ')
}

pub fn decode_dotted(phrase: Vec<Cow<[u8]>>) -> String {
    decode_sequence(phrase, b'.')
}

fn decode_sequence(phrase: Vec<Cow<[u8]>>, delim: u8) -> String {
    if 1 == phrase.len() {
        decode_atom(phrase.into_iter().next().unwrap())
    } else {
        let mut accum = Vec::new();
        let mut first = true;
        for word in phrase {
            if !first {
                accum.push(delim);
            }
            first = false;

            match word {
                Cow::Owned(mut owned) => accum.append(&mut owned),
                Cow::Borrowed(borrowed) => accum.extend_from_slice(borrowed),
            }
        }

        to_utf8(Cow::Owned(accum)).into_owned()
    }
}

pub fn decode_unstructured(mut s: Cow<[u8]>) -> String {
    // Remove folding
    if memchr::memchr(b'\n', &s).is_some() {
        let mut unfolded = Vec::with_capacity(s.len());
        let mut is_unfolding = false;
        for ch in s.iter().copied() {
            if is_unfolding {
                if b' ' == ch || b'\t' == ch || b'\r' == ch || b'\n' == ch {
                    continue;
                } else {
                    is_unfolding = false;
                    unfolded.push(ch);
                }
            } else {
                if b'\r' == ch || b'\n' == ch {
                    unfolded.push(b' ');
                    is_unfolding = true;
                } else {
                    unfolded.push(ch);
                }
            }
        }

        *s.to_mut() = unfolded;
    }

    let s = to_utf8(s);

    encoded_word::ew_decode_unstructured(s.trim()).into_owned()
}
