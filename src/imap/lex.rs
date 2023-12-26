//-
// Copyright (c) 2020, 2023, Jason Lingle
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

//! Utilities for *writing* values under IMAP's "lexical rules".
//!
//! This is write-only since IMAP's lexical syntax is not separable from its
//! grammar.
//!
//! The code here is primarily responsible for two things:
//!
//! - Deciding which form to use to encode certain strings (i.e. atom, quoted
//!   string, or literal).
//!
//! - Various repair strategies for dealing with non-ASCII or binary data where
//!   the protocol doesn't allow it.
//!
//! # Encoding Decisions
//!
//! We're generally pretty conservative here.
//!
//! Given the choice between encoding a string as an atom-like value or some
//! other form, we only use atom if all characters are in the set
//! `a-zA-Z0-9?=+/_.-` (this set is specifically chosen to also include encoded
//! words) and the string is not "NIL".
//!
//! Given the choice between encoding a string as a quoted string or a literal,
//! we only choose the quoted string if it only contains characters other than
//! controls, backslash, double-quote, is less than 100 bytes long, and if the
//! client is not Unicode-aware, non-ASCII characters.
//!
//! # Repair strategies
//!
//! IMAP has many defects in which it arbitrarily makes it impossible to send
//! certain byte ranges.
//!
//! 1. Parsed strings containing Unicode. If the client is Unicode-aware, we
//!    just send the actual data. For other clients, we either use encoded
//!    words to represent the text (if allowed) or censor the illegal bytes (in
//!    the case of things like email addresses that may not contain encoded
//!    words).
//!
//! 2. Mailbox names. RFC 3501 specifies modified UTF-7 here, which is exactly
//!    what we do for non-Unicode-aware clients. Unicode-aware clients get the
//!    true mailbox names.
//!
//! 3. 8-bit MIME. RFC 3501 does not consider the possibility of 8-bit
//!    characters in MIME headers since that did not become a thing until 2007.
//!    RFC 6855 (`UTF8=ACCEPT` extension) would have us in one way or another
//!    downgrade the headers, which invalidates cryptographic signatures. In
//!    reality, even most clients that don't use `UTF8=ACCEPT` deal with 8-bit
//!    data in the MIME headers without issue, so we consider violating RFC
//!    6855 to be a far lesser sin than corrupting the user's mail.
//!
//! 4. Binary data, i.e., the NUL character. For reasons that are unclear, RFC
//!    3501 forbids the NUL byte to occur in literals. (Strangely, it
//!    describes `binary` as a valid Content-Transfer-Encoding and requires
//!    that the actual transfer encoding match what is declared, so it's not
//!    like the 8-bit MIME thing where the case simply wasn't a possibility in
//!    2003.) The standards imply that _someone_ should take it upon themselves
//!    to eliminate the binary sections. Our approach here is similar to that
//!    for 8-bit MIME: Silently changing the data constitutes corruption of the
//!    user's mail and is a greater sin than standards violation. If the client
//!    sees a section with `Content-Transfer-Encoding: binary`, it had better
//!    be prepared to deal with binary data if it requests that section. (It's
//!    also unclear how one would go about writing an IMAP client that would
//!    choke on the NUL character --- you'd have to be storing the binary data
//!    in a C string or something else absurd.)
//!
//! One fortunate thing about all this is that we don't need to worry about the
//! repair strategies when reading stuff from the client, i.e., our parser does
//! not need to know whether the client is Unicode-aware. Free-form strings
//! passed in by the client always either have an explicit charset or a
//! standard repair strategy, so we just follow the standards there.

use std::borrow::Cow;
use std::io::{self, Read, Write};
use std::mem;

use chrono::prelude::*;

use super::literal_source::LiteralSource;
use super::mailbox_name::MailboxName;
use crate::account::model::Flag;
use crate::mime::utf7;

#[derive(Clone, Copy, Debug)]
pub struct LexWriter<W> {
    writer: W,
    unicode_aware: bool,
    literal_plus: bool,
}

impl<W: LexOutput> LexWriter<W> {
    pub fn new(writer: W, unicode_aware: bool, literal_plus: bool) -> Self {
        LexWriter {
            writer,
            unicode_aware,
            literal_plus,
        }
    }

    #[cfg(test)]
    pub fn into_inner(self) -> W {
        self.writer
    }

    pub fn verbatim(&mut self, s: &str) -> io::Result<()> {
        self.writer.write_all(s.as_bytes())?;
        Ok(())
    }

    pub fn nil(&mut self) -> io::Result<()> {
        self.verbatim("NIL")
    }

    pub fn censored_astring(&mut self, s: &str) -> io::Result<()> {
        self.astring(&self.censor(s))
    }

    pub fn unicode_astring(&mut self, s: &str) -> io::Result<()> {
        self.astring(s)
    }

    pub fn censored_nstring(
        &mut self,
        s: &Option<impl AsRef<str>>,
    ) -> io::Result<()> {
        match s.as_ref() {
            None => self.nil(),
            Some(s) => self.string(&self.censor(s.as_ref())),
        }
    }

    pub fn encoded_nstring(
        &mut self,
        s: &Option<impl AsRef<str>>,
    ) -> io::Result<()> {
        match s.as_ref() {
            None => self.nil(),
            Some(s) => self.string(&self.encode(s.as_ref())),
        }
    }

    pub fn censored_string(&mut self, s: &str) -> io::Result<()> {
        self.string(&self.censor(s))
    }

    pub fn mailbox(&mut self, mn: &MailboxName<'_>) -> io::Result<()> {
        if self.is_conservative_atom(&mn.raw) {
            // Nothing to encode if it can just be an atom
            write!(self.writer, "{}", mn.raw)?;
        } else if self.unicode_aware || !mn.utf8 {
            // Nothing to encode if wire format is UTF-8 or the name is already
            // in wire format.
            self.string(&mn.raw)?;
        } else {
            // Else, we need to feed it through possible encoding.
            self.string(&utf7::IMAP.encode(&mn.raw))?;
        }

        Ok(())
    }

    pub fn literal(
        &mut self,
        use_binary_syntax: bool,
        data: impl Read + 'static,
        len: u64,
    ) -> io::Result<()> {
        write!(
            self.writer,
            "{}{{{}{}}}\r\n",
            if use_binary_syntax { "~" } else { "" },
            len,
            if !use_binary_syntax && self.literal_plus {
                "+"
            } else {
                ""
            }
        )?;
        self.writer.splice(data)?;
        Ok(())
    }

    pub fn literal_source(&mut self, ls: &mut LiteralSource) -> io::Result<()> {
        self.literal(
            ls.binary,
            mem::replace(&mut ls.data, Box::new(&[][..])),
            ls.len,
        )
    }

    pub fn flag(&mut self, flag: &Flag) -> io::Result<()> {
        write!(self.writer, "{}", flag)
    }

    pub fn date(&mut self, date: &NaiveDate) -> io::Result<()> {
        write!(self.writer, "\"{}\"", date.format("%-d-%b-%Y"))
    }

    pub fn datetime(
        &mut self,
        datetime: &DateTime<FixedOffset>,
    ) -> io::Result<()> {
        write!(
            self.writer,
            "\"{}\"",
            datetime.format("%_d-%b-%Y %H:%M:%S %z")
        )
    }

    pub fn num_u32(&mut self, value: &u32) -> io::Result<()> {
        write!(self.writer, "{}", *value)
    }

    pub fn num_u64(&mut self, value: &u64) -> io::Result<()> {
        write!(self.writer, "{}", *value)
    }

    fn astring(&mut self, s: &str) -> io::Result<()> {
        if self.is_conservative_atom(s) {
            write!(self.writer, "{}", s)?;
        } else {
            self.string(s)?;
        }

        Ok(())
    }

    fn string(&mut self, s: &str) -> io::Result<()> {
        if self.is_quotable(s) {
            write!(self.writer, "\"{}\"", s)?;
        } else {
            self.literal(
                false,
                io::Cursor::new(s.as_bytes().to_owned()),
                s.len() as u64,
            )?;
        }

        Ok(())
    }

    fn censor<'a>(&self, s: &'a str) -> Cow<'a, str> {
        if self.unicode_aware || s.is_ascii() {
            Cow::Borrowed(s)
        } else {
            Cow::Owned(s.replace(|ch| ch > '\u{7f}', "X"))
        }
    }

    fn encode<'a>(&self, s: &'a str) -> Cow<'a, str> {
        if self.unicode_aware || s.is_ascii() {
            Cow::Borrowed(s)
        } else {
            let mut total_accum = String::new();
            let mut part_accum = String::new();
            let mut first = true;
            // Copy whole characters one at a time, breaking into separate EWs
            // when they start getting too long.
            //
            // We're not allowed to split multi-byte characters, so this more
            // complex algorithm (as opposed to calling s.as_bytes.windows(40))
            // is required.
            for c in s.chars() {
                part_accum.push(c);

                // Max length of encoded word is 76.
                // =?utf-8?b??= is 12 characters, giving us space for 64
                // bytes after encoding. That comes out to 48 bytes raw. UTF-8
                // can be up to 4 bytes/char, so we could set the cut-off at
                // 45, but to be conservative, we break at anything over 40.
                if part_accum.len() > 40 {
                    encode_part(&mut total_accum, &part_accum, first);
                    part_accum.clear();
                    first = false;
                }
            }

            encode_part(&mut total_accum, &part_accum, first);
            Cow::Owned(total_accum)
        }
    }

    fn is_conservative_atom(&self, s: &str) -> bool {
        !"nil".eq_ignore_ascii_case(s)
            && !s.is_empty()
            && s.as_bytes().iter().copied().all(|b| {
                matches!(
                b,
                b'a'..=b'z'
                | b'A'..=b'Z'
                | b'0'..=b'9'
                | b'='
                | b'?'
                | b'/'
                | b'+'
                | b'_'
                | b'.'
                    | b'-')
            })
    }

    fn is_quotable(&self, s: &str) -> bool {
        s.len() < 100
            && s.as_bytes().iter().copied().all(|b| match b {
                0..=31 | 127 | b'\\' | b'"' => false,
                128..=255 => self.unicode_aware,
                _ => true,
            })
    }
}

fn encode_part(dst: &mut String, src: &str, first: bool) {
    if src.is_empty() {
        return;
    }

    if !first {
        dst.push(' ');
    }

    dst.push_str("=?utf-8?b?");
    dst.push_str(&base64::encode_config(src, base64::STANDARD_NO_PAD));
    dst.push_str("?=");
}

pub trait LexOutput: Write {
    /// Splice `data` into the stream at the current position.
    ///
    /// `data` is potentially very large. In async contexts, it is not read
    /// within this call, but is stored with the current position so that it
    /// can be written when needed.
    fn splice<R: Read + 'static>(&mut self, data: R) -> io::Result<()>;
}

/// Adapts a synchronous writer to perform `splice` with `io::copy`.
#[derive(Clone, Copy, Debug)]
pub struct InlineSplice<W>(pub W);

impl<W: Write> Write for InlineSplice<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.0.write(data)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl<W: Write> LexOutput for InlineSplice<W> {
    fn splice<R: Read + 'static>(&mut self, mut data: R) -> io::Result<()> {
        io::copy(&mut data, self)?;
        Ok(())
    }
}

impl LexOutput for Vec<u8> {
    fn splice<R: Read + 'static>(&mut self, mut data: R) -> io::Result<()> {
        io::copy(&mut data, self)?;
        Ok(())
    }
}

impl LexOutput for &mut Vec<u8> {
    fn splice<R: Read + 'static>(&mut self, mut data: R) -> io::Result<()> {
        io::copy(&mut data, self)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::mime::encoded_word;

    fn to_str(l: LexWriter<Vec<u8>>) -> String {
        String::from_utf8(l.into_inner()).unwrap()
    }

    #[test]
    fn nil() {
        let mut l = LexWriter::new(Vec::<u8>::new(), true, false);
        l.nil().unwrap();
        assert_eq!("NIL", to_str(l));
    }

    #[test]
    fn censored_astring_non_unicode() {
        let mut l = LexWriter::new(Vec::<u8>::new(), false, false);
        l.censored_astring("foo").unwrap();
        l.verbatim(" ").unwrap();
        l.censored_astring("nil").unwrap();
        l.verbatim(" ").unwrap();
        l.censored_astring("NIL").unwrap();
        l.verbatim(" ").unwrap();
        l.censored_astring("foo bar").unwrap();
        l.verbatim(" ").unwrap();
        l.censored_astring("foo\\ bar").unwrap();
        l.verbatim(" ").unwrap();
        l.censored_astring("föö").unwrap();

        assert_eq!(
            "foo \"nil\" \"NIL\" \"foo bar\" {8}\r\nfoo\\ bar fXX",
            to_str(l),
        );
    }

    #[test]
    fn censored_astring_unicode() {
        let mut l = LexWriter::new(Vec::<u8>::new(), true, false);
        l.censored_astring("foo").unwrap();
        l.verbatim(" ").unwrap();
        l.censored_astring("nil").unwrap();
        l.verbatim(" ").unwrap();
        l.censored_astring("NIL").unwrap();
        l.verbatim(" ").unwrap();
        l.censored_astring("foo bar").unwrap();
        l.verbatim(" ").unwrap();
        l.censored_astring("foo\\ bar").unwrap();
        l.verbatim(" ").unwrap();
        l.censored_astring("föö").unwrap();

        assert_eq!(
            "foo \"nil\" \"NIL\" \"foo bar\" {8}\r\nfoo\\ bar \"föö\"",
            to_str(l),
        );
    }

    #[test]
    fn mailbox_non_unicode() {
        let mut l = LexWriter::new(Vec::<u8>::new(), false, false);
        l.mailbox(&MailboxName::of_utf8(Cow::Borrowed("INBOX")))
            .unwrap();
        l.verbatim(" ").unwrap();
        l.mailbox(&MailboxName::of_utf8(Cow::Borrowed("Lost & Found")))
            .unwrap();
        l.verbatim(" ").unwrap();
        l.mailbox(&MailboxName::of_utf8(Cow::Borrowed(
            "~peter/mail/台北/日本語",
        )))
        .unwrap();

        assert_eq!(
            "INBOX \"Lost &- Found\" \"~peter/mail/&U,BTFw-/&ZeVnLIqe-\"",
            to_str(l)
        );
    }

    #[test]
    fn mailbox_unicode() {
        let mut l = LexWriter::new(Vec::<u8>::new(), true, false);
        l.mailbox(&MailboxName::of_utf8(Cow::Borrowed("INBOX")))
            .unwrap();
        l.verbatim(" ").unwrap();
        l.mailbox(&MailboxName::of_utf8(Cow::Borrowed("Lost & Found")))
            .unwrap();
        l.verbatim(" ").unwrap();
        l.mailbox(&MailboxName::of_utf8(Cow::Borrowed(
            "~peter/mail/台北/日本語",
        )))
        .unwrap();

        assert_eq!(
            "INBOX \"Lost & Found\" \"~peter/mail/台北/日本語\"",
            to_str(l)
        );
    }

    #[test]
    fn flags_non_unicode() {
        let mut l = LexWriter::new(Vec::<u8>::new(), false, false);

        l.flag(&Flag::Flagged).unwrap();
        l.verbatim(" ").unwrap();
        l.flag(&Flag::Keyword("foo".to_owned())).unwrap();

        assert_eq!("\\Flagged foo", to_str(l));
    }

    #[test]
    fn flags_unicode() {
        let mut l = LexWriter::new(Vec::<u8>::new(), true, false);

        l.flag(&Flag::Flagged).unwrap();
        l.verbatim(" ").unwrap();
        l.flag(&Flag::Keyword("foo".to_owned())).unwrap();

        assert_eq!("\\Flagged foo", to_str(l));
    }

    #[test]
    fn encoded_words_are_decodable() {
        let mut l = LexWriter::new(Vec::<u8>::new(), false, false);
        l.encoded_nstring(&Some("föö")).unwrap();
        assert_eq!(
            Some("föö".to_owned()),
            encoded_word::ew_decode(to_str(l).trim_matches('"'))
        );
    }
}
