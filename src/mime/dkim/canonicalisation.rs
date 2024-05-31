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

use std::fmt;
use std::io::{self, Write};

use super::header::FWS;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum BodyCanonicalisation {
    /// RFC 6376
    #[default]
    Simple,
    /// RFC 6376
    Relaxed,
}

impl fmt::Display for BodyCanonicalisation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Simple => write!(f, "simple"),
            Self::Relaxed => write!(f, "relaxed"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum HeaderCanonicalisation {
    /// RFC 6376
    #[default]
    Simple,
    /// RFC 6376
    Relaxed,
}

impl fmt::Display for HeaderCanonicalisation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Simple => write!(f, "simple"),
            Self::Relaxed => write!(f, "relaxed"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Canonicalisation {
    pub header: HeaderCanonicalisation,
    pub body: BodyCanonicalisation,
}

impl fmt::Display for Canonicalisation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.header, self.body)
    }
}

impl Canonicalisation {
    pub(super) fn parse(s: &str) -> Result<Self, String> {
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

impl HeaderCanonicalisation {
    /// Canonicalise a header and feed the result into `out`.
    ///
    /// `start` and `end` combined are the full header line, excluding the line
    /// ending itself. `end` is assumed to be beyond the colon separating the
    /// header name from the header value. If `end` is non-empty, it may not
    /// begin with whitespace and start may not end with whitespace.
    ///
    /// This function does *not* write the implicit CRLF at the end of the
    /// header value itself.
    pub(super) fn write(
        self,
        mut out: impl Write,
        mut start: &str,
        end: &str,
    ) -> io::Result<()> {
        debug_assert_ne!(Some('\n'), start.chars().next_back());
        debug_assert_ne!(Some('\n'), end.chars().next_back());
        if !end.is_empty() {
            debug_assert_ne!(Some(' '), start.chars().next_back());
            debug_assert_ne!(Some('\t'), start.chars().next_back());
            debug_assert_ne!(Some(' '), end.chars().next());
            debug_assert_ne!(Some('\t'), end.chars().next());
        }

        match self {
            Self::Simple => {
                // RFC 6376 § 3.4.1
                out.write_all(start.as_bytes())?;
                out.write_all(end.as_bytes())?;
            },

            Self::Relaxed => {
                // RFC 6376 § 3.4.2

                let mut char_buf = [0u8; 4];

                // > Delete all WSP characters at the end of each unfolded
                // > header value.
                start = start.trim_matches(FWS);
                if let Some((mut header_name, header_value)) =
                    start.split_once(':')
                {
                    // > Delete any WSP characters remaining before and after
                    // > the colon separating the header field name from the
                    // > header field value. The colon separator MUST be
                    // > retained.
                    header_name = header_name.trim_matches(FWS);
                    start = header_value.trim_matches(FWS);

                    // > Convert all header field names (not the header field
                    // > values) to lowercase.
                    for chunk in header_name.split_inclusive(char::is_uppercase)
                    {
                        let mut chars = chunk.chars();
                        if let Some(last_char) = chars.next_back() {
                            if last_char.is_uppercase() {
                                out.write_all(chars.as_str().as_bytes())?;
                                let lowercase =
                                    last_char.to_lowercase().next().expect(
                                        "to_lowercase always returns \
                                         at least one option",
                                    );
                                let s = lowercase.encode_utf8(&mut char_buf);
                                out.write_all(s.as_bytes())?;

                                continue;
                            }
                        }

                        // No uppercase characters
                        out.write_all(chunk.as_bytes())?;
                    }

                    out.write_all(b":")?;
                }

                // > Unfold all header field continuation lines as described in
                // > RFC 5322; in particular, lines with terminators embedded
                // > in continued header field values (that is, CRLF sequences
                // > followed by WSP) MUST be interpreted without the CRLF.
                // > Implementations MUST NOT remove the CRLF at the end of the
                // > header field value.
                //
                // (Though note that we don't have the CRLF at the end here,
                // and add it back later.)
                //
                // > Convert all sequences of one or more WSP characters to a
                // > single SP character. WSP characters here include those
                // > before and after a line folding boundary.
                //
                // Put together, we're doing `s/[ \t\r\n]+/ /g`. We've deleted
                // the leading and trailing whitespace already, so we can just
                // split on FWS and write the non-empty words separately.
                for chunk in [start, end] {
                    // We restart the index when switching from start to end
                    // because we know that there's not supposed to be any
                    // space between the two.
                    for (ix, part) in
                        chunk.split(FWS).filter(|p| !p.is_empty()).enumerate()
                    {
                        if ix != 0 {
                            out.write_all(b" ")?;
                        }
                        out.write_all(part.as_bytes())?;
                    }
                }
            },
        }

        Ok(())
    }
}

/// Performs body canonicalisation in a streaming fashion.
///
/// The `finish` method *must* be used to write the final data.
pub struct BodyCanonicaliser<W> {
    inner: W,
    mode: BodyCanonicalisation,
    /// For `Relaxed`, set to true if there is a SP character to be written
    /// upon encountering a character other than SP, HT, CR, or LF. Upon CR or
    /// LF, this flag is cleared without emitting the space.
    holding_space: bool,
    /// The number of bytes representing CRLF pairs that have yet to be
    /// emitted. Upon encountering a byte which is not a continuation of
    /// alternating CR-LF bytes, this is flushed. At EOF, the bytes implied by
    /// this field are discarded (in lieu of the singular CRLF we implicitly
    /// add).
    crlfs: usize,
}

impl<W: Write> BodyCanonicaliser<W> {
    pub(super) fn new(inner: W, mode: BodyCanonicalisation) -> Self {
        Self {
            inner,
            mode,
            holding_space: false,
            crlfs: 0,
        }
    }

    fn crlf_buffer_next(&self) -> u8 {
        if self.crlfs % 2 == 0 {
            b'\r'
        } else {
            b'\n'
        }
    }

    pub(super) fn finish(mut self) -> io::Result<W> {
        // If crlfs is odd, we have a lone \r at the end, and therefore the
        // body doesn't end with CRLF.
        if self.crlfs % 2 != 0 {
            self.dump_crlfs()?;
        }

        // If crlfs is non-zero, those are just blank lines, which we discard
        // in both modes.

        // But in either case, we add our own final CRLF.
        self.inner.write_all(b"\r\n")?;

        Ok(self.inner)
    }

    fn dump_crlfs(&mut self) -> io::Result<()> {
        // If holding_space is true and we have line-ending data to write, the
        // space still needs to be written.
        if self.holding_space && self.crlfs == 1 {
            // This should only be reachable in the case of space followed by a
            // lone CR.
            debug_assert_eq!(1, self.crlfs);
            self.inner.write_all(b" ")?;
            self.holding_space = false;
        }

        while self.crlfs > 0 {
            static CRLFS: &[u8] = b"\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n";
            let n = self.crlfs.min(CRLFS.len());
            self.inner.write_all(&CRLFS[..n])?;
            self.crlfs -= n;
        }

        Ok(())
    }
}

impl<W: Write> Write for BodyCanonicaliser<W> {
    fn write(&mut self, src: &[u8]) -> io::Result<usize> {
        // Relevant documentation:
        //
        // Simple: RFC 6376 § 3.4.3
        // Basically, we do `s/(\r\n)*$/\r\n/` (anchored on the whole message).
        //
        // Relaxed: RFC 6376 § 3.4.4
        // First, within each line:
        //   s/[ \t]+/ /g
        //   s/[ \t]+$// (anchored on the line)
        // Then, simple's `s/(\r\n)*$/\r\n/`.
        //
        // RFC 6376 conveniently disregards BINARYMIME (RFC 1830) being a
        // possibility. Quite surprisingly, we aren't urged to convert UNIX
        // line endings to normal ones, so we can handle the concept of "line
        // ending" == "\r\n" extremely literally and hopefully end up doing the
        // same nonsensical mutation to binary data that everyone else who
        // supports BINARYMIME does.

        if src.is_empty() {
            return Ok(0);
        }

        let relaxed = BodyCanonicalisation::Relaxed == self.mode;

        // If we're just getting the start of a \r\n... sequence, start or
        // continue buffering that.
        if self.crlf_buffer_next() == src[0] || b'\r' == src[0] {
            // If we get \r but were expecting \n, the CRLF(s) so far are
            // binary data that gets passed through, and \r becomes the start
            // of a new CRLF sequence.
            if self.crlf_buffer_next() != src[0] {
                self.dump_crlfs()?;
            }

            let mut consumed = 0;
            for byte in src.iter().copied() {
                if self.crlf_buffer_next() == byte {
                    self.crlfs += 1;
                    consumed += 1;
                } else {
                    break;
                }
            }

            // *Completed* line endings inherently clear the holding_space
            // marker (i.e. we drop the whitespace at the end of the line being
            // terminated). A lone \r is not a complete line ending, so it
            // doesn't clear that flag.
            if self.crlfs >= 2 {
                self.holding_space = false;
            }

            return Ok(consumed);
        }

        // In relaxed mode, if the next bytes are HT or SP, consume all the
        // following whitespace characters and set holding_space=true.
        if relaxed && matches!(src[0], b' ' | b'\t') {
            // If we have an odd number of CRLF characters, the final CR is
            // binary data and not part of a line ending, so the CRLF chain is
            // not subject to collapsing.
            if self.crlfs % 2 != 0 {
                // We only get here for the first of several consecutive
                // whitespace characters, but holding_space will be true here
                // if there was space before the partial CRLF sequence.
                // dump_crlfs() will take care of the space character in that
                // case.
                self.dump_crlfs()?;
            }

            self.holding_space = true;
            let consumed = src
                .iter()
                .copied()
                .take_while(|&c| matches!(c, b' ' | b'\t'))
                .count();
            return Ok(consumed);
        }

        // We have a byte which is not the continuation of the final \r\n...
        // sequence, so dump any remaining \r\n bytes.
        self.dump_crlfs()?;

        // We also know the new byte isn't whitespace (or we're not in relaxed
        // mode), so if we're holding a space, emit it now.
        if self.holding_space {
            self.inner.write_all(b" ")?;
            self.holding_space = false;
        }

        // Write all the non-special characters we can.
        let max = src
            .iter()
            .copied()
            .take_while(|&c| match c {
                // Only \r is the start of a line ending. \n is regular binary
                // data unless it comes immediately after \r.
                b'\r' => false,
                b' ' | b'\t' => !relaxed,
                _ => true,
            })
            .count()
            .min(1);
        self.inner.write(&src[..max])
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn simple_header_canonicalisation() {
        let mut out = Vec::new();
        let simple = HeaderCanonicalisation::Simple;

        // RFC 6376 § 3.4.5
        simple.write(&mut out, "A: X", "").unwrap();
        simple.write(&mut out, "B : Y\t\r\n\tZ  ", "").unwrap();
        // Other tests
        simple.write(&mut out, "Reply-To: FoO@bar.com", "").unwrap();
        simple
            .write(&mut out, "DKIM-Signature: foo=bar;b=", ";x  =y")
            .unwrap();
        simple.write(&mut out, "Ü無: Ü無", "").unwrap();

        assert_eq!(
            "A: X\
             B : Y\t\r\n\tZ  \
             Reply-To: FoO@bar.com\
             DKIM-Signature: foo=bar;b=;x  =y\
             Ü無: Ü無",
            String::from_utf8(out).unwrap(),
        );
    }

    #[test]
    fn relaxed_header_canonicalisation() {
        let mut out = Vec::new();
        let relaxed = HeaderCanonicalisation::Relaxed;

        // RFC 6376 § 3.4.5
        relaxed.write(&mut out, "A: X", "").unwrap();
        relaxed.write(&mut out, "B : Y\t\r\n\tZ  ", "").unwrap();
        // Other tests
        relaxed
            .write(&mut out, "Reply-To: FoO@bar.com", "")
            .unwrap();
        relaxed
            .write(&mut out, "DKIM-Signature: foo=bar;b=", ";x  =y")
            .unwrap();
        relaxed.write(&mut out, "Ü無: Ü無", "").unwrap();

        assert_eq!(
            "a:X\
             b:Y Z\
             reply-to:FoO@bar.com\
             dkim-signature:foo=bar;b=;x =y\
             ü無:Ü無",
            String::from_utf8(out).unwrap(),
        );
    }

    fn canonicalise_body(mode: BodyCanonicalisation, data: &[u8]) -> Vec<u8> {
        let mut canonicaliser = BodyCanonicaliser::new(Vec::<u8>::new(), mode);
        canonicaliser.write_all(data).unwrap();
        canonicaliser.finish().unwrap()
    }

    #[test]
    fn simple_body_canonicalisation() {
        let simple = BodyCanonicalisation::Simple;
        // RFC 6376 § 3.4.5 example
        assert_eq!(
            b" C \r\nD \t E\r\n".to_vec(),
            canonicalise_body(simple, b" C \r\nD \t E\r\n\r\n\r\n"),
        );
        // Pathological line ending cases
        assert_eq!(b"\r\n".to_vec(), canonicalise_body(simple, &[]),);
        assert_eq!(
            b"foo\r\n\r\n bar \r\n".to_vec(),
            canonicalise_body(simple, b"foo\r\n\r\n bar \r\n"),
        );
        assert_eq!(
            b"foo\r\n \r\n\t\r\n".to_vec(),
            canonicalise_body(simple, b"foo\r\n \r\n\t\r\n"),
        );
        assert_eq!(
            b"foo\r\n\rbar\r\n".to_vec(),
            canonicalise_body(simple, b"foo\r\n\rbar\r\n"),
        );
        assert_eq!(
            b"foo\rbar\r\n".to_vec(),
            canonicalise_body(simple, b"foo\rbar\r\n"),
        );
        assert_eq!(
            b"foo\r\r\r\n\n\nbar\n\r\n".to_vec(),
            canonicalise_body(simple, b"foo\r\r\r\n\n\nbar\n"),
        );
        assert_eq!(b"foo\r\r\n".to_vec(), canonicalise_body(simple, b"foo\r"),);
        assert_eq!(
            b"foo\r\n\r\r\n".to_vec(),
            canonicalise_body(simple, b"foo\r\n\r"),
        );
    }

    #[test]
    fn relaxed_body_canonicalisation() {
        let relaxed = BodyCanonicalisation::Relaxed;
        // RFC 6376 § 3.4.5 example
        assert_eq!(
            b" C\r\nD E\r\n".to_vec(),
            canonicalise_body(relaxed, b" C \r\nD \t E\r\n\r\n\r\n"),
        );
        // Pathological line ending / blank line cases
        assert_eq!(b"\r\n".to_vec(), canonicalise_body(relaxed, &[]),);
        assert_eq!(
            b"foo\r\n\r\n bar\r\n".to_vec(),
            canonicalise_body(relaxed, b"foo\r\n\r\n bar \r\n"),
        );
        assert_eq!(
            b"foo\r\n".to_vec(),
            canonicalise_body(relaxed, b"foo\r\n \r\n\t\r\n"),
        );
        assert_eq!(
            b"foo\r\n\rbar\r\n".to_vec(),
            canonicalise_body(relaxed, b"foo\r\n\rbar\r\n"),
        );
        assert_eq!(
            b"foo\r\n\r\nbar\r\n".to_vec(),
            canonicalise_body(relaxed, b"foo\r\n \t\r\nbar"),
        );
        assert_eq!(
            b" foo \n bar \n baz\r\n".to_vec(),
            canonicalise_body(relaxed, b" foo \n bar \n baz "),
        );
        assert_eq!(
            b"foo\r\n\rbar\r\n".to_vec(),
            canonicalise_body(relaxed, b"foo\r\n\rbar\r\n"),
        );
        assert_eq!(
            b"foo\rbar\r\n".to_vec(),
            canonicalise_body(relaxed, b"foo\rbar\r\n"),
        );
        assert_eq!(
            b"foo\r\r\r\n\n\nbar\n\r\n".to_vec(),
            canonicalise_body(relaxed, b"foo\r\r\r\n\n\nbar\n"),
        );
        assert_eq!(b"foo\r\r\n".to_vec(), canonicalise_body(relaxed, b"foo\r"),);
        assert_eq!(
            b"foo\r\n\r\r\n".to_vec(),
            canonicalise_body(relaxed, b"foo\r\n\r"),
        );
        assert_eq!(
            b"foo \rbar\r\n".to_vec(),
            canonicalise_body(relaxed, b"foo \rbar"),
        );
        assert_eq!(
            b"foo \r \r\r\n".to_vec(),
            canonicalise_body(relaxed, b"foo\t\r  \r\r\n"),
        );
    }
}
