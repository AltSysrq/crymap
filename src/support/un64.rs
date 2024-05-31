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

//! Implements an "Un-64" pre-compression step.
//!
//! MIME often has large swaths of base64-encoded data, which in many cases is
//! actually an encoding of text. While generic compression algorithms have
//! some success compressing base64, this ability is fairly limited, especially
//! since patterns lying under the base64 encoding can occur in 4 distinct
//! phases and get mixed with adjacent data.
//!
//! "Un-64" is a simple scheme to store data with base64 sections decoded,
//! while still representing the exact contents of the data. The format is
//! pretty simple. It is simply a cycle of the below sequence:
//!
//! 1. A byte giving the size of the unencoded section.
//! 2. A sequence of unencoded bytes which are copied verbatim to the output.
//! 3. A byte giving the size of the encoded section divided by 3.
//! 4. A number of bytes which are encoded to the output with standard base64
//! encoding. Note there will never be any padding since the length is a
//! multiple of 3.
//!
//! The overhead this introduces in data with no base64-encoded sections is 2
//! bytes every 255, a little under 1%. The overhead of switching from
//! unencoded to encoded is also 2 bytes, so a switch requires at least a 3
//! byte net savings to be worth it, which is 12 bytes in the raw stream.

use std::convert::TryInto;
use std::io::{self, BufRead, Cursor, Read, Write};

use crate::support::compression::FinishWrite;

#[derive(Debug, Clone)]
pub struct Reader<R> {
    reader: R,
    buffer: Cursor<Vec<u8>>,
    next_is_encoded: bool,
}

impl<R> Reader<R> {
    pub fn new(reader: R) -> Self {
        Reader {
            reader,
            buffer: Cursor::new(Vec::with_capacity(255)),
            next_is_encoded: false,
        }
    }
}

impl<R: Read> Read for Reader<R> {
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        self.fill_buf()?;
        self.buffer.read(dst)
    }
}

impl<R: Read> BufRead for Reader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if (self.buffer.position() as usize) < self.buffer.get_ref().len() {
            return self.buffer.fill_buf();
        }

        let mut length = [0u8; 1];
        let mut is_encoded;
        loop {
            match self.reader.read_exact(&mut length) {
                Ok(_) => (),
                Err(e) if io::ErrorKind::UnexpectedEof == e.kind() => {
                    return Ok(&[]);
                },
                Err(e) => {
                    return Err(e);
                },
            }

            is_encoded = self.next_is_encoded;
            self.next_is_encoded = !self.next_is_encoded;

            if 0 != length[0] {
                break;
            }
        }

        if is_encoded {
            let mut buf = [0u8; 255 * 3];
            let text_length = length[0] as usize * 4;
            let bin_length = length[0] as usize * 3;

            self.buffer.set_position(text_length as u64);
            self.buffer.get_mut().resize(text_length, 0);
            self.reader.read_exact(&mut buf[..bin_length])?;
            base64::encode_config_slice(
                &buf[..bin_length],
                base64::STANDARD,
                self.buffer.get_mut(),
            );
        } else {
            self.buffer.set_position(length[0].into());
            self.buffer.get_mut().resize(length[0].into(), 0);
            self.reader.read_exact(self.buffer.get_mut())?;
        }

        self.buffer.set_position(0);
        self.buffer.fill_buf()
    }

    fn consume(&mut self, n: usize) {
        self.buffer.consume(n)
    }
}

#[derive(Debug, Clone)]
pub struct Writer<W> {
    writer: W,
    unencoded_buffer: Vec<u8>,
    encoded_buffer: Vec<u8>,
}

impl<W> Writer<W> {
    pub fn new(writer: W) -> Self {
        Writer {
            writer,
            unencoded_buffer: Vec::with_capacity(255),
            encoded_buffer: Vec::with_capacity(255 * 4),
        }
    }
}

impl<W: Write> Writer<W> {
    fn push(&mut self, byte: u8) -> io::Result<()> {
        if is_base64(byte) {
            self.encoded_buffer.push(byte);
            if self.encoded_buffer.len() == 255 * 4 {
                // No more space, flush
                self.dump_unencoded()?;
                // No splitting, we already know it's a multiple of 4 bytes
                // long
                self.dump_encoded()?;
            }
        } else {
            self.flush_encoded()?;

            if 255 == self.unencoded_buffer.len() {
                // No more space, flush
                self.dump_unencoded()?;
                // This will be empty, but we need the empty encoded section to
                // continue with another unencoded section.
                self.dump_encoded()?;
            }

            self.unencoded_buffer.push(byte);
        }

        Ok(())
    }

    /// Ensure `encoded_buffer` is empty.
    ///
    /// If not, flush `unencoded_buffer`, then `encoded_buffer`, leaving any
    /// trailing bytes that were in `encoded_buffer` at the start of
    /// `unencoded_buffer`.
    ///
    /// After this call, `encoded_buffer` will always be empty.
    fn flush_encoded(&mut self) -> io::Result<()> {
        if !self.encoded_buffer.is_empty() {
            // We can't append this byte to the encoded section, but there
            // are encoded bytes. We either need to flush both sections now
            // to start a fresh unencoded section, or move the encoded
            // bytes into the encoded section.
            //
            // Combine if the encoded buffer still fits into the unencoded
            // buffer and is too small to be useful.
            if self.encoded_buffer.len() + self.unencoded_buffer.len() <= 255
                && self.encoded_buffer.len() < 12
            {
                self.unencoded_buffer.append(&mut self.encoded_buffer);
            } else {
                self.dump_unencoded()?;
                self.split_encoded();
                self.dump_encoded()?;
            }
        }

        Ok(())
    }

    fn dump_unencoded(&mut self) -> io::Result<()> {
        self.writer.write_all(&[self
            .unencoded_buffer
            .len()
            .try_into()
            .unwrap()])?;
        self.writer.write_all(&self.unencoded_buffer)?;
        self.unencoded_buffer.clear();
        Ok(())
    }

    fn dump_encoded(&mut self) -> io::Result<()> {
        debug_assert_eq!(0, self.encoded_buffer.len() % 4);
        self.writer.write_all(&[(self.encoded_buffer.len() / 4)
            .try_into()
            .unwrap()])?;

        if !self.encoded_buffer.is_empty() {
            let mut buf = [0u8; 255 * 3];
            let text_length = self.encoded_buffer.len();
            let count = text_length / 4;
            let bin_length = count * 3;

            base64::decode_config_slice(
                &self.encoded_buffer,
                base64::STANDARD,
                &mut buf[..bin_length],
            )
            .unwrap();
            self.writer.write_all(&buf[..bin_length])?;
            self.encoded_buffer.clear();
        }

        Ok(())
    }

    /// If `encoded_buffer` is not a multiple of 4 bytes long, transfer the
    /// remainder to the front of `unencoded_buffer`, which must be empty.
    fn split_encoded(&mut self) {
        debug_assert!(self.unencoded_buffer.is_empty());

        let valid = self.encoded_buffer.len() / 4 * 4;
        self.unencoded_buffer
            .extend_from_slice(&self.encoded_buffer[valid..]);
        self.encoded_buffer.resize(valid, 0);
    }
}

impl<W: Write> Write for Writer<W> {
    fn write(&mut self, src: &[u8]) -> io::Result<usize> {
        for &byte in src {
            self.push(byte)?;
        }
        Ok(src.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_encoded()?;

        if !self.unencoded_buffer.is_empty() {
            self.dump_unencoded()?;
            // Empty, but we need to maintain the invariants
            self.dump_encoded()?;
        }

        self.writer.flush()
    }
}

impl<W: FinishWrite> FinishWrite for Writer<W> {
    fn finish(&mut self) -> io::Result<()> {
        self.flush()?;
        self.writer.finish()
    }
}

#[allow(clippy::manual_range_contains)]
fn is_base64(b: u8) -> bool {
    (b >= b'a' && b <= b'z')
        || (b >= b'A' && b <= b'Z')
        || (b >= b'0' && b <= b'9')
        || b == b'/'
        || b == b'+'
}

#[cfg(test)]
mod test {
    use std::io::{Cursor, Read, Write};

    use proptest::prelude::*;

    use super::*;

    fn blob(n: usize) -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(prop::num::u8::ANY, 1..=n)
    }

    fn base64_string(n: usize) -> impl Strategy<Value = Vec<u8>> {
        blob(n).prop_map(|bytes| base64::encode(&bytes).as_bytes().to_owned())
    }

    fn uncompressed_input() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(
            prop_oneof![
                blob(8),
                base64_string(8),
                blob(32),
                base64_string(32),
                blob(512),
                base64_string(512)
            ],
            0..10,
        )
        .prop_map(|chunks| {
            let mut accum = Vec::new();
            for mut chunk in chunks {
                accum.append(&mut chunk);
            }
            accum
        })
    }

    proptest! {
        #[test]
        fn compress_and_decompress(input in uncompressed_input()) {
            let mut compressed = Vec::<u8>::new();
            {
                let mut writer = Writer::new(&mut compressed);
                writer.write_all(&input).unwrap();
                writer.flush().unwrap();
            }


            let mut decompressed = Vec::<u8>::new();
            {
                let mut reader = Reader::new(Cursor::new(compressed));
                reader.read_to_end(&mut decompressed).unwrap();
            }

            prop_assert_eq!(input, decompressed);
        }
    }
}
