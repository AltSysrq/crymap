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

//! Support for "buffers", which are write-once-read-once values that spill to
//! disk (encrypted) if they exceed a maximum size.

use std::fs;
use std::io::{self, Read, Seek, Write};
use std::mem;
use std::sync::Arc;

use crate::account::model::CommonPaths;
use crate::crypt::naked::*;

const MAX_BUFFER: usize = 65536;

pub struct BufferWriter {
    paths: Arc<CommonPaths>,
    buf: Vec<u8>,
    len: u64,
    on_disk: Option<OnDiskInfo>,
}

pub struct BufferReader {
    buf: Vec<u8>,
    off: usize,
    len: u64,
    on_disk: Option<OnDiskInfo>,
}

struct OnDiskInfo {
    context: NakedCryptContext,
    cryptor: openssl::symm::Crypter,
    file: fs::File,
}

impl BufferWriter {
    /// Create a new, empty buffer.
    pub fn new(paths: Arc<CommonPaths>) -> Self {
        BufferWriter {
            paths,
            buf: Vec::new(),
            len: 0,
            on_disk: None,
        }
    }

    /// Returns the length, in bytes, of the buffer.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// "Flips" the buffer, making it usable for rereading.
    pub fn flip(mut self) -> io::Result<BufferReader> {
        if let Some(on_disk) = self.on_disk.as_mut() {
            on_disk.file.seek(io::SeekFrom::Start(0))?;
            on_disk.cryptor = on_disk.context.decryptor();
        }

        Ok(BufferReader {
            buf: self.buf,
            off: 0,
            len: self.len,
            on_disk: self.on_disk,
        })
    }
}

impl Write for BufferWriter {
    fn write(&mut self, src: &[u8]) -> io::Result<usize> {
        if self.on_disk.is_none() && src.len() + self.buf.len() > MAX_BUFFER {
            let spill = mem::replace(&mut self.buf, Vec::new());
            let context = NakedCryptContext::new();
            let cryptor = context.encryptor();
            let file = tempfile::tempfile_in(&self.paths.tmp)?;
            self.on_disk = Some(OnDiskInfo {
                context,
                cryptor,
                file,
            });
            self.len = 0;
            self.write_all(&spill)?;
        }

        if let Some(on_disk) = self.on_disk.as_mut() {
            if src.len() > self.buf.len() {
                self.buf.resize(src.len(), 0);
            }
            on_disk.cryptor.update(src, &mut self.buf).unwrap();
            on_disk.file.write_all(&self.buf[..src.len()])?;
        } else {
            self.buf.extend_from_slice(src);
        }

        self.len += src.len() as u64;

        Ok(src.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl BufferReader {
    /// Directly create a `BufferReader` from the given data.
    ///
    /// Mainly used for testing.
    pub fn new(data: Vec<u8>) -> Self {
        BufferReader {
            len: data.len() as u64,
            buf: data,
            off: 0,
            on_disk: None,
        }
    }

    /// Returns the length, in bytes, of the buffer.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Rewind to position 0.
    pub fn rewind(&mut self) -> io::Result<()> {
        self.off = 0;
        if let Some(ref mut on_disk) = self.on_disk {
            on_disk.file.seek(io::SeekFrom::Start(0))?;
        }

        Ok(())
    }
}

impl Read for BufferReader {
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        if let Some(on_disk) = self.on_disk.as_mut() {
            if dst.len() > self.buf.len() {
                self.buf.resize(dst.len(), 0);
            }

            let nread = on_disk.file.read(&mut self.buf[..dst.len()])?;
            if 0 == nread {
                return Ok(0);
            }

            on_disk
                .cryptor
                .update(&self.buf[..nread], &mut dst[..nread])
                .unwrap();
            Ok(nread)
        } else {
            let len = dst.len().min(self.buf.len() - self.off);
            dst[..len].copy_from_slice(&self.buf[self.off..self.off + len]);
            self.off += len;
            Ok(len)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn test_read_and_write(copy_buf: &mut [u8], expected: &[u8]) {
        let mut writer = BufferWriter::new(Arc::new(CommonPaths {
            tmp: std::env::temp_dir(),
            garbage: std::env::temp_dir(),
        }));

        let mut in_reader = expected;
        loop {
            let nread = in_reader.read(copy_buf).unwrap();
            if 0 == nread {
                break;
            }

            writer.write_all(&copy_buf[..nread]).unwrap();
        }

        assert_eq!(expected.len() as u64, writer.len());
        let mut reader = writer.flip().unwrap();
        assert_eq!(expected.len() as u64, reader.len());

        let mut actual = Vec::new();
        loop {
            let nread = reader.read(copy_buf).unwrap();
            if 0 == nread {
                break;
            }

            actual.extend_from_slice(&copy_buf[..nread]);
        }

        assert_eq!(expected.len(), actual.len());
        for i in 0..expected.len() {
            assert_eq!(expected[i], actual[i], "Difference at index {}", i);
        }
    }

    #[test]
    fn small() {
        test_read_and_write(&mut [0; 4], b"hello world");
    }

    #[test]
    fn large_with_small_ops() {
        test_read_and_write(
            &mut [0; 17],
            "hello world".repeat(10000).as_bytes(),
        );
    }

    #[test]
    fn large_with_large_ops() {
        test_read_and_write(
            &mut [0; 70000],
            "hello world".repeat(10000).as_bytes(),
        );
    }
}
