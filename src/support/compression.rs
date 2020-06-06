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

//! Provides a façade around compression and decompression, as used for
//! compressing data streams.

use std::io::{self, BufRead, Read, Write};

use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::support::un64;

/// Extends the `Write` trait to have a `finish()` method.
pub trait FinishWrite: Write {
    /// Perform any finishing operations on this object.
    fn finish(&mut self) -> io::Result<()>;
}

impl<W: Write> FinishWrite for zstd::Encoder<W> {
    fn finish(&mut self) -> io::Result<()> {
        self.do_finish()
    }
}

/// Various schemes of supported compression types.
#[derive(
    Serialize_repr, Deserialize_repr, Clone, Copy, Debug, PartialEq, Eq,
)]
#[repr(u8)]
pub enum Compression {
    /// ZStandard compression, with Un-64 as a pre-compressor.
    Un64Zstd = 0,
}

impl Default for Compression {
    fn default() -> Self {
        Compression::Un64Zstd
    }
}

impl Compression {
    /// Wrap `reader` to decompress according to this scheme.
    pub fn decompressor(self, reader: impl Read) -> io::Result<impl BufRead> {
        match self {
            Compression::Un64Zstd => {
                Ok(un64::Reader::new(zstd::Decoder::new(reader)?))
            }
        }
    }

    /// Wrap `writer` to compress according to this scheme.
    pub fn compressor(
        self,
        writer: impl Write,
    ) -> io::Result<impl FinishWrite> {
        match self {
            Compression::Un64Zstd => {
                Ok(un64::Writer::new(zstd::Encoder::new(writer, 5)?))
            }
        }
    }
}
