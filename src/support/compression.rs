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

use std::io::{self, BufRead, Write};

use lazy_static::lazy_static;
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

impl<W: FinishWrite + ?Sized> FinishWrite for Box<W> {
    fn finish(&mut self) -> io::Result<()> {
        (**self).finish()
    }
}

/// Various schemes of supported compression types.
#[derive(
    Serialize_repr, Deserialize_repr, Clone, Copy, Debug, PartialEq, Eq,
)]
#[repr(u8)]
pub enum Compression {
    /// ZStandard compression using the 2020-07-25 base dictionary, with Un-64
    /// as a pre-compressor.
    ///
    /// The pre-built dictionary optimises the headers, so as to minimise the
    /// amount of data that needs to be fetched for operations such as
    /// `Envelope` which only need to consult the headers.
    Un64Zstd20200725 = 0,
    /// Vanilla ZStandard compression
    Zstd = 1,
}

/// A dictionary compiled from the headers of a set of ~6k test messages on
/// 2020-07-25, using the `XCRY ZSTD TRAIN` command.
static ZSTD_DICT_20200725_RAW: &[u8] = include_bytes!("zstd-dict-20200725.dat");

lazy_static! {
    static ref ZSTD_DICT_20200725_ENC: zstd::dict::EncoderDictionary<'static> =
        zstd::dict::EncoderDictionary::new(ZSTD_DICT_20200725_RAW, 5);
    static ref ZSTD_DICT_20200725_DEC: zstd::dict::DecoderDictionary<'static> =
        zstd::dict::DecoderDictionary::new(ZSTD_DICT_20200725_RAW);
}

impl Compression {
    pub const DEFAULT_FOR_MESSAGE: Self = Compression::Un64Zstd20200725;
    pub const DEFAULT_FOR_STATE: Self = Compression::Zstd;

    /// Wrap `reader` to decompress according to this scheme.
    pub fn decompressor<'a>(
        self,
        reader: impl BufRead + 'a,
    ) -> io::Result<Box<dyn BufRead + 'a>> {
        match self {
            Compression::Un64Zstd20200725 => Ok(box_r(un64::Reader::new(
                zstd::Decoder::with_prepared_dictionary(
                    reader,
                    &ZSTD_DICT_20200725_DEC,
                )?,
            ))),
            Compression::Zstd => {
                Ok(box_r(io::BufReader::new(zstd::Decoder::new(reader)?)))
            },
        }
    }

    /// Wrap `writer` to compress according to this scheme.
    pub fn compressor<'a>(
        self,
        writer: impl Write + 'a,
    ) -> io::Result<impl FinishWrite + 'a> {
        match self {
            Compression::Un64Zstd20200725 => Ok(box_w(un64::Writer::new(
                zstd::Encoder::with_prepared_dictionary(
                    writer,
                    &ZSTD_DICT_20200725_ENC,
                )?,
            ))),
            Compression::Zstd => Ok(box_w(zstd::Encoder::new(writer, 5)?)),
        }
    }
}

fn box_r<'a>(r: impl BufRead + 'a) -> Box<dyn BufRead + 'a> {
    Box::new(r)
}

fn box_w<'a>(w: impl FinishWrite + 'a) -> Box<dyn FinishWrite + 'a> {
    Box::new(w)
}
