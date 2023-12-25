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

//! Utilities for reading and writing the message format (which is the same in
//! both versions of the data store).
//!
//! The message format is as follows:
//!
//! - `u32`: `size_xor`
//! - `u16`: `metadata_size`
//! - `[u8; metadata_size]`: CBOR `MessageMetadata`
//! - rest of file: payload, compressed and encrypted with `data_stream`
//!
//! The actual size of the payload (after being uncompressed) is
//! `size_xor ^ metadata.size`.

use std::convert::TryInto;
use std::io::{self, BufRead, Read, Seek, Write};
use std::pin::Pin;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use chrono::prelude::*;
use rand::{rngs::OsRng, Rng};
use tokio::io::{AsyncRead, AsyncReadExt};

use super::{key_store::KeyStore, model::*};
use crate::crypt::data_stream;
use crate::support::{
    compression::{Compression, FinishWrite},
    error::Error,
};

/// Begins reading a message from `src`.
///
/// The metadata is immediately decoded and is returned with the `size`
/// corrected.
///
/// `on_data_stream` is invoked with the `data_stream::Reader` as soon as it
/// has been created.
pub fn read_message<'a, R: Read + 'a>(
    mut src: R,
    csk: Option<data_stream::CachedSessionKey<'_>>,
    key_store: &mut KeyStore,
    on_data_stream: impl FnOnce(&data_stream::Reader<R>),
) -> Result<(MessageMetadata, Box<dyn BufRead + 'a>), Error> {
    let size_xor = src.read_u32::<LittleEndian>()?;
    let stream =
        data_stream::Reader::new(src, csk, |k| key_store.get_private_key(k))?;
    on_data_stream(&stream);
    let compression = stream.metadata.compression;
    let mut stream = compression.decompressor(stream)?;
    let metadata_length = stream.read_u16::<LittleEndian>()?;
    let mut metadata: MessageMetadata =
        serde_cbor::from_reader(stream.by_ref().take(metadata_length.into()))?;
    metadata.size ^= size_xor;

    Ok((metadata, stream))
}

/// Writes a message to `out`, using `key_store` to obtain the public key and
/// the full data from `message_contents` as the payload.
///
/// `internal_date` is passed through to the payload.
///
/// `out`'s position after this returns is unspecified.
pub fn write_message(
    mut out: impl Write + Seek,
    key_store: &mut KeyStore,
    internal_date: DateTime<FixedOffset>,
    mut message_contents: impl Read,
) -> Result<(), Error> {
    let size_xor: u32;
    let metadata = MessageMetadata {
        size: OsRng.gen(),
        internal_date,
        email_id: OsRng.gen(),
    };
    let compression = Compression::DEFAULT_FOR_MESSAGE;

    out.write_u32::<LittleEndian>(0)?;
    {
        let mut crypt_writer = {
            let (key_name, pub_key) = key_store.get_default_public_key()?;

            data_stream::Writer::new(
                &mut out,
                pub_key,
                key_name.to_owned(),
                compression,
            )?
        };
        {
            let mut compressor = compression.compressor(&mut crypt_writer)?;
            let metadata_bytes = serde_cbor::to_vec(&metadata)?;
            compressor.write_u16::<LittleEndian>(
                metadata_bytes.len().try_into().unwrap(),
            )?;
            compressor.write_all(&metadata_bytes)?;

            let size = io::copy(&mut message_contents, &mut compressor)?;
            size_xor = metadata.size ^ size.try_into().unwrap_or(u32::MAX);
            compressor.finish()?;
        }
        crypt_writer.flush()?;
    }

    out.seek(io::SeekFrom::Start(0))?;
    out.write_u32::<LittleEndian>(size_xor)?;
    Ok(())
}

/// Writes a message to `out`, using `key_store` to obtain the public key and
/// the full data from `message_contents` as the payload.
///
/// `internal_date` is passed through to the payload.
///
/// `out`'s position after this returns is unspecified.
#[allow(dead_code)] // TODO REMOVE
pub async fn write_message_async(
    mut out: impl Write + Seek,
    key_store: &mut KeyStore,
    internal_date: DateTime<FixedOffset>,
    mut message_contents: Pin<&mut impl AsyncRead>,
) -> Result<(), Error> {
    let size_xor: u32;
    let metadata = MessageMetadata {
        size: OsRng.gen(),
        internal_date,
        email_id: OsRng.gen(),
    };
    let compression = Compression::DEFAULT_FOR_MESSAGE;

    out.write_u32::<LittleEndian>(0)?;
    {
        let mut crypt_writer = {
            let (key_name, pub_key) = key_store.get_default_public_key()?;

            data_stream::Writer::new(
                &mut out,
                pub_key,
                key_name.to_owned(),
                compression,
            )?
        };
        {
            let mut compressor = compression.compressor(&mut crypt_writer)?;
            let metadata_bytes = serde_cbor::to_vec(&metadata)?;
            compressor.write_u16::<LittleEndian>(
                metadata_bytes.len().try_into().unwrap(),
            )?;
            compressor.write_all(&metadata_bytes)?;

            let mut size = 0u64;
            let mut buffer = [0u8; 1024];
            loop {
                let nread = message_contents.as_mut().read(&mut buffer).await?;
                if 0 == nread {
                    break;
                }

                compressor.write_all(&buffer[..nread])?;
                size += nread as u64;
            }
            size_xor = metadata.size ^ size.try_into().unwrap_or(u32::MAX);
            compressor.finish()?;
        }
        crypt_writer.flush()?;
    }

    out.seek(io::SeekFrom::Start(0))?;
    out.write_u32::<LittleEndian>(size_xor)?;
    Ok(())
}
