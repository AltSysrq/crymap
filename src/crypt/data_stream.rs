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

//! Support for encrypting and decrypting data streams.
//!
//! A data stream is a payload encrypted with a random key itself encrypted
//! with RSA, so that data streams can be written by non-logged-in processes
//! but only read by those with the user's credentials. As the data is more
//! sensitive, authenticated encryption is used to ensure tampering is
//! impossible.
//!
//! Data streams are broken into "slabs" of up to 65536 bytes, each of which is
//! a separate encryption. The division is not semantically important, but is
//! used during reading so that the authentication tag can be checked without
//! needing to read the whole file in (e.g. for search or partial fetch, where
//! we often only want the MIME headers). While this does mean that tampering
//! won't be detected if it is in a slab we don't look at, we do keep the
//! property that we cannot _operate_ on tampered data.
//!
//! A data stream is formatted as follows:
//! - u16 LE: Length of following element
//! - A `Metadata` object in CBOR
//! - Zero or more slabs
//!
//! Each slab is:
//! - u16 LE: data length *minus one*
//! - 16-byte IV
//! - Ciphertext of exactly the given length
//! - 16-byte authentication tag
//!
//! When writing, slab sizes are chosen on a deterministic schedule so that
//! information about the content is not leaked through the slab sizes. The
//! exact sizes are encoded anyway both to facilitate future changes to the
//! schedule, and to account for the last slab which may have arbitrary size.

use std::convert::TryInto;
use std::io::{self, BufRead, Cursor, Read, Write};
use std::sync::Arc;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use openssl::{
    pkey::{HasPublic, Private},
    rsa::Rsa,
};
use rand::{rngs::OsRng, Rng};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

use super::AES_BLOCK;
use crate::support::compression::Compression;
use crate::support::error::Error;

#[derive(
    Serialize_repr, Deserialize_repr, Clone, Copy, Debug, PartialEq, Eq,
)]
#[repr(u8)]
enum Algorithm {
    Aes128Gcm = 0,
}

#[derive(
    Serialize_repr, Deserialize_repr, Clone, Copy, Debug, PartialEq, Eq,
)]
#[repr(u8)]
enum MetaAlgorithm {
    RsaPkcs1Oaep = 0,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Metadata {
    /// The encryption algorithm used.
    #[serde(rename = "a")]
    algorithm: Algorithm,
    /// The algorithm used to encrypt the encryption key.
    #[serde(rename = "b")]
    meta_algorithm: MetaAlgorithm,
    /// The compression algorithm used.
    ///
    /// The data_stream implementation does not use this value, but it is saved
    /// in this metadata block for convenience.
    #[serde(rename = "c")]
    pub compression: Compression,
    /// The name of the key used to encrypt the data.
    #[serde(rename = "m")]
    pub meta_key_id: String,
    /// The RSA-encrypted form of the encryption key.
    #[serde(rename = "k", with = "serde_bytes")]
    encrypted_key: Vec<u8>,
}

/// Implements `std::io::Read` and `std::io::BufRead` on top of a data stream,
/// yielding the cleartext of the underlying encrypted stream.
///
/// Slab boundaries are semantically transparent, though they can be observed
/// by the way partial reads complete.
///
/// Internally, this operates on a slab-by-slab basis. When a `read()` call is
/// made while no data is available, the next slab is fully read in and
/// decrypted. Reads are otherwise simply delegated to the buffer of cleartext
/// in remaining in the slab.
pub struct Reader<R> {
    reader: R,
    key: [u8; AES_BLOCK],
    ciphertext_buffer: Vec<u8>,
    cleartext_buffer: Cursor<Vec<u8>>,
    /// The metadata block at the beginning of the stream.
    pub metadata: Metadata,
}

impl<R: Read> Reader<R> {
    /// Create a new reader.
    ///
    /// `priv_key_lookup` will be invoked on the name of whatever key is
    /// referenced by the metadata to get the private key used to decrypt the
    /// session key.
    ///
    /// The header block is fully read in by this call.
    pub fn new(
        mut reader: R,
        priv_key_lookup: impl FnOnce(&str) -> Result<Arc<Rsa<Private>>, Error>,
    ) -> Result<Self, Error> {
        let meta_length = reader.read_u16::<LittleEndian>()?;
        let meta: Metadata =
            serde_cbor::from_reader(reader.by_ref().take(meta_length.into()))?;
        let priv_key = priv_key_lookup(&meta.meta_key_id)?;

        let key = match meta.meta_algorithm {
            MetaAlgorithm::RsaPkcs1Oaep => {
                // private_decrypt() requires the output buffer to be at least
                // the size of the RSA modulus
                let mut buf =
                    vec![0u8; (priv_key.size() as usize).max(AES_BLOCK)];
                if AES_BLOCK
                    != priv_key.private_decrypt(
                        &meta.encrypted_key,
                        &mut buf,
                        openssl::rsa::Padding::PKCS1_OAEP,
                    )?
                {
                    return Err(Error::BadEncryptedKey);
                }

                let mut k = [0u8; AES_BLOCK];
                k.copy_from_slice(&buf[..AES_BLOCK]);
                k
            }
        };

        Ok(Reader {
            reader,
            key,
            // Extra two blocks are for IV and AEAD tag
            ciphertext_buffer: Vec::with_capacity(1024 + 2 * AES_BLOCK),
            cleartext_buffer: Cursor::new(Vec::with_capacity(1024)),
            metadata: meta,
        })
    }
}

impl<R: Read> Read for Reader<R> {
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        self.fill_buf()?;
        self.cleartext_buffer.read(dst)
    }
}

impl<R: Read> BufRead for Reader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.cleartext_buffer.position()
            >= (self.cleartext_buffer.get_ref().len() as u64)
        {
            let slab_size = 1 + match self.reader.read_u16::<LittleEndian>() {
                Ok(i) => i as usize,
                Err(e) if io::ErrorKind::UnexpectedEof == e.kind() => {
                    return Ok(&[]);
                }
                Err(e) => {
                    return Err(e.into());
                }
            };

            self.ciphertext_buffer.resize(slab_size + 2 * AES_BLOCK, 0);
            self.cleartext_buffer.get_mut().resize(slab_size, 0);
            // If anything goes wrong here, make sure that a further call to
            // read() won't consume the corrupted data
            self.cleartext_buffer.set_position(slab_size as u64);

            self.reader.read_exact(&mut self.ciphertext_buffer)?;
            let mut crypter = match self.metadata.algorithm {
                Algorithm::Aes128Gcm => openssl::symm::Crypter::new(
                    openssl::symm::Cipher::aes_128_gcm(),
                    openssl::symm::Mode::Decrypt,
                    &self.key,
                    Some(&self.ciphertext_buffer[..AES_BLOCK]),
                )
                .map_err(to_ioerr)?,
            };

            crypter.pad(false);
            assert_eq!(
                slab_size,
                crypter
                    .update(
                        &self.ciphertext_buffer
                            [AES_BLOCK..slab_size + AES_BLOCK],
                        &mut self.cleartext_buffer.get_mut()
                    )
                    .map_err(to_ioerr)?
            );
            crypter
                .set_tag(&self.ciphertext_buffer[slab_size + AES_BLOCK..])
                .map_err(to_ioerr)?;
            assert_eq!(0, crypter.finalize(&mut []).map_err(to_ioerr)?);

            // OK, we can safely read the data now
            self.cleartext_buffer.set_position(0);
        }

        self.cleartext_buffer.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        self.cleartext_buffer.consume(amt);
    }
}

/// Implements `std::io::Write` for a data stream, taking cleartext and
/// encrypting it.
///
/// Slab boundaries are generally produced by a hard-wired schedule so as not
/// to leak information about the cleartext. However, the `flush()` method
/// immediately creates a boundary. It should only be used to flush the final,
/// incomplete slab at the end of writing.
pub struct Writer<W> {
    writer: W,
    key: [u8; AES_BLOCK],
    cleartext_buffer: Vec<u8>,
    ciphertext_buffer: Vec<u8>,
    slab_size: usize,
}

impl<W: Write> Writer<W> {
    /// Create a new writer.
    ///
    /// `pub_key_name` must correspond to the name of `pub_key`.
    pub fn new(
        mut writer: W,
        pub_key: &Rsa<impl HasPublic>,
        pub_key_name: String,
        compression: Compression,
    ) -> Result<Self, Error> {
        let key: [u8; AES_BLOCK] = OsRng.gen();
        let mut encrypted_key = vec![0u8; pub_key.size().try_into().unwrap()];
        let encrypted_key_length = pub_key.public_encrypt(
            &key,
            &mut encrypted_key,
            openssl::rsa::Padding::PKCS1_OAEP,
        )?;
        encrypted_key.resize(encrypted_key_length, 0);

        let meta = Metadata {
            algorithm: Algorithm::Aes128Gcm,
            meta_algorithm: MetaAlgorithm::RsaPkcs1Oaep,
            compression,
            meta_key_id: pub_key_name,
            encrypted_key,
        };
        let meta_bytes = serde_cbor::to_vec(&meta)?;
        assert!(meta_bytes.len() < 65536);

        writer
            .write_u16::<LittleEndian>(meta_bytes.len().try_into().unwrap())?;
        writer.write_all(&meta_bytes)?;

        Ok(Writer {
            writer,
            key,
            cleartext_buffer: Vec::with_capacity(1024),
            ciphertext_buffer: Vec::with_capacity(1024),
            slab_size: 256,
        })
    }
}

impl<W: Write> Write for Writer<W> {
    fn write(&mut self, src: &[u8]) -> io::Result<usize> {
        let capacity = self.slab_size - self.cleartext_buffer.len();
        let count = capacity.min(src.len());
        self.cleartext_buffer.extend_from_slice(&src[..count]);

        if count == capacity {
            self.flush()?;
        }

        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.cleartext_buffer.is_empty() {
            return self.writer.flush();
        }

        let iv: [u8; AES_BLOCK] = OsRng.gen();

        self.writer.write_u16::<LittleEndian>(
            (self.cleartext_buffer.len() - 1).try_into().unwrap(),
        )?;
        self.writer.write_all(&iv)?;

        self.ciphertext_buffer
            .resize(self.cleartext_buffer.len(), 0);
        let mut crypter = openssl::symm::Crypter::new(
            openssl::symm::Cipher::aes_128_gcm(),
            openssl::symm::Mode::Encrypt,
            &self.key,
            Some(&iv),
        )
        .map_err(to_ioerr)?;
        assert_eq!(
            self.cleartext_buffer.len(),
            crypter
                .update(&self.cleartext_buffer, &mut self.ciphertext_buffer)
                .map_err(to_ioerr)?
        );
        self.writer.write_all(&self.ciphertext_buffer)?;

        assert_eq!(0, crypter.finalize(&mut []).map_err(to_ioerr)?);

        let mut tag = [0u8; AES_BLOCK];
        crypter.get_tag(&mut tag).map_err(to_ioerr)?;
        self.writer.write_all(&tag)?;

        self.cleartext_buffer.clear();
        self.slab_size = 65536.min(self.slab_size * 2);
        self.writer.flush()
    }
}

fn to_ioerr(e: openssl::error::ErrorStack) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

#[cfg(test)]
mod test {
    use std::io::Cursor;

    use super::*;
    use crate::crypt::test_keys::*;

    #[test]
    fn encrypt_and_decrypt() {
        for &size in &[
            2usize,
            15,
            16,
            17,
            128,
            255,
            256,
            257,
            511,
            512,
            513,
            1024 * 1024,
        ] {
            let mut cleartext = vec![0u8, 1u8];
            while cleartext.len() < size {
                let new = cleartext[cleartext.len() - 2]
                    .wrapping_add(cleartext[cleartext.len() - 1]);
                cleartext.push(new);
            }

            let mut ciphertext = vec![0u8; 0];
            {
                let mut writer = Writer::new(
                    &mut ciphertext,
                    &RSA1024A,
                    "the key name".to_owned(),
                    Compression::DEFAULT_FOR_MESSAGE,
                )
                .unwrap();
                writer.write_all(&cleartext).unwrap();
                writer.flush().unwrap();
            }

            let decrypted = {
                let mut reader = Reader::new(Cursor::new(ciphertext), |_| {
                    Ok(Arc::clone(&RSA1024A))
                })
                .unwrap();
                let mut d = Vec::new();
                reader.read_to_end(&mut d).unwrap();
                d
            };

            if size <= 128 {
                assert_eq!(cleartext, decrypted);
            } else {
                assert_eq!(cleartext.len(), decrypted.len());
                for i in 0..cleartext.len() {
                    assert_eq!(
                        cleartext[i], decrypted[i],
                        "Mismatch at index {}",
                        i
                    );
                }
            }
        }
    }
}
