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

//! Support for encrypting and decrypting "item streams".
//!
//! An item stream is encrypted sequence of framed "items" which can be
//! appended to "live", and can be read at any time, having no point at which
//! the stream is considered "complete". This is used for mutable mailbox
//! metadata.
//!
//! The stream is formatted as follows:
//! - u16 LE: Length of following element
//! - A `Metadata` object in CBOR
//! - 16-byte IV
//! - Encrypted data
//!
//! The encrypted data holds a sequence of frames. Each frame starts with a
//! u16 LE indicating the size of its payload, followed by that many bytes of
//! payload (opaque to the code in this file), and then zero padding to the end
//! of the AES block.

use std::convert::TryInto;
use std::io::{self, Read, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use openssl;
use rand::{rngs::OsRng, Rng};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use thiserror::Error;

use super::AES_BLOCK;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Ssl(#[from] openssl::error::ErrorStack),
    #[error(transparent)]
    Cbor(#[from] serde_cbor::error::Error),
}

#[derive(
    Serialize_repr, Deserialize_repr, Clone, Copy, Debug, PartialEq, Eq,
)]
#[repr(u8)]
enum Algorithm {
    Aes128Cbc = 0,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
struct Metadata {
    #[serde(rename = "a")]
    algorithm: Algorithm,
}

/// Reads encrypted items from a stream.
///
/// The reader does not directly detect EOF conditions since they can occur at
/// different points. The caller should just keep reading until it gets an
/// error, and then check whether the error is an EOF error.
pub struct Reader<R> {
    reader: R,
    crypter: openssl::symm::Crypter,
}

impl<R: Read> Reader<R> {
    /// Create a new reader.
    ///
    /// This will immediately read in the header information, and will return
    /// an EOF error if the header has not been fully written.
    pub fn new(mut reader: R, key: &[u8]) -> Result<Self, Error> {
        let len = reader.read_u16::<LittleEndian>()?;

        let meta: Metadata =
            serde_cbor::from_reader(reader.by_ref().take(len.into()))?;

        let mut iv = [0u8; AES_BLOCK];
        reader.read_exact(&mut iv)?;

        let mut crypter = match meta.algorithm {
            Algorithm::Aes128Cbc => openssl::symm::Crypter::new(
                openssl::symm::Cipher::aes_128_cbc(),
                openssl::symm::Mode::Decrypt,
                key,
                Some(&iv),
            )?,
        };
        crypter.pad(false);

        Ok(Reader { reader, crypter })
    }

    /// Read the next item in.
    ///
    /// On success, the item is stored in `dst`.
    pub fn next(&mut self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let mut ciphertext = [0u8; AES_BLOCK];
        // *2 because the openssl bindings require it
        let mut cleartext = [0u8; AES_BLOCK * 2];

        self.reader.read_exact(&mut ciphertext)?;
        assert_eq!(
            AES_BLOCK,
            self.crypter.update(&ciphertext, &mut cleartext)?
        );

        let len = cleartext[0] as usize | ((cleartext[1] as usize) << 8);
        dst.clear();
        dst.reserve(len);
        dst.extend_from_slice(&cleartext[2..2 + len.min(AES_BLOCK - 2)]);

        while dst.len() < len {
            self.reader.read_exact(&mut ciphertext)?;
            assert_eq!(
                AES_BLOCK,
                self.crypter.update(&ciphertext, &mut cleartext)?
            );
            dst.extend_from_slice(&cleartext[..AES_BLOCK.min(len - dst.len())]);
        }

        Ok(())
    }
}

/// Writes encrypted items to a stream.
pub struct Writer<W> {
    writer: W,
    crypter: openssl::symm::Crypter,
}

impl<W: Write> Writer<W> {
    /// Create a new `Writer` writing to the given destination stream.
    ///
    /// The header information is written immediately.
    pub fn new(mut writer: W, key: &[u8]) -> Result<Self, Error> {
        let iv: [u8; AES_BLOCK] = OsRng.gen();

        let mut crypter = openssl::symm::Crypter::new(
            openssl::symm::Cipher::aes_128_cbc(),
            openssl::symm::Mode::Encrypt,
            key,
            Some(&iv),
        )?;
        crypter.pad(false);

        let meta = Metadata {
            algorithm: Algorithm::Aes128Cbc,
        };
        let meta_bytes = serde_cbor::to_vec(&meta)?;

        writer
            .write_u16::<LittleEndian>(meta_bytes.len().try_into().unwrap())?;
        writer.write_all(&meta_bytes)?;
        writer.write_all(&iv)?;
        Ok(Writer { writer, crypter })
    }

    /// Append the given item to the stream.
    ///
    /// The stream can immediately be read to obtain the new item.
    pub fn append(&mut self, mut item: &[u8]) -> Result<(), Error> {
        assert!(item.len() < 65536);

        let mut cleartext = [0u8; AES_BLOCK];
        // *2 because openssl bindings enforce it
        let mut ciphertext = [0u8; 2 * AES_BLOCK];

        cleartext[0] = item.len() as u8;
        cleartext[1] = (item.len() >> 8) as u8;
        let mut cpy = item.len().min(AES_BLOCK - 2);
        cleartext[2..2 + cpy].copy_from_slice(&item[..cpy]);
        item = &item[cpy..];
        assert_eq!(
            AES_BLOCK,
            self.crypter.update(&cleartext, &mut ciphertext)?
        );
        self.writer.write_all(&ciphertext[..AES_BLOCK])?;

        while item.len() > 0 {
            cleartext = [0u8; AES_BLOCK];
            cpy = item.len().min(AES_BLOCK);
            cleartext[..cpy].copy_from_slice(&item[..cpy]);
            item = &item[cpy..];
            assert_eq!(
                AES_BLOCK,
                self.crypter.update(&cleartext, &mut ciphertext)?
            );
            self.writer.write_all(&ciphertext[..AES_BLOCK])?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::io;
    use std::str;

    use proptest::prelude::*;

    use super::*;

    proptest! {
        #[test]
        fn encrypt_and_decrypt(
            strings in prop::collection::vec(".{0,64}", ..10)
        ) {
            openssl::init();

            let key: [u8; AES_BLOCK] = OsRng.gen();
            let mut buf = io::Cursor::new(Vec::<u8>::new());

            {
                let mut writer = Writer::new(&mut buf, &key).unwrap();
                for s in &strings {
                    writer.append(s.as_bytes()).unwrap();
                    println!("wrote item");
                }
            }

            let mut read = Vec::<String>::new();
            {
                buf.set_position(0);
                let mut reader = Reader::new(&mut buf, &key).unwrap();
                let mut data = Vec::<u8>::new();
                loop {
                    println!("read item");
                    match reader.next(&mut data) {
                        Ok(()) =>
                            read.push(str::from_utf8(&data).unwrap()
                                      .to_owned()),
                        Err(Error::Io(e))
                            if io::ErrorKind::UnexpectedEof == e.kind() =>
                            break,
                        Err(e) => panic!("Unexpected error: {}", e),
                    }
                }
            }

            assert_eq!(strings, read);
        }
    }
}
