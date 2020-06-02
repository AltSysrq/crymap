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

use openssl;
use rand::{rngs::OsRng, Rng};

use super::AES_BLOCK;

/// A context for reading and writing "naked" encrypted streams.
///
/// Naked encrypted streams have no associated metadata, so they are unreadable
/// without this context object. They are used for temporary buffers that must
/// be spilled to disk. Internally, this operates with AES-128-CTR, allowing it
/// to operate on a 1:1 basis.
///
/// Each context has a unique key and IV.
#[derive(Clone, Copy)]
pub struct NakedCryptContext {
    key: [u8; AES_BLOCK],
    iv: [u8; AES_BLOCK],
}

impl NakedCryptContext {
    pub fn new() -> Self {
        NakedCryptContext {
            key: OsRng.gen(),
            iv: OsRng.gen(),
        }
    }

    pub fn encryptor(&self) -> openssl::symm::Crypter {
        let mut c = openssl::symm::Crypter::new(
            openssl::symm::Cipher::aes_128_ctr(),
            openssl::symm::Mode::Encrypt,
            &self.key,
            Some(&self.iv),
        )
        .unwrap();
        c.pad(false);
        c
    }

    pub fn decryptor(&self) -> openssl::symm::Crypter {
        let mut c = openssl::symm::Crypter::new(
            openssl::symm::Cipher::aes_128_ctr(),
            openssl::symm::Mode::Decrypt,
            &self.key,
            Some(&self.iv),
        )
        .unwrap();
        c.pad(false);
        c
    }
}
