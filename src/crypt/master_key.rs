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

//! Code for working with master keys.
//!
//! Each user has a single, unalterable master key which is generated when the
//! user is created. The master key is derived from the user's password in a
//! way that allows the password to be changed at any time.
//!
//! To derive the master key, the password is first hashed with a standard
//! salted password hashing algorithm (see `Algorithm`). That raw hash is then
//! hashed again with two different suffixes to produce the final password hash
//! and the "derived key".
//!
//! The final password hash is stored in the user configuration, and makes it
//! easy to determine whether the input password is correct.
//!
//! The "derived key" is XORed with another byte array, the "master key XOR",
//! also stored in the user config, to derive the master key. This makes it
//! possible for arbitrary passwords to derive arbitrary master keys.
//!
//! Several secondary key families are derived from the master key:
//!
//! - AES key = `KMAC128(master_key, filename, 16, "aes")`, used for all
//! symmetric AES encryption in files
//!
//! - PEM passphrase = `base64_encode(KMAC256(master_key, key_name, 32,
//! "pem"))`, used as a passphrase in RSA PEM files containing private keys.
//!
//! Besides the general benefits of using multiple keys, the secondary key
//! derivation also means that the master key does not need to proliferate in
//! process memory as much, instead being kept in a locked page and zeroed out
//! on destruction.

use chrono::prelude::*;
use rand::{rngs::OsRng, Rng};
use secstr::SecBox;
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Kmac};

use super::AES_BLOCK;
use crate::support::user_config::b64;

const MASTER_SIZE: usize = 32;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum Algorithm {
    /// Use the Argon2i 1.3 algorithm with a memory cost of 4MB, time cost of
    /// 10, 1 lane, and a hash length of 32, with no associated data or secret.
    ///
    /// The final password hash is `KMAC256(salt, argon2_hash, 32, "check")`.
    /// The derived key is `KMAC256(salt, argon_hash, 32, "master")`
    Argon2i_V13_M4096_T10_L1_Kmac256,
}

impl Default for Algorithm {
    fn default() -> Self {
        Algorithm::Argon2i_V13_M4096_T10_L1_Kmac256
    }
}

/// Configuration which represents the derivation of the master key.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MasterKeyConfig {
    /// The hash of the password.
    #[serde(with = "b64")]
    password_hash: Vec<u8>,
    /// The salt used to hash the password.
    #[serde(with = "b64")]
    salt: Vec<u8>,
    /// The algorithm used to generate this particular password hash.
    algorithm: Algorithm,
    /// Sequence of bytes XORed with the key derived from the password to
    /// obtain the master key.
    ///
    /// Currently, this is expected to always be exactly 32 bytes long.
    #[serde(with = "b64")]
    master_key_xor: Vec<u8>,
    /// The last time at which the master key was changed.
    ///
    /// The `MasterKey` code itself always generates `None` for this value.
    #[serde(default)]
    pub last_changed: Option<DateTime<FixedOffset>>,
}

/// A randomly generated master key and secondary keys derived from it.
///
/// Each user has a single, unalterable master key. See the module
/// documentation for more information.
///
/// This is a heavy-weight object, and its memory is locked from paging on
/// systems where this is possible.
pub struct MasterKey {
    master_key: SecBox<[u8; MASTER_SIZE]>,
}

impl MasterKey {
    /// Generate a new master key.
    pub fn new() -> Self {
        // Initialise to 0 and generate each byte individually so that the key
        // does not come into existence outside of the locked area.
        let mut key = SecBox::new(Box::new([0u8; MASTER_SIZE]));
        for i in 0..MASTER_SIZE {
            key.unsecure_mut()[i] = OsRng.gen();
        }
        MasterKey { master_key: key }
    }

    /// Return the symmetric AES encryption key to use for the given filename.
    ///
    /// The filename should be bare and OS-independent.
    pub fn aes_key(&self, filename: &str) -> [u8; AES_BLOCK] {
        let mut k = Kmac::v128(self.master_key.unsecure(), b"aes");
        k.update(filename.as_bytes());

        let mut ret = [0u8; AES_BLOCK];
        k.finalize(&mut ret);
        ret
    }

    /// Return the PEM passphrase to use for an RSA private key of the given
    /// name.
    pub fn pem_passphrase(&self, key_name: &str) -> String {
        let mut k = Kmac::v256(self.master_key.unsecure(), b"pem");
        k.update(key_name.as_bytes());

        let mut hash = [0u8; 32];
        k.finalize(&mut hash);
        base64::encode(&hash)
    }

    /// Given this key and a password, generate a `MasterKeyConfig` which can
    /// be used with that password to re-derive this key.
    ///
    /// The salt is randomly generated each call, so repeated calls will not
    /// yield identical objects.
    pub fn make_config(
        &self,
        password: &[u8],
    ) -> Result<MasterKeyConfig, argon2::Error> {
        let salt: [u8; 32] = OsRng.gen();
        let (password_hash, derived_key) =
            hash_password(password, &salt, Algorithm::default())?;

        let mut master_key_xor = vec![0u8; MASTER_SIZE];
        for i in 0..MASTER_SIZE {
            master_key_xor[i] = self.master_key.unsecure()[i] ^ derived_key[i];
        }

        Ok(MasterKeyConfig {
            password_hash: password_hash[..].to_owned(),
            salt: salt[..].to_owned(),
            algorithm: Algorithm::default(),
            master_key_xor,
            last_changed: None,
        })
    }

    /// Given a `MasterKeyConfig` generated by `make_config()` and a password,
    /// attempt to derive a `MasterKey`.
    ///
    /// Returns `None` if derivation fails for any reason.
    pub fn from_config(
        conf: &MasterKeyConfig,
        password: &[u8],
    ) -> Option<Self> {
        let (password_hash, derived_key) =
            hash_password(password, &conf.salt, conf.algorithm).ok()?;

        if password_hash.len() != conf.password_hash.len()
            || !openssl::memcmp::eq(&password_hash, &conf.password_hash)
            || MASTER_SIZE != conf.master_key_xor.len()
        {
            return None;
        }

        let mut key = SecBox::new(Box::new([0u8; MASTER_SIZE]));
        for i in 0..MASTER_SIZE {
            key.unsecure_mut()[i] = derived_key[i] ^ conf.master_key_xor[i];
        }

        Some(MasterKey { master_key: key })
    }
}

fn hash_password(
    password: &[u8],
    salt: &[u8],
    algorithm: Algorithm,
) -> Result<([u8; 32], [u8; 32]), argon2::Error> {
    let raw_hash = match algorithm {
        Algorithm::Argon2i_V13_M4096_T10_L1_Kmac256 => argon2::hash_raw(
            password,
            salt,
            &argon2::Config {
                hash_length: 32,
                lanes: 1,
                mem_cost: 4096,
                thread_mode: argon2::ThreadMode::Sequential,
                time_cost: 10,
                variant: argon2::Variant::Argon2i,
                version: argon2::Version::Version13,
                ..argon2::Config::default()
            },
        )?,
    };

    let mut password_hash = [0u8; 32];
    {
        let mut k = Kmac::v256(salt, b"check");
        k.update(&raw_hash);
        k.finalize(&mut password_hash);
    }

    let mut derived_key = [0u8; 32];
    {
        let mut k = Kmac::v256(salt, b"master");
        k.update(&raw_hash);
        k.finalize(&mut derived_key);
    }

    Ok((password_hash, derived_key))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn rederive_master_key() {
        let orig = MasterKey::new();
        let config = orig.make_config(b"hunter2").unwrap();
        let derived = MasterKey::from_config(&config, b"hunter2").unwrap();
        assert_eq!(orig.master_key, derived.master_key);
    }

    #[test]
    fn derive_fails_for_bad_password() {
        let config = MasterKey::new().make_config(b"hunter2").unwrap();
        assert!(MasterKey::from_config(&config, b"hunter3").is_none());
    }

    #[test]
    fn config_generation_makes_distinct_hashes() {
        let key = MasterKey::new();
        let config1 = key.make_config(b"hunter2").unwrap();
        let config2 = key.make_config(b"hunter2").unwrap();
        assert_ne!(config1.password_hash, config2.password_hash);
    }
}
