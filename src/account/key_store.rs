//-
// Copyright (c) 2020, 2023, Jason Lingle
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

//! Implementation for the per-user key store.
//!
//! The key store itself is a flat set of files. Private keys are stored in
//! files ending with `.pem`. The part of the file name before `.pem` is the
//! key name. Private keys are stored in PEM format with a passphrase derived
//! from the master key.
//!
//! A single public key is stored in `public`. This file consists of a single
//! line containing the key name, followed by the PEM format of the public key.
//!
//! The public key files are only used when the master key is unavailable
//! (i.e., when delivering mail through an MTA). When the master key is
//! available, public keys are derived from the private keys.
//!
//! The user can configure date-based patterns to be used for internal and
//! external encryption, enabling automatic date-based key rotation. Key
//! rotation can only occur when the user is logged in.

use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use log::{info, warn};
use openssl::{
    pkey::{Private, Public},
    rsa::Rsa,
};
use serde::{Deserialize, Serialize};

use crate::{
    crypt::master_key::MasterKey,
    support::{
        error::Error,
        file_ops::{self, IgnoreKinds},
        log_prefix::LogPrefix,
        safe_name::is_safe_name,
    },
};

const RSA_BITS: u32 = 4096;
const MAX_KEY_FILE_SIZE: u64 = 256 * 1024;

/// Section in the user configuration which controls key assignment and
/// rotation.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct KeyStoreConfig {
    /// The key name pattern used to assign key pairs to internal operations.
    ///
    /// Internal operations are those which are done while the user is logged
    /// in, such as copying mail in from another IMAP server. Keys generated
    /// for internal use do not have a public key stored on disk.
    ///
    /// This is a `strftime`-style  pattern.
    ///
    /// This value must be a "safe string".
    pub internal_key_pattern: String,
    /// The key name pattern used to assign key pairs to external operations.
    ///
    /// External operations are those which are done when the user is *not*
    /// logged in, such as receiving mail through an MTA. Keys generated for
    /// external use have both the public and private keys stored on disk
    /// separately.
    ///
    /// This is a `strftime`-style  pattern.
    ///
    /// During key rotation, any public keys not corresponding to the current
    /// key are deleted.
    ///
    /// This value must be a "safe string".
    pub external_key_pattern: String,
}

impl Default for KeyStoreConfig {
    fn default() -> Self {
        KeyStoreConfig {
            internal_key_pattern: "internal-%Y-%m".to_owned(),
            external_key_pattern: "external-%Y-%m".to_owned(),
        }
    }
}

/// Maintains the key store.
///
/// This can operated in "logged in" mode with a `MasterKey` or in "external"
/// mode without one.
///
/// Public and private keys loaded are cached within this struct. To avoid
/// keeping them in memory too long, long-term processes such as the IMAP
/// server itself should regularly call `clear_cache()` to clear these caches.
pub struct KeyStore {
    log_prefix: LogPrefix,
    root: PathBuf,
    tmp: PathBuf,
    master_key: Option<Arc<MasterKey>>,
    private_keys: HashMap<String, Arc<Rsa<Private>>>,
    public_key: Option<(String, Rsa<Public>)>,
    preferred_private_key: Option<String>,
    rsa_bits: u32,
}

impl KeyStore {
    pub fn new(
        log_prefix: LogPrefix,
        root: PathBuf,
        tmp: PathBuf,
        master_key: Option<Arc<MasterKey>>,
    ) -> Self {
        KeyStore {
            log_prefix,
            root,
            tmp,
            master_key,
            private_keys: HashMap::new(),
            public_key: None,
            preferred_private_key: None,
            rsa_bits: RSA_BITS,
        }
    }

    /// Used by tests to make things faster.
    ///
    /// In real code, the RSA bit count is effectively pegged to `RSA_BITS`.
    #[cfg(test)]
    pub fn set_rsa_bits(&mut self, bits: u32) {
        self.rsa_bits = bits;
    }

    /// Initialise the key store.
    ///
    /// This creates the key store root if it does not already exist.
    ///
    /// If the current preferred key names do not correspond to existing keys,
    /// those keys are generated and the `public` file if applicable is
    /// updated.
    pub fn init(&mut self, config: &KeyStoreConfig) -> Result<(), Error> {
        // Create the key store root if it doesn't already exist
        fs::DirBuilder::new()
            .mode(0o750)
            .create(&self.root)
            .ignore_already_exists()?;

        // Determine the current preferred key names
        let now = chrono::Utc::now();
        let preferred_internal =
            now.format(&config.internal_key_pattern).to_string();
        let preferred_external =
            now.format(&config.external_key_pattern).to_string();

        // Create external first, so if both have the same name, we still get
        // the public key saved on disk.
        let created_external =
            self.create_key_if_not_exists(&preferred_external)?;
        self.create_key_if_not_exists(&preferred_internal)?;

        self.preferred_private_key = Some(preferred_internal);

        if let Some(created_external) = created_external {
            let mut public_data = Vec::<u8>::new();
            writeln!(public_data, "{}", preferred_external)?;
            let mut pem = created_external.public_key_to_pem()?;
            public_data.append(&mut pem);
            file_ops::spit(
                &self.tmp,
                self.root.join("public"),
                true,
                0o440,
                &public_data,
            )?;
            info!(
                "{} Default public key is now '{}'",
                self.log_prefix, preferred_external
            );
        }

        Ok(())
    }

    /// If the key named by `name` does not exist yet, generate and create it.
    ///
    /// If a key was generated and placed at the final location, return that
    /// key.
    ///
    /// If the key already existed (including if another process created
    /// between checking for existence and placing it), return `None`.
    fn create_key_if_not_exists(
        &mut self,
        name: &str,
    ) -> Result<Option<Rsa<Private>>, Error> {
        if !is_safe_name(name) {
            return Err(Error::UnsafeName);
        }

        let master_key = self
            .master_key
            .as_ref()
            .ok_or(Error::MasterKeyUnavailable)?;

        let filename = format!("{}.pem", name);
        let path = self.root.join(&filename);

        if path.is_file() {
            return Ok(None);
        }

        // Doesn't exist, generate the new key
        info!(
            "{} Generating new {}-bit RSA key '{}'",
            self.log_prefix, self.rsa_bits, name
        );
        let generated_key = Rsa::generate(self.rsa_bits)?;
        let generated_key_bytes = generated_key.private_key_to_pem_passphrase(
            // AEAD ciphers aren't supported here
            openssl::symm::Cipher::aes_128_cbc(),
            master_key.pem_passphrase(name).as_bytes(),
        )?;

        match file_ops::spit(
            &self.tmp,
            path,
            false,
            0o400,
            &generated_key_bytes,
        ) {
            Ok(_) => {
                info!(
                    "{} Created '{}' successfully",
                    self.log_prefix, filename
                );
                Ok(Some(generated_key))
            },
            Err(e) if io::ErrorKind::AlreadyExists == e.kind() => {
                info!("{} Lost race to create '{}'", self.log_prefix, filename);
                Ok(None)
            },
            Err(e) => {
                warn!(
                    "{} Failed to create '{}': {}",
                    self.log_prefix, filename, e
                );
                Err(e.into())
            },
        }
    }

    /// Get the default public key to use for encrypting new items.
    ///
    /// If the master key is available and the store has been fully
    /// initialised, the preferred private key is loaded and its public key is
    /// used.
    ///
    /// Otherwise, the external public key is loaded.
    ///
    /// Results from this call are cached.
    ///
    /// On success, returns the key name and the key itself.
    pub fn get_default_public_key(
        &mut self,
    ) -> Result<(&str, &Rsa<Public>), Error> {
        if let Some((ref name, ref key)) = self.public_key {
            return Ok((name, key));
        }

        if let (&Some(ref master_key), &Some(ref name)) =
            (&self.master_key, &self.preferred_private_key)
        {
            let priv_key = load_private_key(
                master_key,
                name,
                &self.root,
                &mut self.private_keys,
            )?;
            let pub_key = Rsa::from_public_components(
                priv_key.n().to_owned()?,
                priv_key.e().to_owned()?,
            )?;

            self.public_key = Some((name.to_owned(), pub_key));
        } else {
            let mut reader = io::BufReader::new(
                fs::File::open(self.root.join("public"))?
                    .take(MAX_KEY_FILE_SIZE),
            );
            let mut name = String::new();
            reader.read_line(&mut name)?;
            // Drop the trailing LF
            name.truncate(name.len() - 1);
            if !is_safe_name(&name) {
                return Err(Error::UnsafeName);
            }

            let mut pem_data = Vec::new();
            reader.read_to_end(&mut pem_data)?;

            let pub_key = Rsa::public_key_from_pem(&pem_data)?;

            self.public_key = Some((name, pub_key));
        }

        Ok(self
            .public_key
            .as_ref()
            .map(|&(ref name, ref key)| (&**name, key))
            .unwrap())
    }

    /// Return the private key of the given name.
    ///
    /// The result is cached.
    pub fn get_private_key(
        &mut self,
        name: &str,
    ) -> Result<Arc<Rsa<Private>>, Error> {
        let master_key = self
            .master_key
            .as_ref()
            .ok_or(Error::MasterKeyUnavailable)?;

        match load_private_key(
            master_key,
            name,
            &self.root,
            &mut self.private_keys,
        ) {
            Ok(k) => Ok(k),
            Err(Error::Io(e)) if io::ErrorKind::NotFound == e.kind() => {
                Err(Error::NamedKeyNotFound)
            },
            Err(e) => Err(e),
        }
    }

    /// Clear all cached keys.
    pub fn clear_cache(&mut self) {
        self.public_key = None;
        self.private_keys.clear();
    }
}

fn load_private_key(
    master_key: &MasterKey,
    name: &str,
    root: &Path,
    cache: &mut HashMap<String, Arc<Rsa<Private>>>,
) -> Result<Arc<Rsa<Private>>, Error> {
    if !is_safe_name(name) {
        return Err(Error::UnsafeName);
    }

    if cache.contains_key(name) {
        return Ok(Arc::clone(cache.get(name).unwrap()));
    }

    let mut pem_data = Vec::new();
    fs::File::open(root.join(format!("{}.pem", name)))?
        .take(MAX_KEY_FILE_SIZE)
        .read_to_end(&mut pem_data)?;
    let priv_key = Rsa::private_key_from_pem_passphrase(
        &pem_data,
        master_key.pem_passphrase(name).as_bytes(),
    )?;

    Ok(Arc::clone(
        cache
            .entry(name.to_owned())
            .or_insert_with(|| Arc::new(priv_key)),
    ))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_key_store() {
        let root = tempfile::tempdir().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let master_key = Arc::new(MasterKey::new());

        let mut authed_store = KeyStore::new(
            LogPrefix::new("authed".to_owned()),
            root.path().to_owned(),
            tmp.path().to_owned(),
            Some(Arc::clone(&master_key)),
        );
        let mut anon_store = KeyStore::new(
            LogPrefix::new("anon".to_owned()),
            root.path().to_owned(),
            tmp.path().to_owned(),
            None,
        );

        authed_store
            .init(&KeyStoreConfig {
                internal_key_pattern: "internal1".to_owned(),
                external_key_pattern: "external1".to_owned(),
            })
            .unwrap();
        // Init twice to ensure it tolerates the files already existing
        authed_store
            .init(&KeyStoreConfig {
                internal_key_pattern: "internal1".to_owned(),
                external_key_pattern: "external1".to_owned(),
            })
            .unwrap();

        {
            let (name, _) = anon_store.get_default_public_key().unwrap();
            assert_eq!("external1", name);
        }

        {
            let (name, _) = authed_store.get_default_public_key().unwrap();
            assert_eq!("internal1", name);
        }

        authed_store.get_private_key("internal1").unwrap();
        authed_store.get_private_key("external1").unwrap();

        authed_store.clear_cache();
        anon_store.clear_cache();

        authed_store
            .init(&KeyStoreConfig {
                internal_key_pattern: "internal2".to_owned(),
                external_key_pattern: "external2".to_owned(),
            })
            .unwrap();

        {
            let (name, _) = anon_store.get_default_public_key().unwrap();
            assert_eq!("external2", name);
        }

        {
            let (name, _) = authed_store.get_default_public_key().unwrap();
            assert_eq!("internal2", name);
        }

        authed_store.get_private_key("internal1").unwrap();
        authed_store.get_private_key("external1").unwrap();
        authed_store.get_private_key("internal2").unwrap();
        authed_store.get_private_key("external2").unwrap();

        assert!(matches!(
            authed_store.get_private_key("nx"),
            Err(Error::NamedKeyNotFound)
        ));
        assert!(matches!(
            anon_store.get_private_key("internal1"),
            Err(Error::MasterKeyUnavailable)
        ));
    }
}
