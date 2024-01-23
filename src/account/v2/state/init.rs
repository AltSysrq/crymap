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

use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;
use std::sync::Arc;

use super::super::storage;
use super::defs::*;
use crate::{
    account::{
        key_store::{KeyStore, KeyStoreConfig},
        model::*,
    },
    crypt::master_key::MasterKey,
    support::{
        error::Error, file_ops::IgnoreKinds, log_prefix::LogPrefix,
        user_config::UserConfig,
    },
};

impl Account {
    /// Sets up a new `Account` object in the given directory.
    ///
    /// The directory must already exist, but it need not have any contents.
    pub fn new(
        log_prefix: LogPrefix,
        root: PathBuf,
        master_key: Arc<MasterKey>,
    ) -> Result<Self, Error> {
        let common_paths = Arc::new(CommonPaths {
            tmp: root.join("tmp"),
            garbage: root.join("garbage"),
        });

        let key_store = KeyStore::new(
            log_prefix.clone(),
            root.join("keys"),
            common_paths.tmp.clone(),
            Some(Arc::clone(&master_key)),
        );

        let metadb_path = root.join(METADB_NAME);
        let deliverydb_path = root.join(DELIVERYDB_NAME);

        let xex_vfs = storage::XexVfs::new(Arc::clone(&master_key))?;
        let metadb =
            storage::MetaDb::new(&log_prefix, metadb_path.clone(), &xex_vfs)?;
        let deliverydb =
            storage::DeliveryDb::new(&log_prefix, &deliverydb_path)?;
        let message_store = storage::MessageStore::new(root.join("messages"));

        Ok(Self {
            master_key,
            metadb,
            metadb_path,
            deliverydb,
            deliverydb_path,
            message_store,
            key_store,
            backup_path: root.join("backups"),
            root,
            common_paths,
            log_prefix,
        })
    }

    /// Perform minimal initialisation of the account.
    ///
    /// This ensures that critical paths exist and initialises the key store.
    /// It should be called whenever the user logs in.
    pub fn init(
        &mut self,
        key_store_config: &KeyStoreConfig,
    ) -> Result<(), Error> {
        self.migrate_v1_to_v2()?;

        fs::DirBuilder::new()
            .mode(0o770)
            .create(&self.common_paths.tmp)
            .ignore_already_exists()?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&self.common_paths.garbage)
            .ignore_already_exists()?;
        self.key_store.init(key_store_config)?;

        // Ensure that, no matter what, we have an INBOX.
        self.create_if_nx(CreateRequest {
            name: "INBOX".to_owned(),
            special_use: vec![],
        })?;

        self.run_maintenance();

        Ok(())
    }

    /// Perform full provisioning of the account.
    ///
    /// In addition to everything `init()` does, this also creates the common
    /// special-use mailboxes:
    ///
    /// - Archive \Archive
    /// - Drafts \Drafts
    /// - Spam \Junk
    /// - Sent \Sent
    /// - Trash \Trash
    ///
    /// (INBOX is also created by way of `init()`.)
    ///
    /// The user configuration is also initialised to the defaults and the
    /// given password.
    pub fn provision(&mut self, password: &[u8]) -> Result<(), Error> {
        let user_config = UserConfig {
            master_key: self
                .master_key
                .make_config(password)
                .expect("Password hashing failed"),
            key_store: KeyStoreConfig::default(),
            smtp_out: Default::default(),
        };

        let user_config_toml = toml::to_vec(&user_config)
            .expect("Failed to serialise user config to TOML");
        fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(self.config_file())?
            .write_all(&user_config_toml)?;

        self.init(&user_config.key_store)?;

        self.create_if_nx(CreateRequest {
            name: "Archive".to_owned(),
            special_use: vec!["\\Archive".to_owned()],
        })?;
        self.create_if_nx(CreateRequest {
            name: "Drafts".to_owned(),
            special_use: vec!["\\Drafts".to_owned()],
        })?;
        self.create_if_nx(CreateRequest {
            name: "Spam".to_owned(),
            special_use: vec!["\\Junk".to_owned()],
        })?;
        self.create_if_nx(CreateRequest {
            name: "Sent".to_owned(),
            special_use: vec!["\\Sent".to_owned()],
        })?;
        self.create_if_nx(CreateRequest {
            name: "Trash".to_owned(),
            special_use: vec!["\\Trash".to_owned()],
        })?;

        // Subscribe to all the default mailboxes since some clients only show
        // subscribed things.
        self.subscribe("INBOX")?;
        self.subscribe("Archive")?;
        self.subscribe("Drafts")?;
        self.subscribe("Spam")?;
        self.subscribe("Sent")?;
        self.subscribe("Trash")?;

        Ok(())
    }
}
