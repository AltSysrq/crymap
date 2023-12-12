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

use std::path::PathBuf;
use std::sync::Arc;

use chrono::prelude::*;

use super::super::storage;
use crate::account::{key_store::KeyStore, model::*};
use crate::crypt::master_key::MasterKey;
use crate::support::small_bitset::SmallBitset;

/// A logged-in user account.
pub struct Account {
    pub(super) master_key: Arc<MasterKey>,
    pub(super) metadb: storage::MetaDb,
    pub(super) deliverydb: storage::DeliveryDb,
    pub(super) message_store: storage::MessageStore,
    pub(super) key_store: KeyStore,
    pub(super) root: PathBuf,
    pub(super) common_paths: Arc<CommonPaths>,
    pub(super) log_prefix: String,
}

/// The state for a selected mailbox.
#[derive(Clone, Debug)]
pub struct Mailbox {
    /// The unique ID of the mailbox.
    pub(super) id: storage::MailboxId,
    /// Whether the mailbox is opened in writable mode.
    pub(super) writable: bool,
    /// The messages currently known to this session, sorted ascending by UID.
    ///
    /// Sequence numbers are indices-plus-one into this `Vec`.
    pub(super) messages: Vec<MessageStatus>,
    /// The flags currently known to this session, sorted ascending by ID.
    pub(super) flags: Vec<(storage::FlagId, Flag)>,
    /// The `HIGHESTMODSEQ` currently reported.
    pub(super) snapshot_modseq: Modseq,
    /// UIDs of messages whose flags have changed but have not yet been sent to
    /// the client.
    pub(super) changed_flags_uids: Vec<Uid>,
}

/// Information about a message retained in a selected mailbox.
#[derive(Clone, Debug)]
pub(super) struct MessageStatus {
    /// The UID of the message within the mailbox.
    pub(super) uid: Uid,
    /// The ID of the message itself.
    pub(super) id: storage::MessageId,
    /// The flags of the message.
    pub(super) flags: SmallBitset,
    /// The latest modseq of the message.
    pub(super) last_modified: Modseq,
    /// Whether the message is considered `\Recent` in this session.
    pub(super) recent: bool,
    /// The `SAVEDATE` of the message.
    pub(super) savedate: DateTime<Utc>,
}

impl Account {
    pub fn config_file(&self) -> PathBuf {
        self.root.join("user.toml")
    }
}

#[cfg(test)]
pub(super) struct TestFixture {
    _root: tempfile::TempDir,
    pub(super) account: Account,
}

#[cfg(test)]
impl TestFixture {
    pub(super) fn new() -> Self {
        let root = tempfile::TempDir::new().unwrap();
        let mut account = Account::new(
            "account".to_owned(),
            root.path().to_owned(),
            std::sync::Arc::new(crate::crypt::master_key::MasterKey::new()),
        )
        .unwrap();

        account.key_store.set_rsa_bits(1024);
        account.provision(b"hunter2").unwrap();

        Self {
            _root: root,
            account,
        }
    }

    pub(super) fn create(&mut self, name: &str) {
        self.account
            .create(CreateRequest {
                name: name.to_owned(),
                special_use: vec![],
            })
            .unwrap();
    }
}
