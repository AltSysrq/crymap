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
use crate::support::{error::Error, small_bitset::SmallBitset};

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
    /// The maximum flag ID currently known by the client.
    pub(super) max_client_known_flag_id: storage::FlagId,
    /// The `HIGHESTMODSEQ` currently reported.
    pub(super) snapshot_modseq: Modseq,
    /// The `next_uid` when the mailbox was initially selected.
    pub(super) initial_next_uid: Uid,
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

impl From<storage::InitialMessageStatus> for MessageStatus {
    fn from(m: storage::InitialMessageStatus) -> Self {
        Self {
            uid: m.uid,
            id: m.id,
            flags: m.flags,
            last_modified: m.last_modified,
            recent: m.recent,
            savedate: m.savedate.0,
        }
    }
}

impl Account {
    pub fn config_file(&self) -> PathBuf {
        self.root.join("user.toml")
    }
}

impl Mailbox {
    pub(super) fn require_writable(&self) -> Result<(), Error> {
        if self.writable {
            Ok(())
        } else {
            Err(Error::MailboxReadOnly)
        }
    }

    pub(super) fn uid_index(&self, uid: Uid) -> Option<usize> {
        self.messages.binary_search_by_key(&uid, |m| m.uid).ok()
    }

    /// Translate a `SeqRange<Seqnum>` to `SeqRange<usize>`.
    ///
    /// If `silent` is true, errors will be silently swallowed and the call
    /// never fails. Otherwise, an out-of-range `Seqnum` results in
    /// `NxMessage`.
    pub(super) fn seqnum_range_to_indices(
        &self,
        seqnums: &SeqRange<Seqnum>,
        silent: bool,
    ) -> Result<SeqRange<u32>, Error> {
        let mut ret = SeqRange::new();
        for seqnum in seqnums.items(u32::MAX) {
            let index = seqnum.to_index();
            if index < self.messages.len() {
                ret.append(index as u32);
            } else if !silent {
                return Err(Error::NxMessage);
            }
        }

        Ok(ret)
    }

    /// Translate a `SeqRange<Uid>` to `SeqRange<Seqnum>`.
    ///
    /// If `silent` is true, errors will be silently swallowed and the call
    /// never fails. Otherwise, a non-existent `Uid` results in `NxMessage`.
    pub(super) fn uid_range_to_seqnum(
        &self,
        uids: &SeqRange<Uid>,
        silent: bool,
    ) -> Result<SeqRange<Seqnum>, Error> {
        let mut ret = SeqRange::new();

        if uids.len() >= self.messages.len() && silent {
            // The client can request something like 1:1000000000, so if we're
            // going to be ignoring all the non-existing UIDs anyway, just see
            // which messages we know about are in the set if the set is bigger
            // than the message count.
            for (ix, m) in self.messages.iter().enumerate() {
                if uids.contains(m.uid) {
                    ret.append(Seqnum::from_index(ix));
                }
            }
        } else {
            for uid in uids.items(u32::MAX) {
                if let Some(index) = self.uid_index(uid) {
                    ret.append(Seqnum::from_index(index));
                } else if !silent {
                    return Err(Error::NxMessage);
                }
            }
        }

        Ok(ret)
    }

    /// Translate a `SeqRange<Uid>` to `SeqRange<usize>`.
    ///
    /// If `silent` is true, errors will be silently swallowed and the call
    /// never fails. Otherwise, a non-existent `Uid` results in `NxMessage`.
    pub(super) fn uid_range_to_indices(
        &self,
        uids: &SeqRange<Uid>,
        silent: bool,
    ) -> Result<SeqRange<u32>, Error> {
        let mut ret = SeqRange::new();

        if uids.len() >= self.messages.len() && silent {
            // The client can request something like 1:1000000000, so if we're
            // going to be ignoring all the non-existing UIDs anyway, just see
            // which messages we know about are in the set if the set is bigger
            // than the message count.
            for (ix, m) in self.messages.iter().enumerate() {
                if uids.contains(m.uid) {
                    ret.append(ix as u32);
                }
            }
        } else {
            for uid in uids.items(u32::MAX) {
                if let Some(index) = self.uid_index(uid) {
                    ret.append(index as u32);
                } else if !silent {
                    return Err(Error::NxMessage);
                }
            }
        }

        Ok(ret)
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
