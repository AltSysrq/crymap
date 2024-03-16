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

use std::borrow::Cow;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use chrono::prelude::*;

use super::super::storage;
use crate::{
    account::{key_store::KeyStore, model::*},
    crypt::master_key::MasterKey,
    support::{error::Error, log_prefix::LogPrefix, small_bitset::SmallBitset},
};

pub(super) const METADB_NAME: &str = "meta.sqlite.xex";
pub(super) const DELIVERYDB_NAME: &str = "delivery.sqlite";

/// A logged-in user account.
pub struct Account {
    pub(super) master_key: Arc<MasterKey>,
    pub(super) metadb: storage::MetaDb,
    pub(super) metadb_path: PathBuf,
    pub(super) deliverydb: storage::DeliveryDb,
    pub(super) deliverydb_path: PathBuf,
    pub(super) message_store: storage::MessageStore,
    pub(super) key_store: KeyStore,
    pub(super) root: PathBuf,
    pub(super) common_paths: Arc<CommonPaths>,
    pub(super) backup_path: PathBuf,
    pub(super) log_prefix: LogPrefix,
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
    /// The last `HIGHESTMODSEQ` reported by a full `poll` operation.
    pub(super) polled_snapshot_modseq: Modseq,
    /// Whether there is an unreported expunge in the backing store.
    pub(super) has_pending_expunge: bool,
    /// The `UIDNEXT` value. This is an exclusive upper bound on the UIDs that
    /// may be present in the mailbox snapshot.
    pub(super) next_uid: Uid,
    /// UIDs of messages whose flags have changed but have not yet been sent to
    /// the client.
    pub(super) changed_flags_uids: Vec<Uid>,
    /// When the client tries to fetch an addressable UID that's been expunged,
    /// we add it to this set. If it is there already, we kill the client
    /// connection. The set gets cleared on a full poll cycle. See
    /// `FetchResponseKind` for more details.
    pub(super) fetch_loopbreaker: HashSet<Uid>,
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

    pub fn common_paths(&self) -> Arc<CommonPaths> {
        Arc::clone(&self.common_paths)
    }
}

impl Mailbox {
    pub fn snapshot_modseq(&self) -> Modseq {
        self.snapshot_modseq
    }

    pub fn has_pending_expunge(&self) -> bool {
        self.has_pending_expunge
    }

    pub fn max_seqnum(&self) -> Seqnum {
        Seqnum::from_index(self.messages.len().saturating_sub(1))
    }

    pub fn next_uid(&self) -> Uid {
        self.next_uid
    }

    pub fn read_only(&self) -> bool {
        !self.writable
    }

    pub fn rfc8474_mailbox_id(&self) -> String {
        self.id.format_rfc8474()
    }

    /// Add the given UIDs into the internal pool of UIDs to be fetched later.
    pub fn add_changed_uids(&mut self, uids: impl Iterator<Item = Uid>) {
        self.changed_flags_uids.extend(uids);
    }

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
        for seqnum in seqnums.items(if silent {
            Seqnum::from_index(self.messages.len().saturating_sub(1)).into()
        } else {
            u32::MAX
        }) {
            let index = seqnum.to_index();
            if index < self.messages.len() {
                ret.append(index as u32);
            } else if !silent {
                return Err(Error::NxMessage);
            }
        }

        Ok(ret)
    }

    /// Translate a `SeqRange<Seqnum>` to `SeqRange<Uid>`.
    ///
    /// If `silent` is true, errors will be silently swallowed and the call
    /// never fails. Otherwise, an out-of-range `Seqnum` results in
    /// `NxMessage`.
    pub(super) fn seqnum_range_to_uid(
        &self,
        seqnums: &SeqRange<Seqnum>,
        silent: bool,
    ) -> Result<SeqRange<Uid>, Error> {
        let mut ret = SeqRange::new();
        for seqnum in seqnums.items(if silent {
            Seqnum::from_index(self.messages.len().saturating_sub(1)).into()
        } else {
            u32::MAX
        }) {
            let index = seqnum.to_index();
            if let Some(message) = self.messages.get(index) {
                ret.append(message.uid);
            } else if !silent {
                return Err(Error::NxMessage);
            }
        }

        Ok(ret)
    }

    /// Ensure a `SeqRange<Uid>` only references UIDs in this snapshot.
    pub(super) fn filter_uid_range<'a>(
        &self,
        uids: &'a SeqRange<Uid>,
    ) -> Cow<'a, SeqRange<Uid>> {
        if uids.len() > self.messages.len() {
            let mut ret = SeqRange::new();
            for m in self.messages.iter() {
                if uids.contains(m.uid) {
                    ret.append(m.uid);
                }
            }

            Cow::Owned(ret)
        } else if uids
            .items(u32::MAX)
            .all(|uid| self.uid_index(uid).is_some())
        {
            Cow::Borrowed(uids)
        } else {
            let mut ret = SeqRange::new();
            for uid in uids.items(u32::MAX) {
                if self.uid_index(uid).is_some() {
                    ret.append(uid);
                }
            }

            Cow::Owned(ret)
        }
    }

    /// Translate a `SeqRange<Uid>` to `SeqRange<Seqnum>`.
    ///
    /// If `silent` is true, errors will be silently swallowed and the call
    /// never fails. Otherwise, a non-existent `Uid` results in `NxMessage`.
    pub fn uid_range_to_seqnum(
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

    /// Returns the in-memory `FlagId` for the given flag.
    pub fn flag_id(&self, flag: &Flag) -> Option<storage::FlagId> {
        self.flags
            .iter()
            .find(|&&(_, ref f)| flag == f)
            .map(|&(id, _)| id)
    }

    pub fn count_unseen(&self) -> usize {
        let Some(unseen) = self.flag_id(&Flag::Seen) else {
            return 0;
        };

        self.messages
            .iter()
            .filter(|m| !m.flags.contains(unseen.0))
            .count()
    }

    pub fn count_deleted(&self) -> usize {
        let Some(deleted) = self.flag_id(&Flag::Deleted) else {
            return 0;
        };

        self.messages
            .iter()
            .filter(|m| m.flags.contains(deleted.0))
            .count()
    }

    #[cfg(test)]
    pub fn test_flag_o(&self, flag: &Flag, message: Uid) -> bool {
        let Some(flag_id) = self.flag_id(flag) else {
            return false;
        };

        let Some(index) = self.uid_index(message) else {
            return false;
        };

        self.messages[index].flags.contains(flag_id.0)
    }

    /// Returns a non-empty `Vec<Flag>` with all flags known to the mailbox if
    /// there are currently any which the client doesn't know about.
    pub(super) fn flags_response_if_changed(&mut self) -> Vec<Flag> {
        let greatest_id = self
            .flags
            .last()
            .expect("there is always at least one flag")
            .0;
        if greatest_id > self.max_client_known_flag_id {
            self.max_client_known_flag_id = greatest_id;
            self.flags.iter().map(|&(_, ref f)| f.clone()).collect()
        } else {
            vec![]
        }
    }
}

#[cfg(test)]
pub(super) struct TestFixture {
    pub(super) root: tempfile::TempDir,
    pub(super) account: Account,
}

#[cfg(test)]
impl TestFixture {
    pub(super) fn new() -> Self {
        let root = tempfile::TempDir::new().unwrap();
        let mut account = Account::new(
            LogPrefix::new("account".to_owned()),
            root.path().to_owned(),
            std::sync::Arc::new(crate::crypt::master_key::MasterKey::new()),
        )
        .unwrap();

        account.key_store.set_rsa_bits(1024);
        account.provision(b"hunter2").unwrap();

        Self { root, account }
    }

    pub(super) fn create(&mut self, name: &str) {
        self.account
            .create(CreateRequest {
                name: name.to_owned(),
                special_use: vec![],
            })
            .unwrap();
    }

    pub(super) fn simple_append(&mut self, dst: &str) -> Uid {
        self.simple_append_data(dst, "foobar".as_bytes())
    }

    pub(super) fn simple_append_data(&mut self, dst: &str, data: &[u8]) -> Uid {
        use crate::support::chronox::*;

        self.account
            .append(
                dst,
                FixedOffset::zero()
                    .from_utc_datetime(&Utc::now().naive_local()),
                std::iter::empty(),
                data,
            )
            .unwrap()
    }
}

#[cfg(test)]
impl std::ops::Deref for TestFixture {
    type Target = Account;

    fn deref(&self) -> &Account {
        &self.account
    }
}

#[cfg(test)]
impl std::ops::DerefMut for TestFixture {
    fn deref_mut(&mut self) -> &mut Account {
        &mut self.account
    }
}
