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

//! Logic for maintaining the "active" state of a mailbox.
//!
//! Nothing here does I/O; it's simply the pure state management.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::mem;

use serde::{Deserialize, Serialize};

use super::model::*;
use crate::support::error::Error;

#[cfg(not(test))]
const MAX_RECENT_EXPUNGEMENTS: usize = 1024;
#[cfg(test)]
const MAX_RECENT_EXPUNGEMENTS: usize = 4;

/// A rollup of all mutable metadata in a single mailbox, as well as the
/// current Seqnum-Uid mapping.
///
/// Its serialised form is used for the rollup files themselves and excludes
/// transient information.
///
/// All mutations take the form of message creation and `StateTransaction`
/// values.
///
/// This struct holds the `\\Recent` status for every message, but does not
/// contain the logic to maintain it.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct MailboxState {
    /// The table of known flags.
    ///
    /// This is used to translate every `Flag` into an integer which indexes
    /// each message's `flags` bitset, so that the full `Flag` object does not
    /// need to be repeated many times in memory or on disk.
    flags: Vec<Flag>,

    /// The UIDs of the current non-expunged messages.
    ///
    /// Sequence numbers correspond (with bias 1) to the elements in this array
    /// from 0..`len-unapplied_create`. That part of the array is therefore
    /// sorted ascending.
    ///
    /// When a new UID is observed, either through a direct call to `seen()`
    /// or observing a transaction that implies its existence, it is tacked on
    /// to the end and `unapplied_create` is incremented. This appending is
    /// always in-order so no separate sorting or deduplication is required.
    ///
    /// When expungements are observed, the UIDs are added to
    /// `unapplied_expunge` and are only later removed from this list.
    ///
    /// This is used for translating between `Seqnum`s and `Uid`s and for the
    /// `EXISTS` response.
    extant_messages: Vec<Uid>,

    /// Information about each non-expunged UID. Unlike `extant_messages`, this
    /// is updated immediately as changes come in.
    ///
    /// When a new UID is observed, either through a direct call to `seen()`
    /// or observing a transaction that implies its existence, it is
    /// immediately added to this map with empty flags and a `GENESIS` CID.
    ///
    /// When an expungement is observed, the entry for the UID is immediately
    /// removed.
    message_status: HashMap<Uid, MessageStatus>,

    /// The greatest known `Modseq` currently in the system.
    ///
    /// This is updated immediately as new transactions arrive.
    ///
    /// The UID is always the greatest UID seen so far, and the CID is the
    /// greatest CID seen so far.
    max_modseq: Option<Modseq>,

    /// The most recent expungements.
    ///
    /// As new expungements are observed, they are appended to this value, and
    /// then it is trimmed to be at most `MAX_RECENT_EXPUNGEMENTS` elements
    /// long.
    ///
    /// This is used for `QRESYNC` requests to be able to return compact
    /// `VANISHED (EARLIER)` lists when the client isn't excessively out of
    /// date.
    recent_expungements: VecDeque<(Modseq, Uid)>,

    /// The number of new elements in `extant_messages` that are not considered
    /// to have sequence numbers.
    ///
    /// Subtracting this from the length of `extant_messages` gives the size of
    /// the mailbox from the perspective of the current snapshot and the
    /// maximum sequence number.
    #[serde(skip)]
    unapplied_create: usize,

    /// UIDs which have been expunged but are still present in
    /// `extant_messages`.
    #[serde(skip)]
    unapplied_expunge: Vec<Uid>,

    /// The maximum `Modseq` that has been reported to the client.
    ///
    /// `CONDSTORE` requires that we do not update this until the client has
    /// actually seen all the new and expunged messages, but we are not allowed
    /// to send the client that information until it performs a command type
    /// that allows it.
    #[serde(skip)]
    report_max_modseq: Option<Modseq>,

    /// UIDs which have seen flag changes that should be passed on to the
    /// client once possible.
    #[serde(skip)]
    changed_flags_uids: Vec<Uid>,
}

/// The current status for a single message.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MessageStatus {
    /// The flags currently set on this message.
    ///
    /// This is a bitset. Flag N is found at byte N/8 and bit N%8. Bytes past
    /// the end of the vec are implicitly 0.
    #[serde(rename = "f", with = "serde_bytes")]
    flags: Vec<u8>,
    /// The `Modseq` of the last point at which this message was modified.
    #[serde(rename = "m")]
    last_modified: Modseq,
    /// The per-session recency status.
    #[serde(skip)]
    recent: bool,
}

impl MailboxState {
    /// Return a new, empty metadata state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Notify the metadata tracker that the given UID has been observed.
    ///
    /// If this is a formerly unseen message, it is assumed to exist and is
    /// added to the internal data structures.
    ///
    /// The new UID is not assigned a sequence number immediately, and can
    /// potentially be expunged before it ever gains a sequence number.
    pub fn seen(&mut self, uid: Uid) {
        let this_uid = uid.0.get();
        let last_uid = self.max_modseq.map(|m| m.uid().0.get()).unwrap_or(0);

        if this_uid > last_uid {
            for uid in last_uid + 1..=this_uid {
                let uid = Uid::of(uid).unwrap();
                self.extant_messages.push(uid);
                self.unapplied_create += 1;
                self.message_status.insert(
                    uid,
                    MessageStatus {
                        flags: vec![],
                        last_modified: Modseq::new(uid, Cid::GENESIS),
                        recent: false,
                    },
                );
            }

            self.max_modseq = Some(
                self.max_modseq
                    .map(|m| m.with_uid(uid))
                    .unwrap_or(Modseq::new(uid, Cid::GENESIS)),
            );
        }
    }

    /// Start a new transaction.
    ///
    /// This only fails if there are no more CIDs available.
    ///
    /// Panics if the mailbox is still in primordial state.
    pub fn start_tx(&self) -> Result<(Cid, StateTransaction), Error> {
        let m = self
            .max_modseq
            .expect("start_tx with no messages")
            .next()
            .ok_or(Error::MailboxFull)?;

        Ok((
            m.cid(),
            StateTransaction {
                max_uid: m.uid(),
                ops: Vec::new(),
            },
        ))
    }

    /// Generate a new `Cid` for the given transaction so that it can be
    /// retried.
    ///
    /// This only fails if there are no more CIDs available.
    ///
    /// Panics if the mailbox is still in primordial state or if `cid` is
    /// already newer than the latest `Modseq`.
    pub fn retry_tx(&self, cid: Cid) -> Result<Cid, Error> {
        let m = self
            .max_modseq
            .expect("retry_tx with no messages")
            .next()
            .ok_or(Error::MailboxFull)?;

        assert!(m.cid() > cid);
        Ok(m.cid())
    }

    /// Determine whether the given transaction is safe to commit by comparing
    /// the `Modseq` on messages it affects with the given `starting_cid`.
    pub fn check(&self, tx: &StateTransaction, starting_cid: Cid) -> bool {
        for op in &tx.ops {
            use self::StateMutation::*;
            match op {
                &AddFlag(uid, _) | &RmFlag(uid, _) | &Expunge(uid) => {
                    if let Some(status) = self.message_status.get(&uid) {
                        if status.last_modified.cid() >= starting_cid {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
            }
        }

        true
    }

    /// Commit the given transaction.
    ///
    /// This is used for both things from the local process and for events from
    /// on disk.
    ///
    /// Any new UIDs implied to exist by the transaction are noticed and
    /// implicitly added.
    ///
    /// Modifications to flags take effect immediately, and expunged messages
    /// are immediately forgotten except for their position in the sequence
    /// numbering.
    ///
    /// The maximum `Modseq` is updated to account for the transaction.
    ///
    /// Sequence numbering is not affected immediately. New UIDs do not get
    /// assigned a sequence number, and expunged ones retain their old sequence
    /// number.
    ///
    /// If `notify` is false, changes to flags will not result in the affected
    /// UIDs being queued for client notification.
    ///
    /// ## Panics
    ///
    /// Panics if `tx` does not have the expected next CID.
    pub fn commit(&mut self, cid: Cid, tx: StateTransaction, notify: bool) {
        // Ensure transactions are committed in order
        assert_eq!(self.next_cid().unwrap(), cid);

        // Add any new messages implied by the transaction
        //
        // This needs to happen before we do anything else since it uses
        // `max_modseq` to determine which UIDs are new.
        self.seen(tx.max_uid);

        // Advance our own idea of the maximum modseq
        let nominal_modseq = Modseq::new(tx.max_uid, cid);
        let canonical_modseq = self
            .max_modseq
            .map(|m| m.combine(nominal_modseq))
            .unwrap_or(nominal_modseq);
        self.max_modseq = Some(canonical_modseq);

        let m = canonical_modseq;
        for op in tx.ops {
            use self::StateMutation::*;
            match op {
                AddFlag(uid, flag) => self.set_flag(uid, m, flag, true, notify),
                RmFlag(uid, flag) => self.set_flag(uid, m, flag, false, notify),
                Expunge(uid) => self.expunge(uid, m),
            }
        }
    }

    /// Flush all pending operations that needed to be buffered.
    ///
    /// Sequence numbers are updated, so that new UIDs are addressable through
    /// sequence numbers, and expunged messages lose their sequence numbers.
    ///
    /// The reported max `Modseq` is updated to the actual, current `Modseq`.
    pub fn flush(&mut self) -> FlushResponse {
        let mut unapplied_create = self.unapplied_create;

        let mut expunged_pairs: Vec<(Seqnum, Uid)> = Vec::new();
        let mut stillborn: Vec<Uid> = Vec::new();
        if !self.unapplied_expunge.is_empty() {
            let max_index = self.num_messages();

            self.unapplied_expunge.sort_unstable();
            self.unapplied_expunge.dedup();
            let mut expunged = self.unapplied_expunge.drain(..).peekable();
            let mut index = 0;

            // Note that this will also expunge things from the
            // unapplied_create range. We need to ensure we don't add those to
            // expunged_pairs since the client never got to see them in the
            // first place.
            self.extant_messages.retain(|&uid| loop {
                let next_expunged =
                    expunged.peek().copied().unwrap_or(Uid::MAX);
                if next_expunged < uid {
                    expunged.next();
                } else if next_expunged == uid {
                    if index < max_index {
                        expunged_pairs.push((Seqnum::from_index(index), uid));
                    } else {
                        // Account for the fact that we removed this one when
                        // we later look for which messages are new.
                        unapplied_create -= 1;
                        stillborn.push(uid);
                    }
                    index += 1;
                    return false;
                } else {
                    index += 1;
                    return true;
                }
            });
        }

        let first_new = self.extant_messages.len() - unapplied_create;
        let new_message_pairs: Vec<(Seqnum, Uid)> = self.extant_messages
            [first_new..]
            .iter()
            .copied()
            .enumerate()
            .map(|(ix, uid)| (Seqnum::from_index(ix + first_new), uid))
            .collect();

        self.unapplied_create = 0;
        self.report_max_modseq = self.max_modseq;

        FlushResponse {
            new: new_message_pairs,
            expunged: expunged_pairs,
            stillborn,
            max_modseq: self.max_modseq,
        }
    }

    /// Return a vec of UIDs whose flags have changed since the last call to
    /// this function.
    pub fn take_changed_flags_uids(&mut self) -> Vec<Uid> {
        self.changed_flags_uids.sort_unstable();
        self.changed_flags_uids.dedup();
        mem::replace(&mut self.changed_flags_uids, Vec::new())
    }

    /// Add the given UID to the next value that will be returned from
    /// `take_changed_flags_uids()`.
    pub fn add_changed_flags_uid(&mut self, uid: Uid) {
        self.changed_flags_uids.push(uid);
    }

    /// Returns the number of messages currently addressable by sequence
    /// numbers.
    pub fn num_messages(&self) -> usize {
        self.extant_messages.len() - self.unapplied_create
    }

    /// Translate the given sequence number into a UID.
    ///
    /// On failure, return `Error::NxMessage`.
    pub fn seqnum_to_uid(&self, seqnum: Seqnum) -> Result<Uid, Error> {
        self.extant_messages[..self.num_messages()]
            .get(seqnum.to_index())
            .copied()
            .ok_or(Error::NxMessage)
    }

    /// Translate a `SeqRange<Seqnum>` to `SeqRange<Uid>`.
    ///
    /// If `silent` is true, errors will be silently swallowed and the call
    /// never fails. Otherwise, the first failure from `seqnum_to_uid()` is
    /// propagated.
    pub fn seqnum_range_to_uid(
        &self,
        seqnums: &SeqRange<Seqnum>,
        silent: bool,
    ) -> Result<SeqRange<Uid>, Error> {
        let mut ret = SeqRange::new();
        for seqnum in seqnums.items(u32::MAX) {
            match self.seqnum_to_uid(seqnum) {
                Ok(uid) => ret.append(uid),
                Err(_) if silent => (),
                Err(e) => return Err(e),
            }
        }

        Ok(ret)
    }

    /// Translate the given UID into a sequence number according to the current
    /// regime.
    ///
    /// On failure, return `Error::ExpungedMessage` if the UID is allocated but
    /// no longer exists, `Error::NxMessage` if the UID is not allocated, or
    /// `Error::UnaddressableMessage` if the UID references an existing message
    /// but is not accessible through the current sequence number regime.
    pub fn uid_to_seqnum(&self, uid: Uid) -> Result<Seqnum, Error> {
        if self.max_modseq.map(|m| uid > m.uid()).unwrap_or(true) {
            return Err(Error::NxMessage);
        }

        self.extant_messages[..self.num_messages()]
            .binary_search(&uid)
            .map(Seqnum::from_index)
            .map_err(|_| {
                if self.extant_messages[self.num_messages()..]
                    .binary_search(&uid)
                    .is_ok()
                {
                    Error::UnaddressableMessage
                } else {
                    Error::ExpungedMessage
                }
            })
    }

    /// Translate a `SeqRange<Uid>` to `SeqRange<Seqnum>`.
    ///
    /// If `silent` is true, errors will be silently swallowed and the call
    /// never fails. Otherwise, the first failure from `uid_to_seqnum()` is
    /// propagated.
    pub fn uid_range_to_seqnum(
        &self,
        uids: &SeqRange<Uid>,
        silent: bool,
    ) -> Result<SeqRange<Seqnum>, Error> {
        let mut ret = SeqRange::new();
        for uid in uids.items(u32::MAX) {
            match self.uid_to_seqnum(uid) {
                Ok(seqnum) => ret.append(seqnum),
                Err(_) if silent => (),
                Err(e) => return Err(e),
            }
        }

        Ok(ret)
    }

    /// Return whether the given UID currently has an assigned sequence number.
    pub fn is_assigned_uid(&self, uid: Uid) -> bool {
        self.extant_messages[..self.num_messages()]
            .binary_search(&uid)
            .is_ok()
    }

    /// Ensure `uid` is valid.
    ///
    /// If it references an expunged message, return
    /// `Err(Error::ExpungedMessage)`. If it references an unallocated UID,
    /// return `Err(Error::NxMessage)`.
    ///
    /// This will accept UIDs which are not currently addressable by sequence
    /// number.
    pub fn validate_uid(&self, uid: Uid) -> Result<(), Error> {
        if self.max_modseq.map(|m| uid > m.uid()).unwrap_or(true) {
            Err(Error::NxMessage)
        } else if !self.message_status.contains_key(&uid) {
            Err(Error::ExpungedMessage)
        } else {
            Ok(())
        }
    }

    /// Return the appropriate error code for a UID, given that it the message
    /// it represents was just found to be missing.
    pub fn missing_uid_error(&self, uid: Uid) -> Error {
        if self.max_modseq.map(|m| uid > m.uid()).unwrap_or(true) {
            Error::NxMessage
        } else {
            Error::ExpungedMessage
        }
    }

    /// Return the raw value of the maximum allocated UID, or 0 if none.
    pub fn max_uid_val(&self) -> u32 {
        self.max_modseq.map(|m| m.uid().0.get()).unwrap_or(0)
    }

    /// Intern `flag` into this state, and return its internal ID.
    pub fn flag_id_mut(&mut self, flag: Flag) -> FlagId {
        FlagId(self.flag_ix_mut(flag))
    }

    /// Return the internal ID of the given flag, or `None` if it does not have
    /// one assigned.
    pub fn flag_id(&self, flag: &Flag) -> Option<FlagId> {
        self.flag_ix(flag).map(FlagId)
    }

    /// Return the flag corresponding to the given flag ID.
    pub fn flag(&self, flag_id: FlagId) -> Option<&Flag> {
        self.flags.get(flag_id.0)
    }

    /// Return an iterator to the flags in this state and their IDs.
    pub fn flags<'a>(
        &'a self,
    ) -> impl Iterator<Item = (FlagId, &'a Flag)> + 'a {
        self.flags.iter().enumerate().map(|(ix, f)| (FlagId(ix), f))
    }

    /// Query the current state of the given flag on the given message.
    ///
    /// If the message does not exist, returns false.
    pub fn test_flag(&self, flag: FlagId, message: Uid) -> bool {
        let flag = flag.0;
        let byte = flag / 8;
        let bit = flag % 8;

        if let Some(status) = self.message_status.get(&message) {
            if let Some(b) = status.flags.get(byte) {
                0 != (b & (1 << bit))
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Convenience for invoking `test_flag` with a `Flag`.
    pub fn test_flag_o(&self, flag: &Flag, message: Uid) -> bool {
        self.flag_id(flag)
            .map(|f| self.test_flag(f, message))
            .unwrap_or(false)
    }

    /// Permanently set the `\\Recent` "flag" on the given message.
    ///
    /// Has no effect if the message has been expunged.
    pub fn set_recent(&mut self, uid: Uid) {
        if let Some(status) = self.message_status.get_mut(&uid) {
            status.recent = true;
        }
    }

    /// Return whether the given message has the `\\Recent` "flag".
    ///
    /// Returns false if the message has been expunged.
    pub fn is_recent(&self, uid: Uid) -> bool {
        self.message_status
            .get(&uid)
            .map(|m| m.recent)
            .unwrap_or(false)
    }

    /// Return the status for a single message, if present
    pub fn message_status(&self, uid: Uid) -> Option<&MessageStatus> {
        self.message_status.get(&uid)
    }

    /// Return an iterator to the UIDs within the current snapshot.
    pub fn uids<'a>(&'a self) -> impl Iterator<Item = Uid> + 'a {
        self.extant_messages[..self.num_messages()].iter().copied()
    }

    /// Return an iterator to the UIDs and sequence numbers within the current
    /// snapshot.
    pub fn seqnums_uids<'a>(
        &'a self,
    ) -> impl Iterator<Item = (Seqnum, Uid)> + 'a {
        self.uids()
            .enumerate()
            .map(|(ix, uid)| (Seqnum::from_index(ix), uid))
    }

    /// Return the `Modseq` for the given message.
    pub fn message_modseq(&self, message: Uid) -> Option<Modseq> {
        self.message_status.get(&message).map(|m| m.last_modified)
    }

    /// Return the true maximum `Modseq`
    pub fn max_modseq(&self) -> Option<Modseq> {
        self.max_modseq
    }

    /// Return the `Modseq` to report to the client through `HIGHESTMODSEQ`.
    pub fn report_max_modseq(&self) -> Option<Modseq> {
        self.report_max_modseq
    }

    /// Return the expected next UID.
    pub fn next_uid(&self) -> Option<Uid> {
        self.max_modseq
            .map(|m| m.uid().next())
            .unwrap_or(Some(Uid::MIN))
    }

    /// Return the expected next CID
    pub fn next_cid(&self) -> Option<Cid> {
        self.max_modseq
            .map(|m| m.cid().next())
            .unwrap_or(Some(Cid::MIN))
    }

    /// Perform the "QRESYNC" operation.
    ///
    /// `resync_from`, if present, gives the `Modseq` that the client is using
    /// as a starting point. If `None`, all changes from all time will be
    /// considered.
    ///
    /// `filter` is used to filter the returned UIDs down to the ones the
    /// client has asked for.
    ///
    /// `seqnum_reference` and `uid_reference` are parallel iterators which are
    /// used in the last ditch effort to find a reasonable starting point for
    /// discovering expunged messages. The last UID where the implied
    /// seqnum-UID mapping matches what is held locally is used as a starting
    /// point to look for expunged messages.
    pub fn qresync(
        &self,
        resync_from: Option<Modseq>,
        mut filter: impl FnMut(&Uid) -> bool,
        seqnum_reference: impl IntoIterator<Item = Seqnum>,
        uid_reference: impl IntoIterator<Item = Uid>,
    ) -> QresyncResponse {
        let max_modseq = match self.max_modseq {
            Some(m) => m,
            None => {
                return QresyncResponse {
                    expunged: Vec::new(),
                    changed: Vec::new(),
                }
            }
        };

        let mut expunged = if self
            .recent_expungements
            .front()
            .copied()
            // >= not > since we're just checking that `resync_from` is
            // included in the known range.
            .and_then(|(m, _)| resync_from.map(|r| r >= m))
            .unwrap_or(false)
        {
            // We can use the fast path as long as resync_from is after the
            // head of recent_expungements, and just dump stuff out of
            // recent_expungements
            let resync_from = resync_from.unwrap();
            self.recent_expungements
                .iter()
                .copied()
                .filter(|&(m, _)| m > resync_from)
                .map(|(_, uid)| uid)
                .filter(&mut filter)
                .collect::<Vec<_>>()
        } else {
            let expunge_start = seqnum_reference
                .into_iter()
                .zip(uid_reference.into_iter())
                .take_while(|&(seqnum, uid)| {
                    Some(uid) == self.seqnum_to_uid(seqnum).ok()
                })
                .last()
                .map(|(_, uid)| uid)
                .unwrap_or(Uid::MIN);

            (expunge_start.0.get()..=max_modseq.uid().0.get())
                .into_iter()
                .map(|uid| Uid::of(uid).unwrap())
                .filter(|uid| !self.message_status.contains_key(uid))
                .filter(&mut filter)
                .collect::<Vec<_>>()
        };
        expunged.sort();

        let changed = self
            .message_status
            .iter()
            .filter(|&(_, status)| {
                resync_from
                    .map(|r| status.last_modified > r)
                    .unwrap_or(true)
            })
            .map(|(&uid, _)| uid)
            .filter(filter)
            .collect::<Vec<_>>();

        QresyncResponse { expunged, changed }
    }

    /// If possible, return an iterator to the UIDs which have been expunged
    /// since the given `Modseq`.
    ///
    /// Returns `None` if this is not precisely known.
    pub fn uids_expunged_since<'a>(
        &'a self,
        since: Modseq,
    ) -> Option<impl Iterator<Item = Uid> + 'a> {
        if self
            .recent_expungements
            .front()
            .copied()
            .map(|(m, _)| since >= m)
            .unwrap_or(false)
        {
            Some(
                self.recent_expungements
                    .iter()
                    .copied()
                    .filter(move |&(m, _)| m > since)
                    .map(|(_, u)| u),
            )
        } else {
            None
        }
    }

    fn set_flag(
        &mut self,
        uid: Uid,
        canonical_modseq: Modseq,
        flag: Flag,
        val: bool,
        notify: bool,
    ) {
        let flag = self.flag_ix_mut(flag);
        let byte = flag / 8;
        let bit = flag % 8;

        if let Some(status) = self.message_status.get_mut(&uid) {
            status.flags.resize((byte + 1).max(status.flags.len()), 0);

            if val {
                status.flags[byte] |= 1 << bit;
            } else {
                status.flags[byte] &= !(1 << bit);
            }

            status.last_modified = canonical_modseq;
        }

        if notify {
            self.changed_flags_uids.push(uid);
        }
    }

    fn expunge(&mut self, uid: Uid, canonical_modseq: Modseq) {
        if let Some(_) = self.message_status.remove(&uid) {
            self.unapplied_expunge.push(uid);
            if let Some(back) = self.recent_expungements.back() {
                assert!(canonical_modseq >= back.0);
            }
            self.recent_expungements.push_back((canonical_modseq, uid));
            while self.recent_expungements.len() > MAX_RECENT_EXPUNGEMENTS {
                self.recent_expungements.pop_front();
            }
        }
    }

    fn flag_ix_mut(&mut self, flag: Flag) -> usize {
        if let Some(ix) = self.flag_ix(&flag) {
            ix
        } else {
            let ix = self.flags.len();
            self.flags.push(flag);
            ix
        }
    }

    fn flag_ix(&self, flag: &Flag) -> Option<usize> {
        self.flags
            .iter()
            .enumerate()
            .filter(|&(_, f)| f == flag)
            .next()
            .map(|(ix, _)| ix)
    }
}

impl MessageStatus {
    /// Returns whether this message is \Recent.
    pub fn is_recent(&self) -> bool {
        self.recent
    }

    /// Returns the flags currently on this message.
    pub fn flags<'a>(&'a self) -> impl Iterator<Item = FlagId> + 'a {
        self.flags
            .iter()
            .copied()
            .flat_map(|byte| {
                (0..8).into_iter().map(move |bit| 0 != byte & (1 << bit))
            })
            .enumerate()
            .filter(|&(_, set)| set)
            .map(|(id, _)| FlagId(id))
    }

    /// Returns whether the given flag is currently set.
    pub fn test_flag(&self, flag: FlagId) -> bool {
        let flag = flag.0;
        let byte = flag / 8;
        let bit = flag % 8;

        if let Some(b) = self.flags.get(byte) {
            0 != (b & (1 << bit))
        } else {
            false
        }
    }

    /// Returns the last `Modseq` of this message.
    pub fn last_modified(&self) -> Modseq {
        self.last_modified
    }
}

/// A sequence of operations to perform against `MailboxState` at a particular
/// point in time.
///
/// The canonical `Modseq` value for a transaction is not stored, so that a
/// writer need not rewrite its staged file every time it tries to commit a
/// transaction.
///
/// The CID of an on-disk transaction comes from the file it was loaded
/// from. The UID is the maximum of `max_uid` and the current `max_modseq`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StateTransaction {
    /// The maximum known UID at the instant the transaction was started.
    ///
    /// This may be less than the UID of the canonical `Modseq`.
    max_uid: Uid,
    /// The operations in this transaction.
    ops: Vec<StateMutation>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
enum StateMutation {
    AddFlag(Uid, Flag),
    RmFlag(Uid, Flag),
    Expunge(Uid),
}

impl StateTransaction {
    /// Create a transaction that is not expected to be strictly ordered with
    /// respect to surrounding changes.
    ///
    /// The change itself does acquire a strict order, but the writer of such a
    /// transaction cannot learn it without further processing.
    pub fn new_unordered(uid: Uid) -> Self {
        StateTransaction {
            max_uid: uid,
            ops: vec![],
        }
    }

    pub fn add_flag(&mut self, uid: Uid, flag: Flag) {
        assert!(uid <= self.max_uid);
        self.ops.push(StateMutation::AddFlag(uid, flag));
    }

    pub fn rm_flag(&mut self, uid: Uid, flag: Flag) {
        assert!(uid <= self.max_uid);
        self.ops.push(StateMutation::RmFlag(uid, flag));
    }

    pub fn expunge(&mut self, uid: Uid) {
        assert!(uid <= self.max_uid);
        self.ops.push(StateMutation::Expunge(uid));
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

/// The result of flushing the mailbox state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlushResponse {
    /// The sequence numbers (using the *new* regime) and UIDs of messages
    /// which the client has not yet seen.
    pub new: Vec<(Seqnum, Uid)>,
    /// The sequence numbers (using the regime from *before* the flush) and
    /// UIDs of messages that have been expunged since the last flush. Only
    /// messages which had defined sequence numbers are included.
    ///
    /// This is sorted ascending. When providing `EXPUNGE` responses, the
    /// elements should be sent in the opposite order to avoid interference
    /// with the sequence numbers. When providing `VANISHED` responses, the
    /// elements should be sent in order to provide the best possible grouping.
    pub expunged: Vec<(Seqnum, Uid)>,
    /// UIDs of messages that were expunged before they could get a sequence
    /// number.
    ///
    /// These are not returned to the client, but must still be processed to
    /// place gravestones over the files for these UIDs.
    pub stillborn: Vec<Uid>,
    /// The new `HIGHESTMODSEQ`, or `None` if still primordial.
    pub max_modseq: Option<Modseq>,
}

/// An interned ID for a flag, valid in one `MailboxState`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlagId(usize);

#[cfg(test)]
mod test {
    use std::collections::BTreeSet;

    use proptest::prelude::*;

    use super::*;

    #[test]
    fn seqnum_mapping() {
        let mut state = MailboxState::new();
        let flush = state.flush();
        assert!(flush.new.is_empty());
        assert!(flush.expunged.is_empty());
        assert_eq!(None, flush.max_modseq);

        state.seen(Uid::u(3));
        let flush = state.flush();
        assert_eq!(
            vec![
                (Seqnum::u(1), Uid::u(1)),
                (Seqnum::u(2), Uid::u(2)),
                (Seqnum::u(3), Uid::u(3))
            ],
            flush.new
        );
        assert!(flush.expunged.is_empty());
        assert_eq!(
            Some(Modseq::new(Uid::u(3), Cid::GENESIS)),
            flush.max_modseq
        );

        assert_eq!(Some(Uid::u(1)), state.seqnum_to_uid(Seqnum::u(1)).ok());
        assert_eq!(Some(Uid::u(2)), state.seqnum_to_uid(Seqnum::u(2)).ok());
        assert_eq!(Some(Uid::u(3)), state.seqnum_to_uid(Seqnum::u(3)).ok());
        assert_eq!(None, state.seqnum_to_uid(Seqnum::u(4)).ok());
        assert_eq!(Some(Seqnum::u(1)), state.uid_to_seqnum(Uid::u(1)).ok());
        assert_eq!(Some(Seqnum::u(2)), state.uid_to_seqnum(Uid::u(2)).ok());
        assert_eq!(Some(Seqnum::u(3)), state.uid_to_seqnum(Uid::u(3)).ok());
        assert_eq!(None, state.uid_to_seqnum(Uid::u(4)).ok());

        // Expunge a message
        let (cid, mut tx) = state.start_tx().unwrap();
        tx.expunge(Uid::u(2));
        state.commit(cid, tx, true);

        // But it doesn't affect the snapshot yet
        assert_eq!(3, state.num_messages());

        // Add a couple more
        state.seen(Uid::u(5));
        assert_eq!(3, state.num_messages());

        // UID-seqnum mapping is unchanged, and we still report the same
        // HIGHESTMODSEQ
        assert_eq!(Some(Uid::u(1)), state.seqnum_to_uid(Seqnum::u(1)).ok());
        assert_eq!(Some(Uid::u(2)), state.seqnum_to_uid(Seqnum::u(2)).ok());
        assert_eq!(Some(Uid::u(3)), state.seqnum_to_uid(Seqnum::u(3)).ok());
        assert_eq!(None, state.seqnum_to_uid(Seqnum::u(4)).ok());
        assert_eq!(Some(Seqnum::u(1)), state.uid_to_seqnum(Uid::u(1)).ok());
        assert_eq!(Some(Seqnum::u(2)), state.uid_to_seqnum(Uid::u(2)).ok());
        assert_eq!(Some(Seqnum::u(3)), state.uid_to_seqnum(Uid::u(3)).ok());
        assert_eq!(None, state.uid_to_seqnum(Uid::u(4)).ok());
        assert_eq!(
            Some(Modseq::new(Uid::u(3), Cid::GENESIS)),
            state.report_max_modseq()
        );

        let flush = state.flush();
        assert_eq!(
            vec![(Seqnum::u(3), Uid::u(4)), (Seqnum::u(4), Uid::u(5))],
            flush.new
        );
        assert_eq!(vec![(Seqnum::u(2), Uid::u(2))], flush.expunged);
        assert_eq!(Some(Modseq::new(Uid::u(5), cid)), flush.max_modseq);

        // New UID-seqnum mapping has come into effect
        assert_eq!(4, state.num_messages());
        assert_eq!(Some(Uid::u(1)), state.seqnum_to_uid(Seqnum::u(1)).ok());
        assert_eq!(Some(Uid::u(3)), state.seqnum_to_uid(Seqnum::u(2)).ok());
        assert_eq!(Some(Uid::u(4)), state.seqnum_to_uid(Seqnum::u(3)).ok());
        assert_eq!(Some(Uid::u(5)), state.seqnum_to_uid(Seqnum::u(4)).ok());
        assert_eq!(None, state.seqnum_to_uid(Seqnum::u(5)).ok());
        assert_eq!(Some(Seqnum::u(1)), state.uid_to_seqnum(Uid::u(1)).ok());
        assert_eq!(None, state.uid_to_seqnum(Uid::u(2)).ok());
        assert_eq!(Some(Seqnum::u(2)), state.uid_to_seqnum(Uid::u(3)).ok());
        assert_eq!(Some(Seqnum::u(3)), state.uid_to_seqnum(Uid::u(4)).ok());
        assert_eq!(Some(Seqnum::u(4)), state.uid_to_seqnum(Uid::u(5)).ok());
        assert_eq!(None, state.uid_to_seqnum(Uid::u(6)).ok());
        assert_eq!(
            Some(Modseq::new(Uid::u(5), cid)),
            state.report_max_modseq()
        );
    }

    #[test]
    fn expunged_new_messages() {
        let mut state = MailboxState::new();

        state.seen(Uid::u(5));
        let (cid, mut tx) = state.start_tx().unwrap();
        tx.expunge(Uid::u(1));
        tx.expunge(Uid::u(3));
        tx.expunge(Uid::u(5));
        state.commit(cid, tx, true);

        let flush = state.flush();
        assert_eq!(
            vec![(Seqnum::u(1), Uid::u(2)), (Seqnum::u(2), Uid::u(4))],
            flush.new
        );
        assert!(flush.expunged.is_empty());
        assert_eq!(vec![Uid::u(1), Uid::u(3), Uid::u(5)], flush.stillborn);

        state.seen(Uid::u(7));
        let (cid, mut tx) = state.start_tx().unwrap();
        tx.expunge(Uid::u(4));
        tx.expunge(Uid::u(6));
        state.commit(cid, tx, true);

        let flush = state.flush();
        assert_eq!(vec![(Seqnum::u(2), Uid::u(7))], flush.new);
        assert_eq!(vec![(Seqnum::u(2), Uid::u(4))], flush.expunged);
        assert_eq!(vec![Uid::u(6)], flush.stillborn);
    }

    #[test]
    fn foreign_commit_updates_max_uid() {
        let mut state = MailboxState::new();
        state.seen(Uid::u(2));
        state.flush();

        let mut state2 = MailboxState::new();
        state2.seen(Uid::u(4));
        let (cid, mut tx) = state2.start_tx().unwrap();
        tx.expunge(Uid::u(4));
        // Commit to `state`, not `state2`
        state.commit(cid, tx, true);

        let flush = state.flush();
        assert_eq!(vec![(Seqnum::u(3), Uid::u(3))], flush.new);
        assert_eq!(vec![Uid::u(4)], flush.stillborn);
    }

    #[test]
    fn seqnum_to_uid_error_states() {
        let mut state = MailboxState::new();
        state.seen(Uid::u(3));
        state.flush();

        let (cid, mut tx) = state.start_tx().unwrap();
        tx.expunge(Uid::u(2));
        state.commit(cid, tx, true);
        state.seen(Uid::u(4));

        // This does *not* happen --- we need to keep understanding the mapping
        // until flush.
        //assert!(matches!(state.seqnum_to_uid(Seqnum::u(2)),
        //                 Err(Error::ExpungedMessage)));
        assert!(matches!(
            state.seqnum_to_uid(Seqnum::u(4)),
            Err(Error::NxMessage)
        ));
        assert!(matches!(
            state.seqnum_to_uid(Seqnum::u(5)),
            Err(Error::NxMessage)
        ));
    }

    #[test]
    fn uid_to_seqnum_error_states() {
        let mut state = MailboxState::new();
        state.seen(Uid::u(3));
        state.flush();

        let (cid, mut tx) = state.start_tx().unwrap();
        tx.expunge(Uid::u(2));
        state.commit(cid, tx, true);
        state.flush();
        state.seen(Uid::u(4));

        assert!(matches!(
            state.uid_to_seqnum(Uid::u(2)),
            Err(Error::ExpungedMessage)
        ));
        assert!(matches!(
            state.uid_to_seqnum(Uid::u(4)),
            Err(Error::UnaddressableMessage)
        ));
        assert!(matches!(
            state.uid_to_seqnum(Uid::u(5)),
            Err(Error::NxMessage)
        ));
    }

    #[test]
    fn test_validate_uid() {
        let mut state = MailboxState::new();
        state.seen(Uid::u(3));
        state.flush();

        let (cid, mut tx) = state.start_tx().unwrap();
        tx.expunge(Uid::u(2));
        state.commit(cid, tx, true);
        state.seen(Uid::u(4));

        assert!(matches!(state.validate_uid(Uid::u(1)), Ok(())));
        assert!(matches!(state.validate_uid(Uid::u(4)), Ok(())));
        assert!(matches!(
            state.validate_uid(Uid::u(2)),
            Err(Error::ExpungedMessage)
        ));
        assert!(matches!(
            state.validate_uid(Uid::u(5)),
            Err(Error::NxMessage)
        ));
    }

    proptest! {
        #[test]
        fn qresync_always_finds_all_expungements(
            expunge_before in prop::collection::vec(1u32..1000u32, 0..100),
            expunge_after in prop::collection::vec(1u32..1000u32, 0..100),
        ) {
            let mut state = MailboxState::new();

            let mut all_expunged = BTreeSet::<Uid>::new();
            for uid in expunge_before {
                let uid = Uid::u(uid);
                state.seen(uid.saturating_next());
                all_expunged.insert(uid);

                let (cid, mut tx) = state.start_tx().unwrap();
                tx.expunge(uid);
                state.commit(cid, tx, true);
            }
            state.flush();

            let mut client_expunged = all_expunged.clone();
            let resync_point = state.report_max_modseq();
            let resync_checkpoints = state.seqnums_uids()
                .filter(|&(seq, _)| 0 == seq.0.get() % 10)
                .collect::<Vec<_>>();

            for uid in expunge_after {
                let uid = Uid::u(uid);
                state.seen(uid.saturating_next());
                all_expunged.insert(uid);

                let (cid, mut tx) = state.start_tx().unwrap();
                tx.expunge(uid);
                state.commit(cid, tx, true);
            }
            state.flush();

            let qresync = state.qresync(
                resync_point,
                |_| true,
                resync_checkpoints.iter().copied().map(|(s, _)| s),
                resync_checkpoints.iter().copied().map(|(_, u)| u));
            for uid in qresync.expunged {
                client_expunged.insert(uid);
            }

            prop_assert_eq!(all_expunged, client_expunged);
        }
    }

    #[test]
    fn flag_operations() {
        let mut state = MailboxState::new();
        state.seen(Uid::u(10));
        state.flush();

        let flagged_flag = state.flag_id_mut(Flag::Flagged);
        let seen_flag = state.flag_id_mut(Flag::Seen);
        let kw_flag = state.flag_id_mut(Flag::Keyword("NotJunk".to_owned()));

        assert!(!state.test_flag(flagged_flag, Uid::u(1)));
        assert!(!state.test_flag(seen_flag, Uid::u(1)));
        assert!(!state.test_flag(kw_flag, Uid::u(1)));

        assert!(!state.test_flag(flagged_flag, Uid::u(11)));
        assert!(!state.test_flag(seen_flag, Uid::u(11)));
        assert!(!state.test_flag(kw_flag, Uid::u(11)));

        let (cid, mut tx) = state.start_tx().unwrap();
        tx.add_flag(Uid::u(1), Flag::Seen);
        tx.add_flag(Uid::u(2), Flag::Flagged);
        state.commit(cid, tx, true);

        assert!(state.test_flag(flagged_flag, Uid::u(2)));

        let (cid, mut tx) = state.start_tx().unwrap();
        tx.add_flag(Uid::u(3), Flag::Keyword("NotJunk".to_owned()));
        tx.rm_flag(Uid::u(2), Flag::Flagged);
        state.commit(cid, tx, false);

        assert!(!state.test_flag(flagged_flag, Uid::u(1)));
        assert!(!state.test_flag(flagged_flag, Uid::u(2)));
        assert!(!state.test_flag(flagged_flag, Uid::u(3)));

        assert!(state.test_flag(seen_flag, Uid::u(1)));
        assert!(!state.test_flag(seen_flag, Uid::u(2)));
        assert!(!state.test_flag(seen_flag, Uid::u(3)));

        assert!(!state.test_flag(kw_flag, Uid::u(1)));
        assert!(!state.test_flag(kw_flag, Uid::u(2)));
        assert!(state.test_flag(kw_flag, Uid::u(3)));

        // We only get notified about changes to 1 and 2 since the commit that
        // altered 3 indicated no notification.
        assert_eq!(vec![Uid::u(1), Uid::u(2)], state.take_changed_flags_uids());
        assert!(state.take_changed_flags_uids().is_empty());
    }
}
