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

//! Support for working with a single mailbox.
//!
//! A mailbox is a collection of messages and their related metadata events. It
//! is functionally independent from any associated child mailboxes.
//!
//! The contents of a mailbox directory are (where `UV` is the UID validity in
//! lowercase hex):
//!
//! - `%`. Symlink to `%UV`.
//!
//! - `%UV/u*`. Directories containing messages in the _hierarchical
//!   identifier_ scheme described below.
//!
//! - `%UV/c*`. Directories containing state transactions in the _hierarchical
//!   identifier_ scheme described below.
//!
//! - `%UV/rollup/*`. Change rollup files.
//!
//! - `%UV/mailbox.toml`. Immutable metadata about this mailbox. Managed by
//!   `MailboxPath`.
//!
//! - `%UV/unsubscribe`. Marker file; if present, the mailbox is not
//!   subscribed. Managed by `MailboxPath`.
//!
//! - `%UV/recent`. Maintains a token for the `\Recent` flag. See
//!   `recency_token`.
//!
//! - Directories containing child mailboxes, each of which is in a
//!   subdirectory corresponding to its name. Managed by `MailboxPath`.
//!
//! The distinction between `%` and `%UV` is to prevent confusion if a mailbox
//! is deleted and recreated while open. Mailboxes are opened through their
//! `%UV` path, so any change in UID validity permanently invalidates them. The
//! symlink is used to be able to access metadata statelessly.
//!
//! There are some wonky special cases to support IMAP's wonky data model.
//!
//! If the `%UV` directory is missing, this is a `\Noselect` mailbox. Mailboxes
//! are normally created as dual-use, but IMAP requires that a `DELETE`
//! operation on a dual-use mailbox with child mailboxes must transmogrify it
//! into a folder-like mailbox.
//!
//! The subscription model is different from what RFC 3501 prescribes. All
//! selectable mailboxes are subscribed by default, which corresponds to most
//! people's expectations (evidenced by the fact that real mail clients
//! scramble to subscribe a mailbox they create as soon as possible). It also
//! lets us fulfil the letter, though perhaps not the spirit, of the
//! requirement that deleting a mailbox does not unsubscribe it. Instead,
//! deleting a mailbox effectively subscribes it should it be recreated.
//! Ultimately, though, the subtleties of subscriptions likely don't matter too
//! much here since they are rarely used productively and the exotic use-cases
//! the standard urges to support (i.e. a shared mailbox that occasionally gets
//! deleted and later recreated) simply won't happen here.
//!
//! In general:
//!
//! - A mailbox exists (i.e., is visible to IMAP) if its directory exists.
//!
//! - A mailbox is selectable if the `%` subdirectory exists. It is assumed
//!   that the contents of that subdirectory will not be partially
//!   instantiated.
//!
//! - A mailbox is subscribed if it is selectable and does not have a
//!   `%UV/unsubscribe` file.
//!
//! ## Hierarchical Identifier scheme
//!
//! Messages and state transactions are stored in a scheme that assigns one
//! path to each 32-bit identifier, with the property that identifiers are
//! assigned in strictly ascending order, and that each identifier is written
//! at most once before being permanently expunged.
//!
//! The nominal path for an identifier is derived as follows:
//!
//! - A path element starting with the identifier type (`c` or `u`) and the
//!   number of directory levels beneath it.
//!
//! - Zero or more directory levels which are two lowercase hexadecimal digits,
//!   representing consecutive bytes from the identifier (MSB-first), starting
//!   from the first non-zero byte (inclusive) and ending on the LSB
//!   (exclusive).
//!
//! - A path element which is the two lowercase hexadecimal digits of the LSB
//!   of the identifier followed by the extension for its type.
//!
//! Examples (for messages):
//! - `1` → `u0/01.eml`
//! - `255` → `u0/ff.eml`
//! - `12345` → `u1/30/39.eml`
//! - `123456` → `u2/01/e2/40.eml`
//! - `16777216` → `u3/01/00/00/00.eml`
//! - `4294967295` → `u3/ff/ff/ff/ff.eml`
//!
//! This scheme is designed to avoid creating excessive directory levels for
//! small mailboxes while keeping each "section" of the tree small enough to
//! iterate efficiently and allowing some garbage collection.
//!
//! The directory-like elements in the path (other than the top one) is a
//! symlink to a directory of the same name, but suffixed with `.d`.
//!
//! When an item is expunged, it is replaced with a symlink to itself. A
//! "garbage collection" process can identify directories containing only such
//! gravestones and replace the directory link with a similar broken symlink,
//! allowing the total file count to be kept low.
//!
//! The gravestone scheme enables a number of consistent, atomic operations:
//!
//! - Reading: Open succeeds iff the item exists; fails with `ENOENT` if it was
//! never allocated; fails with `ELOOP` if the item was expunged.
//!
//! - Creating: `link()` succeeds iff the item is unallocated; fails with
//! `EEXISTS` or `ELOOP` if it was already allocated.
//!
//! - Expunging: Using `rename()` to replace an item with a looped symlink
//! either succeeds atomically or fails with `ELOOP` if the item was already
//! expunged and a garbage-collection operation cleaned the containing
//! directory up.
//!
//! - Monitoring: Watch the directory that will contain the next item (creating
//! if needed). The next mutation event must involve that item or something
//! after it.
//!
//! Each of these schemes also has an associated `X-guess` file, which contains
//! a LE u32 that indicates the best guess for the most recently allocated
//! item. It is updated non-atomically every time an item is created.
//!
//! ## Metadata rollup and garbage collection
//!
//! Whenever a read-write mailbox ingests a state transaction whose CID is
//! evenly divisible by 256, it dumps its state into a rollup file whose name
//! is the `Modseq` in base-10. When new mailbox instances are loaded, they
//! read in the file with the greatest `Modseq`.
//!
//! When a read-write mailbox initialises, any rollups which are older than
//! 24hr become candidates for deletion. If there any, the process scans the
//! change directories for transactions that took place before the `Modseq` of
//! the latest deletion candidate and expunges them all. A garbage collection
//! is performed on the hierarchical identifier scheme. Finally, the obsolete
//! rollups are deleted.
//!
//! The 24 hour grace period is to ensure that backup processes are essentially
//! guaranteed to either see the separate transactions or the rollup that
//! contains them (i.e., to prevent a case where the backup sees no rollups,
//! but then Crymap finishes a rollup and deletes the transactions, then the
//! backup looks at the transactions directory and finds nothing there either).
//!
//! ## Delivery of new messages
//!
//! When a message is to be delivered, it is first fully buffered into a
//! temporary file.
//!
//! We then need to find the UID to assign it. The directory structure used for
//! messages has a simple total order, so we could simply walk down the "right"
//! of the tree to the third level and see if it has any space. However,
//! listing each directory level involves 256 I/O operations. Instead, we use
//! exponential probing starting from either the last known UID plus one in
//! `seqnum` or 1 followed by binary search to find the first unused UID.
//!
//! Create any directories needed for the new UID, and try to rename the
//! temporary file into place. If that fails due to a conflict, increment the
//! UID and try again.
//!
//! ## Message format
//!
//! Each message consists of a u32 LE `size_xor_a` immediately followed by a
//! data stream. The data stream contains a u32 LE `size_xor_b`, a i64 LE
//! `internal_date`, followed by the raw message text.
//!
//! The two size fields together encode the size of the message before
//! compression without revealing this in the cleartext and without requiring
//! buffering. `size_xor_a` is initially written to 0 and a random value is
//! chosen for `size_xor_b`. Once the message is fully written, the actual
//! length is XORed with `size_xor_b` and the result is written over
//! `size_xor_a`.
//!
//! ## Change transaction format and rollup format
//!
//! Change transactions and rollups are stored as unframed `data_stream`s. The
//! cleartext content is CBOR of either `StateTransaction` or `MailboxState`.

use std::convert::TryInto;
use std::fs;
use std::io::{self, BufRead, Read, Seek, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use chrono::prelude::*;
use log::{error, info, warn};
use rand::{rngs::OsRng, Rng};
use serde::{de::DeserializeOwned, Serialize};
use tempfile::NamedTempFile;

use super::hier_id_scheme::*;
use super::key_store::*;
use super::mailbox_path::*;
use super::mailbox_state::*;
use super::model::*;
use super::recency_token;
use crate::crypt::data_stream;
use crate::support::compression::{Compression, FinishWrite};
use crate::support::error::Error;
use crate::support::file_ops::{self, IgnoreKinds};

#[cfg(not(test))]
const OLD_ROLLUP_GRACE_PERIOD: Duration = Duration::from_secs(24 * 3600);
#[cfg(test)]
const OLD_ROLLUP_GRACE_PERIOD: Duration = Duration::from_secs(1);

/// A stateless view of a mailbox.
///
/// The stateless view is capable of inserting messages, performing
/// unconditional flag modifications, and reading messages by UID, but cannot
/// query flags or notice changes.
#[derive(Clone)]
pub struct StatelessMailbox {
    log_prefix: String,
    path: MailboxPath,
    root: PathBuf,
    read_only: bool,
    key_store: Arc<Mutex<KeyStore>>,
    common_paths: Arc<CommonPaths>,
}

impl StatelessMailbox {
    pub fn new(
        mut log_prefix: String,
        path: MailboxPath,
        read_only: bool,
        key_store: Arc<Mutex<KeyStore>>,
        common_paths: Arc<CommonPaths>,
    ) -> Result<Self, Error> {
        log_prefix.push(':');
        log_prefix.push_str(path.name());
        let root = path.scoped_data_path()?;

        Ok(StatelessMailbox {
            log_prefix,
            path,
            root,
            read_only,
            key_store,
            common_paths,
        })
    }

    /// Return the underlying `MailboxPath`.
    pub fn path(&self) -> &MailboxPath {
        &self.path
    }

    /// Return the data directory root for this mailbox instance.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Return the UID validity of this mailbox instance.
    ///
    /// If the mailbox is deleted and recreated, this will continue to reflect
    /// the validity this instance was opened with.
    pub fn uid_validity(&self) -> Result<u32, Error> {
        parse_uid_validity(&self.root)
    }

    /// Check whether this instance is still "OK".
    ///
    /// An instance is broken if the mailbox is deleted or the UID validity has
    /// changed.
    ///
    /// This should be called in response to unexpected errors to see whether
    /// it is desirable to hang up on the client instead of continuing to
    /// futilely try to do operations on the mailbox.
    pub fn is_ok(&self) -> bool {
        self.root.is_dir()
    }

    /// Bring this mailbox into stateful mode.
    ///
    /// This corresponds to `SELECT`, `EXAMINE`, and `STATUS`.
    ///
    /// `QRESYNC` is performed with a separate call after selection.
    pub fn select(self) -> Result<(StatefulMailbox, SelectResponse), Error> {
        StatefulMailbox::select(self)
    }

    /// Open the identified message for reading.
    ///
    /// This doesn't correspond to any particular IMAP command (that would be
    /// too easy!) but is used to implement a number of them.
    ///
    /// On success, returns the length in bytes, the internal date, and a
    /// reader to access the content.
    pub fn open_message(
        &self,
        uid: Uid,
    ) -> Result<(u32, DateTime<Utc>, impl BufRead), Error> {
        let scheme = self.message_scheme();
        let mut file = match fs::File::open(scheme.path_for_id(uid.0.get())) {
            Ok(f) => f,
            Err(e) if Some(nix::libc::ELOOP) == e.raw_os_error() => {
                return Err(Error::ExpungedMessage)
            }
            Err(e) if io::ErrorKind::NotFound == e.kind() => {
                return Err(Error::NxMessage)
            }
            Err(e) => return Err(e.into()),
        };

        let size_xor_a = file.read_u32::<LittleEndian>()?;
        let stream = {
            let mut ks = self.key_store.lock().unwrap();
            data_stream::Reader::new(file, |k| ks.get_private_key(k))?
        };
        let compression = stream.metadata.compression;
        let mut stream = compression.decompressor(stream)?;
        let size_xor_b = stream.read_u32::<LittleEndian>()?;
        let internal_date = stream.read_i64::<LittleEndian>()?;

        Ok((
            size_xor_a ^ size_xor_b,
            Utc.timestamp_millis(internal_date),
            stream,
        ))
    }

    /// Append the given message to this mailbox.
    ///
    /// Returns the UID of the new message.
    ///
    /// This corresponds to the `APPEND` command from RFC 3501 and the
    /// `APPENDUID` response from RFC 4315.
    ///
    /// RFC 3501 also allows setting flags at the same time. This is
    /// accomplished with a follow-up call to `store_plus()` on
    /// `StatefulMailbox`.
    pub fn append(
        &self,
        internal_date: DateTime<Utc>,
        flags: impl IntoIterator<Item = Flag>,
        mut data: impl Read,
    ) -> Result<Uid, Error> {
        self.not_read_only()?;

        let mut buffer_file = NamedTempFile::new_in(&self.common_paths.tmp)?;

        let size_xor_a: u32;
        let size_xor_b: u32 = OsRng.gen();
        let compression = Compression::DEFAULT_FOR_MESSAGE;

        buffer_file.write_u32::<LittleEndian>(0)?;
        {
            let mut crypt_writer = {
                let mut ks = self.key_store.lock().unwrap();
                let (key_name, pub_key) = ks.get_default_public_key()?;

                data_stream::Writer::new(
                    &mut buffer_file,
                    pub_key,
                    key_name.to_owned(),
                    compression,
                )?
            };
            {
                let mut compressor =
                    compression.compressor(&mut crypt_writer)?;
                compressor.write_u32::<LittleEndian>(size_xor_b)?;
                compressor.write_i64::<LittleEndian>(
                    internal_date.timestamp_millis(),
                )?;
                let size = io::copy(&mut data, &mut compressor)?;
                size_xor_a = size_xor_b ^ size.try_into().unwrap_or(u32::MAX);
                compressor.finish()?;
            }
            crypt_writer.flush()?;
        }

        buffer_file.seek(io::SeekFrom::Start(0))?;
        buffer_file.write_u32::<LittleEndian>(size_xor_a)?;
        file_ops::chmod(buffer_file.path(), 0o440)?;

        let uid = self.insert_message(buffer_file.path())?;
        self.propagate_flags_best_effort(uid, flags);
        Ok(uid)
    }

    /// Insert `src` into this mailbox via a hard link.
    ///
    /// This is used for `COPY` and `MOVE`, though it is not exactly either of
    /// those.
    fn insert_message(&self, src: &Path) -> Result<Uid, Error> {
        self.not_read_only()?;

        let scheme = self.message_scheme();

        for _ in 0..1000 {
            let uid = Uid::of(scheme.first_unallocated_id())
                .ok_or(Error::MailboxFull)?;
            if scheme.emplace(src, uid.0.get())? {
                info!(
                    "{} Delivered message to {}",
                    self.log_prefix,
                    uid.0.get()
                );
                return Ok(uid);
            }
        }

        Err(Error::GaveUpInsertion)
    }

    /// Blindly set and clear the given flags on the given message.
    ///
    /// The caller must already know that `uid` refers to an allocated message.
    ///
    /// On success, returns the CID of the change, or `None` if there were not
    /// actually any changes to make.
    fn set_flags_blind(
        &self,
        uid: Uid,
        flags: impl IntoIterator<Item = (bool, Flag)>,
    ) -> Result<Option<Cid>, Error> {
        self.not_read_only()?;

        let mut tx = StateTransaction::new_unordered(uid);
        for (add, flag) in flags {
            if add {
                tx.add_flag(uid, flag);
            } else {
                tx.rm_flag(uid, flag);
            }
        }

        if tx.is_empty() {
            return Ok(None);
        }

        let buffer_file = self.write_state_file(&tx)?;
        let scheme = self.change_scheme();
        for _ in 0..1000 {
            let next_cid = Cid(scheme.first_unallocated_id());
            if next_cid > Cid::MAX {
                return Err(Error::MailboxFull);
            }

            if scheme.emplace(buffer_file.path(), next_cid.0)? {
                return Ok(Some(next_cid));
            }
        }

        Err(Error::GaveUpInsertion)
    }

    /// Try to add all the given flags to `uid`.
    ///
    /// On error, the error is logged.
    fn propagate_flags_best_effort(
        &self,
        uid: Uid,
        flags: impl IntoIterator<Item = Flag>,
    ) {
        if let Err(e) =
            self.set_flags_blind(uid, flags.into_iter().map(|f| (true, f)))
        {
            // If APPEND/COPY/MOVE returns an error, the call must have had no
            // effect, so we can't return an error to the client here since we
            // already emplaced the new message. Transferring the flags is only
            // a SHOULD, however, so we're fine to just log the error and carry
            // on if anything failed.
            warn!(
                "{} Failed to set flags on {}: {}",
                self.log_prefix,
                uid.0.get(),
                e
            );
        }
    }

    /// Reads a file that was written by `write_state_file()`.
    fn read_state_file<T: DeserializeOwned>(
        &self,
        src: &Path,
    ) -> Result<T, Error> {
        let file = fs::File::open(src)?;
        let stream = {
            let mut ks = self.key_store.lock().unwrap();
            data_stream::Reader::new(file, |k| ks.get_private_key(k))?
        };
        let compression = stream.metadata.compression;
        let stream = compression.decompressor(stream)?;

        serde_cbor::from_reader(stream).map_err(|e| e.into())
    }

    /// Writes the given data to a new `NamedTempFile` in the format used for
    /// storing state.
    fn write_state_file(
        &self,
        data: &impl Serialize,
    ) -> Result<NamedTempFile, Error> {
        self.not_read_only()?;

        let mut buffer_file = NamedTempFile::new_in(&self.common_paths.tmp)?;
        {
            let compression = Compression::DEFAULT_FOR_STATE;
            let mut crypt_writer = {
                let mut ks = self.key_store.lock().unwrap();
                let (key_name, pub_key) = ks.get_default_public_key()?;

                data_stream::Writer::new(
                    &mut buffer_file,
                    pub_key,
                    key_name.to_owned(),
                    compression,
                )?
            };
            {
                let mut compressor =
                    compression.compressor(&mut crypt_writer)?;
                serde_cbor::to_writer(&mut compressor, data)?;
                compressor.finish()?;
            }
            crypt_writer.flush()?;
        }

        Ok(buffer_file)
    }

    fn message_scheme(&self) -> HierIdScheme<'_> {
        HierIdScheme {
            root: &self.root,
            prefix: b'u',
            extension: "eml",
        }
    }

    fn change_scheme(&self) -> HierIdScheme<'_> {
        HierIdScheme {
            root: &self.root,
            prefix: b'c',
            extension: "tx",
        }
    }

    fn not_read_only(&self) -> Result<(), Error> {
        if self.read_only {
            Err(Error::MailboxReadOnly)
        } else {
            Ok(())
        }
    }
}

/// A stateful view of a mailbox.
///
/// This has full capabilities of doing all mailbox-specific IMAP commands.
///
/// Stateful mailboxes cannot be opened with anonymous key stores.
#[derive(Clone)]
pub struct StatefulMailbox {
    s: StatelessMailbox,
    state: MailboxState,
    recency_frontier: Option<Uid>,
    suggest_rollup: bool,
}

impl StatefulMailbox {
    /// Return the stateless view of this mailbox.
    pub fn stateless(&self) -> &StatelessMailbox {
        &self.s
    }

    /// Perform a `STORE` operation.
    pub fn seqnum_store(
        &mut self,
        request: &StoreRequest<'_, Seqnum>,
    ) -> Result<StoreResponse<Seqnum>, Error> {
        let ids = self.state.seqnum_range_to_uid(request.ids, false)?;
        self.store(&StoreRequest {
            ids: &ids,
            flags: request.flags,
            remove_listed: request.remove_listed,
            remove_unlisted: request.remove_unlisted,
            loud: request.loud,
            unchanged_since: request.unchanged_since,
        })
        .map(|resp| StoreResponse {
            modified: self
                .state
                .uid_range_to_seqnum(&resp.modified, true)
                .unwrap(),
        })
    }

    /// Perform a `UID STORE` operation.
    pub fn store(
        &mut self,
        request: &StoreRequest<'_, Uid>,
    ) -> Result<StoreResponse<Uid>, Error> {
        let flags: Vec<FlagId> = request
            .flags
            .iter()
            .map(|f| self.state.flag_id_mut(f.to_owned()))
            .collect();

        let fragile = request.unchanged_since.is_some();
        let ret = self.change_transaction(fragile, |this, tx| {
            let mut modified = SeqRange::new();

            for uid in request.ids.items() {
                let status = match this.state.message_status(uid) {
                    Some(status) => status,
                    None => continue,
                };

                if request
                    .unchanged_since
                    .map(|uc| uc < status.last_modified())
                    .unwrap_or(false)
                {
                    modified.append(uid);
                    continue;
                }

                for &flag in &flags {
                    if request.remove_listed != status.test_flag(flag) {
                        if let Some(flag_obj) = this.state.flag(flag) {
                            if request.remove_listed {
                                tx.rm_flag(uid, flag_obj.to_owned());
                            } else {
                                tx.add_flag(uid, flag_obj.to_owned());
                            }
                        }
                    }
                }

                if request.remove_unlisted {
                    for flag in status.flags() {
                        if !flags.contains(&flag) {
                            if let Some(flag_obj) = this.state.flag(flag) {
                                tx.rm_flag(uid, flag_obj.to_owned());
                            }
                        }
                    }
                }
            }

            Ok(StoreResponse { modified })
        })?;

        if request.loud {
            for uid in request.ids.items() {
                self.state.add_changed_flags_uid(uid);
            }
        }

        Ok(ret)
    }

    /// Do a "mini" poll, appropriate for use after a `FETCH`, `STORE`, or
    /// `SEARCH` operation.
    ///
    /// This will not affect the sequence number mapping, and only reports
    /// information that was discovered incidentally since the last poll.
    ///
    /// Returns a list of UIDs that should be sent in unsolicited `FETCH`
    /// responses (as per RFC 7162). This only includes UIDs currently mapped
    /// to sequence numbers, but may include UIDs that have since been
    /// expunged. Flag updates on UIDs not yet mapped to sequence numbers are
    /// lost, since those `FETCH` responses are expected to happen when the
    /// full poll announces the new messages to the client.
    pub fn mini_poll(&mut self) -> Vec<Uid> {
        let mut uids = self.state.take_changed_flags_uids();
        uids.retain(|&u| self.state.is_assigned_uid(u));
        uids
    }

    /// Do a full poll cycle, appropriate for use after all commands but
    /// `FETCH`, `STORE`, or `SEARCH`, and in response to wake-ups during
    /// `IDLE`.
    ///
    /// New messages and changes are detected, and the sequence number mapping
    /// is updated.
    ///
    /// Returns information that must be sent to the client to inform it of any
    /// changes that were detected.
    ///
    /// Errors from this call are not recoverable. If it fails, the client and
    /// server are left in an inconsistent state.
    pub fn poll(&mut self) -> Result<PollResponse, Error> {
        self.poll_for_new_uids();
        self.poll_for_new_changes(Cid::GENESIS)?;

        let flush = self.state.flush();
        let has_new = !flush.new.is_empty();
        let mut fetch = self.mini_poll();
        fetch.extend(flush.new.into_iter().map(|(_, u)| u));
        fetch.sort_unstable();
        fetch.dedup();

        // If there are new UIDs, see if we can claim \Recent on any of them.
        if let Some(max_recent_uid) = flush.max_modseq.map(Modseq::uid) {
            let min_recent_uid = self
                .recency_frontier
                .and_then(Uid::next)
                .unwrap_or(Uid::MIN);
            if min_recent_uid <= max_recent_uid {
                if let Some(claimed_recent_uid) = recency_token::claim(
                    &self.s.root,
                    min_recent_uid,
                    max_recent_uid,
                    self.s.read_only,
                ) {
                    for uid in
                        claimed_recent_uid.0.get()..=max_recent_uid.0.get()
                    {
                        self.state.set_recent(Uid::of(uid).unwrap());
                    }
                }
            }
        }

        // For any newly expunged messages, ensure they have gravestones.
        if !self.s.read_only {
            let message_scheme = self.s.message_scheme();
            for uid in flush
                .expunged
                .iter()
                .map(|&(_, u)| u)
                .chain(flush.stillborn.into_iter())
            {
                if let Err(e) = message_scheme
                    .expunge(uid.0.get(), &self.s.common_paths.tmp)
                {
                    warn!(
                        "{} Failed to fully expunge {}: {}",
                        self.s.log_prefix,
                        uid.0.get(),
                        e
                    );
                }
            }
        }

        if !self.s.read_only && self.suggest_rollup {
            self.suggest_rollup = false;
            if let Err(e) = self.dump_rollup() {
                warn!(
                    "{} Failed to write metadata rollup: {}",
                    self.s.log_prefix, e
                );
            }
        }

        Ok(PollResponse {
            expunge: flush.expunged,
            exists: if has_new {
                Some(self.state.num_messages())
            } else {
                None
            },
            recent: if has_new {
                Some(self.count_recent())
            } else {
                None
            },
            fetch: fetch,
            max_modseq: flush.max_modseq,
        })
    }

    /// Probe for UIDs allocated later than the last known UID.
    fn poll_for_new_uids(&mut self) {
        let messages_scheme = self.s.message_scheme();
        while let Some(next_uid) = self.state.next_uid() {
            if messages_scheme.is_allocated(next_uid.0.get()) {
                self.state.seen(next_uid);
            } else {
                break;
            }
        }
    }

    /// Probe for and load CIDs later than the last known CID.
    ///
    /// If a transaction with an id of `no_notify_cid` is found, any flag
    /// changes it makes are not added to the list of UIDs that have
    /// outstanding flag changes to report to the client.
    fn poll_for_new_changes(
        &mut self,
        no_notify_cid: Cid,
    ) -> Result<(), Error> {
        while let Some(next_cid) = self.state.next_cid() {
            if self.s.change_scheme().is_allocated(next_cid.0) {
                self.apply_change(next_cid, next_cid != no_notify_cid)?;
            } else {
                break;
            }
        }

        Ok(())
    }

    fn apply_change(&mut self, cid: Cid, notify: bool) -> Result<(), Error> {
        self.state.commit(
            cid,
            self.s
                .read_state_file(&self.s.change_scheme().path_for_id(cid.0))?,
            notify,
        );

        if 0 == cid.0 % 256 {
            self.suggest_rollup = true;
        }

        Ok(())
    }

    fn dump_rollup(&self) -> Result<(), Error> {
        let mut path = self.s.root.join("rollup");

        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .ignore_already_exists()?;

        let buffer_file = self.s.write_state_file(&self.state)?;
        file_ops::chmod(buffer_file.path(), 0o400)?;

        path.push(
            self.state
                .max_modseq()
                .expect("Attempted rollup with no changes")
                .raw()
                .to_string(),
        );

        buffer_file
            .persist_noclobber(&path)
            .map_err(|e| e.error)
            .map(|_| ())
            .ignore_already_exists()?;
        Ok(())
    }

    fn select(s: StatelessMailbox) -> Result<(Self, SelectResponse), Error> {
        let mut rollups = Self::list_rollups(&s)?;
        let state = rollups
            .pop()
            .and_then(|r| match s.read_state_file::<MailboxState>(&r.path) {
                Ok(state) => Some(state),
                Err(e) => {
                    error!(
                        "{} Error reading {}, starting from empty state: {}",
                        s.log_prefix,
                        r.path.display(),
                        e
                    );
                    None
                }
            })
            .unwrap_or_else(MailboxState::new);

        let mut this = Self {
            recency_frontier: state.max_modseq().map(Modseq::uid),
            s,
            state,
            suggest_rollup: false,
        };
        this.poll()?;

        if !this.s.read_only {
            let s_clone = this.s.clone();
            rayon::spawn(move || {
                if let Err(err) = s_clone.message_scheme().gc(
                    &s_clone.common_paths.tmp,
                    &s_clone.common_paths.garbage,
                    0,
                ) {
                    warn!(
                        "{} Error garbage collecting messages: {}",
                        s_clone.log_prefix, err
                    );
                    return;
                }

                // We can expunge all data transactions
                let expunge_before_cid = rollups
                    .iter()
                    .filter(|r| r.deletion_candidate)
                    .map(|r| r.cid)
                    .max()
                    .unwrap_or(Cid(0));

                if let Err(err) = s_clone.change_scheme().gc(
                    &s_clone.common_paths.tmp,
                    &s_clone.common_paths.garbage,
                    expunge_before_cid.0,
                ) {
                    warn!(
                        "{} Error garbage collecting changes: {}",
                        s_clone.log_prefix, err
                    );
                } else {
                    for rollup in rollups {
                        if rollup.deletion_candidate {
                            if let Err(err) =
                                fs::remove_file(&rollup.path).ignore_not_found()
                            {
                                warn!(
                                    "{} Error removing {}: {}",
                                    s_clone.log_prefix,
                                    rollup.path.display(),
                                    err
                                );
                            }
                        }
                    }
                }
            });
        }

        let select_response = SelectResponse {
            flags: this.state.flags().map(|(_, f)| f.to_owned()).collect(),
            exists: this.state.num_messages(),
            recent: this.count_recent(),
            unseen: this
                .state
                .seqnums_uids()
                .filter(|&(_, uid)| {
                    this.state
                        .flag_id(&Flag::Seen)
                        .map(|fid| !this.state.test_flag(fid, uid))
                        .unwrap_or(true)
                })
                .next()
                .map(|(s, _)| s),
            uidnext: this.state.next_uid().unwrap_or(Uid::MAX),
            uidvalidity: this.s.uid_validity()?,
            read_only: this.s.read_only,
        };
        Ok((this, select_response))
    }

    fn list_rollups(s: &StatelessMailbox) -> Result<Vec<RollupInfo>, Error> {
        match fs::read_dir(s.root.join("rollup")) {
            Err(e) if io::ErrorKind::NotFound == e.kind() => Ok(vec![]),
            Err(e) => Err(e.into()),
            Ok(it) => {
                let mut ret = Vec::new();
                let now = SystemTime::now();

                for entry in it {
                    let entry = entry?;
                    let modseq = match entry
                        .file_name()
                        .to_str()
                        .and_then(|n| u64::from_str_radix(n, 10).ok())
                        .and_then(Modseq::of)
                    {
                        Some(ms) => ms,
                        // Ignore inscrutable filenames
                        None => continue,
                    };

                    let md = match entry.metadata() {
                        Ok(md) => md,
                        // NotFound => we lost a race with another process
                        // Ignore the now-deleted file and carry on
                        Err(e) if io::ErrorKind::NotFound == e.kind() => {
                            continue
                        }
                        Err(e) => return Err(e.into()),
                    };

                    let deletion_candidate = md
                        .modified()
                        .ok()
                        .and_then(|modified| now.duration_since(modified).ok())
                        .unwrap_or(Duration::from_secs(0))
                        >= OLD_ROLLUP_GRACE_PERIOD;

                    ret.push(RollupInfo {
                        cid: modseq.cid(),
                        path: entry.path(),
                        deletion_candidate,
                    });
                }

                ret.sort();
                // The most recent rollup is never a deletion candidate
                if let Some(last) = ret.last_mut() {
                    last.deletion_candidate = false;
                }

                Ok(ret)
            }
        }
    }

    fn count_recent(&self) -> usize {
        self.state
            .uids()
            .filter(|&u| self.state.is_recent(u))
            .count()
    }

    /// Perform a transactional change against the mailbox's mutable state.
    ///
    /// `f` is called with a transaction and `self` and is expected to modify
    /// the transaction as desired, and return the result of the whole
    /// transaction.
    ///
    /// If `fragile` is true, `f` will be reevaluated if more changes are found
    /// while trying to process the transaction. If `fragile` is false, `f`
    /// will be called only once, which is useful for operations that do not
    /// depend on strict ordering.
    fn change_transaction<R>(
        &mut self,
        fragile: bool,
        mut f: impl FnMut(&Self, &mut StateTransaction) -> Result<R, Error>,
    ) -> Result<R, Error> {
        let (mut cid, mut tx) = self.state.start_tx()?;
        let mut res = f(self, &mut tx)?;
        if tx.is_empty() {
            return Ok(res);
        }

        let mut buffer_file = self.s.write_state_file(&tx)?;

        for _ in 0..1024 {
            if self.s.change_scheme().emplace(buffer_file.path(), cid.0)? {
                // Directly commit instead of needing to do the whole
                // poll/read/decrypt dance
                // TODO Is there *ever* a case where we want !notify?
                self.state.commit(cid, tx, true);
                return Ok(res);
            }

            self.poll_for_new_changes(Cid::GENESIS)?;

            if fragile {
                let (c, t) = self.state.start_tx()?;
                cid = c;
                tx = t;
                res = f(self, &mut tx)?;
                if tx.is_empty() {
                    return Ok(res);
                }
                buffer_file = self.s.write_state_file(&tx)?;
            } else {
                cid = self.state.retry_tx(cid)?;
            }
        }

        Err(Error::GaveUpInsertion)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct RollupInfo {
    // First field since it's the main thing we sort by
    // We only include the CID since we also use this to determine which CIDs
    // can be expunged during cleanup. While Modseqs /should/ be totally
    // ordered, this is a more conservative behaviour.
    cid: Cid,
    path: PathBuf,
    deletion_candidate: bool,
}

#[cfg(test)]
mod test {
    use std::iter;

    use tempfile::TempDir;

    use super::*;
    use crate::crypt::master_key::MasterKey;

    struct Setup {
        root: TempDir,
        stateless: StatelessMailbox,
    }

    fn set_up() -> Setup {
        let root = TempDir::new().unwrap();
        let common_paths = Arc::new(CommonPaths {
            tmp: root.path().to_owned(),
            garbage: root.path().to_owned(),
        });

        let mut key_store = KeyStore::new(
            "key-store".to_owned(),
            root.path().join("keys"),
            common_paths.tmp.clone(),
            Some(Arc::new(MasterKey::new())),
        );
        key_store.set_rsa_bits(1024);
        key_store.init(&KeyStoreConfig::default()).unwrap();

        let key_store = Arc::new(Mutex::new(key_store));

        let mbox_path =
            MailboxPath::root("inbox".to_owned(), root.path()).unwrap();
        mbox_path.create(root.path(), None).unwrap();
        let stateless = StatelessMailbox::new(
            "mailbox".to_owned(),
            mbox_path,
            false,
            key_store,
            common_paths,
        )
        .unwrap();

        Setup { root, stateless }
    }

    #[test]
    fn write_and_read_messages() {
        let setup = set_up();

        let now = Utc::now();
        let now_truncated = Utc.timestamp_millis(now.timestamp_millis());

        assert_eq!(
            Uid::u(1),
            setup
                .stateless
                .append(now, iter::empty(), &mut "hello world".as_bytes())
                .unwrap()
        );
        assert_eq!(
            Uid::u(2),
            setup
                .stateless
                .append(now, iter::empty(), &mut "another message".as_bytes())
                .unwrap()
        );

        let mut content = String::new();
        let (size, date, mut r) =
            setup.stateless.open_message(Uid::u(1)).unwrap();
        assert_eq!(11, size);
        assert_eq!(now_truncated, date);
        r.read_to_string(&mut content).unwrap();
        assert_eq!("hello world", &content);

        content.clear();
        let (size, date, mut r) =
            setup.stateless.open_message(Uid::u(2)).unwrap();
        assert_eq!(15, size);
        assert_eq!(now_truncated, date);
        r.read_to_string(&mut content).unwrap();
        assert_eq!("another message", &content);
    }

    #[test]
    fn write_and_read_state_files() {
        let setup = set_up();

        assert_eq!(
            Some(Cid(1)),
            setup
                .stateless
                .set_flags_blind(Uid::u(1), vec![(true, Flag::Flagged)])
                .unwrap()
        );

        let tx: StateTransaction = setup
            .stateless
            .read_state_file(&setup.stateless.change_scheme().path_for_id(1))
            .unwrap();

        // If we were able to deserialise it at all, the read operation worked.
        // So just make sure we got something non-trivial back.
        assert!(!tx.is_empty());
    }

    #[test]
    fn delete_open_mailbox() {
        let setup = set_up();

        assert!(setup.stateless.is_ok());
        assert_eq!(
            setup.stateless.uid_validity().unwrap(),
            setup.stateless.path().current_uid_validity().unwrap()
        );

        setup.stateless.path().delete(setup.root.path()).unwrap();
        assert!(!setup.stateless.is_ok());
        assert!(matches!(
            setup.stateless.path().current_uid_validity(),
            Err(Error::MailboxUnselectable)
        ));

        // Ensure we get a distinct UID validity
        std::thread::sleep(std::time::Duration::from_millis(2000));

        setup
            .stateless
            .path()
            .create(setup.root.path(), None)
            .unwrap();
        assert_ne!(
            setup.stateless.uid_validity().unwrap(),
            setup.stateless.path().current_uid_validity().unwrap()
        );
        assert!(!setup.stateless.is_ok());
    }
}
