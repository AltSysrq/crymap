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

//! Support for working with mailboxes.
//!
//! A mailbox is an ensemble of a `MessageStore`, a `FlagStore`, its
//! children, and some ancillary data.
//!
//! The contents of a mailbox directory are:
//! - `%/msgs/`. The root of the `MessageStore`.
//! - `%/flags/`. The root of the `FlagStore`.
//! - `%/mailbox.toml`. Immutable metadata, specifically the UID validity and
//!   any special-use flags.
//! - `%/unsubscribe`. Marker file; if present, the mailbox is not subscribed.
//! - Directories containing child mailboxes, each of which is in a
//!   subdirectory corresponding to its name. Only exists if there are any such
//!   children.
//!
//! There are some wonky special cases to support IMAP's wonky data model.
//!
//! If the `s` directory is missing, this is a `\Noselect` mailbox. Mailboxes
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
//!   `%/unsubscribe` file.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

use log::warn;

use super::flag_store::{Flag, FlagStore};
use super::key_store::KeyStore;
use super::mailbox_path::*;
use super::message_store::{MessageStore, Seqnum, Uid};
use crate::support::error::Error;

/// A heavy-weight handle for a mailbox.
///
/// Like `MessageStore`, this has distinct "active" and "passive" modes. Active
/// mode is entered by the `select()` method.
pub struct Mailbox {
    path: MailboxPath,
    log_prefix: String,
    message_store: MessageStore,
    flag_store: FlagStore,
    read_only: bool,
    last_flag_refresh: Option<Instant>,
    uid_validity: u32,
    tmp: PathBuf,
}

impl Mailbox {
    pub fn new(
        path: MailboxPath,
        log_prefix: String,
        read_only: bool,
        tmp: &Path,
        notify: impl Fn() + Send + Sync + 'static,
    ) -> Result<Self, Error> {
        if !path.exists() {
            Err(Error::NxMailbox)
        } else if !path.is_selectable() {
            Err(Error::MailboxUnselectable)
        } else {
            let log_prefix = format!("{}:{}", log_prefix, path.name);
            Ok(Mailbox {
                message_store: MessageStore::new(
                    log_prefix.clone(),
                    path.msgs_path.clone(),
                    tmp.to_owned(),
                    read_only,
                    notify,
                ),
                flag_store: FlagStore::new(path.flags_path.clone(), read_only),
                last_flag_refresh: None,
                uid_validity: 0, //path.metadata()?.imap.uid_validity,
                tmp: tmp.to_owned(),
                log_prefix,
                path,
                read_only,
            })
        }
    }

    /// Clear internal caches.
    ///
    /// This should be called occasionally by the IMAP server code.
    pub fn clear_cache(&mut self) {
        self.flag_store.clear_cache();
    }

    /// Persist any indices currently in use, current status permitting.
    pub fn save_indices(&self) -> Result<(), Error> {
        self.message_store.save_seqnum_index(&self.tmp)?;
        Ok(())
    }

    /// Determine whether this mailbox is still "OK".
    ///
    /// It becomes non-OK if it is deleted or its UID validity changes. This
    /// should be polled occasionally so that the connection can be closed when
    /// such an event happens.
    pub fn is_ok(&self) -> bool {
        // self.path
        //     .metadata()
        //     .map(|md| md.imap.uid_validity == self.uid_validity)
        //     .unwrap_or(false)
        true
    }

    /// The IMAP `SELECT` and `EXAMINE` operations.
    ///
    /// This is also used for `STATUS`, since the only status field that can be
    /// obtained more cheaply than a full `SELECT` is `UIDVALIDITY`, which by
    /// itself is not useful so it is unlikely any clients use it like that.
    /// The server layer transforms the `SelectResponse` to a `STATUS` response
    /// itself.
    ///
    /// This transitions the mailbox into active status.
    pub fn select(&mut self) -> Result<SelectResponse, Error> {
        self.refresh_flags()?;
        self.message_store.poll_active_status()?;

        let mut flags: Vec<Flag> =
            self.flag_store.iter_flags().cloned().collect();
        // Ensure all system flags are represented
        flags.push(Flag::Answered);
        flags.push(Flag::Deleted);
        flags.push(Flag::Draft);
        flags.push(Flag::Flagged);
        flags.push(Flag::Recent);
        flags.push(Flag::Seen);
        flags.sort();
        flags.dedup();

        let unseen = {
            let mut pred = self.flag_store.flag_predicate(&Flag::Seen);
            self.message_store
                .messages()
                .filter(|&(_, uid)| !pred(uid))
                .map(|(s, _)| s)
                .next()
        };

        let recent = self.count_recent();

        Ok(SelectResponse {
            flags,
            exists: self.message_store.message_count(),
            recent,
            unseen,
            uidnext: self.message_store.next_uid(),
            uidvalidity: self.uid_validity,
            read_only: self.read_only,
        })
    }

    /// Poll for new mail and expunged UIDs.
    ///
    /// This is conceptually the implementation of `NOOP`, `CHECK`, and
    /// `XYZZY` and as a response to events during `IDLE`, but is generally run
    /// after most commands.
    ///
    /// Changes take effect immediately, altering the sequence number mapping.
    /// This makes it unusable after a `FETCH`, `STORE`, or `SEARCH` command
    /// (but not the `UID` versions of those commands) since they allow
    /// pipelining.
    ///
    /// Returns `None` if there is nothing to say.
    pub fn poll(&mut self) -> Result<Option<PollResponse>, Error> {
        let status = self.message_store.poll_active_status()?;
        let recent = status.exist.map(|_| self.count_recent());

        if status.expunged.is_empty() && status.exist.is_none() {
            Ok(None)
        } else {
            Ok(Some(PollResponse {
                expunge: status.expunged,
                // RFC 3501 describes EXISTS to be sent whenever the size of
                // the mailbox changes, but the examples only show it being
                // sent when new messages arrive, so that's what we do here.
                exists: status.exist,
                recent: recent,
            }))
        }
    }

    /// Expunge all messages with the `\Deleted` flag.
    ///
    /// This corresponds to the `EXPUNGE` and `CLOSE` commands.
    ///
    /// This produces no response of its own. `poll()` is used to get the
    /// untagged `EXPUNGED` responses that this produces.
    pub fn expunge_deleted(&mut self) -> Result<(), Error> {
        let candidates = self
            .message_store
            .messages()
            .map(|(_, u)| u)
            .collect::<Vec<_>>();
        self.expunge_deleted_uids(candidates)
    }

    /// Expunge messages in the given UID sequence which also have the
    /// `\Deleted` flag.
    ///
    /// This corresponds to the `UID EXPUNGE` command.
    ///
    /// This produces no response of its own. `poll()` is used to get the
    /// untagged `EXPUNGED` responses that this produces.
    pub fn expunge_deleted_uids(
        &mut self,
        uids: impl IntoIterator<Item = Uid>,
    ) -> Result<(), Error> {
        let mut pred = self.flag_store.flag_predicate(&Flag::Deleted);
        let to_expunge = uids.into_iter().filter(|&u| pred(u));

        for uid in to_expunge {
            // We will place gravestones on missing message files because we
            // did believe them to be extant UIDs already (since they had the
            // deleted flag).
            self.message_store.expunge(uid, true)?;
        }

        Ok(())
    }

    /// Append the given message to this mailbox.
    ///
    /// Returns the UID of the new message.
    ///
    /// This corresponds to the `APPEND` command from RFC 3501 and the
    /// `APPENDUID` response from RFC 4315.
    ///
    /// RFC 3501 also allows setting flags at the same time. This is
    /// accomplished with a follow-up call to `store_plus()`.
    ///
    /// TODO RFC 3501 also allows specifying a particular INTERNALDATE, which
    /// we don't pass through. Apparently some clients (like iPhone) use that
    /// as the delivered date instead of.. the message's delivered date?
    pub fn append(
        &mut self,
        key_store: &mut KeyStore,
        src: impl Read,
    ) -> Result<Uid, Error> {
        self.message_store.deliver_message(key_store, src)
    }

    /// Copies the given message from this mailbox to the destination (or self
    /// if `None`).
    ///
    /// A best effort is made to copy the flags on the copy.
    ///
    /// Returns the UID of the new message.
    ///
    /// This corresponds to the `UID COPY` command from RFC 3501 and the
    /// `COPYUID` response from RFC 4315.
    pub fn copy(
        &mut self,
        src: Uid,
        dst: Option<&mut Mailbox>,
    ) -> Result<Uid, Error> {
        self.refresh_flags()?;

        let path = self.message_store.path_for_uid(src);
        let flags = self
            .flag_store
            .get_flags_on_message(src)
            .cloned()
            .collect::<Vec<_>>();

        let dst = dst.unwrap_or(self);

        let new = dst.message_store.insert_message(path)?;
        if let Err(e) = dst.store_plus(new, &flags) {
            warn!(
                "{} Failed to copy flags to {}: {}",
                dst.log_prefix,
                new.0.get(),
                e
            );
        }
        Ok(new)
    }

    /// Copies the given message from this mailbox to the destination (or self
    /// if `None`).
    ///
    /// A best effort is made to copy the flags on the copy.
    ///
    /// Returns the UID of the new message.
    ///
    /// This corresponds to the `COPY` command from RFC 3501 and the `COPYUID`
    /// response from RFC 4315.
    pub fn seqnum_copy(
        &mut self,
        src: Seqnum,
        dst: Option<&mut Mailbox>,
    ) -> Result<Uid, Error> {
        let uid = self
            .message_store
            .seqnum_to_uid(src)
            .ok_or(Error::NxMessage)?;
        self.copy(uid, dst)
    }

    /// Move the given message into the given mailbox (or self if `None`).
    ///
    /// A best effort is made to copy the flags on the copy.
    ///
    /// Returns the UID of the new message.
    ///
    /// This corresponds to the `UID MOVE` command from RFC 6851 and the
    /// `COPYUID` response from RFC 4315.
    pub fn moove(
        &mut self,
        src: Uid,
        dst: Option<&mut Mailbox>,
    ) -> Result<Uid, Error> {
        let new = self.copy(src, dst)?;
        self.message_store.expunge(src, true)?;
        Ok(new)
    }

    /// Move the given message into the given mailbox (or self if `None`).
    ///
    /// A best effort is made to copy the flags on the copy.
    ///
    /// Returns the UID of the new message.
    ///
    /// This corresponds to the `UID MOVE` command from RFC 6851 and the
    /// `COPYUID` response from RFC 4315.
    pub fn seqnum_moove(
        &mut self,
        src: Seqnum,
        dst: Option<&mut Mailbox>,
    ) -> Result<Uid, Error> {
        let uid = self
            .message_store
            .seqnum_to_uid(src)
            .ok_or(Error::NxMessage)?;
        self.moove(uid, dst)
    }

    /// Append `new_data` to `dst` (or self if `None`), then expunge
    /// `to_expunge`.
    ///
    /// Returns the UID of the new message.
    ///
    /// This corresponds to the `UID REPLACE` command from RFC 8508 and the
    /// `APPENDUID` response from RFC 4315.
    pub fn replace(
        &mut self,
        to_expunge: Uid,
        key_store: &mut KeyStore,
        new_data: impl Read,
        dst: Option<&mut Mailbox>,
    ) -> Result<Uid, Error> {
        if self.message_store.uid_to_seqnum(to_expunge).is_none() {
            return Err(Error::NxMessage);
        }

        let new = dst.unwrap_or(self).append(key_store, new_data)?;
        self.message_store.expunge(to_expunge, true)?;
        Ok(new)
    }

    /// Append `new_data` to `dst` (or self if `None`), then expunge
    /// `to_expunge`.
    ///
    /// Returns the UID of the new message.
    ///
    /// This corresponds to the `REPLACE` command from RFC 8508 and the
    /// `APPENDUID` response from RFC 4315.
    pub fn seqnum_replace(
        &mut self,
        to_expunge: Seqnum,
        key_store: &mut KeyStore,
        new_data: impl Read,
        dst: Option<&mut Mailbox>,
    ) -> Result<Uid, Error> {
        self.replace(
            self.message_store
                .seqnum_to_uid(to_expunge)
                .ok_or(Error::NxMessage)?,
            key_store,
            new_data,
            dst,
        )
    }

    /// Adds the given flag(s) to the given message.
    ///
    /// This never affects `\Recent`.
    ///
    /// The new flags are not returned. For that, run a separate fetch
    /// afterwards.
    ///
    /// This corresponds to `UID STORE +FLAGS` and the `.SILENT` variant.
    pub fn store_plus<'a>(
        &mut self,
        uid: Uid,
        flags: impl IntoIterator<Item = &'a Flag>,
    ) -> Result<(), Error> {
        self.flag_store.write_flags_on_message(
            uid,
            flags.into_iter().filter(|f| &&Flag::Recent != f),
            true,
        )
    }

    /// Adds the given flag(s) to the given message.
    ///
    /// This never affects `\Recent`.
    ///
    /// The new flags are not returned. For that, run a separate fetch
    /// afterwards.
    ///
    /// This corresponds to `STORE +FLAGS` and the `.SILENT` variant.
    pub fn seqnum_store_plus<'a>(
        &mut self,
        seqnum: Seqnum,
        flags: impl IntoIterator<Item = &'a Flag>,
    ) -> Result<(), Error> {
        self.store_plus(
            self.message_store
                .seqnum_to_uid(seqnum)
                .ok_or(Error::NxMessage)?,
            flags,
        )
    }

    /// Removes the given flag(s) to the given message.
    ///
    /// This never affects `\Recent`.
    ///
    /// The new flags are not returned. For that, run a separate fetch
    /// afterwards.
    ///
    /// This corresponds to `UID STORE -FLAGS` and the `.SILENT` variant.
    pub fn store_minus<'a>(
        &mut self,
        uid: Uid,
        flags: impl IntoIterator<Item = &'a Flag>,
    ) -> Result<(), Error> {
        self.flag_store.write_flags_on_message(
            uid,
            flags.into_iter().filter(|f| &&Flag::Recent != f),
            false,
        )
    }

    /// Removes the given flag(s) to the given message.
    ///
    /// This never affects `\Recent`.
    ///
    /// The new flags are not returned. For that, run a separate fetch
    /// afterwards.
    ///
    /// This corresponds to `STORE -FLAGS` and the `.SILENT` variant.
    pub fn seqnum_store_minus<'a>(
        &mut self,
        seqnum: Seqnum,
        flags: impl IntoIterator<Item = &'a Flag>,
    ) -> Result<(), Error> {
        self.store_minus(
            self.message_store
                .seqnum_to_uid(seqnum)
                .ok_or(Error::NxMessage)?,
            flags,
        )
    }

    /// Fully replaces the flags on the given message.
    ///
    /// This never affects `\Recent`.
    ///
    /// The new flags are not returned. For that, run a separate fetch
    /// afterwards.
    ///
    /// This corresponds to `STORE FLAGS` and the `.SILENT` variant.
    pub fn store_set<'a>(
        &mut self,
        uid: Uid,
        flags: impl IntoIterator<Item = &'a Flag>,
    ) -> Result<(), Error> {
        self.refresh_flags()?;

        let curr_flags = self
            .flag_store
            .get_flags_on_message(uid)
            .cloned()
            .collect::<Vec<_>>();
        let new_flags = flags.into_iter().collect::<Vec<_>>();

        self.store_plus(
            uid,
            new_flags
                .iter()
                .cloned()
                .filter(|f| !curr_flags.contains(f)),
        )?;
        self.store_minus(
            uid,
            curr_flags.iter().filter(|f| !new_flags.contains(f)),
        )?;
        Ok(())
    }

    /// Fully replaces the flags on the given message.
    ///
    /// This never affects `\Recent`.
    ///
    /// The new flags are not returned. For that, run a separate fetch
    /// afterwards.
    ///
    /// This corresponds to `STORE FLAGS` and the `.SILENT` variant.
    pub fn seqnum_store_set<'a>(
        &mut self,
        seqnum: Seqnum,
        flags: impl IntoIterator<Item = &'a Flag>,
    ) -> Result<(), Error> {
        self.store_set(
            self.message_store
                .seqnum_to_uid(seqnum)
                .ok_or(Error::NxMessage)?,
            flags,
        )
    }

    /// Trigger a flag refresh if that hasn't happened recently.
    ///
    /// This only returns error if it is the first call. Otherwise, the error
    /// is simply logged.
    fn refresh_flags(&mut self) -> Result<(), Error> {
        let first_time = self.last_flag_refresh.is_some();

        if self
            .last_flag_refresh
            .map(|last| last.elapsed().as_secs() < 10)
            .unwrap_or(false)
        {
            // Refreshed within the last 10s, no need to do it again
            return Ok(());
        }

        match self.flag_store.refresh_flags() {
            Ok(()) => {
                self.last_flag_refresh = Some(Instant::now());
                Ok(())
            }
            Err(e) if first_time => Err(e),
            Err(e) => {
                warn!("{} Error refreshing flags: {}", self.log_prefix, e);
                Ok(())
            }
        }
    }

    fn count_recent(&mut self) -> usize {
        let mut pred = self.flag_store.flag_predicate(&Flag::Recent);
        self.message_store
            .messages()
            .map(|(_, u)| u)
            .filter(|&u| pred(u))
            .count()
    }
}

/// All information needed to produce a response to a `SELECT` or `EXAMINE`
/// command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectResponse {
    /// The currently-defined flags. Used for both the `FLAGS` response and the
    /// `PERMANENTFLAGS` response-code. For the latter, `\*` must also be
    /// added.
    /// `* FLAGS (flags...)`
    /// `* OK [PERMANENTFLAGS (flags... \*)]`
    pub flags: Vec<Flag>,
    /// The number of messages that currently exist.
    /// `* exists EXISTS`
    pub exists: usize,
    /// The number of messages with the `\Recent` tag.
    /// `* recent RECENT`
    pub recent: usize,
    /// The sequence number of the first message without the `\Seen` flag.
    /// `None` if all messages are seen. IMAP offers no way to indicate the
    /// latter state.
    /// `* OK [UNSEEN unseen]`
    pub unseen: Option<Seqnum>,
    /// The probable next UID.
    /// `* OK [UIDNEXT uidnext]`
    pub uidnext: Uid,
    /// The current UID validity.
    /// `* OK [UIDVALIDITY uidvalidity]`
    pub uidvalidity: u32,
    /// Whether the mailbox is read-only.
    /// `TAG OK [READ-WRITE|READ-ONLY]`
    pub read_only: bool,
}

/// Unsolicited responses that can be sent after commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PollResponse {
    /// Any sequence numbers to report as expunged.
    ///
    /// This is sorted descending and must be sent in exactly this order.
    ///
    /// ```
    /// * expunge[0] EXPUNGE
    /// * expunge[1] EXPUNGE
    /// ...
    /// ```
    expunge: Vec<Seqnum>,
    /// If the mailbox size has changed, the new size.
    /// `* exists EXISTS`
    exists: Option<usize>,
    /// If there are new messages, the new recent count.
    /// `* recent RECENT`
    recent: Option<usize>,
    // TODO We need to implement realtime updates of flags
}
