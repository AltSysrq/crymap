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

use std::collections::BTreeSet;
use std::convert::TryFrom;
use std::fmt::Write as _;
use std::path::Path;
use std::time::Duration;

use log::info;
use rusqlite::OptionalExtension as _;

use super::{sqlite_xex_vfs::XexVfs, types::*};
use crate::{
    account::model::*,
    support::{
        error::Error, mailbox_paths::parse_mailbox_path,
        small_bitset::SmallBitset,
    },
};

/// A connection to the encrypted `meta.sqlite.xex` database.
pub struct Connection {
    cxn: rusqlite::Connection,
}

static MIGRATION_V1: &str = include_str!("metadb.v1.sql");

impl Connection {
    pub fn new(path: &Path, xex: &XexVfs) -> Result<Self, Error> {
        let mut cxn = rusqlite::Connection::open_with_flags_and_vfs(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_CREATE,
            xex.name(),
        )?;

        cxn.pragma_update(None, "foreign_keys", true)?;
        cxn.pragma_update(None, "journal_mode", "PERSIST")?;
        cxn.pragma_update(None, "journal_size_limit", 1024 * 1024)?;
        cxn.busy_timeout(Duration::from_secs(10))?;

        {
            let txn = cxn.transaction_with_behavior(
                rusqlite::TransactionBehavior::Exclusive,
            )?;
            txn.execute(
                "CREATE TABLE IF NOT EXISTS `migration` (\
                   `version` INTEGER NOT NULL PRIMARY KEY, \
                   `applied_at` INTEGER NOT NULL\
                 ) STRICT",
                (),
            )?;

            let current_version = txn
                .query_row(
                    "SELECT MAX(`version`) FROM `migration`",
                    (),
                    from_single::<Option<u32>>,
                )?
                .unwrap_or(0);

            if current_version < 1 {
                info!("Applying V1 migration to meta DB");
                txn.execute_batch(MIGRATION_V1)?;
                txn.execute(
                    "INSERT INTO `migration` (`version`, `applied_at`) \
                     VALUES (1, ?)",
                    (UnixTimestamp::now(),),
                )?;
            }

            txn.commit()?;
        }

        Ok(Self { cxn })
    }

    /// Creates a mailbox with the given name, parent, and special use.
    ///
    /// On success, returns the ID of the created mailbox.
    pub fn create_mailbox(
        &mut self,
        parent: MailboxId,
        name: &str,
        special_use: Option<MailboxAttribute>,
    ) -> Result<MailboxId, Error> {
        let txn = self.cxn.write_tx()?;

        if 0 == txn.query_row(
            "SELECT COUNT(*) FROM `mailbox` WHERE `id` = ?",
            (parent,),
            from_single::<i64>,
        )? {
            return Err(Error::NxMailbox);
        }

        if 0 != txn.query_row(
            "SELECT COUNT(*) FROM `mailbox` \
             WHERE `parent_id` = ? AND `name` = ?",
            (parent, name),
            from_single::<i64>,
        )? {
            return Err(Error::MailboxExists);
        }

        txn.execute(
            "INSERT INTO `mailbox` (`parent_id`, `name`, `special_use`)\
             VALUES (?, ?, ?)",
            (parent, name, special_use),
        )?;

        let id = MailboxId(txn.last_insert_rowid());
        txn.commit()?;

        Ok(id)
    }

    /// Finds the ID of the mailbox with the given path, or returns
    /// `Error::NxMailbox` if it does not exist.
    ///
    /// This will never return `MailboxId::ROOT`. If `path` has no components,
    /// it returns `Error::NxMailbox`.
    pub fn find_mailbox(&mut self, path: &str) -> Result<MailboxId, Error> {
        self.cxn.enable_write(false)?;

        let mut id = MailboxId::ROOT;
        for part in parse_mailbox_path(path) {
            id = self
                .cxn
                .query_row(
                    "SELECT `id` FROM `mailbox` \
                     WHERE `parent_id` = ? AND `name` = ?",
                    (id, part),
                    from_single,
                )
                .optional()?
                .ok_or(Error::NxMailbox)?;
        }

        if MailboxId::ROOT == id {
            return Err(Error::NxMailbox);
        }

        Ok(id)
    }

    /// Finds the ID of the immediate parent mailbox of the given path,
    /// returning the ID and the name of the would-be child under that parent.
    /// `path` itself need not refer to an existing mailbox; only the parent
    /// must exist.
    ///
    /// This can return `MailboxId::ROOT` if `path` names a top-level mailbox,
    /// but if `path` has no components, it will return `NxMailbox`.
    pub fn find_mailbox_parent<'a>(
        &mut self,
        path: &'a str,
    ) -> Result<(MailboxId, &'a str), Error> {
        self.cxn.enable_write(false)?;

        let mut parent = MailboxId::ROOT;
        let mut it = parse_mailbox_path(path).peekable();
        while let Some(part) = it.next() {
            if it.peek().is_none() {
                return Ok((parent, part));
            }

            parent = self
                .cxn
                .query_row(
                    "SELECT `id` FROM `mailbox` \
                     WHERE `parent_id` = ? AND `name` = ?",
                    (parent, part),
                    from_single,
                )
                .optional()?
                .ok_or(Error::NxMailbox)?;
        }

        Err(Error::NxMailbox)
    }

    /// Fetches the mailbox with the given ID.
    pub fn fetch_mailbox(&mut self, id: MailboxId) -> Result<Mailbox, Error> {
        self.cxn.enable_write(false)?;

        self.cxn
            .query_row(
                "SELECT * FROM `mailbox` WHERE `id` = ?",
                (id,),
                Mailbox::from_row,
            )
            .optional()?
            .ok_or(Error::NxMailbox)
    }

    /// Retrieves all mailboxes currently in the account, excluding the root.
    pub fn fetch_all_mailboxes(&mut self) -> Result<Vec<Mailbox>, Error> {
        self.cxn.enable_write(false)?;

        self.cxn
            .prepare("SELECT * FROM `mailbox` WHERE `id` != 0")?
            .query_map((), from_row)?
            .collect::<Result<Vec<Mailbox>, _>>()
            .map_err(Into::into)
    }

    /// Moves and renames `mailbox_id` to have name `new_name` and be placed
    /// under `new_parent`.
    pub fn move_mailbox(
        &mut self,
        mailbox_id: MailboxId,
        new_parent: MailboxId,
        new_name: &str,
    ) -> Result<(), Error> {
        let txn = self.cxn.write_tx()?;

        // Fetch the current information about the mailbox to ensure it still
        // exists and to check whether the rename is a noop.
        let (current_parent, current_name) = txn
            .query_row(
                "SELECT `parent_id`, `name` FROM `mailbox` \
                 WHERE `id` = ?",
                (mailbox_id,),
                from_row::<(MailboxId, String)>,
            )
            .optional()?
            .ok_or(Error::NxMailbox)?;

        if new_parent == current_parent && new_name == current_name {
            return Err(Error::RenameToSelf);
        }

        // Walk up the tree and ensure `new_parent` is not a descendent of
        // `mailbox`. This also handles verifying that the new parent actually
        // exists.
        let mut ancestor = new_parent;
        while MailboxId::ROOT != ancestor {
            if ancestor == mailbox_id {
                return Err(Error::RenameIntoSelf);
            }

            ancestor = txn
                .query_row(
                    "SELECT `parent_id` FROM `mailbox` WHERE `id` = ?",
                    (ancestor,),
                    from_single,
                )
                .optional()?
                .ok_or(Error::NxMailbox)?;
        }

        // Ensure the new name is not already in use.
        if 0 != txn.query_row(
            "SELECT COUNT(*) FROM `mailbox` \
             WHERE `parent_id` = ? AND `name` = ?",
            (new_parent, new_name),
            from_single::<i64>,
        )? {
            return Err(Error::MailboxExists);
        }

        // Everything looks sensible; go ahead with the rename.

        txn.execute(
            "UPDATE `mailbox` SET `parent_id` = ?, `name` = ? \
             WHERE `id` = ?",
            (new_parent, new_name, mailbox_id),
        )?;

        txn.commit()?;
        Ok(())
    }

    /// Deletes the mailbox with the given ID.
    ///
    /// All messages and expungement records are removed from the mailbox. If
    /// the mailbox has inferiors, it is marked `\Noselect`. Otherwise, it is
    /// deleted entirely.
    ///
    /// Returns `NxMailbox` if the mailbox does not exist. Returns
    /// `MailboxHasInferiors` if it exists, is already `\Noselect`, and still
    /// has inferiors.
    pub fn delete_mailbox(&mut self, id: MailboxId) -> Result<(), Error> {
        let txn = self.cxn.write_tx()?;

        let selectable = txn
            .query_row(
                "SELECT `selectable` FROM `mailbox` \
                 WHERE `id` = ?",
                (id,),
                from_single::<bool>,
            )
            .optional()?
            .ok_or(Error::NxMailbox)?;

        let has_inferiors = 0
            != txn.query_row(
                "SELECT COUNT(*) FROM `mailbox` \
                 WHERE `parent_id` = ?",
                (id,),
                from_single::<i64>,
            )?;

        if !selectable && has_inferiors {
            // Nothing further we can do.
            return Err(Error::MailboxHasInferiors);
        }

        // Bump the activity time for all messages in the mailbox so that they
        // linger a while after being orphaned.
        txn.execute(
            "UPDATE `message` SET `last_activity` = ? \
             FROM (SELECT DISTINCT `message_id` FROM `mailbox_message` \
                   WHERE `mailbox_id` = ?) \
             WHERE `message`.`id` = `message_id`",
            (UnixTimestamp::now(), id),
        )?;

        // Remove external references to the mailbox.
        txn.execute(
            "DELETE FROM `mailbox_message_far_flag` \
             WHERE `mailbox_id` = ?",
            (id,),
        )?;
        txn.execute(
            "DELETE FROM `mailbox_message` \
             WHERE `mailbox_id` = ?",
            (id,),
        )?;
        txn.execute(
            "DELETE FROM `mailbox_message_expungement` \
             WHERE `mailbox_id` = ?",
            (id,),
        )?;

        // Remove the mailbox entirely if it has no inferiors; otherwise, just
        // make it \Noselect.
        if has_inferiors {
            txn.execute(
                "UPDATE `mailbox` SET `selectable` = 0 \
                 WHERE `id` = ?",
                (id,),
            )?;
        } else {
            txn.execute("DELETE FROM `mailbox` WHERE `id` = ?", (id,))?;
        }

        txn.commit()?;

        Ok(())
    }

    /// Adds `path` as a new subscription.
    ///
    /// No normalisation is applied to `path`; this is the responsibility of
    /// the API layer of the state-storage system.
    ///
    /// If the subscription already exists, does nothing.
    pub fn add_subscription(&mut self, path: &str) -> Result<(), Error> {
        self.cxn.enable_write(true)?;
        self.cxn.execute(
            "INSERT OR IGNORE INTO `subscription` (`path`) VALUES (?)",
            (path,),
        )?;
        Ok(())
    }

    /// Removes the subscription identified by `path`.
    ///
    /// If no such subscription exists, does nothing.
    pub fn rm_subscription(&mut self, path: &str) -> Result<(), Error> {
        self.cxn.enable_write(true)?;
        self.cxn
            .execute("DELETE FROM `subscription` WHERE `path` = ?", (path,))?;
        Ok(())
    }

    /// Returns all subscriptions in the account.
    ///
    /// Unsubscribed parents of subscribed mailboxes are not represented here.
    /// Their existence must be inferred from the results.
    pub fn fetch_all_subscriptions(
        &mut self,
    ) -> Result<BTreeSet<String>, Error> {
        self.cxn.enable_write(false)?;
        self.cxn
            .prepare("SELECT `path` FROM `subscription`")?
            .query_map((), from_single)?
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(Into::into)
    }

    /// Finds the ID of the given flag, if it exists. Returns `None` without
    /// modifying the database otherwise.
    pub fn look_up_flag_id(
        &mut self,
        flag: &Flag,
    ) -> Result<Option<FlagId>, Error> {
        self.cxn.enable_write(false)?;
        self.cxn
            .query_row(
                "SELECT `id` FROM `flag` WHERE `flag` = ?",
                (flag,),
                from_single,
            )
            .optional()
            .map_err(Into::into)
    }

    /// Interns `flag` into the database.
    ///
    /// If `flag` is already defined, the database is not modified and the
    /// existing ID is returned. Otherwise, `flag` is added to the database and
    /// its new ID is returned.
    pub fn intern_flag(&mut self, flag: &Flag) -> Result<FlagId, Error> {
        let txn = self.cxn.write_tx()?;
        if let Some(existing) = txn
            .query_row(
                "SELECT `id` FROM `flag` WHERE `flag` = ?",
                (flag,),
                from_single,
            )
            .optional()?
        {
            return Ok(existing);
        }

        txn.execute("INSERT INTO `flag` (`flag`) VALUES (?)", (flag,))?;
        let flag_id = usize::try_from(txn.last_insert_rowid())
            .map_err(|_| Error::MailboxFull)?;

        txn.commit()?;

        Ok(FlagId(flag_id))
    }

    /// Retrieves all flags that currently exist in the account.
    pub fn fetch_all_flags(&mut self) -> Result<Vec<(FlagId, Flag)>, Error> {
        self.cxn.enable_write(false)?;
        self.cxn
            .prepare("SELECT `id`, `flag` FROM `flag` ORDER BY `id`")?
            .query_map((), from_row)?
            .collect::<Result<_, _>>()
            .map_err(Into::into)
    }

    /// Interns each `path` as a message.
    ///
    /// Any created message is initially orphaned, so if the message is not
    /// eventually added to a mailbox, it will be deleted instead of being
    /// dropped into `INBOX`.
    pub fn intern_messages_as_orphans(
        &mut self,
        paths: &mut dyn Iterator<Item = &str>,
    ) -> Result<Vec<MessageId>, Error> {
        let txn = self.cxn.write_tx()?;

        let ret = paths
            .map(|path| intern_message_as_orphan(&txn, path))
            .collect::<Result<Vec<_>, _>>()?;
        txn.commit()?;

        Ok(ret)
    }

    /// Append already-interned messages into the given mailbox, with the given
    /// initial flags if requested.
    ///
    /// Returns the UID of the first message so inserted. (If there are no
    /// messages, this will be a UID of a non-existent message.) Each message
    /// is assigned a UID 1 greater than the previous.
    pub fn append_mailbox_messages(
        &mut self,
        mailbox_id: MailboxId,
        messages: &mut dyn Iterator<Item = (MessageId, Option<&SmallBitset>)>,
    ) -> Result<Uid, Error> {
        let txn = self.cxn.write_tx()?;

        require_selectable_mailbox(&txn, mailbox_id)?;
        let uid =
            append_mailbox_messages(&txn, mailbox_id, &mut messages.map(Ok))?;
        txn.commit()?;

        Ok(uid)
    }

    /// Atomically interns messages by path and then adds them to the given
    /// mailbox with the set per-message flags.
    pub fn intern_and_append_mailbox_messages(
        &mut self,
        mailbox_id: MailboxId,
        messages: &mut dyn Iterator<Item = (&str, Option<&SmallBitset>)>,
    ) -> Result<Uid, Error> {
        let txn = self.cxn.write_tx()?;

        require_selectable_mailbox(&txn, mailbox_id)?;

        let mut messages = messages.map(|(path, flags)| {
            intern_message_as_orphan(&txn, path).map(|id| (id, flags))
        });

        let uid = append_mailbox_messages(&txn, mailbox_id, &mut messages)?;
        txn.commit()?;

        Ok(uid)
    }

    /// Expunges the given messages by UID from the mailbox.
    ///
    /// This does not consider whether or not the messages have the `\Deleted`
    /// flag. UIDs not present in the mailbox are silently ignored.
    pub fn expunge_mailbox_messages(
        &mut self,
        mailbox_id: MailboxId,
        messages: &mut dyn Iterator<Item = Uid>,
    ) -> Result<(), Error> {
        let txn = self.cxn.write_tx()?;

        require_selectable_mailbox(&txn, mailbox_id)?;

        {
            let modseq = new_modseq(&txn, mailbox_id)?;
            let now = UnixTimestamp::now();

            let mut select_message_id = txn.prepare(
                "SELECT `message_id` FROM `mailbox_message` \
                 WHERE `mailbox_id` = ? AND `uid` = ?",
            )?;
            let mut delete_from_mailbox_message_far_flag = txn.prepare(
                "DELETE FROM `mailbox_message_far_flag` \
                 WHERE `mailbox_id` = ? AND `uid` = ?",
            )?;
            let mut delete_from_mailbox_message = txn.prepare(
                "DELETE FROM `mailbox_message` \
                 WHERE `mailbox_id` = ? AND `uid` = ?",
            )?;
            let mut update_last_activity = txn.prepare(
                "UPDATE `message` SET `last_activity` = ?2 WHERE `id` = ?1",
            )?;
            let mut insert_mailbox_message_expungement = txn.prepare(
                "INSERT INTO `mailbox_message_expungement` \
                 (`mailbox_id`, `uid`, `expunged_modseq`) \
                 VALUES (?, ?, ?)",
            )?;

            for uid in messages {
                let Some(message_id) = select_message_id
                    .query_row((mailbox_id, uid), from_single::<MessageId>)
                    .optional()?
                else {
                    continue;
                };

                delete_from_mailbox_message_far_flag
                    .execute((mailbox_id, uid))?;
                delete_from_mailbox_message.execute((mailbox_id, uid))?;
                update_last_activity.execute((message_id, now))?;
                insert_mailbox_message_expungement
                    .execute((mailbox_id, uid, modseq))?;
            }

            txn.execute(
                "UPDATE `mailbox` SET `expunge_modseq` = ? WHERE `id` = ?",
                (modseq, mailbox_id),
            )?;
        }

        txn.commit()?;

        Ok(())
    }

    /// Modifies the flags of the given sequence of messages in a mailbox.
    ///
    /// If `remove_listed` is true, flags found in `flags` are unset.
    /// Otherwise, flags found in `flags` are set.
    ///
    /// If `remove_unlisted` is `true`, flags not found in `flags` are unset.
    ///
    /// Messages where `flags_modseq > unchanged_since` are skipped.
    ///
    /// Returns the messages that were actually modified.
    ///
    /// UIDs corresponding to no existing message are silently ignored.
    pub fn modify_mailbox_message_flags(
        &mut self,
        mailbox_id: MailboxId,
        flags: &SmallBitset,
        remove_listed: bool,
        remove_unlisted: bool,
        unchanged_since: Modseq,
        messages: &mut dyn Iterator<Item = Uid>,
    ) -> Result<Vec<Uid>, Error> {
        debug_assert!(!remove_listed || !remove_unlisted);

        let mut modified = Vec::<Uid>::new();

        let txn = self.cxn.write_tx()?;
        require_selectable_mailbox(&txn, mailbox_id)?;

        {
            let modseq = new_modseq(&txn, mailbox_id)?;

            // For the near flags, we can fuse the unchanged_since check,
            // modification check, all addition/removal, and updating
            // `flags_modseq` into one operation per message.
            let mut update_near_flags = if 0 == flags.near_bits() {
                if remove_unlisted {
                    Some(txn.prepare(
                        "UPDATE `mailbox_message` \
                         SET `near_flags` = 0, `flags_modseq` = ?4 \
                         WHERE `mailbox_id` = ?1 AND `uid` = ?2 \
                         AND `flags_modseq` <= ?3 \
                         AND `near_flags` != 0",
                    )?)
                } else {
                    None
                }
            } else {
                let mut or_flags = 0i64;
                let mut nand_flags = 0i64;

                if remove_listed {
                    nand_flags |= flags.near_bits() as i64;
                } else {
                    or_flags |= flags.near_bits() as i64;
                }
                if remove_unlisted {
                    nand_flags |= !flags.near_bits() as i64;
                }

                let flags_expr =
                    format!("((`near_flags` | {or_flags}) & ~ {nand_flags})");
                Some(txn.prepare(&format!(
                    "UPDATE `mailbox_message` \
                     SET `near_flags` = {flags_expr}, `flags_modseq` = ?4 \
                     WHERE `mailbox_id` = ?1 AND `uid` = ?2 \
                     AND `flags_modseq` <= ?3 \
                     AND `near_flags` != {flags_expr}",
                ))?)
            };

            // For the far flags, we need separate steps for add/remove, and
            // also need to do the modseq check and update manually.
            let mut add_far_flags = if !flags.has_far() || remove_listed {
                None
            } else {
                let mut query =
                    "INSERT OR IGNORE INTO `mailbox_message_far_flag` \
                     (`mailbox_id`, `uid`, `flag_id`) VALUES"
                        .to_owned();
                for (i, far_flag) in flags.iter_far().enumerate() {
                    if 0 != i {
                        query.push(',');
                    }
                    let _ = write!(query, " (?1, ?2, {far_flag})");
                }

                Some(txn.prepare(&query)?)
            };

            let mut rm_far_flags = if remove_unlisted {
                if flags.has_far() {
                    let mut query = "DELETE FROM `mailbox_message_far_flag` \
                         WHERE `mailbox_id` = ? AND `uid` = ? \
                         AND `flag_id` NOT IN ("
                        .to_owned();
                    for (i, far_flag) in flags.iter_far().enumerate() {
                        if 0 != i {
                            query.push(',');
                        }
                        let _ = write!(query, "{far_flag}");
                    }
                    query.push(')');

                    Some(txn.prepare(&query)?)
                } else {
                    Some(txn.prepare(
                        "DELETE FROM `mailbox_message_far_flag` \
                         WHERE `mailbox_id` = ? AND `uid` = ?",
                    )?)
                }
            } else if remove_listed {
                let mut query = "DELETE FROM `mailbox_message_far_flag` \
                                 WHERE `mailbox_id` = ? AND `uid` = ? \
                                 AND `flag_id` IN ("
                    .to_owned();
                for (i, far_flag) in flags.iter_far().enumerate() {
                    if 0 != i {
                        query.push(',');
                    }
                    let _ = write!(query, "{far_flag}");
                }
                query.push(')');

                Some(txn.prepare(&query)?)
            } else {
                None
            };

            let mut is_updatable =
                if add_far_flags.is_some() || rm_far_flags.is_some() {
                    Some(txn.prepare(
                        "SELECT 1 FROM `mailbox_message` \
                         WHERE `mailbox_id` = ? AND `uid` = ? \
                         AND `flags_modseq` <= ?",
                    )?)
                } else {
                    None
                };

            let mut update_flags_modseq =
                if add_far_flags.is_some() || rm_far_flags.is_some() {
                    Some(txn.prepare(
                        "UPDATE `mailbox_message` \
                         SET `flags_modseq` = ?3 \
                         WHERE `mailbox_id` = ?1 AND `uid` = ?2",
                    )?)
                } else {
                    None
                };

            for uid in messages {
                let mut modified_with_modseq_update = false;
                let mut modified_without_modseq_update = false;

                if let Some(ref mut is_updatable) = is_updatable {
                    if !is_updatable.exists((
                        mailbox_id,
                        uid,
                        unchanged_since,
                    ))? {
                        continue;
                    }
                }

                if let Some(ref mut update_near_flags) = update_near_flags {
                    modified_with_modseq_update |= 0
                        != update_near_flags.execute((
                            mailbox_id,
                            uid,
                            unchanged_since,
                            modseq,
                        ))?;
                }

                if let Some(ref mut rm_far_flags) = rm_far_flags {
                    modified_without_modseq_update |=
                        0 != rm_far_flags.execute((mailbox_id, uid))?;
                }

                if let Some(ref mut add_far_flags) = add_far_flags {
                    modified_without_modseq_update |=
                        0 != add_far_flags.execute((mailbox_id, uid))?;
                }

                if let Some(ref mut update_flags_modseq) = update_flags_modseq {
                    if modified_without_modseq_update
                        && !modified_with_modseq_update
                    {
                        update_flags_modseq
                            .execute((mailbox_id, uid, modseq))?;
                    }
                }

                if modified_with_modseq_update || modified_without_modseq_update
                {
                    modified.push(uid);
                }
            }
        }

        txn.commit()?;
        Ok(modified)
    }

    /// Directly fetches the raw data for the given message.
    fn fetch_raw_message(
        &mut self,
        message_id: MessageId,
    ) -> Result<RawMessage, Error> {
        self.cxn.enable_write(false)?;
        self.cxn
            .query_row(
                "SELECT * FROM `message` WHERE `id` = ?",
                (message_id,),
                from_row,
            )
            .optional()?
            .ok_or(Error::NxMessage)
    }

    /// Directly fetches the raw data for the given mailbox message.
    fn fetch_raw_mailbox_message(
        &mut self,
        mailbox_id: MailboxId,
        uid: Uid,
    ) -> Result<RawMailboxMessage, Error> {
        self.cxn.enable_write(false)?;
        self.cxn
            .query_row(
                "SELECT * FROM `mailbox_message` \
                 WHERE `mailbox_id` = ? AND `uid` = ?",
                (mailbox_id, uid),
                from_row,
            )
            .optional()?
            .ok_or(Error::NxMessage)
    }

    /// Fetches the flags bitset for the given mailbox message.
    ///
    /// This is only useful for tests, as the real IMAP code needs to manage
    /// flags at a snapshot level.
    #[cfg(test)]
    fn fetch_mailbox_message_flags(
        &mut self,
        mailbox_id: MailboxId,
        uid: Uid,
    ) -> Result<SmallBitset, Error> {
        let txn = self.cxn.read_tx()?;
        let near = txn
            .query_row(
                "SELECT `near_flags` FROM `mailbox_message` \
                 WHERE `mailbox_id` = ? AND `uid` = ?",
                (mailbox_id, uid),
                from_single::<i64>,
            )
            .optional()?
            .ok_or(Error::NxMessage)?;

        let mut bitset = SmallBitset::new_with_near(near as u64);
        for flag in txn
            .prepare(
                "SELECT `flag_id` FROM `mailbox_message_far_flag` \
                 WHERE `mailbox_id` = ? AND `uid` = ?",
            )?
            .query_map((mailbox_id, uid), from_single::<usize>)?
        {
            bitset.insert(flag?);
        }

        Ok(bitset)
    }

    /// Fetches the `Modseq` at which a mailbox message was expunged (if there
    /// is such a record).
    ///
    /// This is only useful for tests. Real code needs to query the table for a
    /// range; additionally, this lookup is inefficient as there is no index on
    /// the key it uses.
    #[cfg(test)]
    fn fetch_mailbox_message_expunge_modseq(
        &mut self,
        mailbox_id: MailboxId,
        uid: Uid,
    ) -> Result<Option<Modseq>, Error> {
        self.cxn.enable_write(false)?;
        self.cxn
            .query_row(
                "SELECT `expunged_modseq` FROM `mailbox_message_expungement` \
                 WHERE `mailbox_id` = ? AND `uid` = ?",
                (mailbox_id, uid),
                from_single,
            )
            .optional()
            .map_err(Into::into)
    }

    /// Zero the `last_activity` field of the given message.
    #[cfg(test)]
    fn zero_message_last_activity(
        &mut self,
        message_id: MessageId,
    ) -> Result<(), Error> {
        self.cxn.enable_write(true)?;
        self.cxn.execute(
            "UPDATE `message` SET `last_activity` = 0 WHERE `id` = ?",
            (message_id,),
        )?;
        Ok(())
    }

    /// Fetches the initial snapshot state for a mailbox (as in `SELECT` or
    /// `EXAMINE`).
    ///
    /// `writable` controls whether the `recent_uid` field gets updated.
    pub fn select(
        &mut self,
        mailbox_id: MailboxId,
        writable: bool,
        qresync: Option<&QresyncRequest>,
    ) -> Result<InitialSnapshot, Error> {
        let txn = if writable {
            self.cxn.write_tx()?
        } else {
            self.cxn.read_tx()?
        };

        let (selectable, next_uid, recent_uid, max_modseq) = txn
            .query_row(
                "SELECT `selectable`, `next_uid`, `recent_uid`, `max_modseq` \
                 FROM `mailbox` WHERE `id` = ?",
                (mailbox_id,),
                from_row::<(bool, Uid, Uid, Modseq)>,
            )
            .optional()?
            .ok_or(Error::NxMailbox)?;

        if !selectable {
            return Err(Error::MailboxUnselectable);
        }

        let flags = txn
            .prepare("SELECT `id`, `flag` FROM `flag` ORDER BY `id`")?
            .query_map((), from_row::<(FlagId, Flag)>)?
            .collect::<Result<Vec<_>, _>>()?;

        let messages =
            fetch_initial_messages(&txn, mailbox_id, Uid::MIN, recent_uid)?;

        if writable && recent_uid != next_uid {
            txn.execute(
                "UPDATE `mailbox` SET `recent_uid` = `next_uid` \
                 WHERE `id` = ?",
                (mailbox_id,),
            )?;
        }

        let qresync_response = if let Some(qresync) =
            qresync.filter(|q| i64::from(q.uid_validity) == mailbox_id.0)
        {
            // Note that this code deliberately never looks at
            // `mapping_reference`: because we remember all expungements, the
            // case where we would use it never occurs.
            //
            // Comparisons against `resync_from` are `>` and not `>=` since the
            // client implies that it knows the state at `modseq ==
            // resync_from`.

            let accept_uid = |uid: Uid| -> bool {
                qresync
                    .known_uids
                    .as_ref()
                    .map_or(true, |k| k.contains(uid))
            };

            let mut expunged = SeqRange::<Uid>::new();
            for uid in txn
                .prepare(
                    "SELECT `uid` FROM `mailbox_message_expungement` \
                     WHERE `mailbox_id` = ? AND `expunged_modseq` > ? \
                     ORDER BY `uid`",
                )?
                .query_map(
                    (mailbox_id, qresync.resync_from),
                    from_single::<Uid>,
                )?
            {
                let uid = uid?;
                if accept_uid(uid) {
                    expunged.append(uid);
                }
            }

            let changed = txn
                .prepare(
                    // `flags_modseq` is always >= `append_modseq`, so we only
                    // need to query one of them.
                    "SELECT `uid` FROM `mailbox_message` \
                     WHERE `mailbox_id` = ? AND `flags_modseq` > ? \
                     ORDER BY `uid`",
                )?
                .query_map(
                    (mailbox_id, qresync.resync_from),
                    from_single::<Uid>,
                )?
                .filter_map(|res| match res {
                    Ok(uid) if !accept_uid(uid) => None,
                    res => Some(res),
                })
                .collect::<Result<Vec<Uid>, _>>()?;

            Some(QresyncResponse { expunged, changed })
        } else {
            None
        };

        txn.commit()?;

        Ok(InitialSnapshot {
            flags,
            messages,
            next_uid,
            max_modseq,
            qresync: qresync_response,
        })
    }
}

trait ConnectionExt {
    fn read_tx(&mut self) -> rusqlite::Result<rusqlite::Transaction<'_>>;
    fn write_tx(&mut self) -> rusqlite::Result<rusqlite::Transaction<'_>>;
    fn enable_write(&mut self, enabled: bool) -> rusqlite::Result<()>;
}

impl ConnectionExt for rusqlite::Connection {
    fn read_tx(&mut self) -> rusqlite::Result<rusqlite::Transaction<'_>> {
        self.enable_write(false)?;
        self.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
    }

    fn write_tx(&mut self) -> rusqlite::Result<rusqlite::Transaction<'_>> {
        self.enable_write(true)?;
        self.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
    }

    #[cfg(debug_assertions)]
    fn enable_write(&mut self, enabled: bool) -> rusqlite::Result<()> {
        // PRAGMA doesn't actually support templates, so switch the whole query
        // string based on `enabled`.
        self.execute(
            if enabled {
                "PRAGMA query_only = false"
            } else {
                "PRAGMA query_only = true"
            },
            (),
        )?;
        Ok(())
    }

    #[cfg(not(debug_assertions))]
    fn enable_write(&mut self, _: bool) -> rusqlite::Result<()> {
        Ok(())
    }
}

fn intern_message_as_orphan(
    cxn: &rusqlite::Connection,
    path: &str,
) -> Result<MessageId, Error> {
    let existing = cxn
        .prepare_cached("SELECT `id` FROM `message` WHERE `path` = ?")?
        .query_row((path,), from_single)
        .optional()?;
    if let Some(existing) = existing {
        return Ok(existing);
    }

    cxn.prepare_cached(
        "INSERT INTO `message` (`path`, `last_activity`) VALUES (?, ?)",
    )?
    .execute((path, UnixTimestamp::now()))?;

    Ok(MessageId(cxn.last_insert_rowid()))
}

fn append_mailbox_messages(
    cxn: &rusqlite::Connection,
    mailbox_id: MailboxId,
    messages: &mut dyn Iterator<
        Item = Result<(MessageId, Option<&SmallBitset>), Error>,
    >,
) -> Result<Uid, Error> {
    let modseq = new_modseq(cxn, mailbox_id)?;

    // Read the UID for the first new message out of the database. While here,
    // also re-assert that the mailbox exists and is selectable, though
    // `require_selectable_mailbox` ought to have been called first to
    // distinguish the two cases.
    let first_uid = cxn
        .query_row(
            "SELECT `next_uid` FROM `mailbox` WHERE `id` = ? AND `selectable`",
            (mailbox_id,),
            from_single::<Uid>,
        )
        .optional()?
        .ok_or(Error::NxMailbox)?;

    let mut next_uid = first_uid;

    let now = UnixTimestamp::now();
    let mut mailbox_message_insert = cxn.prepare(
        "INSERT INTO `mailbox_message` ( \
           `mailbox_id`, `uid`, `message_id`, `near_flags`, \
           `savedate`, `append_modseq`, `flags_modseq` \
         ) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )?;
    let mut mailbox_message_far_flag_insert = cxn.prepare(
        "INSERT INTO `mailbox_message_far_flag` (\
           `mailbox_id`, `uid`, `flag_id` \
         ) VALUES (?, ?, ?)",
    )?;

    for message in messages {
        let (message_id, flags) = message?;

        let uid = next_uid;
        next_uid = next_uid.next().ok_or(Error::MailboxFull)?;

        mailbox_message_insert.execute((
            mailbox_id,
            uid,
            message_id,
            flags.map_or(0, |f| f.near_bits() as i64),
            now,
            modseq,
            modseq,
        ))?;

        if let Some(flags) = flags {
            if flags.has_far() {
                for far_flag in flags.iter_far() {
                    mailbox_message_far_flag_insert.execute((
                        mailbox_id,
                        uid,
                        FlagId(far_flag),
                    ))?;
                }
            }
        }
    }

    if next_uid > first_uid {
        cxn.execute(
            "UPDATE `mailbox` \
             SET `next_uid` = ?, `append_modseq` = ? \
             WHERE `id` = ?",
            (next_uid, modseq, mailbox_id),
        )?;
    }

    Ok(first_uid)
}

/// Fetches the `InitialMessageStatus` for every message in `mailbox_id` whose
/// UID is at least `min_uid`.
///
/// `recent_uid` is used to determine the value of the `recent` field.
fn fetch_initial_messages(
    txn: &rusqlite::Connection,
    mailbox_id: MailboxId,
    min_uid: Uid,
    recent_uid: Uid,
) -> Result<Vec<InitialMessageStatus>, Error> {
    let mut messages = txn
        .prepare(
            "SELECT `uid`, `message_id`, `near_flags`,
                    MAX(`flags_modseq`, `append_modseq`) \
             FROM `mailbox_message` \
             WHERE `mailbox_id` = ? AND `uid` >= ? \
             ORDER BY `uid`",
        )?
        .query_map(
            (mailbox_id, min_uid),
            from_row::<(Uid, MessageId, i64, Modseq)>,
        )?
        .map(|res| {
            res.map(|(uid, id, near_flags, modseq)| InitialMessageStatus {
                uid,
                id,
                flags: SmallBitset::new_with_near(near_flags as u64),
                last_modified: modseq,
                recent: uid >= recent_uid,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    {
        let mut msg_it = messages.iter_mut().peekable();

        for far_flag in txn
            .prepare(
                "SELECT `uid`, `flag_id` \
                 FROM `mailbox_message_far_flag` \
                 WHERE `mailbox_id` = ? \
                 ORDER BY `uid`",
            )?
            .query_map((mailbox_id,), from_row::<(Uid, FlagId)>)?
        {
            let (uid, FlagId(flag_id)) = far_flag?;
            while msg_it.peek().unwrap().uid < uid {
                msg_it.next();
            }

            let msg = msg_it.peek_mut().unwrap();
            debug_assert_eq!(uid, msg.uid);
            msg.flags.insert(flag_id);
        }
    }

    Ok(messages)
}

/// Ensures that `id` represents an extant and selectable mailbox.
fn require_selectable_mailbox(
    cxn: &rusqlite::Connection,
    id: MailboxId,
) -> Result<(), Error> {
    match cxn
        .prepare_cached("SELECT `selectable` FROM `mailbox` WHERE `id` = ?")?
        .query_row((id,), from_single)
        .optional()?
    {
        None => Err(Error::NxMailbox),
        Some(false) => Err(Error::MailboxUnselectable),
        Some(true) => Ok(()),
    }
}

/// Allocates a new `Modseq` for a change within the given mailbox.
fn new_modseq(
    cxn: &rusqlite::Connection,
    id: MailboxId,
) -> Result<Modseq, Error> {
    let max_modseq = cxn.prepare_cached(
        "SELECT `max_modseq` FROM `mailbox` WHERE `id` = ? AND `selectable`",
    )?
        .query_row((id,), from_single::<Modseq>)
        .optional()?
        .ok_or(Error::NxMailbox)?;

    let this_modseq = max_modseq.next().ok_or(Error::MailboxFull)?;

    cxn.prepare_cached("UPDATE `mailbox` SET `max_modseq` = ? WHERE `id` = ?")?
        .execute((this_modseq, id))?;

    Ok(this_modseq)
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use tempfile::TempDir;

    use super::*;
    use crate::crypt::master_key::MasterKey;

    struct Fixture {
        _tmpdir: TempDir,
        cxn: Connection,
    }

    impl Fixture {
        fn new() -> Self {
            let tmpdir = TempDir::new().unwrap();
            let master_key = Arc::new(MasterKey::new());
            let xex = XexVfs::new(master_key).unwrap();
            let cxn =
                Connection::new(&tmpdir.path().join("meta.sqlite.xex"), &xex)
                    .unwrap();

            Self {
                _tmpdir: tmpdir,
                cxn,
            }
        }
    }

    #[test]
    fn test_mailbox_crud() {
        let mut fixture = Fixture::new();

        // Creation

        let foo_id = fixture
            .cxn
            .create_mailbox(MailboxId::ROOT, "foo", None)
            .unwrap();
        assert_eq!(MailboxId(1), foo_id);

        let foobar_id =
            fixture.cxn.create_mailbox(foo_id, "bar", None).unwrap();
        let baz_id = fixture
            .cxn
            .create_mailbox(
                MailboxId::ROOT,
                "baz",
                Some(MailboxAttribute::Important),
            )
            .unwrap();

        assert_matches!(
            Err(Error::MailboxExists),
            fixture.cxn.create_mailbox(MailboxId::ROOT, "foo", None),
        );
        assert_matches!(
            Err(Error::MailboxExists),
            fixture.cxn.create_mailbox(foo_id, "bar", None),
        );
        assert_matches!(
            Err(Error::NxMailbox),
            fixture.cxn.create_mailbox(MailboxId(-1), "quux", None),
        );

        // Retrieval

        let mut mailboxes = fixture
            .cxn
            .fetch_all_mailboxes()
            .unwrap()
            .into_iter()
            .map(|mb| (mb.name, mb.parent_id, mb.special_use))
            .collect::<Vec<_>>();
        mailboxes.sort();

        assert_eq!(
            vec![
                ("bar".to_owned(), foo_id, None),
                (
                    "baz".to_owned(),
                    MailboxId::ROOT,
                    Some(MailboxAttribute::Important)
                ),
                ("foo".to_owned(), MailboxId::ROOT, None),
            ],
            mailboxes
        );

        let mut foobar = fixture.cxn.fetch_mailbox(foobar_id).unwrap();
        assert_eq!("bar", foobar.name);
        assert_eq!(foo_id, foobar.parent_id);

        assert_matches!(
            Err(Error::NxMailbox),
            fixture.cxn.fetch_mailbox(MailboxId(-1)),
        );

        // Path resolution

        assert_eq!(foo_id, fixture.cxn.find_mailbox("foo").unwrap());
        assert_eq!(foobar_id, fixture.cxn.find_mailbox("foo/bar").unwrap());
        assert_eq!(baz_id, fixture.cxn.find_mailbox("baz").unwrap());
        assert_matches!(Err(Error::NxMailbox), fixture.cxn.find_mailbox(""));
        assert_matches!(Err(Error::NxMailbox), fixture.cxn.find_mailbox("bar"));
        assert_matches!(
            Err(Error::NxMailbox),
            fixture.cxn.find_mailbox("foo/baz"),
        );
        assert_matches!(
            Err(Error::NxMailbox),
            fixture.cxn.find_mailbox("foo/bar/baz"),
        );

        assert_eq!(
            (MailboxId::ROOT, "quux"),
            fixture.cxn.find_mailbox_parent("quux").unwrap(),
        );
        assert_eq!(
            (MailboxId::ROOT, "foo"),
            fixture.cxn.find_mailbox_parent("foo").unwrap(),
        );
        assert_eq!(
            (MailboxId::ROOT, "INBOX"),
            fixture.cxn.find_mailbox_parent("InBoX").unwrap(),
        );
        assert_eq!(
            (foo_id, "quux"),
            fixture.cxn.find_mailbox_parent("foo/quux").unwrap(),
        );
        assert_eq!(
            (foobar_id, "quux"),
            fixture.cxn.find_mailbox_parent("foo/bar/quux").unwrap(),
        );
        assert_eq!(
            (foo_id, "InBoX"),
            fixture.cxn.find_mailbox_parent("//foo/InBoX").unwrap(),
        );
        assert_matches!(
            Err(Error::NxMailbox),
            fixture.cxn.find_mailbox_parent(""),
        );
        assert_matches!(
            Err(Error::NxMailbox),
            fixture.cxn.find_mailbox_parent("foo/bar/baz/quux"),
        );

        // Renaming

        fixture
            .cxn
            .move_mailbox(foobar_id, foo_id, "foobar")
            .unwrap();
        foobar = fixture.cxn.fetch_mailbox(foobar_id).unwrap();
        assert_eq!("foobar", foobar.name);
        assert_eq!(foo_id, foobar.parent_id);

        fixture
            .cxn
            .move_mailbox(foobar_id, baz_id, "foobar")
            .unwrap();
        foobar = fixture.cxn.fetch_mailbox(foobar_id).unwrap();
        assert_eq!("foobar", foobar.name);
        assert_eq!(baz_id, foobar.parent_id);

        fixture.cxn.move_mailbox(foobar_id, foo_id, "bar").unwrap();
        foobar = fixture.cxn.fetch_mailbox(foobar_id).unwrap();
        assert_eq!("bar", foobar.name);
        assert_eq!(foo_id, foobar.parent_id);

        assert_matches!(
            Err(Error::RenameToSelf),
            fixture.cxn.move_mailbox(foobar_id, foo_id, "bar"),
        );
        assert_matches!(
            Err(Error::RenameIntoSelf),
            fixture.cxn.move_mailbox(foo_id, foobar_id, "plugh"),
        );
        assert_matches!(
            Err(Error::RenameIntoSelf),
            fixture.cxn.move_mailbox(foo_id, foo_id, "foo"),
        );
        assert_matches!(
            Err(Error::NxMailbox),
            fixture.cxn.move_mailbox(MailboxId(-1), foo_id, "plugh"),
        );
        assert_matches!(
            Err(Error::NxMailbox),
            fixture.cxn.move_mailbox(foo_id, MailboxId(-1), "plugh"),
        );
        assert_matches!(
            Err(Error::MailboxExists),
            fixture.cxn.move_mailbox(baz_id, MailboxId::ROOT, "foo"),
        );

        // Deletion. Deleting messages and whatnot isn't tested here, but this
        // at least checks that the queries are syntactically valid.

        let mut foo = fixture.cxn.fetch_mailbox(foo_id).unwrap();
        assert!(foo.selectable);

        fixture.cxn.delete_mailbox(foo_id).unwrap();
        foo = fixture.cxn.fetch_mailbox(foo_id).unwrap();
        assert!(!foo.selectable);

        assert_matches!(
            Err(Error::MailboxHasInferiors),
            fixture.cxn.delete_mailbox(foo_id),
        );

        fixture.cxn.delete_mailbox(foobar_id).unwrap();
        assert_matches!(
            Err(Error::NxMailbox),
            fixture.cxn.fetch_mailbox(foobar_id),
        );

        fixture.cxn.delete_mailbox(foo_id).unwrap();
        assert_matches!(
            Err(Error::NxMailbox),
            fixture.cxn.fetch_mailbox(foo_id),
        );
    }

    #[test]
    fn test_subscription_crud() {
        let mut fixture = Fixture::new();

        fixture.cxn.add_subscription("foo").unwrap();
        fixture.cxn.add_subscription("bar").unwrap();
        fixture.cxn.add_subscription("foo").unwrap();

        assert_eq!(
            vec!["bar".to_owned(), "foo".to_owned()],
            fixture
                .cxn
                .fetch_all_subscriptions()
                .unwrap()
                .into_iter()
                .collect::<Vec<String>>(),
        );

        fixture.cxn.rm_subscription("foo").unwrap();
        fixture.cxn.rm_subscription("quux").unwrap();

        assert_eq!(
            vec!["bar".to_owned()],
            fixture
                .cxn
                .fetch_all_subscriptions()
                .unwrap()
                .into_iter()
                .collect::<Vec<String>>(),
        );
    }

    #[test]
    fn test_flag_interning() {
        let mut fixture = Fixture::new();

        let keyword = Flag::Keyword("Keyword".to_owned());
        assert_eq!(None, fixture.cxn.look_up_flag_id(&keyword).unwrap());
        assert_eq!(FlagId(5), fixture.cxn.intern_flag(&keyword).unwrap());
        assert_eq!(
            Some(FlagId(5)),
            fixture.cxn.look_up_flag_id(&keyword).unwrap(),
        );
        assert_eq!(FlagId(5), fixture.cxn.intern_flag(&keyword).unwrap());
        assert!(fixture
            .cxn
            .fetch_all_flags()
            .unwrap()
            .contains(&(FlagId(5), keyword.clone())));
    }

    #[test]
    fn test_message_crud() {
        let mut fixture = Fixture::new();

        // Create a bunch of flags. Some will be near flags, others far flags.
        let flags = (0..100)
            .map(|f| {
                fixture
                    .cxn
                    .intern_flag(&Flag::Keyword(format!("flag{f}")))
                    .unwrap()
            })
            .collect::<Vec<FlagId>>();

        let unselectable_id = fixture
            .cxn
            .create_mailbox(MailboxId::ROOT, "unselectable", None)
            .unwrap();
        let child_id = fixture
            .cxn
            .create_mailbox(unselectable_id, "child", None)
            .unwrap();

        // Insert a couple messages into `unselectable`, give one of them a far
        // flag, and expunge the other. This will add entries to all the
        // mailbox-specific sub-tables, which we can then validate were removed
        // when we delete `unselectable` (making it \Noselect rather than
        // actually removing it).
        let us_uid_flag = fixture
            .cxn
            .intern_and_append_mailbox_messages(
                unselectable_id,
                &mut [("foo", None), ("bar", None)].iter().copied(),
            )
            .unwrap();
        assert_eq!(Uid::u(1), us_uid_flag);

        let us_flag_flags = SmallBitset::from(vec![flags[99].0]);
        fixture
            .cxn
            .modify_mailbox_message_flags(
                unselectable_id,
                &us_flag_flags,
                false,
                false,
                Modseq::MAX,
                &mut [us_uid_flag].iter().copied(),
            )
            .unwrap();

        let us_flag_mboxmsg = fixture
            .cxn
            .fetch_raw_mailbox_message(unselectable_id, us_uid_flag)
            .unwrap();
        // The flag we set should be a far flag.
        assert_eq!(0, us_flag_mboxmsg.near_flags);

        assert_eq!(Modseq::of(2), us_flag_mboxmsg.append_modseq);
        assert_eq!(Modseq::of(3), us_flag_mboxmsg.flags_modseq);

        // Ensure the flags are what we think. Since we eliminated the
        // possibility of the flag being a near flag above, success implies a
        // far flag entry.
        assert_eq!(
            us_flag_flags,
            fixture
                .cxn
                .fetch_mailbox_message_flags(unselectable_id, us_uid_flag)
                .unwrap(),
        );

        let us_uid_expunge = us_uid_flag.next().unwrap();
        fixture
            .cxn
            .expunge_mailbox_messages(
                unselectable_id,
                &mut [us_uid_expunge].iter().copied(),
            )
            .unwrap();

        // Validate that it has in fact been expunged.
        assert_matches!(
            Err(Error::NxMessage),
            fixture
                .cxn
                .fetch_raw_mailbox_message(unselectable_id, us_uid_expunge),
        );
        assert_eq!(
            Some(Modseq::of(4)),
            fixture
                .cxn
                .fetch_mailbox_message_expunge_modseq(
                    unselectable_id,
                    us_uid_expunge
                )
                .unwrap(),
        );

        let mut unselectable =
            fixture.cxn.fetch_mailbox(unselectable_id).unwrap();
        assert_eq!(Modseq::of(4), unselectable.expunge_modseq);
        assert_eq!(Modseq::of(2), unselectable.append_modseq);
        assert_eq!(Uid::u(3), unselectable.next_uid);

        // Delete `unselectable`, making it `\Noselect`.
        fixture.cxn.delete_mailbox(unselectable_id).unwrap();
        unselectable = fixture.cxn.fetch_mailbox(unselectable_id).unwrap();
        assert!(!unselectable.selectable);

        assert_matches!(
            Err(Error::NxMessage),
            fixture
                .cxn
                .fetch_raw_mailbox_message(unselectable_id, us_uid_flag),
        );
        assert_eq!(
            None,
            fixture
                .cxn
                .fetch_mailbox_message_expunge_modseq(
                    unselectable_id,
                    us_uid_expunge
                )
                .unwrap()
        );

        // Now we can test all the expected failure modes of the message CRUD
        // operations.

        assert_matches!(
            Err(Error::MailboxUnselectable),
            fixture.cxn.append_mailbox_messages(
                unselectable_id,
                &mut [(us_flag_mboxmsg.message_id, None)].iter().copied(),
            ),
        );
        assert_matches!(
            Err(Error::NxMailbox),
            fixture.cxn.append_mailbox_messages(
                MailboxId(-1),
                &mut [(us_flag_mboxmsg.message_id, None)].iter().copied(),
            ),
        );
        assert_matches!(
            Err(Error::MailboxUnselectable),
            fixture.cxn.intern_and_append_mailbox_messages(
                unselectable_id,
                &mut [("foo", None)].iter().copied(),
            ),
        );
        assert_matches!(
            Err(Error::NxMailbox),
            fixture.cxn.intern_and_append_mailbox_messages(
                MailboxId(-1),
                &mut [("foo", None)].iter().copied(),
            ),
        );
        assert_matches!(
            Err(Error::MailboxUnselectable),
            fixture.cxn.expunge_mailbox_messages(
                unselectable_id,
                &mut [us_uid_flag].iter().copied(),
            ),
        );
        assert_matches!(
            Err(Error::NxMailbox),
            fixture.cxn.expunge_mailbox_messages(
                MailboxId(-1),
                &mut [us_uid_flag].iter().copied(),
            ),
        );
        assert_matches!(
            Err(Error::MailboxUnselectable),
            fixture.cxn.modify_mailbox_message_flags(
                unselectable_id,
                &SmallBitset::new(),
                false,
                false,
                Modseq::MAX,
                &mut [us_uid_flag].iter().copied(),
            ),
        );
        assert_matches!(
            Err(Error::NxMailbox),
            fixture.cxn.modify_mailbox_message_flags(
                MailboxId(-1),
                &SmallBitset::new(),
                false,
                false,
                Modseq::MAX,
                &mut [us_uid_flag].iter().copied(),
            ),
        );

        // Add a message to child by the two-step process, inserting them with
        // initial flags (both near and far).
        let child_init_flags = SmallBitset::from(vec![flags[0].0, flags[99].0]);
        let child_msg_ids = fixture
            .cxn
            .intern_messages_as_orphans(
                &mut ["foo", "bar", "baz"].iter().copied(),
            )
            .unwrap();
        let child_msg_uid123 = fixture
            .cxn
            .append_mailbox_messages(
                child_id,
                &mut child_msg_ids
                    .iter()
                    .map(|&id| (id, Some(&child_init_flags))),
            )
            .unwrap();
        let child_msg_uid4 = fixture
            .cxn
            .intern_and_append_mailbox_messages(
                child_id,
                &mut [("foo", Some(&child_init_flags))].iter().copied(),
            )
            .unwrap();

        assert_eq!(Uid::u(1), child_msg_uid123);
        assert_eq!(Uid::u(4), child_msg_uid4);

        let child_mboxmsg1 = fixture
            .cxn
            .fetch_raw_mailbox_message(child_id, child_msg_uid123)
            .unwrap();
        let child_mboxmsg4 = fixture
            .cxn
            .fetch_raw_mailbox_message(child_id, child_msg_uid4)
            .unwrap();
        // Because messages 1 and 4 both have path "foo", they both have the
        // same underlying message ID.
        assert_eq!(child_mboxmsg1.message_id, child_mboxmsg4.message_id);

        // Ensure all the flags were set properly.
        assert_eq!(
            child_init_flags,
            fixture
                .cxn
                .fetch_mailbox_message_flags(child_id, child_msg_uid123)
                .unwrap(),
        );
        assert_eq!(
            child_init_flags,
            fixture
                .cxn
                .fetch_mailbox_message_flags(
                    child_id,
                    child_msg_uid123.next().unwrap()
                )
                .unwrap(),
        );
        assert_eq!(
            child_init_flags,
            fixture
                .cxn
                .fetch_mailbox_message_flags(child_id, child_msg_uid4)
                .unwrap(),
        );

        // Brute-force various operations with every flag we've defined
        // combining with known near- and far-flags to exercise every path in
        // modify_mailbox_message_flags and check the boundary conditions.
        for &FlagId(flag) in &flags[1..99] {
            let uid = child_msg_uid123;

            // Clear the flags left over from prior code.
            fixture
                .cxn
                .modify_mailbox_message_flags(
                    child_id,
                    &SmallBitset::new(),
                    false,
                    true,
                    Modseq::MAX,
                    &mut [uid].iter().copied(),
                )
                .unwrap();

            macro_rules! read_modseq {
                () => {
                    fixture
                        .cxn
                        .fetch_raw_mailbox_message(child_id, uid)
                        .unwrap()
                        .flags_modseq
                };
            }

            macro_rules! read_flags {
                () => {
                    fixture
                        .cxn
                        .fetch_mailbox_message_flags(child_id, uid)
                        .unwrap()
                };
            }

            let start_modseq = read_modseq!();

            // Set *just* the flag in question. This covers the fused update
            // case where all conditions pass for near flags and the insertion
            // case for far flags.
            assert_eq!(
                vec![uid],
                fixture
                    .cxn
                    .modify_mailbox_message_flags(
                        child_id,
                        &SmallBitset::from(vec![flag]),
                        false,
                        true,
                        start_modseq,
                        &mut [uid].iter().copied(),
                    )
                    .unwrap(),
            );
            let mut modseq = read_modseq!();
            assert!(modseq > start_modseq);
            assert_eq!(SmallBitset::from(vec![flag]), read_flags!());

            // Try clearing the flag, setting a near flag, setting a far flag,
            // and clearing all flags with the old modseq. Nothing should
            // happen. This covers the inline modseq case for near flags and
            // the manual check for far flags.
            for (flags, remove_listed, remove_unlisted) in vec![
                (vec![flag], true, false),
                (vec![flags[0].0], true, false),
                (vec![flags[99].0], true, false),
                (vec![], false, true),
            ] {
                assert!(fixture
                    .cxn
                    .modify_mailbox_message_flags(
                        child_id,
                        &SmallBitset::from(flags),
                        remove_listed,
                        remove_unlisted,
                        start_modseq,
                        &mut [uid].iter().copied(),
                    )
                    .unwrap()
                    .is_empty());
                assert_eq!(modseq, read_modseq!());
                assert_eq!(SmallBitset::from(vec![flag]), read_flags!());
            }

            // Setting the flag when it's already set does nothing, and the
            // value of remove_unlisted changes nothing since there are no
            // other flags. This partially covers the no-op check for near
            // flags and fully covers the no-op checks for far flag insertion
            // and bulk far flag removal.
            for &remove_unlisted in &[false, true] {
                assert!(fixture
                    .cxn
                    .modify_mailbox_message_flags(
                        child_id,
                        &SmallBitset::from(vec![flag]),
                        false,
                        remove_unlisted,
                        modseq,
                        &mut [uid].iter().copied(),
                    )
                    .unwrap()
                    .is_empty());
                assert_eq!(modseq, read_modseq!());
                assert_eq!(SmallBitset::from(vec![flag]), read_flags!());
            }

            // Toggling other flags leaves this one alone.
            for &other_flag in &[flags[0].0, flags[99].0] {
                assert_eq!(
                    vec![uid],
                    fixture
                        .cxn
                        .modify_mailbox_message_flags(
                            child_id,
                            &SmallBitset::from(vec![other_flag]),
                            false,
                            false,
                            modseq,
                            &mut [uid].iter().copied(),
                        )
                        .unwrap(),
                    "flag={flag}, other_flag={other_flag}",
                );
                let mut new_modseq = read_modseq!();
                assert!(new_modseq > modseq);
                modseq = new_modseq;
                assert_eq!(
                    SmallBitset::from(vec![other_flag, flag]),
                    read_flags!(),
                );

                assert_eq!(
                    vec![uid],
                    fixture
                        .cxn
                        .modify_mailbox_message_flags(
                            child_id,
                            &SmallBitset::from(vec![other_flag]),
                            true,
                            false,
                            modseq,
                            &mut [uid].iter().copied(),
                        )
                        .unwrap(),
                );
                new_modseq = read_modseq!();
                assert!(new_modseq > modseq);
                modseq = new_modseq;
                assert_eq!(SmallBitset::from(vec![flag]), read_flags!(),);
            }

            // Clearing another flag by remove_unlisted while re-setting the
            // flag in question is detected as a change. This covers no-op
            // detection for specific far flag removal and further tests the
            // no-op detection for near flags.
            for &other_flag in &[flags[0].0, flags[99].0] {
                assert_eq!(
                    vec![uid],
                    fixture
                        .cxn
                        .modify_mailbox_message_flags(
                            child_id,
                            &SmallBitset::from(vec![other_flag]),
                            false,
                            false,
                            modseq,
                            &mut [uid].iter().copied(),
                        )
                        .unwrap(),
                );
                let mut new_modseq = read_modseq!();
                assert!(new_modseq > modseq);
                modseq = new_modseq;
                assert_eq!(
                    SmallBitset::from(vec![other_flag, flag]),
                    read_flags!(),
                );

                assert_eq!(
                    vec![uid],
                    fixture
                        .cxn
                        .modify_mailbox_message_flags(
                            child_id,
                            &SmallBitset::from(vec![flag]),
                            false,
                            true,
                            modseq,
                            &mut [uid].iter().copied(),
                        )
                        .unwrap(),
                );
                new_modseq = read_modseq!();
                assert!(new_modseq > modseq);
                modseq = new_modseq;
                assert_eq!(SmallBitset::from(vec![flag]), read_flags!(),);
            }

            // Clearing this flag when it's already clear is a no-op, even when
            // other flags are present.
            assert_eq!(
                vec![uid],
                fixture
                    .cxn
                    .modify_mailbox_message_flags(
                        child_id,
                        &SmallBitset::from(vec![flags[0].0, flags[99].0]),
                        false,
                        true,
                        modseq,
                        &mut [uid].iter().copied(),
                    )
                    .unwrap(),
            );
            let new_modseq = read_modseq!();
            assert!(new_modseq > modseq);
            modseq = new_modseq;
            assert_eq!(
                SmallBitset::from(vec![flags[0].0, flags[99].0]),
                read_flags!(),
            );

            assert!(fixture
                .cxn
                .modify_mailbox_message_flags(
                    child_id,
                    &SmallBitset::from(vec![flag]),
                    true,
                    false,
                    modseq,
                    &mut [uid].iter().copied(),
                )
                .unwrap()
                .is_empty());
            assert_eq!(modseq, read_modseq!());
            assert_eq!(
                SmallBitset::from(vec![flags[0].0, flags[99].0]),
                read_flags!(),
            );
        }

        // Set all the flags on a couple messages to ensure that mailbox
        // deletion and message expungement handle the far flags.
        let all_flags =
            SmallBitset::from(flags.iter().map(|f| f.0).collect::<Vec<_>>());
        assert_eq!(
            vec![
                child_msg_uid123,
                child_msg_uid123.next().unwrap(),
                child_msg_uid4
            ],
            fixture
                .cxn
                .modify_mailbox_message_flags(
                    child_id,
                    &all_flags,
                    false,
                    false,
                    Modseq::MAX,
                    &mut [
                        child_msg_uid123,
                        child_msg_uid123.next().unwrap(),
                        child_msg_uid4
                    ]
                    .iter()
                    .copied(),
                )
                .unwrap(),
        );
        // Verify bulk-deletion of many flags. This is mainly a concern
        // regarding syntax of dynamically-generated SQL.
        assert_eq!(
            vec![child_msg_uid4],
            fixture
                .cxn
                .modify_mailbox_message_flags(
                    child_id,
                    &all_flags,
                    true,
                    false,
                    Modseq::MAX,
                    &mut [child_msg_uid4].iter().copied(),
                )
                .unwrap(),
        );

        // Expunge a message with many flags. Also ensure that last_activity
        // gets updated when expunged.
        fixture
            .cxn
            .zero_message_last_activity(child_msg_ids[0])
            .unwrap();
        fixture
            .cxn
            .expunge_mailbox_messages(
                child_id,
                &mut [child_msg_uid123].iter().copied(),
            )
            .unwrap();
        assert_ne!(
            UnixTimestamp::zero(),
            fixture
                .cxn
                .fetch_raw_message(child_msg_ids[0])
                .unwrap()
                .last_activity,
        );

        // Now we can verify that deleting everything works.
        fixture.cxn.delete_mailbox(child_id).unwrap();
        fixture.cxn.delete_mailbox(unselectable_id).unwrap();
        assert!(fixture.cxn.fetch_all_mailboxes().unwrap().is_empty());
    }

    #[test]
    fn test_select() {
        let mut fixture = Fixture::new();

        let inbox = fixture
            .cxn
            .create_mailbox(MailboxId::ROOT, "INBOX", None)
            .unwrap();
        let message_id = fixture
            .cxn
            .intern_messages_as_orphans(&mut ["foo"].iter().copied())
            .unwrap()[0];

        let mut init_state = fixture.cxn.select(inbox, true, None).unwrap();
        assert!(init_state.messages.is_empty());
        assert_eq!(Uid::MIN, init_state.next_uid);
        assert_eq!(Modseq::MIN, init_state.max_modseq);
        assert!(init_state.qresync.is_none());

        let msg1_uid = fixture
            .cxn
            .append_mailbox_messages(
                inbox,
                &mut [(message_id, None)].iter().copied(),
            )
            .unwrap();
        let msg2_uid = fixture
            .cxn
            .append_mailbox_messages(
                inbox,
                &mut [(message_id, None)].iter().copied(),
            )
            .unwrap();

        // Read-only select: We'll get \Recent flags, but the next session will
        // also see them.
        init_state = fixture.cxn.select(inbox, false, None).unwrap();
        assert_eq!(
            vec![
                InitialMessageStatus {
                    uid: msg1_uid,
                    id: message_id,
                    flags: SmallBitset::new(),
                    last_modified: Modseq::of(2),
                    recent: true,
                },
                InitialMessageStatus {
                    uid: msg2_uid,
                    id: message_id,
                    flags: SmallBitset::new(),
                    last_modified: Modseq::of(3),
                    recent: true,
                },
            ],
            init_state.messages,
        );
        assert_eq!(Uid::u(3), init_state.next_uid);
        assert_eq!(Modseq::of(3), init_state.max_modseq);

        init_state = fixture.cxn.select(inbox, true, None).unwrap();
        assert!(init_state.messages.iter().all(|m| m.recent));

        // Since we did a RW select, the next will not see anything as recent.
        init_state = fixture.cxn.select(inbox, true, None).unwrap();
        assert!(init_state.messages.iter().all(|m| !m.recent));

        // Add a third message. Another select will then see that message alone
        // as recent.
        let msg3_uid = fixture
            .cxn
            .append_mailbox_messages(
                inbox,
                &mut [(message_id, None)].iter().copied(),
            )
            .unwrap();
        init_state = fixture.cxn.select(inbox, true, None).unwrap();
        assert!(!init_state.messages[0].recent);
        assert!(!init_state.messages[1].recent);
        assert!(init_state.messages[2].recent);

        let before_msg_flags = init_state.max_modseq;

        // Add a bunch of flags to messages 1 and 3, then verify we get all of
        // them when selecting.
        let flags = (0..100)
            .map(|id| {
                fixture
                    .cxn
                    .intern_flag(&Flag::Keyword(format!("f{id}")))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let all_flags_bitset = SmallBitset::from(
            flags.iter().map(|&FlagId(ix)| ix).collect::<Vec<_>>(),
        );
        fixture
            .cxn
            .modify_mailbox_message_flags(
                inbox,
                &all_flags_bitset,
                false,
                false,
                Modseq::MAX,
                &mut [msg1_uid, msg3_uid].iter().copied(),
            )
            .unwrap();

        init_state = fixture.cxn.select(inbox, false, None).unwrap();
        assert_eq!(all_flags_bitset, init_state.messages[0].flags);
        assert_eq!(SmallBitset::new(), init_state.messages[1].flags);
        assert_eq!(all_flags_bitset, init_state.messages[2].flags);

        let after_msg_flags = init_state.max_modseq;

        let msg4_uid = fixture
            .cxn
            .append_mailbox_messages(
                inbox,
                &mut [(message_id, None)].iter().copied(),
            )
            .unwrap();
        let msg5_uid = fixture
            .cxn
            .append_mailbox_messages(
                inbox,
                &mut [(message_id, None)].iter().copied(),
            )
            .unwrap();

        // Expunge a couple messages separately for the qresync tests.
        fixture
            .cxn
            .expunge_mailbox_messages(inbox, &mut [msg4_uid].iter().copied())
            .unwrap();
        let before_expunge_2 =
            fixture.cxn.fetch_mailbox(inbox).unwrap().max_modseq;
        fixture
            .cxn
            .expunge_mailbox_messages(inbox, &mut [msg2_uid].iter().copied())
            .unwrap();

        let latest_modseq =
            fixture.cxn.fetch_mailbox(inbox).unwrap().max_modseq;

        // Qresync against the latest modseq returns nothing.
        init_state = fixture
            .cxn
            .select(
                inbox,
                false,
                Some(&QresyncRequest {
                    uid_validity: inbox.0 as u32,
                    resync_from: latest_modseq,
                    known_uids: None,
                    mapping_reference: None,
                }),
            )
            .unwrap();
        assert_eq!(
            Some(QresyncResponse {
                expunged: vec![].into(),
                changed: vec![],
            }),
            init_state.qresync,
        );
        assert!(init_state.qresync.as_ref().unwrap().expunged.is_empty());
        assert!(init_state.qresync.as_ref().unwrap().changed.is_empty());

        // Qresync with the wrong UID validity returns no response at all.
        init_state = fixture
            .cxn
            .select(
                inbox,
                false,
                Some(&QresyncRequest {
                    uid_validity: inbox.0 as u32 + 1,
                    resync_from: Modseq::MIN,
                    known_uids: None,
                    mapping_reference: None,
                }),
            )
            .unwrap();
        assert!(init_state.qresync.is_none());

        // Qresync from the init modseq returns all extant UIDs and both
        // expunges (even though the UIDs for those expunges weren't known at
        // that time).
        init_state = fixture
            .cxn
            .select(
                inbox,
                false,
                Some(&QresyncRequest {
                    uid_validity: inbox.0 as u32,
                    resync_from: Modseq::MIN,
                    known_uids: None,
                    mapping_reference: None,
                }),
            )
            .unwrap();
        assert_eq!(
            Some(QresyncResponse {
                expunged: vec![msg2_uid, msg4_uid].into(),
                changed: vec![msg1_uid, msg3_uid, msg5_uid],
            }),
            init_state.qresync,
        );

        // If we specify a known UID range, we only get updates for things in
        // that range.
        init_state = fixture
            .cxn
            .select(
                inbox,
                false,
                Some(&QresyncRequest {
                    uid_validity: inbox.0 as u32,
                    resync_from: Modseq::MIN,
                    known_uids: Some(SeqRange::range(msg1_uid, msg3_uid)),
                    mapping_reference: None,
                }),
            )
            .unwrap();
        assert_eq!(
            Some(QresyncResponse {
                expunged: vec![msg2_uid].into(),
                changed: vec![msg1_uid, msg3_uid],
            }),
            init_state.qresync,
        );

        // Fetching with resync_from = before_msg_flags, we'll get told about
        // msg1 and msg3 because of the flags change, even though they already
        // existed.
        init_state = fixture
            .cxn
            .select(
                inbox,
                false,
                Some(&QresyncRequest {
                    uid_validity: inbox.0 as u32,
                    resync_from: before_msg_flags,
                    known_uids: None,
                    mapping_reference: None,
                }),
            )
            .unwrap();
        assert_eq!(
            Some(QresyncResponse {
                expunged: vec![msg2_uid, msg4_uid].into(),
                changed: vec![msg1_uid, msg3_uid, msg5_uid],
            }),
            init_state.qresync,
        );

        // But with resync_from = after_msg_flags, there were no further
        // updates to 1 and 3, so we don't see those.
        init_state = fixture
            .cxn
            .select(
                inbox,
                false,
                Some(&QresyncRequest {
                    uid_validity: inbox.0 as u32,
                    resync_from: after_msg_flags,
                    known_uids: None,
                    mapping_reference: None,
                }),
            )
            .unwrap();
        assert_eq!(
            Some(QresyncResponse {
                expunged: vec![msg2_uid, msg4_uid].into(),
                changed: vec![msg5_uid],
            }),
            init_state.qresync,
        );

        // With resync_from = before_expunge_2, the only change is the
        // expungement of message 2.
        init_state = fixture
            .cxn
            .select(
                inbox,
                false,
                Some(&QresyncRequest {
                    uid_validity: inbox.0 as u32,
                    resync_from: before_expunge_2,
                    known_uids: None,
                    mapping_reference: None,
                }),
            )
            .unwrap();
        assert_eq!(
            Some(QresyncResponse {
                expunged: vec![msg2_uid].into(),
                changed: vec![],
            }),
            init_state.qresync,
        );
    }
}
