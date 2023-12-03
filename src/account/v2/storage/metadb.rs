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
use std::path::Path;
use std::time::Duration;

use chrono::prelude::*;
use log::info;
use rusqlite::OptionalExtension as _;

use super::{sqlite_xex_vfs::XexVfs, types::*};
use crate::{
    account::model::*,
    support::{error::Error, mailbox_paths::parse_mailbox_path},
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

        cxn.execute("PRAGMA foreign_keys = ON", ())?;
        cxn.busy_timeout(Duration::from_secs(10))?;

        {
            let txn = cxn.transaction_with_behavior(
                rusqlite::TransactionBehavior::Exclusive,
            )?;
            txn.execute(
                "CREATE TABLE IF NOT EXISTS `migration` (\
                   `version` INTEGER NOT NULL PRIMARY KEY, \
                   `applied_at` TEXT NOT NULL\
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
                    (Utc::now(),),
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
}

/// All data pertaining to a particular mailbox.
#[derive(Debug, Clone)]
pub struct Mailbox {
    pub id: MailboxId,
    pub parent_id: MailboxId,
    pub name: String,
    pub selectable: bool,
    pub special_use: Option<MailboxAttribute>,
    pub next_uid: Uid,
    pub recent_uid: Uid,
    pub next_modseq: Modseq,
    pub append_modseq: Modseq,
    pub expunge_modseq: Modseq,
}

impl FromRow for Mailbox {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get("id")?,
            parent_id: row.get("parent_id")?,
            name: row.get("name")?,
            selectable: row.get("selectable")?,
            special_use: row.get("special_use")?,
            next_uid: row.get("next_uid")?,
            recent_uid: row.get("recent_uid")?,
            next_modseq: row.get("next_modseq")?,
            append_modseq: row.get("append_modseq")?,
            expunge_modseq: row.get("expunge_modseq")?,
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
}
