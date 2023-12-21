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

use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use chrono::prelude::*;
use rusqlite::OptionalExtension as _;

use super::types::*;
use crate::support::error::Error;

/// A connection to the cleartext `delivery.sqlite` database.
pub struct Connection {
    cxn: rusqlite::Connection,
}

static MIGRATIONS: &[&str] = &[include_str!("deliverydb.v1.sql")];

impl Connection {
    pub fn new(path: &Path) -> Result<Self, Error> {
        let mut cxn = rusqlite::Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;

        // See notes in metadb::Connection::new about setting the permissions
        // this way.
        let _ = fs::set_permissions(
            &path,
            // Needs to be group writable since the MDA may run under a
            // different user.
            fs::Permissions::from_mode(0o660),
        );

        cxn.pragma_update(None, "foreign_keys", true)?;
        cxn.pragma_update(None, "journal_mode", "PERSIST")?;
        cxn.pragma_update(None, "journal_size_limit", 64 * 1024)?;
        cxn.busy_timeout(Duration::from_secs(10))?;

        super::db_migrations::apply_migrations(
            &mut cxn, "delivery", MIGRATIONS,
        )?;

        Ok(Self { cxn })
    }

    pub fn queue_delivery(&mut self, delivery: &Delivery) -> Result<(), Error> {
        let mut flags = String::new();
        for flag in &delivery.flags {
            if !flags.is_empty() {
                flags.push(' ');
            }
            let _ = write!(flags, "{}", flag);
        }

        self.cxn.execute(
            "INSERT INTO `delivery` (`path`, `mailbox`, `flags`, `savedate`) \
             VALUES (?, ?, ?, ?)",
            (&delivery.path, &delivery.mailbox, &flags, delivery.savedate),
        )?;
        Ok(())
    }

    /// Select, mark as in-flight, and return 1 arbitrary entry from the
    /// delivery queue, if any.
    pub fn pop_delivery(&mut self) -> Result<Option<Delivery>, Error> {
        self.cxn
            .prepare_cached(
                "UPDATE `delivery` \
                 SET `delivered` = ?
                 WHERE ROWID = ( \
                   SELECT MIN(ROWID) FROM `delivery` WHERE `delivered` IS NULL \
                 ) RETURNING *",
            )?
            .query_row((UnixTimestamp::now(),), from_row)
            .optional()
            .map_err(Into::into)
    }

    /// Returns whether the given path is an outstanding or in-flight delivery.
    pub fn is_delivery(&mut self, path: &str) -> Result<bool, Error> {
        self.cxn
            .prepare_cached("SELECT 1 FROM `delivery` WHERE `path` = ?")?
            .exists((path,))
            .map_err(Into::into)
    }

    /// Clear old entries from the delivery database.
    pub fn clear_old_deliveries(&mut self) -> Result<(), Error> {
        self.cxn.execute(
            "DELETE FROM `delivery` WHERE `delivered` < ?",
            (UnixTimestamp(Utc::now() - chrono::Duration::hours(1)),),
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::account::model::Flag;
    use tempfile::TempDir;

    #[test]
    fn test_delivery() {
        let tmpdir = TempDir::new().unwrap();
        let mut cxn =
            Connection::new(&tmpdir.path().join("delivery.sqlite")).unwrap();

        let delivery1 = Delivery {
            path: "foo/bar".to_owned(),
            mailbox: "INBOX".to_owned(),
            flags: vec![Flag::Flagged, Flag::Keyword("foo".to_owned())],
            savedate: UnixTimestamp(DateTime::from_timestamp(42, 0).unwrap()),
        };
        let delivery2 = Delivery {
            path: "baz/quux".to_owned(),
            mailbox: "Spam".to_owned(),
            flags: vec![],
            savedate: UnixTimestamp(DateTime::from_timestamp(54, 0).unwrap()),
        };

        cxn.queue_delivery(&delivery1).unwrap();
        cxn.queue_delivery(&delivery2).unwrap();
        assert!(cxn.is_delivery("foo/bar").unwrap());
        assert!(cxn.is_delivery("baz/quux").unwrap());
        assert!(!cxn.is_delivery("nonexistent").unwrap());

        cxn.clear_old_deliveries().unwrap();
        assert!(cxn.is_delivery("foo/bar").unwrap());
        assert!(cxn.is_delivery("baz/quux").unwrap());

        let mut popped = Vec::new();
        popped.push(cxn.pop_delivery().unwrap().unwrap());
        popped.push(cxn.pop_delivery().unwrap().unwrap());
        assert_eq!(None, cxn.pop_delivery().unwrap());

        assert!(popped.contains(&delivery1));
        assert!(popped.contains(&delivery2));

        assert!(cxn.is_delivery("foo/bar").unwrap());
        assert!(cxn.is_delivery("baz/quux").unwrap());
        cxn.clear_old_deliveries().unwrap();
        assert!(cxn.is_delivery("foo/bar").unwrap());
        assert!(cxn.is_delivery("baz/quux").unwrap());
    }
}
