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

use std::path::Path;

use chrono::prelude::*;
use log::info;

use super::sqlite_xex_vfs::XexVfs;
use crate::support::error::Error;

/// A connection to the encrypted `meta.sqlite.xex` database.
pub struct Connection {
    cxn: rusqlite::Connection,
}

static MIGRATION_V1: &'static str = include_str!("metadb.v1.sql");

impl Connection {
    pub fn new(path: &Path, xex: &XexVfs) -> Result<Self, Error> {
        let mut cxn = rusqlite::Connection::open_with_flags_and_vfs(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_CREATE,
            xex.name(),
        )?;

        cxn.execute("PRAGMA foreign_keys = ON", ())?;

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
                .query_row_and_then(
                    "SELECT MAX(`version`) FROM `migration`",
                    (),
                    |row| row.get::<_, Option<u32>>(0),
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
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use tempfile::TempDir;

    use super::*;
    use crate::crypt::master_key::MasterKey;

    #[test]
    fn test_setup() {
        let tmpdir = TempDir::new().unwrap();
        let master_key = Arc::new(MasterKey::new());
        let xex = XexVfs::new(master_key).unwrap();
        let _cxn =
            Connection::new(&tmpdir.path().join("meta.sqlite.xex"), &xex)
                .unwrap();
    }
}
