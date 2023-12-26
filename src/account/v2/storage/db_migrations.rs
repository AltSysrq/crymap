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

use log::info;

use super::types::*;
use crate::support::{error::Error, log_prefix::LogPrefix};

pub fn apply_migrations(
    log_prefix: &LogPrefix,
    cxn: &mut rusqlite::Connection,
    db_name: &str,
    migrations: &[&str],
) -> Result<(), Error> {
    let latest_version = migrations.len();

    if Ok(latest_version)
        == cxn.query_row(
            "SELECT MAX(`version`) FROM `migration`",
            (),
            from_single::<usize>,
        )
    {
        return Ok(());
    }

    let txn = cxn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Exclusive)?;
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
            from_single::<Option<usize>>,
        )?
        .unwrap_or(0);

    for (version, migration) in migrations
        .iter()
        .copied()
        .enumerate()
        .map(|(ix, migration)| (ix + 1, migration))
        .skip(current_version)
    {
        info!("{log_prefix} Applying #{version} migration to {db_name} DB");
        txn.execute_batch(migration)?;
        txn.execute(
            "INSERT INTO `migration` (`version`, `applied_at`) \
             VALUES (1, ?)",
            (UnixTimestamp::now(),),
        )?;
    }

    txn.commit()?;

    Ok(())
}
