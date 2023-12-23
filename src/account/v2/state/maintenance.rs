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

use std::fs;
use std::io;
use std::path::PathBuf;

use chrono::prelude::*;
use log::{error, info, warn};

use super::super::storage;
use super::defs::*;
use crate::support::error::Error;

impl Account {
    pub(super) fn run_maintenance(&mut self) {
        if let Err(e) = self.run_maintenance_impl() {
            error!("{} Error running maintenance: {e:?}", self.log_prefix);
        }
    }

    fn run_maintenance_impl(&mut self) -> Result<(), Error> {
        let now = Utc::now();

        if !self.metadb.start_maintenance(
            "daily",
            storage::UnixTimestamp(now - chrono::Duration::hours(24)),
        )? {
            return Ok(());
        }

        info!("{} Running daily maintenance...", self.log_prefix);
        self.clean_up_orphans(now)?;
        // Process any pending deliveries immediately before running
        // unaccounted recovery so that optimisations are not defeated by
        // pending messages. (This could still happen if a message is delivered
        // in the short interval between here and gathering information, but
        // that's rare enough to not matter: we still do the right thing, just
        // more slowly.)
        self.drain_deliveries();
        self.recover_unaccounted_files(now)?;
        self.make_database_backup(now.date_naive())?;
        self.remove_old_database_backups();
        self.clean_tmp();
        self.clean_garbage();
        Ok(())
    }

    fn clean_up_orphans(&mut self, now: DateTime<Utc>) -> Result<(), Error> {
        let orphans = self.metadb.fetch_orphaned_messages(
            storage::UnixTimestamp(now - chrono::Duration::hours(24)),
        )?;

        for (id, path) in orphans {
            match self.message_store.delete(path.as_ref()) {
                Ok(()) => {},
                Err(e) if io::ErrorKind::NotFound == e.kind() => {},
                Err(e) => {
                    error!("{} rm {path}: {e:?}", self.log_prefix);
                    continue;
                },
            }

            self.metadb.forget_message(id)?;
        }

        Ok(())
    }

    fn recover_unaccounted_files(
        &mut self,
        now: DateTime<Utc>,
    ) -> Result<(), Error> {
        // Finding unaccounted files is done on the basis of a "message
        // summary". Messages are classified into 256 buckets and assigned
        // non-zero 16-bit increments based on their path alone. The summary is
        // the sum of those increments for each bucket.
        //
        // With high probability, if the database and message store disagree
        // for a message group, the summaries will also be different. The only
        // way for them to disagree on actual contents but agree on the summary
        // is for the database to have files that don't actually exist AND for
        // the message store to have unaccounted files AND that the sums of
        // their increments happen to be equal.

        // First, we compute the summary data based only on looking at message
        // paths to quickly discover which buckets need more attention.
        //
        // There's no way to avoid the full message store scan, but we're only
        // making one system call per directory entry, so it shouldn't be too
        // slow.
        let database_summary = self.metadb.summarise_messages()?;
        let mut computed_summary = Box::new([0u64; 256]);
        for path in self.message_store.list(None) {
            let Ok(path) = path.into_os_string().into_string() else {
                continue;
            };

            let (bucket, incr) = storage::message_summary_values(&path);
            computed_summary[usize::from(bucket)] += u64::from(incr);
        }

        // If the summary exactly matches, there's nothing to do.
        if database_summary == computed_summary {
            return Ok(());
        }

        // If the summary doesn't match, make another pass and look for
        // messages that are actually missing.

        let inbox_id = self.metadb.find_mailbox("INBOX")?;

        let mut recovered = 0;
        for path in self
            .message_store
            .list(Some(now - chrono::Duration::hours(1)))
        {
            let Ok(path) = path.into_os_string().into_string() else {
                continue;
            };

            let (bucket, _) = storage::message_summary_values(&path);
            if database_summary[usize::from(bucket)]
                == computed_summary[usize::from(bucket)]
            {
                continue;
            }

            // Skip messages represented in either database. While the two
            // checks are nominally racy, there's a 1 hour minimum delay
            // between the message starting delivery and disappearing from
            // deliverydb, so in practise this is fine.
            if self.metadb.is_known_message(&path)? {
                continue;
            }
            if self.deliverydb.is_delivery(&path)? {
                continue;
            }

            if self
                .metadb
                .recover_message_into_mailbox(inbox_id, &path, None)?
            {
                recovered += 1;
            }
        }

        if recovered > 0 {
            warn!(
                "{} Recovered {recovered} messages into INBOX",
                self.log_prefix,
            );
        }

        Ok(())
    }

    fn make_database_backup(&mut self, today: NaiveDate) -> Result<(), Error> {
        if !self.backup_path.is_dir() {
            fs::create_dir(&self.backup_path)?;
        }

        let backup_name = format!(
            "{}.{:04}-{:02}-{:02}",
            METADB_NAME,
            today.year(),
            today.month(),
            today.day(),
        );

        let backup_path = self.backup_path.join(backup_name);

        match self.metadb.back_up(&self.common_paths.tmp, &backup_path) {
            // If something else already created the backup, ignore.
            Err(Error::Io(e)) if io::ErrorKind::AlreadyExists == e.kind() => {
                Ok(())
            },
            r => r,
        }
    }

    fn remove_old_database_backups(&mut self) {
        const MAX_BACKUPS: usize = 7;

        let Ok(readdir) = fs::read_dir(&self.backup_path) else {
            return;
        };

        let mut candidates = Vec::<PathBuf>::new();
        for entry in readdir {
            let Ok(entry) = entry else {
                break;
            };

            let path = entry.path();
            if path.file_name().is_some_and(|name| {
                name.to_str()
                    .is_some_and(|name| name.starts_with(METADB_NAME))
            }) {
                candidates.push(path);
            }
        }

        // Sorting puts the oldest backups first.
        candidates.sort();

        if candidates.len() <= MAX_BACKUPS {
            return;
        }

        for path in &candidates[..candidates.len() - MAX_BACKUPS] {
            let _ = fs::remove_file(path);
        }
    }

    fn clean_tmp(&self) {
        let Ok(readdir) = fs::read_dir(&self.common_paths.tmp) else {
            return;
        };
        for entry in readdir {
            let Ok(entry) = entry else {
                break;
            };

            if entry
                .metadata()
                .ok()
                // Take the latest of mtime and ctime for considering whether
                // to remove. Files in active use (mtime) should be retained,
                // but we also want to avoid collecting config backups too
                // early (ctime gets reset when the file is link()ed into the
                // backup location).
                .and_then(|md| match (md.modified(), md.created()) {
                    (Err(_), Err(_)) => None,
                    (Ok(mtime), Err(_)) => Some(mtime),
                    (Err(_), Ok(ctime)) => Some(ctime),
                    (Ok(mtime), Ok(ctime)) => Some(mtime.max(ctime)),
                })
                .and_then(|mtime| mtime.elapsed().ok())
                .map_or(false, |elapsed| elapsed.as_secs() > 24 * 3600)
            {
                let path = entry.path();
                warn!(
                    "{} Removing orphaned temp file: {}",
                    self.log_prefix,
                    path.display()
                );
                if path.is_dir() {
                    let _ = fs::remove_dir_all(entry.path());
                } else {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
    }

    fn clean_garbage(&self) {
        // "garbage" is a holdover from V1. We clean it anyway in case there
        // are leftover files.

        let Ok(readdir) = fs::read_dir(&self.common_paths.garbage) else {
            return;
        };

        for entry in readdir {
            let Ok(entry) = entry else {
                break;
            };
            let path = entry.path();
            if path.is_dir() {
                let _ = fs::remove_dir_all(entry.path());
            } else {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::io::{self, Seek};
    use std::sync::Arc;

    use super::*;
    use crate::support::{chronox::*, log_prefix::LogPrefix};

    #[test]
    fn no_error_at_top_level() {
        let mut fixture = TestFixture::new();
        fixture.account.metadb.clear_maintenance("daily").unwrap();
        // Create a file under garbage to validate that the maintenance
        // actually runs.
        let garbage_path = fixture.account.common_paths.garbage.join("foo");
        fs::write(&garbage_path, b"foo").unwrap();
        assert!(garbage_path.is_file());
        fixture.account.run_maintenance_impl().unwrap();
        assert!(!garbage_path.is_file());
    }

    #[test]
    fn unaccounted_recovery() {
        let mut fixture = TestFixture::new();
        let mut delivery = super::super::DeliveryAccount::new(
            LogPrefix::new("delivery".to_owned()),
            fixture.root.path().to_owned(),
        )
        .unwrap();

        let now = Utc::now();

        // Add 1000 messages which are represented in the message store the
        // meta database.
        for i in 0..1000 {
            let data = format!("archive-{i}");
            fixture
                .append(
                    "Archive",
                    now.into(),
                    std::iter::empty(),
                    data.as_bytes(),
                )
                .unwrap();
        }

        // Queue some messages for delivery. These will be represented in the
        // message store and the delivery database.
        for i in 0..7 {
            let data = format!("delivery-{i}");
            delivery.deliver("Spam", &[], data.as_bytes()).unwrap();
        }

        // Directly create some messages in the message store. These will be
        // only represented in the message store and are the messages that
        // should be recovered.
        for i in 0..17 {
            let raw_data = format!("recover-{i}");
            let mut tmp = tempfile::NamedTempFile::new_in(
                &fixture.account.common_paths.tmp,
            )
            .unwrap();
            crate::account::message_format::write_message(
                &mut tmp,
                &mut fixture.account.key_store,
                now.into(),
                raw_data.as_bytes(),
            )
            .unwrap();
            tmp.seek(io::SeekFrom::Start(0)).unwrap();
            let path = storage::MessageStore::canonical_path(&mut tmp).unwrap();
            fixture
                .account
                .message_store
                .insert(tmp.path(), &path)
                .unwrap();
        }

        // Try to append some messages to a \Noselect mailbox. The \Noselect
        // state is only detected after the messages have been added to the
        // message store. To ensure they do not get recovered, the append code
        // is supposed to intern the messages as orphans first in a separate
        // transaction, so these won't be recovered.
        fixture.create("noselect/foo");
        fixture.delete("noselect").unwrap();
        for i in 0..3 {
            let data = format!("noselect-{i}");
            assert_matches!(
                Err(Error::MailboxUnselectable),
                fixture.append(
                    "noselect",
                    now.into(),
                    std::iter::empty(),
                    data.as_bytes(),
                ),
            );
        }

        // Change the modification timestamp of all the files to 25hr ago to
        // make them candidates for recovery.
        let timeval = nix::sys::time::TimeVal::new(
            (now - chrono::Duration::hours(25)).timestamp()
                as nix::sys::time::time_t,
            0,
        );
        for entry in walkdir::WalkDir::new(fixture.root.path()) {
            let entry = entry.unwrap();
            if entry.file_type().is_file() {
                nix::sys::stat::utimes(entry.path(), &timeval, &timeval)
                    .unwrap();
            }
        }

        // Directly create some more messages in the message store. These are
        // essentially deliveries that have not yet been added to the delivery
        // database. They should be excluded from recovery due to their
        // recency.
        for i in 0..5 {
            let raw_data = format!("new-{i}");
            let mut tmp = tempfile::NamedTempFile::new_in(
                &fixture.account.common_paths.tmp,
            )
            .unwrap();
            crate::account::message_format::write_message(
                &mut tmp,
                &mut fixture.account.key_store,
                now.into(),
                raw_data.as_bytes(),
            )
            .unwrap();
            tmp.seek(io::SeekFrom::Start(0)).unwrap();
            let path = storage::MessageStore::canonical_path(&mut tmp).unwrap();
            fixture
                .account
                .message_store
                .insert(tmp.path(), &path)
                .unwrap();
        }

        fixture.recover_unaccounted_files(now).unwrap();
        let (inbox, _) = fixture.select("INBOX", false, None).unwrap();
        assert_eq!(17, inbox.select_response().unwrap().exists);
    }

    #[test]
    fn database_backups() {
        let mut fixture = TestFixture::new();

        for i in 1..20 {
            // Use a far future date so that the backups we create here are
            // ordered after the one that implicitly happened when the database
            // was opened.
            fixture
                .account
                .make_database_backup(NaiveDate::from_ymdx(3023, 1, i))
                .unwrap();
            fixture.account.remove_old_database_backups();
            // Again, to ensure it doesn't fail on a duplicate.
            fixture
                .account
                .make_database_backup(NaiveDate::from_ymdx(3023, 1, i))
                .unwrap();
        }

        let mut backups = Vec::<String>::new();
        for entry in fs::read_dir(&fixture.account.backup_path).unwrap() {
            let name = entry.unwrap().file_name().into_string().unwrap();
            if !name.starts_with(METADB_NAME) {
                continue;
            }

            backups.push(name);
        }
        backups.sort();

        assert_eq!(
            vec![
                format!("{METADB_NAME}.3023-01-13"),
                format!("{METADB_NAME}.3023-01-14"),
                format!("{METADB_NAME}.3023-01-15"),
                format!("{METADB_NAME}.3023-01-16"),
                format!("{METADB_NAME}.3023-01-17"),
                format!("{METADB_NAME}.3023-01-18"),
                format!("{METADB_NAME}.3023-01-19"),
            ],
            backups,
        );

        fixture.create("foo");

        let backup_src =
            fixture.account.backup_path.join(backups.last().unwrap());
        let backup_dst = fixture.account.metadb_path.clone();
        let master_key = Arc::clone(&fixture.master_key);
        drop(fixture.account);
        fs::rename(&backup_src, &backup_dst).unwrap();
        fixture.account = Account::new(
            LogPrefix::new("recovered".to_owned()),
            fixture.root.path().to_owned(),
            master_key,
        )
        .unwrap();

        assert_matches!(
            Err(Error::NxMailbox),
            fixture.select("foo", false, None),
        );
    }
}
