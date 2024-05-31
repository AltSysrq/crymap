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
use std::sync::Arc;

use log::{error, info};

use super::super::storage;
use super::defs::*;
use crate::{
    account::{model::*, v1},
    support::error::Error,
};

impl Account {
    pub(super) fn migrate_v1_to_v2(&mut self) -> Result<(), Error> {
        // The V1 storage model can be identified by the presence of the `mail`
        // directory under the root. When migration completes, we move the old
        // files to a different directory.
        if !self.root.join("mail").is_dir() {
            return Ok(());
        }

        info!(
            "{} Beginning migration from V1 storage model",
            self.log_prefix
        );
        let result = self.metadb.migrate_v1_to_v2(&mut |migrator| {
            let v1_account = v1::account::Account::new(
                self.log_prefix.to_string(),
                self.root.clone(),
                Some(Arc::clone(&self.master_key)),
            );

            let list = v1_account.list(&ListRequest {
                reference: String::new(),
                patterns: vec!["*".to_owned()],
                select_subscribed: false,
                select_special_use: false,
                recursive_match: false,
                // We need to do subscriptions in another path to migrate
                // subscriptions to non-existent mailboxes.
                return_subscribed: false,
                return_children: false,
                return_special_use: true,
                lsub_style: false,
            })?;

            for list_response in list {
                let stateless =
                    match v1_account.mailbox(&list_response.name, true) {
                        Ok(s) => s,
                        Err(Error::MailboxUnselectable) => continue,
                        Err(e) => {
                            error!(
                                "{} Couldn't get handle on mailbox '{}', \
                                 skipping migration: {e:?}",
                                self.log_prefix, list_response.name,
                            );
                            continue;
                        },
                    };

                let (stateful, select) = match stateless.select() {
                    Ok(s) => s,
                    Err(Error::MailboxUnselectable) => continue,
                    Err(e) => {
                        error!(
                            "{} Couldn't select mailbox '{}', \
                             skipping migration: {e:?}",
                            self.log_prefix, list_response.name,
                        );
                        continue;
                    },
                };

                migrator(storage::V1MigrationEvent::Mailbox {
                    path: &list_response.name,
                    special_use: list_response
                        .attributes
                        .iter()
                        .copied()
                        .find(|attr| attr.is_special_use()),
                    flags: &select.flags,
                })?;

                for uid in stateful.uids() {
                    let src_path = stateful.stateless().message_path(uid);
                    let canonical_path = match fs::File::open(&src_path)
                        .and_then(storage::MessageStore::canonical_path)
                    {
                        Ok(p) => p,
                        Err(e) => {
                            error!(
                                "{} Couldn't read {src_path:?}; the message \
                                 will not be migrated: {e:?}",
                                self.log_prefix,
                            );
                            continue;
                        },
                    };

                    let savedate = fs::metadata(&src_path)
                        .and_then(|md| md.created())
                        .map(|st| storage::UnixTimestamp(st.into()))
                        .unwrap_or_else(|_| storage::UnixTimestamp::now());

                    if let Err(e) =
                        self.message_store.insert(&src_path, &canonical_path)
                    {
                        error!(
                            "{} Couldn't add {src_path:?} to the V2 message \
                             store; the message will not be migrated: {e:?}",
                            self.log_prefix,
                        );
                        continue;
                    }

                    let message_flags = stateful.message_flags(uid).unwrap();
                    migrator(storage::V1MigrationEvent::Message {
                        path: canonical_path
                            .to_str()
                            .expect("canonical paths are always UTF-8"),
                        flags: message_flags,
                        savedate,
                    })?;
                }
            }

            let lsub = v1_account.list(&ListRequest {
                reference: String::new(),
                patterns: vec!["*".to_owned()],
                select_subscribed: true,
                select_special_use: false,
                recursive_match: false,
                return_subscribed: true,
                return_children: false,
                return_special_use: false,
                lsub_style: true,
            })?;

            for lsub_response in lsub {
                if lsub_response
                    .attributes
                    .contains(&MailboxAttribute::Subscribed)
                {
                    migrator(storage::V1MigrationEvent::Subscription {
                        path: &lsub_response.name,
                    })?;
                }
            }

            Ok(())
        });

        if let Err(e) = result {
            // Ensure there's an obviously relevant log message.
            error!("{} Failed V1 migration: {e:?}", self.log_prefix);
            return Err(e);
        }

        // Move the old files to their new home.
        let success_dir = self.root.join("crymap-v1-files");
        if fs::create_dir(&success_dir).is_ok() {
            let _ =
                fs::rename(self.root.join("mail"), success_dir.join("mail"));
            let _ = fs::rename(
                self.root.join("shadow"),
                success_dir.join("shadow"),
            );
        }

        info!("{} Migration from V1 succeeded", self.log_prefix);

        result
    }
}

#[cfg(test)]
mod test {
    use chrono::prelude::*;

    use super::*;
    use crate::support::log_prefix::LogPrefix;

    #[test]
    fn test_migration() {
        let root = tempfile::TempDir::new().unwrap();
        let master_key = Arc::new(crate::crypt::master_key::MasterKey::new());
        let v1_account = v1::account::Account::new(
            "v1_account".to_owned(),
            root.path().to_owned(),
            Some(Arc::clone(&master_key)),
        );
        v1_account.provision(b"hunter2").unwrap();

        // Verify that nested mailboxes work, as well as the non-default
        // special-use attributes.
        v1_account
            .create(CreateRequest {
                name: "Parent/Important".to_owned(),
                special_use: vec!["\\Important".to_owned()],
            })
            .unwrap();
        // foobar will have "foo" and "bar" as flags, added in that order.
        v1_account
            .create(CreateRequest {
                name: "foobar".to_owned(),
                special_use: vec![],
            })
            .unwrap();
        // barfoo will have "bar" and "foo" as flags, added in that order. This
        // will ensure that flag ID translation occurs and we don't just use
        // the original mailbox-specific bitsets.
        v1_account
            .create(CreateRequest {
                name: "barfoo".to_owned(),
                special_use: vec![],
            })
            .unwrap();

        v1_account.subscribe("some/subscription/path").unwrap();

        let foobar = v1_account.mailbox("foobar", false).unwrap();
        foobar
            .append(
                Utc::now().into(),
                [Flag::Seen, Flag::Keyword("foo".to_owned())],
                &mut b"foo".as_slice(),
            )
            .unwrap();
        foobar
            .append(
                Utc::now().into(),
                [Flag::Deleted, Flag::Keyword("bar".to_owned())],
                &mut b"bar".as_slice(),
            )
            .unwrap();

        let barfoo = v1_account.mailbox("barfoo", false).unwrap();
        barfoo
            .append(
                Utc::now().into(),
                [Flag::Deleted, Flag::Keyword("bar".to_owned())],
                &mut b"bar2".as_slice(),
            )
            .unwrap();
        barfoo
            .append(
                Utc::now().into(),
                [Flag::Seen, Flag::Keyword("foo".to_owned())],
                &mut b"foo2".as_slice(),
            )
            .unwrap();

        let inbox = v1_account.mailbox("INBOX", false).unwrap();
        // Create a duplicate of "foo" so that there will be two source files
        // that get consolidated into one.
        foobar
            .select()
            .unwrap()
            .0
            .seqnum_copy(
                &CopyRequest {
                    ids: SeqRange::just(Seqnum::u(1)),
                },
                &inbox,
            )
            .unwrap();

        let mut v2_account = Account::new(
            LogPrefix::new("v2_account".to_owned()),
            root.path().to_owned(),
            Arc::clone(&master_key),
        )
        .unwrap();
        let user_config = v2_account.load_config().unwrap();
        // Init runs the migration implicitly.
        v2_account.init(&user_config.key_store).unwrap();

        let important_id =
            v2_account.metadb.find_mailbox("Parent/Important").unwrap();
        let important = v2_account.metadb.fetch_mailbox(important_id).unwrap();
        assert_eq!(Some(MailboxAttribute::Important), important.special_use);

        let subscriptions =
            v2_account.metadb.fetch_all_subscriptions().unwrap();
        assert!(subscriptions.contains(&"some/subscription/path".to_owned()));
        assert!(!subscriptions.contains(&"some/subscription".to_owned()));

        let (foobar, _) = v2_account.select("foobar", false, None).unwrap();
        assert_eq!(2, foobar.messages.len());
        assert_eq!(
            "uid=1 [\\Seen foo] foo",
            slurp_message(&mut v2_account, &foobar, 0),
        );
        assert_eq!(
            "uid=2 [\\Deleted bar] bar",
            slurp_message(&mut v2_account, &foobar, 1),
        );

        let (barfoo, _) = v2_account.select("barfoo", false, None).unwrap();
        assert_eq!(2, barfoo.messages.len());
        assert_eq!(
            "uid=1 [\\Deleted bar] bar2",
            slurp_message(&mut v2_account, &barfoo, 0),
        );
        assert_eq!(
            "uid=2 [\\Seen foo] foo2",
            slurp_message(&mut v2_account, &barfoo, 1),
        );

        let (inbox, _) = v2_account.select("INBOX", false, None).unwrap();
        assert_eq!(1, inbox.messages.len());
        assert_eq!(
            "uid=1 [\\Seen foo] foo",
            slurp_message(&mut v2_account, &inbox, 0),
        );

        assert!(!root.path().join("mail").is_dir());
        assert!(!root.path().join("shadow").is_dir());
        assert!(root.path().join("crymap-v1-files/mail").is_dir());
        assert!(root.path().join("crymap-v1-files/shadow").is_dir());

        // Opening the account again has no additional effect.
        let mut v2_account2 = Account::new(
            LogPrefix::new("v2_account2".to_owned()),
            root.path().to_owned(),
            Arc::clone(&master_key),
        )
        .unwrap();
        v2_account2.init(&user_config.key_store).unwrap();
    }

    fn slurp_message(
        account: &mut Account,
        mailbox: &Mailbox,
        index: usize,
    ) -> String {
        let message = &mailbox.messages[index];
        let mut flag_strings = message
            .flags
            .iter()
            .map(|ix| mailbox.flags[ix].1.as_str())
            .collect::<Vec<_>>();
        flag_strings.sort();

        let mut s = format!("uid={} [", message.uid.0.get());
        for (i, flag) in flag_strings.into_iter().enumerate() {
            if 0 != i {
                s.push(' ');
            }
            s.push_str(flag);
        }
        s.push_str("] ");

        let (_, mut r) = account.open_message(message.id).unwrap();
        r.read_to_string(&mut s).unwrap();

        s
    }
}
