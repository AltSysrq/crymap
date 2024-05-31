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
use std::path::PathBuf;
use std::sync::Arc;

use chrono::prelude::*;
use log::error;

use super::super::storage;
use super::defs::*;
use crate::{
    account::{key_store::KeyStore, model::*},
    support::{error::Error, log_prefix::LogPrefix, small_bitset::SmallBitset},
};

/// A not-logged-in handle on an account which can be used for delivering
/// messages.
pub struct DeliveryAccount {
    deliverydb: storage::DeliveryDb,
    key_store: KeyStore,
    message_store: storage::MessageStore,
    common_paths: Arc<CommonPaths>,
    log_prefix: LogPrefix,
}

impl DeliveryAccount {
    /// Sets up a new `Account` object in the given directory.
    ///
    /// The directory must already exist, but it need not have any contents.
    pub fn new(log_prefix: LogPrefix, root: PathBuf) -> Result<Self, Error> {
        let common_paths = Arc::new(CommonPaths {
            tmp: root.join("tmp"),
            garbage: root.join("garbage"),
        });

        let key_store = KeyStore::new(
            log_prefix.clone(),
            root.join("keys"),
            common_paths.tmp.clone(),
            None,
        );

        let deliverydb_path = root.join("delivery.sqlite");
        let deliverydb =
            storage::DeliveryDb::new(&log_prefix, &deliverydb_path)?;
        let message_store = storage::MessageStore::new(root.join("messages"));

        Ok(Self {
            deliverydb,
            key_store,
            message_store,
            common_paths,
            log_prefix,
        })
    }

    /// Buffer the given data stream into a file that can later be delivered
    /// directly.
    ///
    /// The returned object is a reference to a file in the temporary directory
    /// which will be deleted when dropped, but does not contain an actual file
    /// handle.
    pub fn buffer_message(
        &mut self,
        data: impl std::io::Read,
    ) -> Result<BufferedMessage, Error> {
        super::messages::buffer_message(
            &mut self.key_store,
            &self.common_paths,
            Utc::now().into(),
            data,
        )
    }

    /// Deliver the given data as a message into the given mailbox with the
    /// requested flags.
    pub fn deliver(
        &mut self,
        mailbox: &str,
        flags: &[Flag],
        data: impl std::io::Read,
    ) -> Result<(), Error> {
        let buffered = self.buffer_message(data)?;
        self.deliver_buffered(mailbox, flags, &buffered)
    }

    /// Deliver the given message into the given mailbox with the requested
    /// flags.
    pub fn deliver_buffered(
        &mut self,
        mailbox: &str,
        flags: &[Flag],
        message: &BufferedMessage,
    ) -> Result<(), Error> {
        let canonical_path = fs::File::open(&message.0)
            .and_then(storage::MessageStore::canonical_path)?;
        // Unaccounted message recovery ignores very new files, so placing the
        // file into the message store before adding it to the database is
        // fine.
        self.message_store.insert(&message.0, &canonical_path)?;
        self.deliverydb.queue_delivery(&storage::Delivery {
            path: canonical_path
                .into_os_string()
                .into_string()
                .expect("all canonical paths are UTF-8"),
            mailbox: mailbox.to_owned(),
            flags: flags.to_owned(),
            savedate: storage::UnixTimestamp::now(),
        })?;

        // Clean up the database at delivery time since this is also the only
        // path that can make it grow. This way we have one less transaction
        // per IMAP command cycle.
        if let Err(e) = self.deliverydb.clear_old_deliveries() {
            error!("{} Failed to clear old deliveries: {e:?}", self.log_prefix,);
        }

        Ok(())
    }
}

impl Account {
    /// Process all deliveries currently queued in the delivery database.
    ///
    /// This should be called after every command and before invoking `poll()`
    /// or `mini_poll()` if there is a selected mailbox.
    pub fn drain_deliveries(&mut self) {
        loop {
            // By successfully removing an entry, we're committing to
            // delivering it. If we can't for some reason and drop it on the
            // floor, the message will be subject to unaccounted message
            // recovery after 1 hour.
            let delivery = match self.deliverydb.pop_delivery() {
                Ok(None) => return,
                Ok(Some(d)) => d,
                Err(e) => {
                    error!("{} Failed to pop delivery: {e:?}", self.log_prefix);
                    return;
                },
            };

            let inbox_id = match self.metadb.find_mailbox("INBOX") {
                Ok(id) => id,
                Err(e) => {
                    error!(
                        "{} Failed to look up INBOX for delivery: {e:?}",
                        self.log_prefix,
                    );
                    return;
                },
            };

            let dst_id = match self.metadb.find_mailbox(&delivery.mailbox) {
                Ok(id) => id,
                Err(e) => {
                    error!(
                        "{} Delivering message to INBOX instead of '{}': \
                         {e:?}",
                        self.log_prefix, delivery.mailbox,
                    );
                    inbox_id
                },
            };

            let mut flags = SmallBitset::new();
            for flag in delivery.flags {
                if let Ok(flag_id) = self.metadb.intern_flag(&flag) {
                    flags.insert(flag_id.0);
                }
            }

            let r = self.metadb.intern_and_append_mailbox_messages(
                dst_id,
                &mut [(delivery.path.as_str(), Some(&flags))].into_iter(),
            );
            if let Err(e) = r {
                error!(
                    "{} Failed to deliver message to '{}', \
                     retrying with INBOX: {e:?}",
                    self.log_prefix, delivery.mailbox,
                );

                let r = self.metadb.intern_and_append_mailbox_messages(
                    inbox_id,
                    &mut [(delivery.path.as_str(), Some(&flags))].into_iter(),
                );
                if let Err(e) = r {
                    error!(
                        "{} Failed to deliver message to INBOX: {e:?}",
                        self.log_prefix,
                    );
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn deliver_success() {
        let mut fixture = TestFixture::new();
        let mut delivery = DeliveryAccount::new(
            LogPrefix::new("delivery".to_owned()),
            fixture.root.path().to_owned(),
        )
        .unwrap();

        let buf1 = delivery.buffer_message(b"foobar" as &[u8]).unwrap();
        let buf2 = delivery.buffer_message(b"barfoo" as &[u8]).unwrap();
        delivery.deliver_buffered("INBOX", &[], &buf1).unwrap();
        delivery
            .deliver_buffered(
                "iNbOx",
                &[Flag::Flagged, Flag::Keyword("foo".to_owned())],
                &buf2,
            )
            .unwrap();
        delivery.deliver_buffered("Archive", &[], &buf1).unwrap();

        let (mb, _) = fixture.select("INBOX", false, None).unwrap();
        assert_eq!(2, mb.select_response().unwrap().exists);
        assert!(mb.test_flag_o(&Flag::Flagged, Uid::u(2)));
        assert!(mb.test_flag_o(&Flag::Keyword("foo".to_owned()), Uid::u(2)));

        let (mb, _) = fixture.select("Archive", false, None).unwrap();
        assert_eq!(1, mb.select_response().unwrap().exists);
    }

    #[test]
    fn deliver_bad_destination() {
        let mut fixture = TestFixture::new();
        let mut delivery = DeliveryAccount::new(
            LogPrefix::new("delivery".to_owned()),
            fixture.root.path().to_owned(),
        )
        .unwrap();

        fixture.create("noselect/foo");
        fixture.delete("noselect").unwrap();

        let buf1 = delivery.buffer_message(b"foobar" as &[u8]).unwrap();
        delivery.deliver_buffered("", &[], &buf1).unwrap();
        delivery.deliver_buffered("noselect", &[], &buf1).unwrap();
        delivery
            .deliver_buffered("nonexistent", &[], &buf1)
            .unwrap();

        // All three messages get dumped into the INBOX since they couldn't be
        // delivered to the requested destination.
        let (mb, _) = fixture.select("INBOX", false, None).unwrap();
        assert_eq!(3, mb.select_response().unwrap().exists);
    }
}
