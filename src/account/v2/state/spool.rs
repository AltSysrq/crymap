//-
// Copyright (c) 2024, Jason Lingle
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

use std::fmt;
use std::fs;
use std::io;

use chrono::prelude::*;

use super::super::storage;
use super::defs::*;
use crate::{account::model::*, support::error::Error};

/// Identifies a message spooled for outbound delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpooledMessageId(storage::MessageId);

impl fmt::Display for SpooledMessageId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&(self.0).0, f)
    }
}

impl SpooledMessageId {
    #[cfg(test)]
    pub const DUMMY: Self = Self(storage::MessageId(0));
}

/// A message spooled for outbound delivery.
pub struct SpooledMessage {
    /// The ID of this message.
    pub id: SpooledMessageId,
    /// The suggested SMTP transfer type.
    pub transfer: storage::SmtpTransfer,
    /// The time at which this message may be despooled.
    pub expires: DateTime<Utc>,
    /// The SMTP `MAIL FROM` address.
    pub mail_from: String,
    /// The outstanding email addresses for delivery.
    pub destinations: Vec<String>,
    /// The total size of the message
    pub size: u32,
    /// Reader for the message data.
    pub data: Box<dyn io::BufRead>,
}

impl Account {
    /// Adds the given message to the message spool, returning the ID of the
    /// message.
    ///
    /// If the user has configured for outbound messages to be saved to a
    /// mailbox, the message is also added to that mailbox.
    pub fn spool_message(
        &mut self,
        message: BufferedMessage,
        transfer: storage::SmtpTransfer,
        mail_from: String,
        destinations: Vec<String>,
    ) -> Result<SpooledMessageId, Error> {
        let user_config = self.load_config()?;

        // The workflow here is similar to append_buffered().
        let canonical_path = fs::File::open(&message.0)
            .and_then(storage::MessageStore::canonical_path)?;
        let message_id =
            self.metadb
                .intern_messages_as_orphans(&mut std::iter::once(
                    canonical_path
                        .to_str()
                        .expect("canonical paths are always UTF-8"),
                ))?[0];
        self.message_store.insert(&message.0, &canonical_path)?;

        if let Some(ref save_mailbox) = user_config.smtp_out.save {
            if let Ok(mailbox_id) = self.metadb.find_mailbox(save_mailbox) {
                let seen_flag_id = self.metadb.intern_flag(&Flag::Seen)?;
                self.metadb.append_mailbox_messages(
                    mailbox_id,
                    &mut std::iter::once((
                        message_id,
                        Some(&std::iter::once(seen_flag_id.0).collect()),
                    )),
                )?;
            }
        }

        self.metadb.insert_message_spool(&storage::MessageSpool {
            message_id,
            transfer,
            expires: storage::UnixTimestamp(
                Utc::now() + chrono::Duration::days(30),
            ),
            mail_from,
            destinations,
        })?;

        Ok(SpooledMessageId(message_id))
    }

    /// Opens the spooled message with the given ID for reading.
    pub fn open_spooled_message(
        &mut self,
        id: SpooledMessageId,
    ) -> Result<SpooledMessage, Error> {
        let spooled = self
            .metadb
            .fetch_message_spool(id.0)?
            .ok_or(Error::NxMessage)?;
        let (metadata, reader) = self.open_message(id.0)?;
        Ok(SpooledMessage {
            id,
            transfer: spooled.transfer,
            expires: spooled.expires.0,
            mail_from: spooled.mail_from,
            destinations: spooled.destinations,
            size: metadata.size,
            data: reader,
        })
    }

    /// Removes the given destinations from the spooled message with the given
    /// ID.
    ///
    /// The message will be despooled if there are no remaining destinations.
    pub fn delete_spooled_message_destinations(
        &mut self,
        id: SpooledMessageId,
        destinations: &mut dyn Iterator<Item = &str>,
    ) -> Result<(), Error> {
        self.metadb
            .delete_message_spool_destinations(id.0, destinations)
    }

    pub fn fetch_foreign_smtp_tls_status(
        &mut self,
        domain: &str,
    ) -> Result<Option<ForeignSmtpTlsStatus>, Error> {
        self.metadb.fetch_foreign_smtp_tls_status(domain)
    }

    pub fn put_foreign_smtp_tls_status(
        &mut self,
        status: &ForeignSmtpTlsStatus,
    ) -> Result<(), Error> {
        self.metadb.put_foreign_smtp_tls_status(status)
    }

    pub fn delete_foreign_smtp_tls_status(
        &mut self,
        domain: &str,
    ) -> Result<(), Error> {
        self.metadb.delete_foreign_smtp_tls_status(domain)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn spool_message_default() {
        let mut fixture = TestFixture::new();
        let buffered_message = fixture
            .buffer_message(Utc::now().into(), b"foo bar".as_slice())
            .unwrap();
        let spool_id = fixture
            .spool_message(
                buffered_message,
                storage::SmtpTransfer::EightBit,
                "foo@example.com".to_owned(),
                vec!["bar@example.net".to_owned()],
            )
            .unwrap();

        let mut spooled = fixture.open_spooled_message(spool_id).unwrap();
        assert_eq!("foo@example.com", spooled.mail_from);
        assert_eq!(vec!["bar@example.net".to_owned()], spooled.destinations);
        assert_eq!(7, spooled.size);

        let mut data = Vec::<u8>::new();
        spooled.data.read_to_end(&mut data).unwrap();
        assert_eq!(b"foo bar".to_vec(), data);
    }

    #[test]
    fn spool_message_into_sent() {
        let mut fixture = TestFixture::new();
        fixture
            .update_config(SetUserConfigRequest {
                smtp_out_save: Some(Some("Sent".to_owned())),
                ..Default::default()
            })
            .unwrap();
        let buffered_message = fixture
            .buffer_message(Utc::now().into(), b"foo bar".as_slice())
            .unwrap();
        fixture
            .spool_message(
                buffered_message,
                storage::SmtpTransfer::Binary,
                "foo@example.com".to_owned(),
                vec!["bar@example.net".to_owned()],
            )
            .unwrap();

        let (sent, _) = fixture.select("Sent", false, None).unwrap();
        assert_eq!(1, sent.select_response().unwrap().exists);
        assert!(sent.test_flag_o(&Flag::Seen, Uid::u(1)));
    }
}
