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

use std::collections::HashMap;
use std::fs;
use std::io::Read;

use chrono::prelude::*;
use tempfile::NamedTempFile;

use super::super::storage;
use super::defs::*;
use crate::{
    account::{message_format, model::*},
    support::{error::Error, file_ops, small_bitset::SmallBitset},
};

impl Account {
    /// Buffer the given data stream into a file that can later be appended
    /// directly.
    ///
    /// This is used when reading `APPEND` commands to directly transfer the
    /// network input into the final file, instead of going through the extra
    /// time and memory use of the `crate::support::buffer` system.
    ///
    /// The returned object is a reference to a file in the temporary directory
    /// which will be deleted when dropped, but does not contain an actual file
    /// handle.
    pub fn buffer_message(
        &mut self,
        internal_date: DateTime<FixedOffset>,
        data: impl Read,
    ) -> Result<BufferedMessage, Error> {
        let mut buffer_file = NamedTempFile::new_in(&self.common_paths.tmp)?;
        message_format::write_message(
            &mut buffer_file,
            &mut self.key_store,
            internal_date,
            data,
        )?;

        file_ops::chmod(buffer_file.path(), 0o440)?;
        buffer_file.as_file_mut().sync_all()?;
        Ok(BufferedMessage(buffer_file.into_temp_path()))
    }

    /// Append the message(s) from the request to the given mailbox.
    ///
    /// This corresponds to the `APPEND` command from RFC 3501, the
    /// `MULTIAPPEND` extension from RFC 3502, and the `APPENDUID` response
    /// from RFC 4315.
    ///
    /// This does not handle the special case of 0-length inputs cancelling the
    /// request. That must be handled at the protocol level.
    pub fn multiappend(
        &mut self,
        mailbox: &str,
        request: AppendRequest,
    ) -> Result<AppendResponse, Error> {
        let message_count = request.items.len() as u32;
        let (uid_validity, base_uid) =
            self.append_buffered(mailbox, request.items)?;
        let mut response = AppendResponse {
            uid_validity,
            uids: SeqRange::new(),
        };
        response.uids.insert(
            base_uid,
            Uid::of(base_uid.0.get() + message_count - 1).unwrap(),
        );

        Ok(response)
    }

    /// Append the given message to the requested mailbox
    ///
    /// Returns the UID of the new message.
    ///
    /// This is not exactly the RFC 3501 `APPEND` command; see `multiappend`
    /// for that.
    pub fn append(
        &mut self,
        mailbox: &str,
        internal_date: DateTime<FixedOffset>,
        flags: impl IntoIterator<Item = Flag>,
        data: impl Read,
    ) -> Result<Uid, Error> {
        let buffer_file = self.buffer_message(internal_date, data)?;
        self.append_buffered(
            mailbox,
            vec![AppendItem {
                buffer_file,
                flags: flags.into_iter().collect(),
            }],
        )
        .map(|(_, uid)| uid)
    }

    /// Append messages which were buffered with `buffer_message` to the
    /// mailbox at the given path.
    ///
    /// Returns the UID of the first new message and the UID validity of the
    /// mailbox. If there was more than one message appended, later messages
    /// have successive UIDs.
    pub fn append_buffered(
        &mut self,
        mailbox: &str,
        items: Vec<AppendItem>,
    ) -> Result<(u32, Uid), Error> {
        let mailbox_id = self.metadb.find_mailbox(mailbox)?;

        let canonical_paths = items
            .iter()
            .map(|item| {
                fs::File::open(&item.buffer_file.0)
                    .and_then(storage::MessageStore::canonical_path)
            })
            .collect::<Result<Vec<_>, _>>()?;

        // First, intern all the messages into the database as orphans so that
        // if we fail after moving the files into the message store but before
        // adding them to the destination mailbox, they'll be recognised as
        // orphaned messages and deleted rather than being recovered into the
        // inbox.
        //
        // TODO Add a unit test that recovery won't bring these files into
        // existence. This case can be triggered easily by trying to append to
        // a \Noselect mailbox, since that isn't discovered until the final
        // step.
        let message_ids = self.metadb.intern_messages_as_orphans(
            &mut canonical_paths.iter().map(|path| {
                path.to_str().expect("canonical paths are always UTF-8")
            }),
        )?;

        // Next, put the files into their final place.
        for (item, dst) in items.iter().zip(&canonical_paths) {
            self.message_store.insert(&item.buffer_file.0, dst)?;
        }

        // Convert all flags we'll need into their internal representations.
        //
        // Flags are case-insensitive so they aren't `Hash`. For simplicity, we
        // just look at the raw strings instead, which means we could do some
        // redundant lookups if the client mixes case, but otherwise this is
        // fine.
        let mut flag_cache = HashMap::<&str, storage::FlagId>::new();
        let flags = items
            .iter()
            .map(|item| {
                item.flags
                    .iter()
                    .map(|flag| {
                        if let Some(&known) = flag_cache.get(flag.as_str()) {
                            return Ok::<usize, Error>(known.0);
                        }

                        let interned = self.metadb.intern_flag(flag)?;
                        flag_cache.insert(flag.as_str(), interned);
                        Ok(interned.0)
                    })
                    .collect::<Result<SmallBitset, _>>()
            })
            .collect::<Result<Vec<SmallBitset>, _>>()?;

        let first_uid = self.metadb.append_mailbox_messages(
            mailbox_id,
            &mut message_ids.into_iter().zip(flags.iter().map(Some)),
        )?;

        Ok((mailbox_id.as_uid_validity()?, first_uid))
    }
}
