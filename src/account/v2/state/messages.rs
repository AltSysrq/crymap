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
    account::{key_store::KeyStore, message_format, model::*},
    support::{error::Error, file_ops, small_bitset::SmallBitset},
};

/// Buffer the given data stream into a file that can later be moved into the
/// message store.
///
/// The returned object is a reference to a file in the temporary directory
/// which will be deleted when dropped, but does not contain an actual file
/// handle.
pub(super) fn buffer_message(
    key_store: &mut KeyStore,
    common_paths: &CommonPaths,
    internal_date: DateTime<FixedOffset>,
    data: impl Read,
) -> Result<BufferedMessage, Error> {
    let mut buffer_file = NamedTempFile::new_in(&common_paths.tmp)?;
    message_format::write_message(
        &mut buffer_file,
        key_store,
        internal_date,
        data,
    )?;

    file_ops::chmod(buffer_file.path(), 0o440)?;
    buffer_file.as_file_mut().sync_all()?;
    Ok(BufferedMessage(buffer_file.into_temp_path()))
}

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
        buffer_message(
            &mut self.key_store,
            &self.common_paths,
            internal_date,
            data,
        )
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
    #[cfg(any(test, feature = "dev-tools"))]
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

    /// The RFC 3501 `COPY` command.
    pub fn seqnum_copy(
        &mut self,
        mb: &Mailbox,
        request: &CopyRequest<Seqnum>,
        dst: &str,
    ) -> Result<CopyResponse, Error> {
        self.copy(
            mb,
            &CopyRequest {
                ids: mb.seqnum_range_to_uid(&request.ids, false)?,
            },
            dst,
        )
    }

    /// The RFC 3501 `UID COPY` command.
    pub fn copy(
        &mut self,
        mb: &Mailbox,
        request: &CopyRequest<Uid>,
        dst: &str,
    ) -> Result<CopyResponse, Error> {
        let dst_id = self.metadb.find_mailbox(dst)?;
        let from_uids = mb.filter_uid_range(&request.ids);
        let ret = self.metadb.copy_mailbox_messages(
            mb.id,
            &mut from_uids.items(u32::MAX),
            dst_id,
        );
        ret
    }

    /// The RFC 3501 `MOVE` command.
    pub fn seqnum_moove(
        &mut self,
        mb: &Mailbox,
        request: &CopyRequest<Seqnum>,
        dst: &str,
    ) -> Result<CopyResponse, Error> {
        self.moove(
            mb,
            &CopyRequest {
                ids: mb.seqnum_range_to_uid(&request.ids, false)?,
            },
            dst,
        )
    }

    /// The RFC 3501 `UID MOVE` command.
    pub fn moove(
        &mut self,
        mb: &Mailbox,
        request: &CopyRequest<Uid>,
        dst: &str,
    ) -> Result<CopyResponse, Error> {
        mb.require_writable()?;
        let dst_id = self.metadb.find_mailbox(dst)?;
        let from_uids = mb.filter_uid_range(&request.ids);
        let ret = self.metadb.move_mailbox_messages(
            mb.id,
            from_uids.items(u32::MAX),
            dst_id,
        );
        ret
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::support::chronox::*;

    #[test]
    fn copy_into_self() {
        let mut fixture = TestFixture::new();
        let uid1 = fixture.simple_append("INBOX");
        let uid2 = fixture.simple_append("INBOX");

        let (mut mb, _) = fixture.select("INBOX", true, None).unwrap();
        fixture
            .store(
                &mut mb,
                &StoreRequest {
                    ids: &SeqRange::just(uid1),
                    flags: &[Flag::Answered],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                },
            )
            .unwrap();
        fixture
            .store(
                &mut mb,
                &StoreRequest {
                    ids: &SeqRange::just(uid2),
                    flags: &[Flag::Draft],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                },
            )
            .unwrap();

        // Re-select as read-only to verify that the read-onliness doesn't
        // impact our ability to use the mailbox as a destination.
        mb = fixture.select("INBOX", false, None).unwrap().0;
        let uids3 = fixture
            .copy(
                &mb,
                &CopyRequest {
                    ids: SeqRange::just(uid1),
                },
                "InBoX",
            )
            .unwrap()
            .to_uids
            .items(u32::MAX)
            .collect::<Vec<_>>();
        assert_eq!(1, uids3.len());

        let poll = fixture.poll(&mut mb).unwrap();
        assert_eq!(Some(3), poll.exists);
        assert_eq!(0, poll.expunge.len());

        assert!(mb.test_flag_o(&Flag::Answered, uids3[0]));
        assert!(!mb.test_flag_o(&Flag::Draft, uids3[0]));

        let uids4 = fixture
            .seqnum_copy(
                &mb,
                &CopyRequest {
                    ids: SeqRange::range(Seqnum::u(1), Seqnum::u(2)),
                },
                "INBOX",
            )
            .unwrap()
            .to_uids
            .items(u32::MAX)
            .collect::<Vec<_>>();
        assert_eq!(2, uids4.len());

        let poll = fixture.poll(&mut mb).unwrap();
        assert_eq!(Some(5), poll.exists);
        assert_eq!(0, poll.expunge.len());

        assert!(mb.test_flag_o(&Flag::Answered, uids4[0]));
        assert!(!mb.test_flag_o(&Flag::Draft, uids4[0]));
        assert!(!mb.test_flag_o(&Flag::Answered, uids4[1]));
        assert!(mb.test_flag_o(&Flag::Draft, uids4[1]));
    }

    #[test]
    fn copy_into_other() {
        let mut fixture = TestFixture::new();
        let uid1 = fixture.simple_append("INBOX");
        let uid2 = fixture.simple_append("INBOX");

        let (mut inbox, _) = fixture.select("INBOX", true, None).unwrap();
        let (mut archive, _) = fixture.select("Archive", false, None).unwrap();

        fixture
            .store(
                &mut inbox,
                &StoreRequest {
                    ids: &SeqRange::just(uid1),
                    flags: &[Flag::Answered],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                },
            )
            .unwrap();
        fixture
            .store(
                &mut inbox,
                &StoreRequest {
                    ids: &SeqRange::just(uid2),
                    flags: &[Flag::Draft],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                },
            )
            .unwrap();
        fixture.poll(&mut inbox).unwrap();

        let uids3 = fixture
            .copy(
                &inbox,
                &CopyRequest {
                    ids: SeqRange::just(uid1),
                },
                "Archive",
            )
            .unwrap()
            .to_uids
            .items(u32::MAX)
            .collect::<Vec<_>>();
        assert_eq!(1, uids3.len());

        let poll = fixture.poll(&mut archive).unwrap();
        assert_eq!(Some(1), poll.exists);
        assert_eq!(0, poll.expunge.len());

        assert!(archive.test_flag_o(&Flag::Answered, uids3[0]));
        assert!(!archive.test_flag_o(&Flag::Draft, uids3[0]));

        let uids4 = fixture
            .seqnum_copy(
                &inbox,
                &CopyRequest {
                    ids: SeqRange::range(Seqnum::u(1), Seqnum::u(2)),
                },
                "Archive",
            )
            .unwrap()
            .to_uids
            .items(u32::MAX)
            .collect::<Vec<_>>();
        assert_eq!(2, uids4.len());

        let poll = fixture.poll(&mut archive).unwrap();
        assert_eq!(Some(3), poll.exists);
        assert_eq!(0, poll.expunge.len());

        assert!(archive.test_flag_o(&Flag::Answered, uids4[0]));
        assert!(!archive.test_flag_o(&Flag::Draft, uids4[0]));
        assert!(!archive.test_flag_o(&Flag::Answered, uids4[1]));
        assert!(archive.test_flag_o(&Flag::Draft, uids4[1]));
    }

    #[test]
    fn moove_into_other() {
        let mut fixture = TestFixture::new();
        let uid1 = fixture.simple_append("INBOX");
        let uid2 = fixture.simple_append("INBOX");

        let (mut inbox, _) = fixture.select("INBOX", true, None).unwrap();
        let (mut archive, _) = fixture.select("Archive", false, None).unwrap();

        fixture
            .store(
                &mut inbox,
                &StoreRequest {
                    ids: &SeqRange::just(uid1),
                    flags: &[Flag::Answered],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                },
            )
            .unwrap();
        fixture
            .store(
                &mut inbox,
                &StoreRequest {
                    ids: &SeqRange::just(uid2),
                    flags: &[Flag::Draft],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                },
            )
            .unwrap();
        fixture.poll(&mut inbox).unwrap();

        let uids3 = fixture
            .moove(
                &inbox,
                &CopyRequest {
                    ids: SeqRange::just(uid1),
                },
                "Archive",
            )
            .unwrap()
            .to_uids
            .items(u32::MAX)
            .collect::<Vec<_>>();
        assert_eq!(1, uids3.len());

        let poll = fixture.poll(&mut archive).unwrap();
        assert_eq!(Some(1), poll.exists);
        assert_eq!(0, poll.expunge.len());

        assert!(archive.test_flag_o(&Flag::Answered, uids3[0]));
        assert!(!archive.test_flag_o(&Flag::Draft, uids3[0]));

        let poll = fixture.poll(&mut inbox).unwrap();
        assert_eq!(1, poll.expunge.len());

        let uids4 = fixture
            .seqnum_moove(
                &inbox,
                &CopyRequest {
                    ids: SeqRange::just(Seqnum::u(1)),
                },
                "Archive",
            )
            .unwrap()
            .to_uids
            .items(u32::MAX)
            .collect::<Vec<_>>();
        assert_eq!(1, uids4.len());

        let poll = fixture.poll(&mut archive).unwrap();
        assert_eq!(Some(2), poll.exists);
        assert_eq!(0, poll.expunge.len());

        assert!(!archive.test_flag_o(&Flag::Answered, uids4[0]));
        assert!(archive.test_flag_o(&Flag::Draft, uids4[0]));

        let poll = fixture.poll(&mut inbox).unwrap();
        assert_eq!(1, poll.expunge.len());
    }

    #[test]
    fn moove_into_self() {
        let mut fixture = TestFixture::new();
        let uid1 = fixture.simple_append("INBOX");

        let (mb, _) = fixture.select("INBOX", true, None).unwrap();
        assert_matches!(
            Err(Error::MoveIntoSelf),
            fixture.moove(
                &mb,
                &CopyRequest {
                    ids: SeqRange::just(uid1),
                },
                "iNbOx",
            ),
        );
        assert_matches!(
            Err(Error::MoveIntoSelf),
            fixture.seqnum_moove(
                &mb,
                &CopyRequest {
                    ids: SeqRange::just(Seqnum::u(1)),
                },
                "iNbOx",
            ),
        );
    }

    #[test]
    fn moove_from_readonly() {
        let mut fixture = TestFixture::new();
        let uid1 = fixture.simple_append("INBOX");

        let (mb, _) = fixture.select("INBOX", false, None).unwrap();
        assert_matches!(
            Err(Error::MailboxReadOnly),
            fixture.moove(
                &mb,
                &CopyRequest {
                    ids: SeqRange::just(uid1),
                },
                "Archive",
            ),
        );
        assert_matches!(
            Err(Error::MailboxReadOnly),
            fixture.seqnum_moove(
                &mb,
                &CopyRequest {
                    ids: SeqRange::just(Seqnum::u(1)),
                },
                "Archive",
            ),
        );
    }

    #[test]
    fn moove_nx() {
        let mut fixture = TestFixture::new();
        let uid1 = fixture.simple_append("INBOX");
        let uid2 = fixture.simple_append("INBOX");
        let uid3 = fixture.simple_append("INBOX");

        let (mb1, _) = fixture.select("INBOX", true, None).unwrap();
        fixture.vanquish(&mb1, &SeqRange::just(uid2)).unwrap();
        // Don't poll --- the mailbox state should still think the message
        // still exists, leaving it to the database layer to discover it
        // doesn't.

        let response = fixture
            .moove(
                &mb1,
                &CopyRequest {
                    ids: SeqRange::range(uid1, uid3),
                },
                "Archive",
            )
            .unwrap();

        assert_eq!(2, response.from_uids.len());
        assert_eq!(2, response.to_uids.len());
    }

    #[test]
    fn test_multiappend() {
        let mut fixture = TestFixture::new();
        let internal_date =
            FixedOffset::zero().from_utc_datetime(&Utc::now().naive_local());

        let mut append_request = AppendRequest::default();
        append_request.items.push(AppendItem {
            buffer_file: fixture
                .buffer_message(internal_date, b"foo" as &[u8])
                .unwrap(),
            flags: vec![Flag::Answered],
        });
        append_request.items.push(AppendItem {
            buffer_file: fixture
                .buffer_message(internal_date, b"bar" as &[u8])
                .unwrap(),
            flags: vec![Flag::Draft],
        });

        let uids = fixture
            .multiappend("INBOX", append_request)
            .unwrap()
            .uids
            .items(u32::MAX)
            .collect::<Vec<_>>();
        assert_eq!(2, uids.len());

        let (mb, _) = fixture.select("INBOX", false, None).unwrap();
        assert_eq!(2, mb.select_response().unwrap().exists);

        assert!(mb.test_flag_o(&Flag::Answered, uids[0]));
        assert!(!mb.test_flag_o(&Flag::Answered, uids[1]));
        assert!(!mb.test_flag_o(&Flag::Draft, uids[0]));
        assert!(mb.test_flag_o(&Flag::Draft, uids[1]));
    }
}
