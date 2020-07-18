//-
// Copyright (c) 2020, Jason Lingle
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

use std::convert::TryInto;
use std::fs;
use std::io::{self, BufRead, Read, Seek, Write};
use std::path::Path;
use std::sync::Arc;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use chrono::prelude::*;
use log::info;
use rand::{rngs::OsRng, Rng};
use tempfile::{NamedTempFile, TempPath};

use super::defs::*;
use crate::account::mailbox_path::MailboxPath;
use crate::account::model::*;
use crate::crypt::data_stream;
use crate::support::compression::{Compression, FinishWrite};
use crate::support::error::Error;
use crate::support::file_ops;

#[derive(Debug)]
pub struct BufferedMessage(TempPath);

impl StatelessMailbox {
    /// Open the identified message for reading.
    ///
    /// This doesn't correspond to any particular IMAP command (that would be
    /// too easy!) but is used to implement a number of them.
    ///
    /// On success, returns the length in bytes, the internal date, and a
    /// reader to access the content.
    pub fn open_message<'a>(
        &'a self,
        uid: Uid,
    ) -> Result<(MessageMetadata, Box<dyn BufRead + 'a>), Error> {
        let scheme = self.message_scheme();
        let mut file = match fs::File::open(scheme.path_for_id(uid.0.get())) {
            Ok(f) => f,
            Err(e) if Some(nix::libc::ELOOP) == e.raw_os_error() => {
                return Err(Error::ExpungedMessage)
            }
            Err(e) if io::ErrorKind::NotFound == e.kind() => {
                return Err(Error::NxMessage)
            }
            Err(e) => return Err(e.into()),
        };

        let size_xor = file.read_u32::<LittleEndian>()?;
        let stream = data_stream::Reader::new(file, |k| {
            let mut ks = self.key_store.lock().unwrap();
            ks.get_private_key(k)
        })?;
        let compression = stream.metadata.compression;
        let mut stream = compression.decompressor(stream)?;
        let metadata_length = stream.read_u16::<LittleEndian>()?;
        let mut metadata: MessageMetadata = serde_cbor::from_reader(
            stream.by_ref().take(metadata_length.into()),
        )?;
        metadata.size ^= size_xor;

        Ok((metadata, stream))
    }

    /// Append the message(s) from the request to the mailbox.
    ///
    /// This corresponds to the `APPEND` command from RFC 3501, the
    /// `MULTIAPPEND` extension from RFC 3502, and the `APPENDUID` response
    /// from RFC 4315.
    ///
    /// This does not handle the special case of 0-length inputs cancelling the
    /// request. That must be handled at the protocol level.
    pub fn multiappend(
        &self,
        request: AppendRequest,
    ) -> Result<AppendResponse, Error> {
        let mut response = AppendResponse {
            uid_validity: self.uid_validity()?,
            uids: SeqRange::new(),
        };

        let message_count = request.items.len() as u32;
        let base_uid = self.append_buffered(request.items)?;
        response.uids.insert(
            base_uid,
            Uid::of(base_uid.0.get() + message_count - 1).unwrap(),
        );

        Ok(response)
    }

    /// Append the given message to this mailbox.
    ///
    /// Returns the UID of the new message.
    ///
    /// This is not exactly the RFC 3501 `APPEND` command; see `multiappend`
    /// for that.
    pub fn append(
        &self,
        internal_date: DateTime<FixedOffset>,
        flags: impl IntoIterator<Item = Flag>,
        data: impl Read,
    ) -> Result<Uid, Error> {
        let buffer_file = self.buffer_message(internal_date, data)?;
        self.append_buffered(vec![AppendItem {
            buffer_file,
            flags: flags.into_iter().collect(),
        }])
    }

    /// Append a message which was buffered with `buffer_message` to this
    /// mailbox.
    ///
    /// Returns the UID of the first new message. If there was more than one
    /// message appended, later messages have successive UIDs.
    pub fn append_buffered(
        &self,
        items: Vec<AppendItem>,
    ) -> Result<Uid, Error> {
        let paths = items
            .iter()
            .map(|item| item.buffer_file.0.as_ref())
            .collect::<Vec<_>>();
        let uid = self.insert_messages(&paths)?;
        self.propagate_flags_best_effort(
            items
                .into_iter()
                .enumerate()
                .map(|(ix, item)| {
                    (Uid::of(uid.0.get() + ix as u32).unwrap(), item.flags)
                })
                .collect::<Vec<_>>(),
        );
        Ok(uid)
    }

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
        &self,
        internal_date: DateTime<FixedOffset>,
        mut data: impl Read,
    ) -> Result<BufferedMessage, Error> {
        self.not_read_only()?;

        let mut buffer_file = NamedTempFile::new_in(&self.common_paths.tmp)?;

        let size_xor: u32;
        let metadata = MessageMetadata {
            size: OsRng.gen(),
            internal_date: internal_date,
        };
        let compression = Compression::DEFAULT_FOR_MESSAGE;

        buffer_file.write_u32::<LittleEndian>(0)?;
        {
            let mut crypt_writer = {
                let mut ks = self.key_store.lock().unwrap();
                let (key_name, pub_key) = ks.get_default_public_key()?;

                data_stream::Writer::new(
                    &mut buffer_file,
                    pub_key,
                    key_name.to_owned(),
                    compression,
                )?
            };
            {
                let mut compressor =
                    compression.compressor(&mut crypt_writer)?;
                let metadata_bytes = serde_cbor::to_vec(&metadata)?;
                compressor.write_u16::<LittleEndian>(
                    metadata_bytes.len().try_into().unwrap(),
                )?;
                compressor.write_all(&metadata_bytes)?;

                let size = io::copy(&mut data, &mut compressor)?;
                size_xor = metadata.size ^ size.try_into().unwrap_or(u32::MAX);
                compressor.finish()?;
            }
            crypt_writer.flush()?;
        }

        buffer_file.seek(io::SeekFrom::Start(0))?;
        buffer_file.write_u32::<LittleEndian>(size_xor)?;
        file_ops::chmod(buffer_file.path(), 0o440)?;
        buffer_file.as_file_mut().sync_all()?;
        Ok(BufferedMessage(buffer_file.into_temp_path()))
    }

    /// Insert `src` into this mailbox via a hard link.
    ///
    /// This is used for `COPY` and `MOVE`, though it is not exactly either of
    /// those.
    ///
    /// If `src` is more than 1 element long, the return value gives the UID of
    /// the first message, and subsequent messages have subsequent UIDs.
    fn insert_messages(&self, src: &[&Path]) -> Result<Uid, Error> {
        self.not_read_only()?;

        let scheme = self.message_scheme();

        if 1 == src.len() {
            for _ in 0..1000 {
                let uid = Uid::of(scheme.first_unallocated_id())
                    .ok_or(Error::MailboxFull)?;
                if scheme.emplace(src[0], uid.0.get())? {
                    info!(
                        "{} Delivered message to {}",
                        self.log_prefix,
                        uid.0.get()
                    );
                    return Ok(uid);
                }
            }

            Err(Error::GaveUpInsertion)
        } else {
            let base_id = scheme.emplace_many(
                src,
                &self.common_paths.tmp,
                Uid::MAX.0.get(),
            )?;
            info!(
                "{} Delivered messages to {}..={}",
                self.log_prefix,
                base_id,
                base_id + src.len() as u32
            );
            Ok(Uid::of(base_id).unwrap())
        }
    }
}

impl StatefulMailbox {
    /// The RFC 3501 `COPY` command.
    pub fn seqnum_copy(
        &self,
        request: &CopyRequest<Seqnum>,
        dst: &StatelessMailbox,
    ) -> Result<AppendResponse, Error> {
        self.copy(
            &CopyRequest {
                ids: self.state.seqnum_range_to_uid(&request.ids, false)?,
            },
            dst,
        )
    }

    /// The RFC 3501 `UID COPY` command.
    pub fn copy(
        &self,
        request: &CopyRequest<Uid>,
        dst: &StatelessMailbox,
    ) -> Result<AppendResponse, Error> {
        let mut response = AppendResponse {
            uid_validity: self.s.uid_validity()?,
            uids: SeqRange::new(),
        };

        let mut path_bufs = Vec::new();
        let mut flags = Vec::new();
        for uid in request.ids.items(self.state.max_uid_val()) {
            let status = match self.state.message_status(uid) {
                Some(status) => status,
                // RFC 3501 requires that non-existent UIDs are silently
                // ignored.
                None => continue,
            };

            flags.push(
                status
                    .flags()
                    .filter_map(|id| self.state.flag(id).cloned())
                    .collect::<Vec<_>>(),
            );
            path_bufs.push(self.s.message_scheme().path_for_id(uid.0.get()));
        }

        if path_bufs.is_empty() {
            return Ok(response);
        }

        let paths = path_bufs.iter().map(|p| p as &Path).collect::<Vec<_>>();
        let base_uid = dst.insert_messages(&paths)?;
        let message_count = paths.len() as u32;
        dst.propagate_flags_best_effort(
            flags
                .into_iter()
                .enumerate()
                .map(|(ix, f)| {
                    (Uid::of(base_uid.0.get() + ix as u32).unwrap(), f)
                })
                .collect(),
        );

        response.uids.insert(
            base_uid,
            Uid::of(base_uid.0.get() + message_count - 1).unwrap(),
        );
        Ok(response)
    }
}

#[cfg(test)]
mod test {
    use std::iter;

    use chrono::prelude::*;

    use super::super::test_prelude::*;
    use super::*;

    #[test]
    fn write_and_read_messages() {
        let setup = set_up();

        let zone = FixedOffset::east(3600);
        let now = zone.from_utc_datetime(&Utc::now().naive_local());

        assert_eq!(
            Uid::u(1),
            setup
                .stateless
                .append(now, iter::empty(), &mut "hello world".as_bytes())
                .unwrap()
        );
        assert_eq!(
            Uid::u(2),
            setup
                .stateless
                .append(now, iter::empty(), &mut "another message".as_bytes())
                .unwrap()
        );

        let mut content = String::new();
        let (md, mut r) = setup.stateless.open_message(Uid::u(1)).unwrap();
        assert_eq!(11, md.size);
        assert_eq!(now, md.internal_date);
        r.read_to_string(&mut content).unwrap();
        assert_eq!("hello world", &content);

        content.clear();
        let (md, mut r) = setup.stateless.open_message(Uid::u(2)).unwrap();
        assert_eq!(15, md.size);
        assert_eq!(now, md.internal_date);
        r.read_to_string(&mut content).unwrap();
        assert_eq!("another message", &content);
    }

    #[test]
    fn copy_into_self() {
        let setup = set_up();

        let (mut mb1, _) = setup.stateless.clone().select().unwrap();
        let (mut mb2, _) = setup.stateless.clone().select().unwrap();

        let uid1 = simple_append(mb1.stateless());
        let uid2 = simple_append(mb1.stateless());
        mb1.stateless()
            .set_flags_blind(vec![
                (uid1, vec![(true, Flag::Answered)]),
                (uid2, vec![(true, Flag::Draft)]),
            ])
            .unwrap();
        mb1.poll().unwrap();
        mb2.poll().unwrap();

        let uids3 = mb1
            .copy(
                &CopyRequest {
                    ids: SeqRange::just(uid1),
                },
                mb2.stateless(),
            )
            .unwrap()
            .uids
            .items(u32::MAX)
            .collect::<Vec<_>>();
        assert_eq!(1, uids3.len());

        let poll = mb1.poll().unwrap();
        assert_eq!(Some(3), poll.exists);
        assert_eq!(0, poll.expunge.len());

        let poll = mb2.poll().unwrap();
        assert_eq!(Some(3), poll.exists);
        assert_eq!(0, poll.expunge.len());

        assert!(mb1.state.test_flag_o(&Flag::Answered, uids3[0]));
        assert!(!mb1.state.test_flag_o(&Flag::Draft, uids3[0]));
        assert!(mb2.state.test_flag_o(&Flag::Answered, uids3[0]));
        assert!(!mb2.state.test_flag_o(&Flag::Draft, uids3[0]));

        let uids4 = mb1
            .copy(
                &CopyRequest {
                    ids: SeqRange::range(uid1, uid2),
                },
                mb2.stateless(),
            )
            .unwrap()
            .uids
            .items(u32::MAX)
            .collect::<Vec<_>>();
        assert_eq!(2, uids4.len());

        let poll = mb1.poll().unwrap();
        assert_eq!(Some(5), poll.exists);
        assert_eq!(0, poll.expunge.len());

        let poll = mb2.poll().unwrap();
        assert_eq!(Some(5), poll.exists);
        assert_eq!(0, poll.expunge.len());

        assert!(mb1.state.test_flag_o(&Flag::Answered, uids4[0]));
        assert!(!mb1.state.test_flag_o(&Flag::Draft, uids4[0]));
        assert!(mb2.state.test_flag_o(&Flag::Answered, uids4[0]));
        assert!(!mb2.state.test_flag_o(&Flag::Draft, uids4[0]));

        assert!(!mb1.state.test_flag_o(&Flag::Answered, uids4[1]));
        assert!(mb1.state.test_flag_o(&Flag::Draft, uids4[1]));
        assert!(!mb2.state.test_flag_o(&Flag::Answered, uids4[1]));
        assert!(mb2.state.test_flag_o(&Flag::Draft, uids4[1]));
    }

    #[test]
    fn copy_into_other() {
        let setup = set_up();

        let (mut mb1, _) = setup.stateless.select().unwrap();

        let mbox2_path = MailboxPath::root(
            "archive".to_owned(),
            setup.root.path(),
            setup.root.path(),
        )
        .unwrap();
        mbox2_path.create(setup.root.path(), None).unwrap();
        let stateless2 = StatelessMailbox::new(
            "mailbox".to_owned(),
            mbox2_path,
            false,
            Arc::clone(&setup.key_store),
            Arc::clone(&setup.common_paths),
        )
        .unwrap();
        let (mut mb2, _) = stateless2.select().unwrap();

        let uid1 = simple_append(mb1.stateless());
        let uid2 = simple_append(mb1.stateless());
        mb1.stateless()
            .set_flags_blind(vec![
                (uid1, vec![(true, Flag::Answered)]),
                (uid2, vec![(true, Flag::Draft)]),
            ])
            .unwrap();
        mb1.poll().unwrap();

        simple_append(mb2.stateless());
        mb2.poll().unwrap();

        let uids3 = mb1
            .copy(
                &CopyRequest {
                    ids: SeqRange::just(uid1),
                },
                mb2.stateless(),
            )
            .unwrap()
            .uids
            .items(u32::MAX)
            .collect::<Vec<_>>();
        assert_eq!(1, uids3.len());

        let poll = mb2.poll().unwrap();
        assert_eq!(Some(2), poll.exists);
        assert_eq!(0, poll.expunge.len());

        assert!(mb2.state.test_flag_o(&Flag::Answered, uids3[0]));
        assert!(!mb2.state.test_flag_o(&Flag::Draft, uids3[0]));

        let uids4 = mb1
            .copy(
                &CopyRequest {
                    ids: SeqRange::range(uid1, uid2),
                },
                mb2.stateless(),
            )
            .unwrap()
            .uids
            .items(u32::MAX)
            .collect::<Vec<_>>();
        assert_eq!(2, uids4.len());

        let poll = mb2.poll().unwrap();
        assert_eq!(Some(4), poll.exists);
        assert_eq!(0, poll.expunge.len());

        assert!(mb2.state.test_flag_o(&Flag::Answered, uids4[0]));
        assert!(!mb2.state.test_flag_o(&Flag::Draft, uids4[0]));

        assert!(!mb2.state.test_flag_o(&Flag::Answered, uids4[1]));
        assert!(mb2.state.test_flag_o(&Flag::Draft, uids4[1]));
    }

    #[test]
    fn bulk_copy_into_empty_other() {
        let setup = set_up();

        let (mut mb1, _) = setup.stateless.select().unwrap();

        let mbox2_path = MailboxPath::root(
            "archive".to_owned(),
            setup.root.path(),
            setup.root.path(),
        )
        .unwrap();
        mbox2_path.create(setup.root.path(), None).unwrap();
        let stateless2 = StatelessMailbox::new(
            "mailbox".to_owned(),
            mbox2_path,
            false,
            Arc::clone(&setup.key_store),
            Arc::clone(&setup.common_paths),
        )
        .unwrap();
        let (mut mb2, _) = stateless2.select().unwrap();

        let uid1 = simple_append(mb1.stateless());
        let uid2 = simple_append(mb1.stateless());
        mb1.stateless()
            .set_flags_blind(vec![
                (uid1, vec![(true, Flag::Answered)]),
                (uid2, vec![(true, Flag::Draft)]),
            ])
            .unwrap();
        mb1.poll().unwrap();

        let uids3 = mb1
            .copy(
                &CopyRequest {
                    ids: SeqRange::range(uid1, uid2),
                },
                mb2.stateless(),
            )
            .unwrap()
            .uids
            .items(u32::MAX)
            .collect::<Vec<_>>();
        assert_eq!(2, uids3.len());

        let poll = mb2.poll().unwrap();
        assert_eq!(Some(2), poll.exists);
        assert_eq!(0, poll.expunge.len());

        assert!(mb2.state.test_flag_o(&Flag::Answered, uids3[0]));
        assert!(!mb2.state.test_flag_o(&Flag::Draft, uids3[0]));

        assert!(!mb2.state.test_flag_o(&Flag::Answered, uids3[1]));
        assert!(mb2.state.test_flag_o(&Flag::Draft, uids3[1]));
    }

    #[test]
    fn test_multiappend() {
        let setup = set_up();
        let (mut mb1, _) = setup.stateless.select().unwrap();

        let internal_date =
            FixedOffset::east(0).from_utc_datetime(&Utc::now().naive_local());
        let mut append_request = AppendRequest::default();
        append_request.items.push(AppendItem {
            buffer_file: mb1
                .stateless()
                .buffer_message(internal_date, b"foo" as &[u8])
                .unwrap(),
            flags: vec![Flag::Answered],
        });
        append_request.items.push(AppendItem {
            buffer_file: mb1
                .stateless()
                .buffer_message(internal_date, b"bar" as &[u8])
                .unwrap(),
            flags: vec![Flag::Draft],
        });

        let uids = mb1
            .stateless()
            .multiappend(append_request)
            .unwrap()
            .uids
            .items(u32::MAX)
            .collect::<Vec<_>>();
        assert_eq!(2, uids.len());

        let poll = mb1.poll().unwrap();
        assert_eq!(Some(2), poll.exists);
        assert_eq!(0, poll.expunge.len());

        assert!(mb1.state.test_flag_o(&Flag::Answered, uids[0]));
        assert!(!mb1.state.test_flag_o(&Flag::Answered, uids[1]));
        assert!(!mb1.state.test_flag_o(&Flag::Draft, uids[0]));
        assert!(mb1.state.test_flag_o(&Flag::Draft, uids[1]));

        let mut append_request = AppendRequest::default();
        append_request.items.push(AppendItem {
            buffer_file: mb1
                .stateless()
                .buffer_message(internal_date, b"xyzzy" as &[u8])
                .unwrap(),
            flags: vec![Flag::Deleted],
        });
        append_request.items.push(AppendItem {
            buffer_file: mb1
                .stateless()
                .buffer_message(internal_date, b"plugh" as &[u8])
                .unwrap(),
            flags: vec![Flag::Seen],
        });

        let uids2 = mb1
            .stateless()
            .multiappend(append_request)
            .unwrap()
            .uids
            .items(u32::MAX)
            .collect::<Vec<_>>();
        assert_eq!(2, uids2.len());

        let poll = mb1.poll().unwrap();
        assert_eq!(Some(4), poll.exists);
        assert_eq!(0, poll.expunge.len());

        assert!(mb1.state.test_flag_o(&Flag::Deleted, uids2[0]));
        assert!(!mb1.state.test_flag_o(&Flag::Deleted, uids2[1]));
        assert!(!mb1.state.test_flag_o(&Flag::Seen, uids2[0]));
        assert!(mb1.state.test_flag_o(&Flag::Seen, uids2[1]));
    }
}
