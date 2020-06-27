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

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use chrono::prelude::*;
use log::info;
use rand::{rngs::OsRng, Rng};
use tempfile::NamedTempFile;

use super::defs::*;
use crate::account::model::*;
use crate::crypt::data_stream;
use crate::support::compression::{Compression, FinishWrite};
use crate::support::error::Error;
use crate::support::file_ops;

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
        let stream = {
            let mut ks = self.key_store.lock().unwrap();
            data_stream::Reader::new(file, |k| ks.get_private_key(k))?
        };
        let compression = stream.metadata.compression;
        let mut stream = compression.decompressor(stream)?;
        let metadata_length = stream.read_u16::<LittleEndian>()?;
        let mut metadata: MessageMetadata = serde_cbor::from_reader(
            stream.by_ref().take(metadata_length.into()),
        )?;
        metadata.size ^= size_xor;

        Ok((metadata, stream))
    }

    /// Append the given message to this mailbox.
    ///
    /// Returns the UID of the new message.
    ///
    /// This corresponds to the `APPEND` command from RFC 3501 and the
    /// `APPENDUID` response from RFC 4315.
    ///
    /// RFC 3501 also allows setting flags at the same time. This is
    /// accomplished with a follow-up call to `store_plus()` on
    /// `StatefulMailbox`.
    pub fn append(
        &self,
        internal_date: DateTime<FixedOffset>,
        flags: impl IntoIterator<Item = Flag>,
        mut data: impl Read,
    ) -> Result<Uid, Error> {
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

        let uid = self.insert_message(buffer_file.path())?;
        self.propagate_flags_best_effort(uid, flags);
        Ok(uid)
    }

    /// Insert `src` into this mailbox via a hard link.
    ///
    /// This is used for `COPY` and `MOVE`, though it is not exactly either of
    /// those.
    fn insert_message(&self, src: &Path) -> Result<Uid, Error> {
        self.not_read_only()?;

        let scheme = self.message_scheme();

        for _ in 0..1000 {
            let uid = Uid::of(scheme.first_unallocated_id())
                .ok_or(Error::MailboxFull)?;
            if scheme.emplace(src, uid.0.get())? {
                info!(
                    "{} Delivered message to {}",
                    self.log_prefix,
                    uid.0.get()
                );
                return Ok(uid);
            }
        }

        Err(Error::GaveUpInsertion)
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
}
