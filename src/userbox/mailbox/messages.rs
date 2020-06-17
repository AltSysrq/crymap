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
use crate::crypt::data_stream;
use crate::support::compression::{Compression, FinishWrite};
use crate::support::error::Error;
use crate::support::file_ops;
use crate::userbox::model::*;

impl StatelessMailbox {
    /// Open the identified message for reading.
    ///
    /// This doesn't correspond to any particular IMAP command (that would be
    /// too easy!) but is used to implement a number of them.
    ///
    /// On success, returns the length in bytes, the internal date, and a
    /// reader to access the content.
    pub fn open_message(
        &self,
        uid: Uid,
    ) -> Result<(u32, DateTime<Utc>, impl BufRead), Error> {
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

        let size_xor_a = file.read_u32::<LittleEndian>()?;
        let stream = {
            let mut ks = self.key_store.lock().unwrap();
            data_stream::Reader::new(file, |k| ks.get_private_key(k))?
        };
        let compression = stream.metadata.compression;
        let mut stream = compression.decompressor(stream)?;
        let size_xor_b = stream.read_u32::<LittleEndian>()?;
        let internal_date = stream.read_i64::<LittleEndian>()?;

        Ok((
            size_xor_a ^ size_xor_b,
            Utc.timestamp_millis(internal_date),
            stream,
        ))
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
        internal_date: DateTime<Utc>,
        flags: impl IntoIterator<Item = Flag>,
        mut data: impl Read,
    ) -> Result<Uid, Error> {
        self.not_read_only()?;

        let mut buffer_file = NamedTempFile::new_in(&self.common_paths.tmp)?;

        let size_xor_a: u32;
        let size_xor_b: u32 = OsRng.gen();
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
                compressor.write_u32::<LittleEndian>(size_xor_b)?;
                compressor.write_i64::<LittleEndian>(
                    internal_date.timestamp_millis(),
                )?;
                let size = io::copy(&mut data, &mut compressor)?;
                size_xor_a = size_xor_b ^ size.try_into().unwrap_or(u32::MAX);
                compressor.finish()?;
            }
            crypt_writer.flush()?;
        }

        buffer_file.seek(io::SeekFrom::Start(0))?;
        buffer_file.write_u32::<LittleEndian>(size_xor_a)?;
        file_ops::chmod(buffer_file.path(), 0o440)?;

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

        let now = Utc::now();
        let now_truncated = Utc.timestamp_millis(now.timestamp_millis());

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
        let (size, date, mut r) =
            setup.stateless.open_message(Uid::u(1)).unwrap();
        assert_eq!(11, size);
        assert_eq!(now_truncated, date);
        r.read_to_string(&mut content).unwrap();
        assert_eq!("hello world", &content);

        content.clear();
        let (size, date, mut r) =
            setup.stateless.open_message(Uid::u(2)).unwrap();
        assert_eq!(15, size);
        assert_eq!(now_truncated, date);
        r.read_to_string(&mut content).unwrap();
        assert_eq!("another message", &content);
    }
}
