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

use std::fs;
use std::io::Write;
use std::path::Path;

use serde::{de::DeserializeOwned, Serialize};
use tempfile::NamedTempFile;

use super::super::mailbox_state::*;
use super::defs::*;
use crate::crypt::data_stream;
use crate::support::compression::{Compression, FinishWrite};
use crate::support::error::Error;

impl StatelessMailbox {
    /// Reads a file that was written by `write_state_file()`.
    pub(super) fn read_state_file<T: DeserializeOwned>(
        &self,
        src: &Path,
    ) -> Result<T, Error> {
        let file = fs::File::open(src)?;
        let stream = data_stream::Reader::new(file, |k| {
            let mut ks = self.key_store.lock().unwrap();
            ks.get_private_key(k)
        })?;
        let compression = stream.metadata.compression;
        let stream = compression.decompressor(stream)?;

        serde_cbor::from_reader(stream).map_err(|e| e.into())
    }

    /// Writes the given data to a new `NamedTempFile` in the format used for
    /// storing state.
    pub(super) fn write_state_file(
        &self,
        data: &impl Serialize,
    ) -> Result<NamedTempFile, Error> {
        let mut buffer_file = NamedTempFile::new_in(&self.common_paths.tmp)?;
        {
            let compression = Compression::DEFAULT_FOR_STATE;
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
                serde_cbor::to_writer(&mut compressor, data)?;
                compressor.finish()?;
            }
            crypt_writer.flush()?;
        }
        buffer_file.as_file_mut().sync_all()?;

        Ok(buffer_file)
    }
}

impl StatefulMailbox {
    /// Perform a transactional change against the mailbox's mutable state.
    ///
    /// `f` is called with a transaction and `self` and is expected to modify
    /// the transaction as desired, and return the result of the whole
    /// transaction.
    ///
    /// `f` will be reevaluated if more changes are found while trying to
    /// process the transaction.
    ///
    /// If `tx` ends up being an empty transaction, nothing is committed and
    /// the result is directly returned.
    pub(super) fn change_transaction<R>(
        &mut self,
        mut f: impl FnMut(&Self, &mut StateTransaction) -> Result<R, Error>,
    ) -> Result<R, Error> {
        // Ensure we're working with the latest state
        self.poll_for_new_changes()?;

        for _ in 0..1000 {
            let (cid, mut tx) = self.state.start_tx()?;
            let res = f(self, &mut tx)?;
            if tx.is_empty() {
                return Ok(res);
            }

            let buffer_file = self.s.write_state_file(&tx)?;

            if self.s.change_scheme().emplace(buffer_file.path(), cid.0)? {
                // Directly commit instead of needing to do the whole
                // poll/read/decrypt dance
                self.state.commit(cid, tx);
                self.see_cid(cid);
                self.s.notify_all_best_effort();
                return Ok(res);
            }

            self.poll_for_new_changes()?;
        }

        Err(Error::GaveUpInsertion)
    }
}

#[cfg(test)]
mod test {
    use chrono::prelude::*;

    use super::super::super::model::*;
    use super::super::test_prelude::*;
    use super::*;
    use crate::account::model::*;
    use crate::support::chronox::*;

    #[test]
    fn write_and_read_state_files() {
        let setup = set_up();

        assert_eq!(
            Some(Cid(1)),
            setup
                .stateless
                .set_flags_blind(vec![(Uid::u(1), vec![(true, Flag::Flagged)])])
                .unwrap()
        );

        let tx: StateTransaction = setup
            .stateless
            .read_state_file(
                &setup
                    .stateless
                    .change_scheme()
                    .access_path_for_id(1)
                    .assume_exists(),
            )
            .unwrap();

        // If we were able to deserialise it at all, the read operation worked.
        // So just make sure we got something non-trivial back.
        assert!(!tx.is_empty());
    }

    #[test]
    fn append_with_flags() {
        let setup = set_up();
        let (mut mb1, _) = setup.stateless.select().unwrap();

        let uid = mb1
            .stateless()
            .append(
                FixedOffset::zero()
                    .from_utc_datetime(&Utc::now().naive_local()),
                vec![Flag::Flagged, Flag::Keyword("foo".to_owned())],
                &mut "foobar".as_bytes(),
            )
            .unwrap();
        mb1.poll().unwrap();

        assert!(mb1.state.test_flag_o(&Flag::Flagged, uid));
        assert!(mb1.state.test_flag_o(&Flag::Keyword("foo".to_owned()), uid));
    }

    #[test]
    fn misordered_blind_change_accepted() {
        let setup = set_up();
        let (mut mb1, _) = setup.stateless.select().unwrap();

        let uid1 = simple_append(mb1.stateless());
        let uid2 = simple_append(mb1.stateless());
        mb1.poll().unwrap();
        mb1.store(&StoreRequest {
            ids: &SeqRange::just(uid2),
            flags: &[Flag::Flagged],
            remove_listed: false,
            remove_unlisted: false,
            loud: false,
            unchanged_since: None,
        })
        .unwrap();
        mb1.poll().unwrap();

        // Blindly set flags on UID 1, which will create a change with nominal
        // modseq (1,2) even though it comes after the (2,1) we just created
        // above. When reading the stream, it should get fixed up to (2,2).
        mb1.s
            .set_flags_blind(vec![(uid1, vec![(true, Flag::Seen)])])
            .unwrap();

        let poll = mb1.poll().unwrap();
        assert_eq!(
            Some(V1Modseq::new(uid2, Cid(2))),
            poll.max_modseq.and_then(V1Modseq::import)
        );
        assert_eq!(
            V1Modseq::new(uid2, Cid(2)),
            mb1.state.message_status(uid1).unwrap().last_modified()
        );
    }
}
