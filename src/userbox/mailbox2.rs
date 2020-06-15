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

//! Support for working with a single mailbox.
//!
//! A mailbox is a collection of messages and their related metadata events. It
//! is functionally independent from any associated child mailboxes.
//!
//! The contents of a mailbox directory are (where `UV` is the UID validity in
//! lowercase hex):
//!
//! - `%`. Symlink to `%UV`.
//!
//! - `%UV/u*`. Directories containing messages in the _hierarchical
//!   identifier_ scheme described below.
//!
//! - `%UV/c*`. Directories containing state transactions in the _hierarchical
//!   identifier_ scheme described below.
//!
//! - `%UV/rollup/*`. Change rollup files.
//!
//! - `%UV/mailbox.toml`. Immutable metadata about this mailbox. Managed by
//!   `MailboxPath`.
//!
//! - `%UV/unsubscribe`. Marker file; if present, the mailbox is not
//!   subscribed. Managed by `MailboxPath`.
//!
//! - `%UV/recent`. Maintains a token for the `\Recent` flag. See
//!   `recency_token`.
//!
//! - Directories containing child mailboxes, each of which is in a
//!   subdirectory corresponding to its name. Managed by `MailboxPath`.
//!
//! The distinction between `%` and `%UV` is to prevent confusion if a mailbox
//! is deleted and recreated while open. Mailboxes are opened through their
//! `%UV` path, so any change in UID validity permanently invalidates them. The
//! symlink is used to be able to access metadata statelessly.
//!
//! There are some wonky special cases to support IMAP's wonky data model.
//!
//! If the `%UV` directory is missing, this is a `\Noselect` mailbox. Mailboxes
//! are normally created as dual-use, but IMAP requires that a `DELETE`
//! operation on a dual-use mailbox with child mailboxes must transmogrify it
//! into a folder-like mailbox.
//!
//! The subscription model is different from what RFC 3501 prescribes. All
//! selectable mailboxes are subscribed by default, which corresponds to most
//! people's expectations (evidenced by the fact that real mail clients
//! scramble to subscribe a mailbox they create as soon as possible). It also
//! lets us fulfil the letter, though perhaps not the spirit, of the
//! requirement that deleting a mailbox does not unsubscribe it. Instead,
//! deleting a mailbox effectively subscribes it should it be recreated.
//! Ultimately, though, the subtleties of subscriptions likely don't matter too
//! much here since they are rarely used productively and the exotic use-cases
//! the standard urges to support (i.e. a shared mailbox that occasionally gets
//! deleted and later recreated) simply won't happen here.
//!
//! In general:
//!
//! - A mailbox exists (i.e., is visible to IMAP) if its directory exists.
//!
//! - A mailbox is selectable if the `%` subdirectory exists. It is assumed
//!   that the contents of that subdirectory will not be partially
//!   instantiated.
//!
//! - A mailbox is subscribed if it is selectable and does not have a
//!   `%UV/unsubscribe` file.
//!
//! ## Hierarchical Identifier scheme
//!
//! Messages and state transactions are stored in a scheme that assigns one
//! path to each 32-bit identifier, with the property that identifiers are
//! assigned in strictly ascending order, and that each identifier is written
//! at most once before being permanently expunged.
//!
//! The nominal path for an identifier is derived as follows:
//!
//! - A path element starting with the identifier type (`c` or `u`) and the
//!   number of directory levels beneath it.
//!
//! - Zero or more directory levels which are two lowercase hexadecimal digits,
//!   representing consecutive bytes from the identifier (MSB-first), starting
//!   from the first non-zero byte (inclusive) and ending on the LSB
//!   (exclusive).
//!
//! - A path element which is the two lowercase hexadecimal digits of the LSB
//!   of the identifier followed by the extension for its type.
//!
//! Examples (for messages):
//! - `1` → `u0/01.eml`
//! - `255` → `u0/ff.eml`
//! - `12345` → `u1/30/39.eml`
//! - `123456` → `u2/01/e2/40.eml`
//! - `16777216` → `u3/01/00/00/00.eml`
//! - `4294967295` → `u3/ff/ff/ff/ff.eml`
//!
//! This scheme is designed to avoid creating excessive directory levels for
//! small mailboxes while keeping each "section" of the tree small enough to
//! iterate efficiently and allowing some garbage collection.
//!
//! The directory-like elements in the path (other than the top one) is a
//! symlink to a directory of the same name, but suffixed with `.d`.
//!
//! When an item is expunged, it is replaced with a symlink to itself. A
//! "garbage collection" process can identify directories containing only such
//! gravestones and replace the directory link with a similar broken symlink,
//! allowing the total file count to be kept low.
//!
//! The gravestone scheme enables a number of consistent, atomic operations:
//!
//! - Reading: Open succeeds iff the item exists; fails with `ENOENT` if it was
//! never allocated; fails with `ELOOP` if the item was expunged.
//!
//! - Creating: `link()` succeeds iff the item is unallocated; fails with
//! `EEXISTS` or `ELOOP` if it was already allocated.
//!
//! - Expunging: Using `rename()` to replace an item with a looped symlink
//! either succeeds atomically or fails with `ELOOP` if the item was already
//! expunged and a garbage-collection operation cleaned the containing
//! directory up.
//!
//! - Monitoring: Watch the directory that will contain the next item (creating
//! if needed). The next mutation event must involve that item or something
//! after it.
//!
//! Each of these schemes also has an associated `X-guess` file, which contains
//! a LE u32 that indicates the best guess for the most recently allocated
//! item. It is updated non-atomically every time an item is created.
//!
//! ## Metadata rollup and garbage collection
//!
//! Whenever a read-write mailbox ingests a state transaction whose CID is
//! evenly divisible by 256, it dumps its state into a rollup file whose name
//! is the `Modseq` in base-10. When new mailbox instances are loaded, they
//! read in the file with the greatest `Modseq`.
//!
//! When a read-write mailbox initialises, any rollups which are older than
//! 24hr become candidates for deletion. If there any, the process scans the
//! change directories for transactions that took place before the `Modseq` of
//! the latest deletion candidate and expunges them all. A garbage collection
//! is performed on the hierarchical identifier scheme. Finally, the obsolete
//! rollups are deleted.
//!
//! The 24 hour grace period is to ensure that backup processes are essentially
//! guaranteed to either see the separate transactions or the rollup that
//! contains them (i.e., to prevent a case where the backup sees no rollups,
//! but then Crymap finishes a rollup and deletes the transactions, then the
//! backup looks at the transactions directory and finds nothing there either).
//!
//! ## Delivery of new messages
//!
//! When a message is to be delivered, it is first fully buffered into a
//! temporary file.
//!
//! We then need to find the UID to assign it. The directory structure used for
//! messages has a simple total order, so we could simply walk down the "right"
//! of the tree to the third level and see if it has any space. However,
//! listing each directory level involves 256 I/O operations. Instead, we use
//! exponential probing starting from either the last known UID plus one in
//! `seqnum` or 1 followed by binary search to find the first unused UID.
//!
//! Create any directories needed for the new UID, and try to rename the
//! temporary file into place. If that fails due to a conflict, increment the
//! UID and try again.
//!
//! ## Message format
//!
//! Each message consists of a u32 LE `size_xor_a` immediately followed by a
//! data stream. The data stream contains a u32 LE `size_xor_b`, a i64 LE
//! `internal_date`, followed by the raw message text.
//!
//! The two size fields together encode the size of the message before
//! compression without revealing this in the cleartext and without requiring
//! buffering. `size_xor_a` is initially written to 0 and a random value is
//! chosen for `size_xor_b`. Once the message is fully written, the actual
//! length is XORed with `size_xor_b` and the result is written over
//! `size_xor_a`.
//!
//! ## Change transaction format and rollup format
//!
//! Change transactions and rollups are stored as unframed `data_stream`s. The
//! cleartext content is CBOR of either `StateTransaction` or `MailboxState`.

use std::convert::TryInto;
use std::fs;
use std::io::{self, BufRead, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use chrono::prelude::*;
use log::{info, warn};
use rand::{rngs::OsRng, Rng};
use serde::{de::DeserializeOwned, Serialize};
use tempfile::NamedTempFile;

use super::hier_id_scheme::*;
use super::key_store::*;
use super::mailbox_path::*;
use super::mailbox_state::*;
use super::model::*;
use crate::crypt::data_stream;
use crate::support::compression::{Compression, FinishWrite};
use crate::support::error::Error;
use crate::support::file_ops;

/// A stateless view of a mailbox.
///
/// The stateless view is capable of inserting messages, performing
/// unconditional flag modifications, and reading messages by UID, but cannot
/// query flags or notice changes.
#[derive(Clone)]
pub struct StatelessMailbox {
    log_prefix: String,
    path: MailboxPath,
    root: PathBuf,
    read_only: bool,
    key_store: Arc<Mutex<KeyStore>>,
    common_paths: Arc<CommonPaths>,
}

impl StatelessMailbox {
    pub fn new(
        mut log_prefix: String,
        path: MailboxPath,
        read_only: bool,
        key_store: Arc<Mutex<KeyStore>>,
        common_paths: Arc<CommonPaths>,
    ) -> Result<Self, Error> {
        log_prefix.push(':');
        log_prefix.push_str(path.name());
        let root = path.scoped_data_path()?;

        Ok(StatelessMailbox {
            log_prefix,
            path,
            root,
            read_only,
            key_store,
            common_paths,
        })
    }

    /// Return the underlying `MailboxPath`.
    pub fn path(&self) -> &MailboxPath {
        &self.path
    }

    /// Return the data directory root for this mailbox instance.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Return the UID validity of this mailbox instance.
    ///
    /// If the mailbox is deleted and recreated, this will continue to reflect
    /// the validity this instance was opened with.
    pub fn uid_validity(&self) -> Result<u32, Error> {
        parse_uid_validity(&self.root)
    }

    /// Check whether this instance is still "OK".
    ///
    /// An instance is broken if the mailbox is deleted or the UID validity has
    /// changed.
    ///
    /// This should be called in response to unexpected errors to see whether
    /// it is desirable to hang up on the client instead of continuing to
    /// futilely try to do operations on the mailbox.
    pub fn is_ok(&self) -> bool {
        self.root.is_dir()
    }

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

    /// Blindly set and clear the given flags on the given message.
    ///
    /// The caller must already know that `uid` refers to an allocated message.
    ///
    /// On success, returns the CID of the change, or `None` if there were not
    /// actually any changes to make.
    fn set_flags_blind(
        &self,
        uid: Uid,
        flags: impl IntoIterator<Item = (bool, Flag)>,
    ) -> Result<Option<Cid>, Error> {
        self.not_read_only()?;

        let mut tx = StateTransaction::new_unordered(uid);
        for (add, flag) in flags {
            if add {
                tx.add_flag(uid, flag);
            } else {
                tx.rm_flag(uid, flag);
            }
        }

        if tx.is_empty() {
            return Ok(None);
        }

        let buffer_file = self.write_state_file(&tx)?;
        let scheme = self.change_scheme();
        for _ in 0..1000 {
            let next_cid = Cid(scheme.first_unallocated_id());
            if next_cid > Cid::MAX {
                return Err(Error::MailboxFull);
            }

            if scheme.emplace(buffer_file.path(), next_cid.0)? {
                return Ok(Some(next_cid));
            }
        }

        Err(Error::GaveUpInsertion)
    }

    /// Try to add all the given flags to `uid`.
    ///
    /// On error, the error is logged.
    fn propagate_flags_best_effort(
        &self,
        uid: Uid,
        flags: impl IntoIterator<Item = Flag>,
    ) {
        if let Err(e) =
            self.set_flags_blind(uid, flags.into_iter().map(|f| (true, f)))
        {
            // If APPEND/COPY/MOVE returns an error, the call must have had no
            // effect, so we can't return an error to the client here since we
            // already emplaced the new message. Transferring the flags is only
            // a SHOULD, however, so we're fine to just log the error and carry
            // on if anything failed.
            warn!(
                "{} Failed to set flags on {}: {}",
                self.log_prefix,
                uid.0.get(),
                e
            );
        }
    }

    /// Reads a file that was written by `write_state_file()`.
    fn read_state_file<T: DeserializeOwned>(
        &self,
        src: &Path,
    ) -> Result<T, Error> {
        let file = fs::File::open(src)?;
        let stream = {
            let mut ks = self.key_store.lock().unwrap();
            data_stream::Reader::new(file, |k| ks.get_private_key(k))?
        };
        let compression = stream.metadata.compression;
        let stream = compression.decompressor(stream)?;

        serde_cbor::from_reader(stream).map_err(|e| e.into())
    }

    /// Writes the given data to a new `NamedTempFile` in the format used for
    /// storing state.
    fn write_state_file(
        &self,
        data: &impl Serialize,
    ) -> Result<NamedTempFile, Error> {
        self.not_read_only()?;

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

        Ok(buffer_file)
    }

    fn message_scheme(&self) -> HierIdScheme<'_> {
        HierIdScheme {
            root: &self.root,
            prefix: b'u',
            extension: "eml",
        }
    }

    fn change_scheme(&self) -> HierIdScheme<'_> {
        HierIdScheme {
            root: &self.root,
            prefix: b'c',
            extension: "tx",
        }
    }

    fn not_read_only(&self) -> Result<(), Error> {
        if self.read_only {
            Err(Error::MailboxReadOnly)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod test {
    use std::iter;

    use tempfile::TempDir;

    use super::*;
    use crate::crypt::master_key::MasterKey;

    struct Setup {
        root: TempDir,
        stateless: StatelessMailbox,
    }

    fn set_up() -> Setup {
        let root = TempDir::new().unwrap();
        let common_paths = Arc::new(CommonPaths {
            tmp: root.path().to_owned(),
            garbage: root.path().to_owned(),
        });

        let mut key_store = KeyStore::new(
            "key-store".to_owned(),
            root.path().join("keys"),
            common_paths.tmp.clone(),
            Some(Arc::new(MasterKey::new())),
        );
        key_store.set_rsa_bits(1024);
        key_store.init(&KeyStoreConfig::default()).unwrap();

        let key_store = Arc::new(Mutex::new(key_store));

        let mbox_path =
            MailboxPath::root("inbox".to_owned(), root.path()).unwrap();
        mbox_path.create(root.path(), None).unwrap();
        let stateless = StatelessMailbox::new(
            "mailbox".to_owned(),
            mbox_path,
            false,
            key_store,
            common_paths,
        )
        .unwrap();

        Setup { root, stateless }
    }

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

    #[test]
    fn write_and_read_state_files() {
        let setup = set_up();

        assert_eq!(
            Some(Cid(1)),
            setup
                .stateless
                .set_flags_blind(Uid::u(1), vec![(true, Flag::Flagged)])
                .unwrap()
        );

        let tx: StateTransaction = setup
            .stateless
            .read_state_file(&setup.stateless.change_scheme().path_for_id(1))
            .unwrap();

        // If we were able to deserialise it at all, the read operation worked.
        // So just make sure we got something non-trivial back.
        assert!(!tx.is_empty());
    }

    #[test]
    fn delete_open_mailbox() {
        let setup = set_up();

        assert!(setup.stateless.is_ok());
        assert_eq!(
            setup.stateless.uid_validity().unwrap(),
            setup.stateless.path().current_uid_validity().unwrap()
        );

        setup.stateless.path().delete(setup.root.path()).unwrap();
        assert!(!setup.stateless.is_ok());
        assert!(matches!(
            setup.stateless.path().current_uid_validity(),
            Err(Error::MailboxUnselectable)
        ));

        // Ensure we get a distinct UID validity
        std::thread::sleep(std::time::Duration::from_millis(2000));

        setup
            .stateless
            .path()
            .create(setup.root.path(), None)
            .unwrap();
        assert_ne!(
            setup.stateless.uid_validity().unwrap(),
            setup.stateless.path().current_uid_validity().unwrap()
        );
        assert!(!setup.stateless.is_ok());
    }
}
