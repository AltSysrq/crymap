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

//! Implements the low-level message store.
//!
//! The message store itself stores message files, including gravestones for
//! expunged messages, monitors for asynchronous changes to the set of existing
//! messages, and maintains the UID-sequence-number mapping. It does not deal
//! with flags or more complex operations, nor does it maintain the
//! UID-validity number.
//!
//! # Message directories layout
//!
//! The message store primarily operates in terms of UIDs. Each message is
//! stored in exactly one file. The path for a message (relative to the root)
//! is as follows:
//!
//! - `z#`, where `#` is 3 minus the number of leading zero *bytes* in the UID.
//! (Note that UID 0 is never used, so there is no special case for the 0 UID.)
//!
//! - Zero to three directory levels of the format `XX`, where `XX` is the
//! lowercase hexadecimal representation of the non-zero bytes of the UID,
//! excluding the final byte, in descending order of significance.
//!
//! - A file whose name is of the form `XX.eml`, where `XX` is the lowercase
//! hexadecimal representation of the least significant byte of the UID.
//!
//! Examples;
//! - `1` → `z0/01.eml`
//! - `255` → `z0/ff.eml`
//! - `12345` → `z1/30/39.eml`
//! - `123456` → `z2/01/e2/40.eml`
//! - `16777216` → `z3/01/00/00/00.eml`
//! - `4294967295` → `z3/ff/ff/ff/ff.eml`
//!
//! This scheme is designed to avoid creating excessive directory levels for
//! small mailboxes while keeping each "section" of the tree small enough to
//! iterate efficiently.
//!
//! # Expunging messages
//!
//! The root of the message store contains a file named `expunge-log`. When a
//! message is expunged, it is replaced with a symlink to itself (see below)
//! and its UID is appended to this file. The file can contain duplicate UIDs
//! since this not an atomic process. The file is strictly append-only. It
//! serves both as a conduit for notifications about expungement and its length
//! serves as a monotonic counter for maintaining the sequence number index
//! (next section).
//!
//! Expunged messages are replaced with a self-referencing symlink instead of
//! an empty file for two reasons:
//!
//! 1. It makes it possible to identify expunged messages in a directory
//! listing without needing to `stat()` each file.
//!
//! 2. If an attempt is made to read an expunged file, it fails with the unique
//! `ELOOP` error rather than requiring us to detect the empty file. It also
//! means that messages that are truncated do not look like they are expunged.
//!
//! We cannot simply delete expunged message files because insertion of new
//! messages relies on a non-overwriting rename to avoid assigning expunged
//! UIDs to new messages.
//!
//! When a process reads an element out of `expunge-log`, it checks that the
//! message really has been expunged and does so if it has not, since writing
//! to `expunge-log` happens before and is not atomic with the actual
//! expungement.
//!
//! # Sequence number index
//!
//! (Rant) Sequence numbers are an abomination. They should have been EXPUNGEd
//! with the IMAP4 revision, compatibility with IMAP2 be damned. It's
//! inconvenient for the client as it forces the client to keep track of a set
//! of ever-changing identifiers. It's inconvenient for the server, which has
//! to emulate these ever-changing identifiers even though any practical server
//! implementation will have the messages stored by some fixed identifier. The
//! shifting of sequence numbers happens based on events in the protocol and
//! not in real time, so you can't even off-load it to a shared database since
//! each process needs to track the sequence numbers independently. The one and
//! only model where it is convenient for the server is in a system which
//! doesn't allow concurrent mailbox access and stores a list of message
//! references in a naïve list in memory, or which simply does a linear
//! iteration over an `mbox` file for every operation. UIDs should have wholly
//! replace sequence numbers and IMAP2 clients connecting to IMAP4 be left to
//! deal with the resulting holes in the sequence in whatever failure mode that
//! bring. (/Rant)
//!
//! The root of the message store may contain a file named `seqnum`. It
//! consists of the following data:
//!
//! - u8: 0, Format version
//! - u32 LE: last known UID
//! - u64 LE: last processed offset in `expunge-log`
//! - u32 LE array to end of file: non-expunged UIDs in ascending order
//!
//! When a mailbox is opened, `seqnum` is fully loaded into memory, then
//! `expunge-log` is processed to find messages expunged since then and the
//! last known UID is used as a starting point to scan for new messages.
//!
//! When a mailbox is closed, if any changes were made to the sequence number
//! index, it is dumped to a new file which then replaces `seqnum`.
//!
//! Translation from sequence number to UID is simply a direct array lookup
//! (after accounting for the fact that sequence numbers start at 1 instead of
//! 0). Translation from UID to sequence number involves a binary search to
//! find the index of the UID.
//!
//! This system is designed to remain reasonably snappy for mailboxes up to
//! hundreds of thousands or millions of existing messages, while also not
//! getting bogged down by the ever-growing accumulation of expunged UIDs.
//!
//! # Delivery of new messages
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
//! # Message format
//!
//! Each message consists of a u32 LE `size_xor_a` immediately followed by a
//! data stream. The data stream contains a u32 LE `size_xor_b` followed by the
//! raw message text.
//!
//! The two size fields together encode the size of the message before
//! compression without revealing this in the cleartext and without requiring
//! buffering. `size_xor_a` is initially written to 0 and a random value is
//! chosen for `size_xor_b`. Once the message is fully written, the actual
//! length is XORed with `size_xor_b` and the result is written over
//! `size_xor_a`.
//!
//! # IMAP interaction
//!
//! A brief overview of how IMAP commands map to calls to this store (only
//! considering things that could reasonably involve it):
//!
//! - Anything involving sequence numbers: `uid_to_seqnum` and `seqnum_to_uid`.
//! - `SELECT`: `poll_active_status()`
//! - `EXAMINE`: `poll_active_status()` and set `read_only: true`
//! - `CREATE`, `DELETE`, `RENAME`: None, handled by userbox
//! - `APPEND`: `deliver_message()`
//! - `STATUS`: `EXAMINE` plus `message_count()`
//! - `EXPUNGE`: `expunge()` (with coordination from the userbox)
//! - `SEARCH`: `read_message()` (with coordination from the userbox)
//! - `FETCH`: `read_message()`
//! - `COPY`: `insert_message()`
//! - `NOOP`, `CHECK`, etc: `poll_active_status()`
//! - `UIDNEXT` response: `next_uid()`
//! - `INTERNALDATE` attribute: `message_internal_date()`
//! - `RFC822-SIZE` attribute: `read_message()` result

use std::convert::TryInto;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, BufRead, Read, Seek, Write};
use std::num::NonZeroU32;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
use std::sync::Arc;

use byteorder::{ByteOrder, LittleEndian, ReadBytesExt, WriteBytesExt};
use log::{error, info, warn};
use notify::Watcher;
use rand::{rngs::OsRng, Rng};

use crate::crypt::data_stream;
use crate::support::compression::{Compression, FinishWrite};
use crate::support::error::Error;
use crate::support::file_ops;
use crate::userbox::key_store::KeyStore;

/// Uniquely identifies a message within a single mailbox.
///
/// UIDs start at 1 and increase monotonically as messages are added to the
/// mailbox. UIDs are never reused.
///
/// RFC 3501 does not actually require them to start at 1. The benefits of
/// starting from 0 are pretty minimal though and doing so has the potential to
/// break clients that assume UIDs start from 1 like sequence numbers.
///
/// In this implementation, UIDs are assigned strictly sequentially.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Uid(pub NonZeroU32);

impl Uid {
    pub fn of(uid: u32) -> Option<Self> {
        NonZeroU32::new(uid).map(Uid)
    }

    #[cfg(test)]
    pub fn u(uid: u32) -> Self {
        Uid::of(uid).unwrap()
    }
}

/// An abomination.
///
/// The sequence number of a message is one plus the number of non-expunged
/// messages that have a UID less than it, counting based on a point-in-time
/// snapshot instead of the real message state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Seqnum(pub NonZeroU32);

impl Seqnum {
    pub fn of(seqnum: u32) -> Option<Self> {
        NonZeroU32::new(seqnum).map(Seqnum)
    }

    #[cfg(test)]
    pub fn u(seqnum: u32) -> Self {
        Seqnum::of(seqnum).unwrap()
    }
}

/// The basic message store. See the module docs for more details on the model.
///
/// The implementation can be thought of as having two modes of operation:
/// "passive", in which all operations are stateless, but notifications and
/// sequence numbers are unsupported, and "active", in which changes to the
/// mailbox are detected in real time and the sequence number mapping is
/// maintained. Passive mode is mainly used for offline message delivery, while
/// active mode is used for actual IMAP connections.
pub struct MessageStore {
    log_prefix: String,
    root: PathBuf,
    tmp: PathBuf,
    read_only: bool,
    seqnum_index: Option<SeqnumIndex>,
    expunge_log_appender: Option<fs::File>,
    notifications: Arc<Notifications>,
    watcher: Option<notify::RecommendedWatcher>,
    watched_message_path: Option<PathBuf>,
    watcher_failed: bool,
}

struct Notifications {
    expunge_log_updated: AtomicBool,
    youve_got_mail: AtomicBool,
    notify: Box<dyn Fn() + Send + Sync>,
}

impl MessageStore {
    /// Create a new message store rooted at `root`.
    ///
    /// If `read_only` is true, no write operations will be accepted.
    ///
    /// `notify` will be called whenever changes are detected in the mailbox
    /// asynchronously. Change monitoring only starts once the store enters
    /// active mode.
    pub fn new(
        log_prefix: String,
        root: PathBuf,
        tmp: PathBuf,
        read_only: bool,
        notify: impl Fn() + Send + Sync + 'static,
    ) -> Self {
        MessageStore {
            log_prefix,
            root,
            tmp,
            read_only,
            seqnum_index: None,
            expunge_log_appender: None,
            watcher: None,
            watched_message_path: None,
            watcher_failed: false,
            notifications: Arc::new(Notifications {
                expunge_log_updated: AtomicBool::new(true),
                youve_got_mail: AtomicBool::new(true),
                notify: Box::new(notify),
            }),
        }
    }

    /// Deliver a message into this message store.
    ///
    /// Data will be read from `src` through its end.
    ///
    /// Returns the UID of the new message.
    ///
    /// In passive mode, the `seqnum` file is consulted if present to get a
    /// guess for the UID. In active mode, the internal sequence number index
    /// is used. There are otherwise no behavioural differences between active
    /// and passive mode here.
    pub fn deliver_message(
        &mut self,
        key_store: &mut KeyStore,
        mut src: impl Read,
    ) -> Result<Uid, Error> {
        if self.read_only {
            return Err(Error::MailboxReadOnly);
        }

        let (key_name, pub_key) = key_store.get_default_public_key()?;

        let compression = Compression::DEFAULT_FOR_MESSAGE;
        let len_xor_b: u32 = OsRng.gen();
        let len_xor_a: u32;

        let mut buffer_file = tempfile::NamedTempFile::new_in(&self.tmp)?;
        buffer_file.write_u32::<LittleEndian>(0)?;
        {
            let mut crypt_writer = data_stream::Writer::new(
                &mut buffer_file,
                pub_key,
                key_name.to_owned(),
                compression,
            )?;
            {
                let mut compressor =
                    compression.compressor(&mut crypt_writer)?;
                compressor.write_u32::<LittleEndian>(len_xor_b)?;
                let len = io::copy(&mut src, &mut compressor)?;
                len_xor_a = len_xor_b ^ len.try_into().unwrap_or(u32::MAX);
                compressor.finish()?;
            }
            crypt_writer.flush()?;
        }

        buffer_file.seek(io::SeekFrom::Start(0))?;
        buffer_file.write_u32::<LittleEndian>(len_xor_a)?;

        file_ops::chmod(buffer_file.path(), 0o440)?;
        self.insert_message(buffer_file.path())
    }

    /// Link the given file in as a new message.
    ///
    /// It is assumed that `src_file` is already a suitably formatted message
    /// for this mailbox.
    ///
    /// This creates a hard link to the original file, so the caller must be
    /// sure that nothing will remove it later.
    ///
    /// Returns the UID of the new message.
    ///
    /// In passive mode, the `seqnum` file is consulted if present to get a
    /// guess for the UID. In active mode, the internal sequence number index
    /// is used. There are otherwise no behavioural differences between active
    /// and passive mode here.
    pub fn insert_message(
        &mut self,
        src_file: impl AsRef<Path>,
    ) -> Result<Uid, Error> {
        if self.read_only {
            return Err(Error::MailboxReadOnly);
        }

        let src_file = src_file.as_ref();

        let uid_guess = self.probable_last_uid();
        let mut uid =
            probe_for_first_uid(uid_guess, |uid| self.is_uid_allocated(uid));

        loop {
            let uid_path = self.path_for_uid(uid);
            self.ensure_message_dirs_exist(&uid_path)?;

            match nix::unistd::linkat(
                None,
                src_file,
                None,
                &uid_path,
                nix::unistd::LinkatFlags::SymlinkFollow,
            ) {
                Ok(_) => {
                    info!(
                        "{} Delivered message to UID {}",
                        self.log_prefix,
                        uid.0.get()
                    );
                    if let &mut Some(ref mut seqnum_index) =
                        &mut self.seqnum_index
                    {
                        seqnum_index.exists(uid);
                        self.notifications.set_youve_got_mail();
                    }
                    return Ok(uid);
                }
                Err(nix::Error::Sys(nix::errno::Errno::EEXIST)) => {
                    if u32::MAX == uid.0.get() {
                        error!(
                            "{} Mailbox is full! \
                                Can't deliver any more messages!",
                            self.log_prefix
                        );
                        return Err(Error::MailboxFull);
                    } else {
                        info!(
                            "{} Lost race to deliver UID {}, trying next one",
                            self.log_prefix,
                            uid.0.get()
                        );
                        uid = Uid::of(uid.0.get() + 1).unwrap();
                    }
                }
                Err(nix::Error::Sys(nix::errno::Errno::ELOOP)) => {
                    return Err(Error::ExpungedMessage);
                }
                Err(nix::Error::Sys(nix::errno::Errno::ENOENT)) => {
                    return Err(Error::NxMessage);
                }
                Err(e) => {
                    error!(
                        "{} Failed to deliver message to UID {}: {}",
                        self.log_prefix,
                        uid.0.get(),
                        e
                    );
                    return Err(e.into());
                }
            }
        }
    }

    /// Expunge the given UID.
    ///
    /// If `force_ghost` is `false`, this only works if the UID refers to a
    /// real message or an expunged message. (In the latter case, the call is a
    /// no-op.) If `force_ghost` is `true`, an attempt will be made to place
    /// the gravestone even if nothing exists at the UID's path yet. (This is
    /// used to repair missing gravestones.)
    ///
    /// This behaves the same in both active and passive mode. In active mode,
    /// the sequence number index is immediately updated.
    pub fn expunge(
        &mut self,
        uid: Uid,
        force_ghost: bool,
    ) -> Result<(), Error> {
        if self.read_only {
            return Err(Error::MailboxReadOnly);
        }

        let dest_file = self.path_for_uid(uid);
        // Make sure this is a useful and valid expungement
        match classify_message_file(&dest_file) {
            // Nothing to do, but make sure it's expunged in the index as well
            MessageFileClassification::Gravestone => {
                if let Some(index) = self.seqnum_index.as_mut() {
                    index.expunged(uid);
                    self.notifications.set_expunge_log_updated();
                }
                return Ok(());
            }
            // Usual case
            MessageFileClassification::Message => (),
            // Don't create a gravestone where there was no UID before unless
            // this is explicitly requested
            MessageFileClassification::Unknown if force_ghost => (),
            MessageFileClassification::Unknown => return Err(Error::NxMessage),
        }

        self.expunge_internal(uid, dest_file, true)
    }

    fn expunge_internal(
        &mut self,
        uid: Uid,
        dest_file: PathBuf,
        write_expunge_log: bool,
    ) -> Result<(), Error> {
        // Stage a gravestone in the temporary directory
        let mut stage_path: PathBuf;
        loop {
            stage_path = self.tmp.join(format!(
                "{:x}.{:x}",
                uid.0.get(),
                OsRng.gen::<u64>()
            ));
            match std::os::unix::fs::symlink(
                dest_file.file_name().unwrap(),
                &stage_path,
            ) {
                Ok(_) => break,
                Err(e) if io::ErrorKind::AlreadyExists == e.kind() => continue,
                Err(e) => return Err(e.into()),
            }
        }

        info!("{} Expunging {}", self.log_prefix, uid.0.get());

        // Write this event to the expungement log
        if write_expunge_log {
            self.expunge_log_appender()?
                .write_u32::<LittleEndian>(uid.0.get())?;
        }

        // Move the gravestone on top of the message
        //
        // In the case of concurrent access, this may replace the gravestone
        // with a new one, which is safe.
        fs::rename(&stage_path, &dest_file)?;

        // Only now is it safe to mark it as expunged in the sequence number
        // index
        if let Some(index) = self.seqnum_index.as_mut() {
            index.expunged(uid);
            self.notifications.set_expunge_log_updated();
        }
        Ok(())
    }

    /// Opens a message identified by UID for reading.
    ///
    /// If this returns `Error::NxMessage`, consider using `expunge()` with
    /// `force_ghost: true` to repair the missing gravestone.
    ///
    /// On success, returns the stream and its length, in bytes.
    ///
    /// This call has no differences between active and passive mode.
    pub fn read_message(
        &self,
        key_store: &mut KeyStore,
        uid: Uid,
    ) -> Result<(u32, impl BufRead), Error> {
        let mut file = match fs::File::open(self.path_for_uid(uid)) {
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
        let stream =
            data_stream::Reader::new(file, |k| key_store.get_private_key(k))?;
        let compression = stream.metadata.compression;
        let mut stream = compression.decompressor(stream)?;
        let size_xor_b = stream.read_u32::<LittleEndian>()?;

        Ok((size_xor_a ^ size_xor_b, stream))
    }

    /// Return the "internal date" for the identified message.
    ///
    /// This is just the ctime of the file.
    pub fn message_internal_date(
        &self,
        uid: Uid,
    ) -> Result<std::time::SystemTime, Error> {
        match fs::metadata(self.path_for_uid(uid)) {
            Ok(md) => Ok(md.created()?),
            Err(e) if Some(nix::libc::ELOOP) == e.raw_os_error() => {
                Err(Error::ExpungedMessage)
            }
            Err(e) if io::ErrorKind::NotFound == e.kind() => {
                Err(Error::NxMessage)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Return whether there are any pending notifications that
    /// `poll_active_status()` would handle.
    ///
    /// If asynchronous notifications are not available, this will always
    /// return true, so the caller must ensure that at least some time is spent
    /// inactive.
    pub fn has_pending_notifications(&self) -> bool {
        self.notifications.expunge_log_updated.load(SeqCst)
            || self.notifications.youve_got_mail.load(SeqCst)
    }

    /// Return what is believed to be the next UID to be allocated.
    ///
    /// This is only valid in active mode.
    pub fn next_uid(&self) -> Uid {
        Uid::of(
            self.seqnum_index
                .as_ref()
                .expect("next_uid called on passive store")
                .last_known_uid
                .map(|u| u.0.get())
                .unwrap_or(0)
                .saturating_add(1),
        )
        .unwrap()
    }

    /// Translate the given UID to a sequence number.
    ///
    /// This is only valid in active mode.
    pub fn uid_to_seqnum(&self, uid: Uid) -> Option<Seqnum> {
        self.seqnum_index
            .as_ref()
            .expect("uid_to_seqnum called on passive store")
            .uid_to_seqnum(uid)
    }

    /// Translate the given sequence number to a UID.
    ///
    /// This is only valid in active mode.
    pub fn seqnum_to_uid(&self, seqnum: Seqnum) -> Option<Uid> {
        self.seqnum_index
            .as_ref()
            .expect("seqnum_to_uid called on passive store")
            .seqnum_to_uid(seqnum)
    }

    /// Return the current number of messages present, according to the current
    /// sequence number mapping.
    pub fn message_count(&self) -> usize {
        self.seqnum_index
            .as_ref()
            .expect("message_count called on passive store")
            .valid_size
    }

    /// Return an iterator over the messages in this store, identified by
    /// sequence number and UID.
    pub fn messages<'a>(&'a self) -> impl Iterator<Item = (Seqnum, Uid)> + 'a {
        let seqnum_index = self
            .seqnum_index
            .as_ref()
            .expect("messages called on passive store");
        seqnum_index.extant_uids[..seqnum_index.valid_size]
            .iter()
            .cloned()
            .enumerate()
            .map(|(ix, uid)| {
                (Seqnum::of(ix as u32 + 1).unwrap(), Uid::of(uid).unwrap())
            })
    }

    /// If active and not read-only, save the current sequence number index.
    pub fn save_seqnum_index(&self, tmp: &Path) -> Result<(), Error> {
        if self.read_only {
            return Ok(());
        }

        let seqnum_index = match self.seqnum_index.as_ref() {
            None => return Ok(()),
            Some(i) => i,
        };

        seqnum_index.save(tmp, &self.root.join("seqnum"))?;
        Ok(())
    }

    /// Update active mode state.
    ///
    /// If this store was passive, it immediately becomes active.
    ///
    /// If there have been any changes to the active state, they are processed
    /// now and applied, altering the sequence number mapping.
    ///
    /// On success, an `ActiveStatus` is returned which holds the information
    /// (i.e., for `EXISTS` and `EXPUNGE` responses) which should be passed on
    /// to the client. On failure, the sequence number mapping is unchanged,
    /// but the store will remain in active status.
    pub fn poll_active_status(&mut self) -> Result<ActiveStatus, Error> {
        if self.seqnum_index.is_none() {
            let path = self.root.join("seqnum");
            self.seqnum_index = Some(match SeqnumIndex::load(&path) {
                Ok(index) => index,
                Err(e) if io::ErrorKind::NotFound == e.kind() => {
                    SeqnumIndex::new()
                }
                Err(e) => {
                    warn!(
                        "{} Failed to load {}, starting from scratch: {}",
                        self.log_prefix,
                        path.display(),
                        e
                    );
                    SeqnumIndex::new()
                }
            });
        }

        macro_rules! seqnum_index {
            () => {
                self.seqnum_index.as_mut().unwrap()
            };
        };
        if self.notifications.expunge_log_updated.swap(false, SeqCst) {
            // Something may have changed in expunge-log; read the portion we
            // haven't seen yet.
            match fs::File::open(self.root.join("expunge-log")) {
                Ok(mut f) => {
                    f.seek(io::SeekFrom::Start(
                        seqnum_index!().expunge_log_offset,
                    ))?;
                    let f = io::BufReader::new(f);
                    self.read_expunge_log_events(f)?;
                }

                Err(e) if io::ErrorKind::NotFound == e.kind() => {
                    // Only complain if we've read something out of it before
                    if seqnum_index!().expunge_log_offset != 0 {
                        error!("{} expunge-log has vanished!", self.log_prefix);
                        // Hope it shows up again later and start reading from the
                        // beginning
                        seqnum_index!().expunge_log_offset = 0;
                        seqnum_index!().file_changed = true;
                    }
                }

                Err(e) => {
                    error!(
                        "{} Unable to open expunge-log: {}",
                        self.log_prefix, e
                    );
                    return Err(e.into());
                }
            }
        }

        if self.notifications.youve_got_mail.swap(false, SeqCst) {
            // Linearly probe for new UIDs.
            //
            // It might be tempting to set a limit here and if we hit it, set
            // `youve_got_mail` to true, so that this poll completes quickly
            // and the next poll continues it. However, that is unsound, since
            // an earlier session may have already returned UIDs we haven't
            // discovered yet, so we must always find all of them on the first
            // go.
            let mut uid = seqnum_index!()
                .last_known_uid
                .map(|u| u.0.get())
                .unwrap_or(0);
            while uid != u32::MAX {
                uid += 1;
                let uid = Uid::of(uid).unwrap();
                match classify_message_file(self.path_for_uid(uid)) {
                    MessageFileClassification::Message => {
                        seqnum_index!().exists(uid)
                    }
                    MessageFileClassification::Gravestone => {
                        seqnum_index!().expunged(uid)
                    }
                    MessageFileClassification::Unknown => break,
                }
            }
        }

        self.configure_watcher();

        let seqnum_index = seqnum_index!();
        let has_new = seqnum_index.has_new;
        let mut expunged_seqnums = seqnum_index
            .expunged_uids
            .iter()
            .copied()
            .filter_map(|uid| {
                Uid::of(uid).and_then(|u| seqnum_index.uid_to_seqnum(u))
            })
            .collect::<Vec<_>>();
        expunged_seqnums.sort_by_key(|&v| std::cmp::Reverse(v));
        expunged_seqnums.dedup();

        seqnum_index.apply_changes();

        Ok(ActiveStatus {
            exist: if has_new {
                Some(seqnum_index.extant_uids.len())
            } else {
                None
            },
            expunged: expunged_seqnums,
        })
    }

    fn read_expunge_log_events(
        &mut self,
        mut f: impl Read,
    ) -> Result<(), Error> {
        loop {
            let uid = match f.read_u32::<LittleEndian>() {
                Ok(u) => u,
                Err(e) if io::ErrorKind::UnexpectedEof == e.kind() => break,
                Err(e) => return Err(e.into()),
            };

            self.seqnum_index.as_mut().unwrap().expunge_log_offset += 4;

            if let Some(uid) = Uid::of(uid) {
                self.handle_expunge_log_event(uid)?;
            }
        }

        Ok(())
    }

    fn handle_expunge_log_event(&mut self, uid: Uid) -> Result<(), Error> {
        // Ensure it has been fully expunged; if not, take care of that now,
        // also repairing the file if it's missing entirely.
        let actually_expunged: bool;
        let path = self.path_for_uid(uid);
        if MessageFileClassification::Gravestone != classify_message_file(&path)
        {
            if self.read_only {
                // Read only, can't repair
                actually_expunged = false;
            } else {
                warn!(
                    "{} Repairing incomplete expunge of {}",
                    self.log_prefix,
                    uid.0.get()
                );
                if let Err(e) = self.expunge_internal(
                    uid, path,
                    // Make sure not to write to expunge-log so we don't get
                    // stuck in an infinite loop if this fails.
                    false,
                ) {
                    error!(
                        "{} Repair of incomplete expunge of {} failed: {}",
                        self.log_prefix,
                        uid.0.get(),
                        e
                    );
                    actually_expunged = false;
                } else {
                    actually_expunged = true;
                }
            }
        } else {
            actually_expunged = true;
        }

        if actually_expunged {
            // That done, we can safely mark it as expunged in our own data
            // structures.
            self.seqnum_index.as_mut().unwrap().expunged(uid);
        }

        Ok(())
    }

    fn configure_watcher(&mut self) {
        if self.watcher.is_none() && !self.watcher_failed {
            let watcher = match self.create_watcher() {
                Ok(w) => w,
                Err(e) => {
                    error!(
                        "{} Error setting up watcher, will poll instead: {}",
                        self.log_prefix, e
                    );
                    self.watcher_failed = true;
                    return;
                }
            };
            self.watcher = Some(watcher);
        }

        // Ensure we're watching for new files in the directory that will
        // receive the next UID
        let mut create_path = self.path_for_uid(self.next_uid());
        if Some(create_path.parent().unwrap())
            != self.watched_message_path.as_ref().map(|p| &**p)
        {
            let _ = self.ensure_message_dirs_exist(&create_path);
            create_path.pop();

            {
                let watcher = match self.watcher.as_mut() {
                    None => {
                        // Ensure the next poll cycle checks what it needs to
                        self.notifications.set_all();
                        return;
                    }
                    Some(w) => w,
                };

                if let Some(old_path) = self.watched_message_path.take() {
                    let _ = watcher.unwatch(old_path);
                }

                match watcher
                    .watch(&create_path, notify::RecursiveMode::NonRecursive)
                {
                    Ok(_) => self.watched_message_path = Some(create_path),
                    Err(e) => {
                        warn!(
                            "{} Failed to watch {}: {}",
                            self.log_prefix,
                            create_path.display(),
                            e
                        );
                        // Next poll cycle will try again, and there will be
                        // one shortly since we set the new mail flag
                    }
                }
            }

            // Since we changed the location we're watching for new messages,
            // it's possible we missed something in the new location since
            // probing, so ensure the next poll cycle happens soon
            self.notifications.set_youve_got_mail();
        }
    }

    fn create_watcher(
        &mut self,
    ) -> Result<notify::RecommendedWatcher, notify::Error> {
        let notifications = Arc::clone(&self.notifications);
        let log_prefix = self.log_prefix.clone();

        let mut watcher = notify::immediate_watcher(
            move |evt: notify::Result<notify::Event>| match evt {
                Ok(evt) if is_useful_event(&evt) => {
                    notifications.see_path_event(evt.paths.get(0))
                }
                Ok(_) => (),
                Err(e) => {
                    warn!("{} Watcher error: {}", log_prefix, e);
                    notifications.set_all();
                }
            },
        )?;

        watcher.configure(notify::Config::PreciseEvents(true))?;

        // Do our best to ensure that expunge-log already exists
        if !self.read_only {
            let _ = self.expunge_log_appender();
        }
        watcher.watch(
            self.root.join("expunge-log"),
            notify::RecursiveMode::NonRecursive,
        )?;

        Ok(watcher)
    }

    /// Returns the path that does or would hold the given UID.
    pub fn path_for_uid(&self, uid: Uid) -> PathBuf {
        self.root.join(path_for_uid(uid))
    }

    fn ensure_message_dirs_exist(&self, uid_path: &Path) -> io::Result<()> {
        match fs::DirBuilder::new()
            .recursive(true)
            .mode(0o770)
            .create(uid_path.parent().expect("UID path missing parent"))
        {
            Ok(_) => Ok(()),
            Err(e) if io::ErrorKind::AlreadyExists == e.kind() => Ok(()),
            Err(e) => {
                error!(
                    "{} Cannot create dir hierarchy for {}: {}",
                    self.log_prefix,
                    uid_path.display(),
                    e
                );
                Err(e.into())
            }
        }
    }

    fn probable_last_uid(&self) -> Uid {
        if let &Some(ref seqnum_index) = &self.seqnum_index {
            seqnum_index.last_known_uid.unwrap_or(Uid::of(1).unwrap())
        } else {
            Uid::of(
                fs::File::open(self.root.join("seqnum"))
                    .and_then(|mut f| {
                        let mut buf = [0u8; 5];
                        f.read_exact(&mut buf)?;
                        if 0 != buf[0] {
                            // Unknown version, just start from 1
                            Ok(1)
                        } else {
                            Ok(LittleEndian::read_u32(&buf[1..]))
                        }
                    })
                    .unwrap_or(1),
            )
            .unwrap_or(Uid::of(1).unwrap())
        }
    }

    fn is_uid_allocated(&self, uid: Uid) -> bool {
        fs::symlink_metadata(self.path_for_uid(uid)).is_ok()
    }

    fn expunge_log_appender(&mut self) -> io::Result<&mut fs::File> {
        if self.expunge_log_appender.is_some() {
            Ok(self.expunge_log_appender.as_mut().unwrap())
        } else {
            let l = fs::OpenOptions::new()
                .write(true)
                .append(true)
                .create(true)
                .mode(0o600)
                .open(self.root.join("expunge-log"))?;
            self.expunge_log_appender = Some(l);
            Ok(self.expunge_log_appender.as_mut().unwrap())
        }
    }
}

impl Notifications {
    fn see_path_event(&self, path: Option<&PathBuf>) {
        if Some(OsStr::new("expunge-log")) == path.and_then(|p| p.file_name()) {
            self.set_expunge_log_updated();
        } else {
            self.set_youve_got_mail();
        }
    }

    fn set_all(&self) {
        self.expunge_log_updated.store(true, SeqCst);
        self.youve_got_mail.store(true, SeqCst);
        self.notify();
    }

    fn set_expunge_log_updated(&self) {
        self.expunge_log_updated.store(true, SeqCst);
        self.notify();
    }

    fn set_youve_got_mail(&self) {
        self.youve_got_mail.store(true, SeqCst);
        self.notify();
    }

    fn notify(&self) {
        (self.notify)()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveStatus {
    /// If present, new messages have been added since the last activity poll,
    /// and this value indicates how many exist now.
    pub exist: Option<usize>,
    /// The sequence numbers of any messages that have been expunged since the
    /// last activity poll, sorted descending and deduplicated.
    ///
    /// By the time the `ActiveStatus` is constructed, these sequence numbers
    /// are no longer valid.
    pub expunged: Vec<Seqnum>,
}

/// Tracks the UID to sequence number mapping.
///
/// Changes to the set of existing messages are buffered inside this struct but
/// do not affect the mapping until `apply_changes()` is called. This allows
/// such changes to be stored here as soon as they are discovered, leaving the
/// IMAP protocol flow free to decide when they get applied.
///
/// Since buffered changes can only be applied all at once, care must be taken
/// about `EXPUNGE` notifications: they must be sent in *descending* order so
/// that each notification doesn't perturb the sequence number mapping of the
/// next.
#[derive(Debug, PartialEq)]
struct SeqnumIndex {
    /// The last known UID value.
    ///
    /// Unlike the sequence number mapping, this is updated as soon as an
    /// extant UID greater than the current value is seen.
    last_known_uid: Option<Uid>,
    /// The first offset in `expunge-log` which has not yet been processed.
    expunge_log_offset: u64,
    /// UIDs currently considered to exist.
    ///
    /// Sorted ascending unless `!has_new`.
    ///
    /// Exists and expunge operations are performed lazily. New UIDs are simply
    /// added to the end of the vec and `has_new` is set to true to reflect
    /// that it is not sorted. Expunged UIDs are added to `expunged_uids` and
    /// removed later in a single pass.
    extant_uids: Vec<u32>,
    /// UIDs to mark expunged but which have not yet been removed from
    /// `extant_uids`.
    expunged_uids: Vec<u32>,
    /// Whether any changes have been made to the index since it was created.
    file_changed: bool,
    /// Whether `extant_uids` has received additional messages and so is
    /// possibly out of order.
    has_new: bool,
    /// The length of the valid portion of `extant_uids`.
    valid_size: usize,
}

impl SeqnumIndex {
    /// Create a new, empty index
    fn new() -> Self {
        SeqnumIndex {
            last_known_uid: None,
            expunge_log_offset: 0,
            extant_uids: Vec::new(),
            expunged_uids: Vec::new(),
            file_changed: false,
            has_new: false,
            valid_size: 0,
        }
    }

    /// Read the index out of the given file.
    fn load(from: impl AsRef<Path>) -> io::Result<Self> {
        let mut reader = io::BufReader::new(fs::File::open(from)?);
        if 0 != reader.read_u8()? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unsupported version",
            ));
        }

        let last_known_uid = Uid::of(reader.read_u32::<LittleEndian>()?);
        let expunge_log_offset = reader.read_u64::<LittleEndian>()?;
        let mut uids = Vec::new();
        loop {
            match reader.read_u32::<LittleEndian>() {
                Ok(uid) => {
                    if uid > 0 {
                        uids.push(uid);
                    }
                }
                Err(e) if io::ErrorKind::UnexpectedEof == e.kind() => break,
                Err(e) => return Err(e),
            }
        }

        let mut index = SeqnumIndex {
            last_known_uid,
            expunge_log_offset,
            extant_uids: uids,
            expunged_uids: Vec::new(),
            file_changed: false,
            has_new: true,
            valid_size: 0,
        };
        index.apply_changes();
        Ok(index)
    }

    /// Write this index to the given file, staging it inside `tmp`.
    ///
    /// Panics if not in a consistent state (call `apply_changes()` first).
    fn save(
        &self,
        tmp: impl AsRef<Path>,
        to: impl AsRef<Path>,
    ) -> io::Result<()> {
        assert!(!self.has_new && self.expunged_uids.is_empty());

        let mut tmp = tempfile::NamedTempFile::new_in(tmp)?;
        {
            let mut writer = io::BufWriter::new(&mut tmp);
            writer.write_u8(0)?;
            writer.write_u32::<LittleEndian>(
                self.last_known_uid.map(|u| u.0.get()).unwrap_or(0),
            )?;
            writer.write_u64::<LittleEndian>(self.expunge_log_offset)?;

            for &uid in &self.extant_uids {
                writer.write_u32::<LittleEndian>(uid)?;
            }

            writer.flush()?;
        }

        file_ops::chmod(tmp.path(), 0o440)?;
        tmp.as_file_mut().sync_all()?;
        tmp.persist(to)?;
        Ok(())
    }

    /// Translate the given UID to a sequence number according to the current
    /// translation state.
    fn uid_to_seqnum(&self, uid: Uid) -> Option<Seqnum> {
        self.extant_uids[..self.valid_size]
            .binary_search(&uid.0.get())
            .ok()
            .and_then(|sn| Seqnum::of(sn as u32 + 1))
    }

    /// Translate the given sequence number to a UID according to the current
    /// translation state.
    fn seqnum_to_uid(&self, seqnum: Seqnum) -> Option<Uid> {
        self.extant_uids[..self.valid_size]
            .get(seqnum.0.get() as usize - 1)
            .copied()
            .and_then(Uid::of)
    }

    /// Record that the given UID now exists.
    ///
    /// This does not need to be called in order when multiple UIDs are
    /// discovered at the same time, and is safe to call multiple times for the
    /// same UID, including a UID already in the mapping.
    ///
    /// This does not affect the mapping until `apply_changes()` is called.
    ///
    /// `last_known_uid` is immediately updated to include this UID.
    fn exists(&mut self, uid: Uid) {
        self.file_changed = true;
        self.see_uid(uid);
        self.extant_uids.push(uid.0.get());
        self.has_new = true;
    }

    /// Record that the given UID has been expunged.
    ///
    /// This does not need to be called in order when multiple UIDs are
    /// expunged at the same time, and is safe to call multiple times for the
    /// same UID, including a UID not in the mapping.
    ///
    /// This does not affect the mapping until `apply_changes()` is called.
    ///
    /// `last_known_uid` is immediately updated to include this UID.
    fn expunged(&mut self, uid: Uid) {
        self.file_changed = true;
        self.see_uid(uid);
        self.expunged_uids.push(uid.0.get());
    }

    fn see_uid(&mut self, uid: Uid) {
        match self.last_known_uid {
            None => self.last_known_uid = Some(uid),
            Some(v) if v < uid => self.last_known_uid = Some(uid),
            _ => (),
        }
    }

    /// Apply all pending changes to the mapping state.
    fn apply_changes(&mut self) {
        self.ensure_sorted();
        self.flush_expunged();
        self.valid_size = self.extant_uids.len();
    }

    fn flush_expunged(&mut self) {
        if !self.expunged_uids.is_empty() {
            self.ensure_sorted();
            self.expunged_uids.sort_unstable();
            let mut expunged = self.expunged_uids.drain(..).peekable();
            self.extant_uids.retain(|&uid| loop {
                let next_expunged =
                    expunged.peek().copied().unwrap_or(u32::MAX);
                if next_expunged < uid {
                    expunged.next();
                } else {
                    return next_expunged > uid;
                }
            });
        }
    }

    fn ensure_sorted(&mut self) {
        if self.has_new {
            self.has_new = false;
            self.extant_uids.sort_unstable();
            self.extant_uids.dedup();
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageFileClassification {
    Message,
    Gravestone,
    Unknown,
}

fn classify_message_file(path: impl AsRef<Path>) -> MessageFileClassification {
    match fs::symlink_metadata(path) {
        Ok(md) if md.file_type().is_file() => {
            MessageFileClassification::Message
        }
        Ok(md) if md.file_type().is_symlink() => {
            MessageFileClassification::Gravestone
        }
        _ => MessageFileClassification::Unknown,
    }
}

fn path_for_uid(uid: Uid) -> PathBuf {
    let uid = uid.0.get();
    let mut buf = PathBuf::new();
    let first_octet: u32;

    if uid < 1 << 8 {
        buf.push("z0");
        first_octet = 3;
    } else if uid < 1 << 16 {
        buf.push("z1");
        first_octet = 2;
    } else if uid < 1 << 24 {
        buf.push("z2");
        first_octet = 1;
    } else {
        buf.push("z3");
        first_octet = 0;
    }

    for octet in first_octet..3 {
        buf.push(format!("{:02x}", (uid >> (8 * (3 - octet))) & 0xFF));
    }
    buf.push(format!("{:02x}.eml", uid & 0xFF));
    buf
}

/// Search for the first free UID.
///
/// `guess` is a UID which is believed to be the last allocated UID, or 1 if no
/// UIDs are allocated. The algorithm produces the same result regardless of
/// the value of `guess`, but it is most efficient when it is correct.
///
/// `exists` tests whether the UID is currently allocated. It does not need to
/// return consistent results, though the algorithm assumes it at least has the
/// monotonic properties of IMAP UIDs.
///
/// The returned UID is a suggested starting point for linear probing. In the
/// presence of concurrent modification to the UID allocations, it may well
/// already be allocated.
fn probe_for_first_uid(guess: Uid, exists: impl Fn(Uid) -> bool) -> Uid {
    let mut maximum_used = 0u32;
    let mut minimum_free = u32::MAX;

    // Exponentially probe to find a better "free" endpoint than u32::MAX and
    // do discover more allocated UIDs along the way
    let mut exp_probe = 1u32;
    while exp_probe != 0 {
        let probe = guess.0.get().saturating_add(exp_probe);
        if u32::MAX == probe {
            // Further probing is useless since we've hit the end of the UID space
            break;
        }

        exp_probe <<= 1;

        if exists(Uid::of(probe).unwrap()) {
            maximum_used = probe;
        } else {
            minimum_free = probe;
            break;
        }
    }

    // If probing didn't find any used slots, see if the guess was exactly
    // right
    if 0 == maximum_used && exists(guess) {
        maximum_used = guess.0.get();
    }

    // Binary search until we find the UID frontier
    while maximum_used < minimum_free - 1 {
        let mid = ((maximum_used as u64 + minimum_free as u64) / 2) as u32;
        if exists(Uid::of(mid).unwrap()) {
            maximum_used = mid;
        } else {
            minimum_free = mid;
        }
    }

    // Suggest starting one beyond the maximum existing UID found to be more
    // conservative in the presence of concurrent modification
    Uid::of(maximum_used.saturating_add(1)).unwrap()
}

fn is_useful_event(evt: &notify::Event) -> bool {
    match &evt.kind {
        &notify::event::EventKind::Create(_)
        | &notify::event::EventKind::Modify(_) => true,
        _ => false,
    }
}

#[cfg(test)]
mod test {
    use std::sync::{Condvar, Mutex};

    use proptest::prelude::*;
    use tempfile::TempDir;

    use super::*;
    use crate::crypt::master_key::MasterKey;
    use crate::userbox::key_store::KeyStoreConfig;

    #[test]
    fn test_path_for_uid() {
        assert_eq!(
            ["z0", "01.eml"].iter().collect::<PathBuf>(),
            path_for_uid(Uid::u(1))
        );
        assert_eq!(
            ["z0", "ff.eml"].iter().collect::<PathBuf>(),
            path_for_uid(Uid::u(255))
        );
        assert_eq!(
            ["z1", "30", "39.eml"].iter().collect::<PathBuf>(),
            path_for_uid(Uid::u(12345))
        );
        assert_eq!(
            ["z2", "01", "e2", "40.eml"].iter().collect::<PathBuf>(),
            path_for_uid(Uid::u(123456))
        );
        assert_eq!(
            ["z3", "01", "00", "00", "00.eml"]
                .iter()
                .collect::<PathBuf>(),
            path_for_uid(Uid::u(16777216))
        );
        assert_eq!(
            ["z3", "ff", "ff", "ff", "ff.eml"]
                .iter()
                .collect::<PathBuf>(),
            path_for_uid(Uid::u(4294967295))
        );
    }

    #[test]
    fn seqnum_index_operations() {
        let mut index = SeqnumIndex::new();
        assert_eq!(None, index.last_known_uid);

        index.exists(Uid::u(1));
        index.exists(Uid::u(3));
        index.exists(Uid::u(5));
        index.apply_changes();
        assert_eq!(Some(Uid::u(5)), index.last_known_uid);

        assert_eq!(Some(Seqnum::u(1)), index.uid_to_seqnum(Uid::u(1)));
        assert_eq!(Some(Seqnum::u(2)), index.uid_to_seqnum(Uid::u(3)));
        assert_eq!(Some(Seqnum::u(3)), index.uid_to_seqnum(Uid::u(5)));
        assert_eq!(None, index.uid_to_seqnum(Uid::u(2)));
        assert_eq!(None, index.uid_to_seqnum(Uid::u(6)));

        assert_eq!(Some(Uid::u(1)), index.seqnum_to_uid(Seqnum::u(1)));
        assert_eq!(Some(Uid::u(3)), index.seqnum_to_uid(Seqnum::u(2)));
        assert_eq!(Some(Uid::u(5)), index.seqnum_to_uid(Seqnum::u(3)));
        assert_eq!(None, index.seqnum_to_uid(Seqnum::u(4)));

        assert_eq!(3, index.valid_size);

        index.exists(Uid::u(6));
        index.exists(Uid::u(7));
        assert_eq!(3, index.valid_size);
        assert_eq!(Some(Uid::u(7)), index.last_known_uid);
        index.expunged(Uid::u(3));
        assert_eq!(3, index.valid_size);

        assert_eq!(Some(Seqnum::u(1)), index.uid_to_seqnum(Uid::u(1)));
        assert_eq!(Some(Seqnum::u(2)), index.uid_to_seqnum(Uid::u(3)));
        assert_eq!(Some(Seqnum::u(3)), index.uid_to_seqnum(Uid::u(5)));
        assert_eq!(None, index.uid_to_seqnum(Uid::u(2)));
        assert_eq!(None, index.uid_to_seqnum(Uid::u(6)));

        assert_eq!(Some(Uid::u(1)), index.seqnum_to_uid(Seqnum::u(1)));
        assert_eq!(Some(Uid::u(3)), index.seqnum_to_uid(Seqnum::u(2)));
        assert_eq!(Some(Uid::u(5)), index.seqnum_to_uid(Seqnum::u(3)));
        assert_eq!(None, index.seqnum_to_uid(Seqnum::u(4)));

        index.apply_changes();

        assert_eq!(4, index.valid_size);

        assert_eq!(Some(Seqnum::u(1)), index.uid_to_seqnum(Uid::u(1)));
        assert_eq!(None, index.uid_to_seqnum(Uid::u(3)));
        assert_eq!(Some(Seqnum::u(2)), index.uid_to_seqnum(Uid::u(5)));
        assert_eq!(Some(Seqnum::u(3)), index.uid_to_seqnum(Uid::u(6)));
        assert_eq!(Some(Seqnum::u(4)), index.uid_to_seqnum(Uid::u(7)));
        assert_eq!(None, index.uid_to_seqnum(Uid::u(8)));

        assert_eq!(Some(Uid::u(1)), index.seqnum_to_uid(Seqnum::u(1)));
        assert_eq!(Some(Uid::u(5)), index.seqnum_to_uid(Seqnum::u(2)));
        assert_eq!(Some(Uid::u(6)), index.seqnum_to_uid(Seqnum::u(3)));
        assert_eq!(Some(Uid::u(7)), index.seqnum_to_uid(Seqnum::u(4)));
        assert_eq!(None, index.seqnum_to_uid(Seqnum::u(5)));
    }

    #[test]
    fn seqnum_index_bulk_expunge() {
        let mut index = SeqnumIndex::new();
        for i in 1..=20 {
            index.exists(Uid::u(i));
        }
        index.apply_changes();

        index.expunged(Uid::u(10));
        index.expunged(Uid::u(12));
        index.expunged(Uid::u(15));
        index.expunged(Uid::u(11));
        index.expunged(Uid::u(11));
        index.expunged(Uid::u(13));
        index.expunged(Uid::u(14));
        index.apply_changes();

        assert_eq!(14, index.valid_size);
        for i in 1..=20 {
            if i < 10 {
                assert_eq!(Some(Seqnum::u(i)), index.uid_to_seqnum(Uid::u(i)));
                assert_eq!(Some(Uid::u(i)), index.seqnum_to_uid(Seqnum::u(i)));
            } else if i < 16 {
                assert_eq!(None, index.uid_to_seqnum(Uid::u(i)));
            } else {
                assert_eq!(
                    Some(Seqnum::u(i - 6)),
                    index.uid_to_seqnum(Uid::u(i))
                );
                assert_eq!(
                    Some(Uid::u(i)),
                    index.seqnum_to_uid(Seqnum::u(i - 6))
                );
            }
        }
    }

    #[test]
    fn seqnum_save_load() {
        let mut orig = SeqnumIndex::new();
        orig.exists(Uid::u(1));
        orig.exists(Uid::u(3));
        orig.exists(Uid::u(5));
        orig.apply_changes();
        assert!(orig.file_changed);

        let td = tempfile::tempdir().unwrap();
        let persist_path = td.path().join("saved");
        orig.save(td.path(), &persist_path).unwrap();

        let mut loaded = SeqnumIndex::load(&persist_path).unwrap();
        // Set file_changed for equality comparison
        loaded.file_changed = true;
        assert_eq!(orig, loaded);
    }

    fn test_probe_for_first_uid(guess: u32, last_used: u32) -> u32 {
        probe_for_first_uid(Uid::u(guess), |u| u.0.get() <= last_used)
            .0
            .get()
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 65536,
            ..ProptestConfig::default()
        })]
        #[test]
        fn uid_probing_fuzz(guess in 1u32.., last_used in 0u32..) {
            prop_assert_eq!(last_used.saturating_add(1),
                            test_probe_for_first_uid(guess, last_used));
        }
    }

    #[test]
    fn uid_probing_special_cases() {
        assert_eq!(1, test_probe_for_first_uid(1, 0));
        assert_eq!(2, test_probe_for_first_uid(1, 1));
        assert_eq!(3, test_probe_for_first_uid(1, 2));
        assert_eq!(1001, test_probe_for_first_uid(1000, 1000));
        assert_eq!(1002, test_probe_for_first_uid(1000, 1001));
        assert_eq!(1011, test_probe_for_first_uid(1000, 1010));
        assert_eq!(u32::MAX, test_probe_for_first_uid(1, u32::MAX));
    }

    struct Setup {
        root: TempDir,
        authed_key_store: KeyStore,
        anon_key_store: KeyStore,
        passive_store: MessageStore,
        active_store: MessageStore,
        cond: Arc<Condvar>,
        mutex: Arc<Mutex<()>>,
    }

    fn set_up() -> Setup {
        let root = TempDir::new().unwrap();
        let key_store_root = root.path().join("key");
        let message_store_root = root.path().join("msg");
        let tmp = root.path().join("tmp");
        fs::create_dir(&tmp).unwrap();
        fs::create_dir(&message_store_root).unwrap();

        let cond = Arc::new(Condvar::new());
        let mutex = Arc::new(Mutex::<()>::new(()));

        let master_key = Arc::new(MasterKey::new());
        let mut authed_key_store = KeyStore::new(
            "authed-key".to_owned(),
            key_store_root.clone(),
            tmp.clone(),
            Some(Arc::clone(&master_key)),
        );
        authed_key_store.set_rsa_bits(1024);
        authed_key_store.init(&KeyStoreConfig::default()).unwrap();

        let anon_key_store = KeyStore::new(
            "anon-key".to_owned(),
            key_store_root.clone(),
            tmp.clone(),
            None,
        );

        let passive_store = MessageStore::new(
            "passive-store".to_owned(),
            message_store_root.clone(),
            tmp.clone(),
            false,
            || (),
        );

        let cond2 = Arc::clone(&cond);
        let mutex2 = Arc::clone(&mutex);
        let active_store = MessageStore::new(
            "active-store".to_owned(),
            message_store_root.clone(),
            tmp.clone(),
            false,
            move || {
                let _lock = mutex2.lock().unwrap();
                cond2.notify_all();
            },
        );

        Setup {
            root,
            authed_key_store,
            anon_key_store,
            passive_store,
            active_store,
            cond,
            mutex,
        }
    }

    impl Setup {
        fn expect_notificaion_soon(&mut self) -> ActiveStatus {
            let _ = self
                .cond
                .wait_timeout_while(
                    self.mutex.lock().unwrap(),
                    std::time::Duration::new(10, 0),
                    |_| !self.active_store.has_pending_notifications(),
                )
                .unwrap();
            self.active_store.poll_active_status().unwrap()
        }
    }

    #[test]
    fn write_and_read_messages() {
        let mut setup = set_up();

        assert_eq!(
            Uid::u(1),
            setup
                .passive_store
                .deliver_message(
                    &mut setup.anon_key_store,
                    &mut "hello world".as_bytes()
                )
                .unwrap()
        );
        assert_eq!(
            Uid::u(2),
            setup
                .passive_store
                .deliver_message(
                    &mut setup.authed_key_store,
                    &mut "crymap".as_bytes()
                )
                .unwrap()
        );

        let mut string = String::new();
        let (len, mut r) = setup
            .passive_store
            .read_message(&mut setup.authed_key_store, Uid::u(1))
            .unwrap();
        assert_eq!(11, len);
        r.read_to_string(&mut string).unwrap();
        assert_eq!("hello world", string);

        string.clear();
        let (len, mut r) = setup
            .passive_store
            .read_message(&mut setup.authed_key_store, Uid::u(2))
            .unwrap();
        assert_eq!(6, len);
        r.read_to_string(&mut string).unwrap();
        assert_eq!("crymap", string);
    }

    #[test]
    fn passive_expungement() {
        let mut setup = set_up();

        assert_eq!(
            Uid::u(1),
            setup
                .passive_store
                .deliver_message(
                    &mut setup.anon_key_store,
                    &mut "hello world".as_bytes(),
                )
                .unwrap()
        );
        setup.passive_store.expunge(Uid::u(1), false).unwrap();
        // Another call has no effect
        setup.passive_store.expunge(Uid::u(1), false).unwrap();

        // Trying to read it returns the right error
        assert!(matches!(
            setup
                .passive_store
                .read_message(&mut setup.authed_key_store, Uid::u(1)),
            Err(Error::ExpungedMessage)
        ));

        // A new message is delivered after the expunged one
        assert_eq!(
            Uid::u(2),
            setup
                .passive_store
                .deliver_message(
                    &mut setup.authed_key_store,
                    &mut "crymap".as_bytes()
                )
                .unwrap()
        );
    }

    #[test]
    fn read_or_expunge_nx_message() {
        let mut setup = set_up();
        assert!(matches!(
            setup.passive_store.expunge(Uid::u(1), false),
            Err(Error::NxMessage)
        ));
        assert!(matches!(
            setup
                .passive_store
                .read_message(&mut setup.authed_key_store, Uid::u(1)),
            Err(Error::NxMessage)
        ));
    }

    #[test]
    fn active_mode_state_tracking() {
        let mut setup = set_up();

        assert_eq!(
            1,
            deliver_simple(
                &mut setup.active_store,
                &mut setup.authed_key_store
            )
        );

        let status = setup.active_store.poll_active_status().unwrap();
        assert_eq!(Some(1), status.exist);
        assert_eq!(0, status.expunged.len());

        let status = setup.active_store.poll_active_status().unwrap();
        assert_eq!(None, status.exist);
        assert_eq!(0, status.expunged.len());

        assert_eq!(
            2,
            deliver_simple(
                &mut setup.active_store,
                &mut setup.authed_key_store
            )
        );
        assert_eq!(
            3,
            deliver_simple(
                &mut setup.active_store,
                &mut setup.authed_key_store
            )
        );

        let status = setup.active_store.poll_active_status().unwrap();
        assert_eq!(Some(3), status.exist);
        assert_eq!(0, status.expunged.len());

        setup.active_store.expunge(Uid::u(2), false).unwrap();
        // Sequence number mapping isn't updated yet
        assert_eq!(3, setup.active_store.message_count());
        assert_eq!(
            Some(Seqnum::u(3)),
            setup.active_store.uid_to_seqnum(Uid::u(3))
        );
        assert_eq!(
            Some(Uid::u(3)),
            setup.active_store.seqnum_to_uid(Seqnum::u(3))
        );

        let status = setup.active_store.poll_active_status().unwrap();
        assert_eq!(None, status.exist);
        assert_eq!(vec![Seqnum::u(2)], status.expunged);

        assert_eq!(2, setup.active_store.message_count());
        assert_eq!(
            Some(Seqnum::u(2)),
            setup.active_store.uid_to_seqnum(Uid::u(3))
        );
        assert_eq!(
            Some(Uid::u(3)),
            setup.active_store.seqnum_to_uid(Seqnum::u(2))
        );

        let status = setup.active_store.poll_active_status().unwrap();
        assert_eq!(None, status.exist);
        assert_eq!(0, status.expunged.len());
    }

    #[test]
    fn active_mode_async_notifications() {
        let mut setup = set_up();

        let status = setup.active_store.poll_active_status().unwrap();
        assert_eq!(None, status.exist);
        assert_eq!(0, status.expunged.len());

        for i in 0..1024 {
            // Clear any spurious notifications
            setup.active_store.poll_active_status().unwrap();

            assert_eq!(
                i + 1,
                deliver_simple(
                    &mut setup.passive_store,
                    &mut setup.anon_key_store
                )
            );
            let status = setup.expect_notificaion_soon();
            assert_eq!(Some(i as usize + 1), status.exist);
            assert_eq!(0, status.expunged.len());
        }

        for i in 0..1024 {
            // Clear any spurious notifications
            setup.active_store.poll_active_status().unwrap();

            setup.passive_store.expunge(Uid::u(i + 1), false).unwrap();
            let status = setup.expect_notificaion_soon();
            assert_eq!(None, status.exist);
            assert_eq!(vec![Seqnum::u(1)], status.expunged);
        }
    }

    #[test]
    fn insert_message_error_cases() {
        let mut setup = set_up();

        assert_eq!(
            1,
            deliver_simple(
                &mut setup.passive_store,
                &mut setup.authed_key_store
            )
        );
        assert_eq!(
            2,
            deliver_simple(
                &mut setup.passive_store,
                &mut setup.authed_key_store
            )
        );
        setup.passive_store.expunge(Uid::u(1), false).unwrap();

        assert!(matches!(
            setup
                .passive_store
                .insert_message(setup.passive_store.path_for_uid(Uid::u(1))),
            Err(Error::ExpungedMessage)
        ));
        assert!(matches!(
            setup
                .passive_store
                .insert_message(setup.passive_store.path_for_uid(Uid::u(3))),
            Err(Error::NxMessage)
        ));
    }

    fn deliver_simple(
        store: &mut MessageStore,
        key_store: &mut KeyStore,
    ) -> u32 {
        store
            .deliver_message(key_store, &mut "message".as_bytes())
            .unwrap()
            .0
            .get()
    }
}
