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
//!
//! ## About the layout of this module
//!
//! This module is collectively a single abstraction, i.e., it should be
//! thought of as one large rust file. It is simply split apart because it's
//! unwieldy otherwise.

// Basic struct definitions
mod defs;
pub use defs::{StatefulMailbox, StatelessMailbox};

// Internal support --- R/W of messages and state transactions
mod change_tx;
mod messages; // Also includes low-level APPEND-like operation

// IMAP commands
// Methods are not 1:1 in cases where the IMAP model does not naturally fit the
// architecture. E.g., SELECT, EXAMINE, and STATUS are all the same operation
// and do not include QRESYNC support, which is a separate operation. It is up
// to the IMAP protocol layer to decompose/recompose/reformat these
// discrepancies.
mod expunge; // EXPUNGE, UID EXPUNGE
mod flags; // STORE, UID STORE
mod poll; // NOOP, CHECK, during IDLE, after commands
mod select; // SELECT, EXAMINE, STATUS, also garbage collection

#[cfg(test)]
mod test_prelude {
    pub(super) use super::defs::*;

    use std::iter;
    use std::sync::{Arc, Mutex};

    use chrono::prelude::*;
    use tempfile::TempDir;

    use crate::account::key_store::{KeyStore, KeyStoreConfig};
    use crate::account::mailbox_path::MailboxPath;
    use crate::account::model::*;
    use crate::crypt::master_key::MasterKey;

    pub(super) struct Setup {
        pub root: TempDir,
        pub stateless: StatelessMailbox,
    }

    pub(super) fn set_up() -> Setup {
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

    pub(super) fn simple_append(dst: &StatelessMailbox) -> Uid {
        dst.append(Utc::now(), iter::empty(), &mut "foobar".as_bytes())
            .unwrap()
    }
}
