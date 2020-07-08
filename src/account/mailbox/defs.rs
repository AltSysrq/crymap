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

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{atomic::AtomicBool, Arc, Mutex};

use crate::account::hier_id_scheme::HierIdScheme;
use crate::account::key_store::KeyStore;
use crate::account::mailbox_path::*;
use crate::account::mailbox_state::*;
use crate::account::model::*;
use crate::support::error::Error;

/// A stateless view of a mailbox.
///
/// The stateless view is capable of inserting messages, performing
/// unconditional flag modifications, and reading messages by UID, but cannot
/// query flags or notice changes.
#[derive(Clone)]
pub struct StatelessMailbox {
    pub(super) log_prefix: String,
    pub(super) path: MailboxPath,
    pub(super) root: PathBuf,
    pub(super) read_only: bool,
    pub(super) key_store: Arc<Mutex<KeyStore>>,
    pub(super) common_paths: Arc<CommonPaths>,
}

/// A stateful view of a mailbox.
///
/// This has full capabilities of doing all mailbox-specific IMAP commands.
///
/// Stateful mailboxes cannot be opened with anonymous key stores.
#[derive(Clone)]
pub struct StatefulMailbox {
    pub(super) s: StatelessMailbox,
    pub(super) state: MailboxState,
    pub(super) recency_frontier: Option<Uid>,
    /// When the client tries to fetch an addressable UID that's been expunged,
    /// we add it to this set. If it is there already, we kill the client
    /// connection. The set gets cleared on a full poll cycle. See
    /// `FetchResponseKind` for more details.
    pub(super) fetch_loopbreaker: HashSet<Uid>,
    /// The flags which have already been sent to the client in `FLAGS`
    /// responses.
    pub(super) client_known_flags: Vec<Flag>,
    /// If non-zero, decrement at the end of the poll cycle. If it becomes
    /// zero, generate a new rollup file.
    pub(super) suggest_rollup: u32,
    pub(super) rollups_since_gc: u32,
    pub(super) gc_in_progress: Arc<AtomicBool>,
    /// Used by tests to force GCs to occur synchronously to keep the tests
    /// deterministic
    pub(super) synchronous_gc: bool,
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

    /// Return the log prefix used for messages regarding this mailbox.
    pub fn log_prefix(&self) -> &str {
        &self.log_prefix
    }

    /// Return whether this mailbox is opened read-only
    pub fn read_only(&self) -> bool {
        self.read_only
    }

    pub(super) fn message_scheme(&self) -> HierIdScheme<'_> {
        HierIdScheme {
            root: &self.root,
            prefix: b'u',
            extension: "eml",
        }
    }

    pub(super) fn change_scheme(&self) -> HierIdScheme<'_> {
        HierIdScheme {
            root: &self.root,
            prefix: b'c',
            extension: "tx",
        }
    }

    pub(super) fn not_read_only(&self) -> Result<(), Error> {
        if self.read_only {
            Err(Error::MailboxReadOnly)
        } else {
            Ok(())
        }
    }
}

impl StatefulMailbox {
    /// Return the stateless view of this mailbox.
    pub fn stateless(&self) -> &StatelessMailbox {
        &self.s
    }

    /// Return the maximum `Seqnum` of any message.
    pub fn max_seqnum(&self) -> Option<Seqnum> {
        self.state.max_seqnum()
    }

    /// Return the maximum UID of any message.
    pub fn max_uid(&self) -> Option<Uid> {
        self.state.max_uid()
    }
}

// Not a great place for these tests, but there's nowhere better right now.
#[cfg(test)]
mod test {
    use super::super::test_prelude::*;
    use super::*;

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
