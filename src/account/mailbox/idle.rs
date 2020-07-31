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

//! Support for idling, i.e., blocking until the idle is cancelled or a change
//! is discovered. This is used for the IDLE extension, but the functionality
//! here does not alone implement it.
//!
//! Notifications are implemented by "one-shot" UNIX sockets. When a process
//! goes into idle, it binds a UNIX datagram socket named `$pid.$serno` in the
//! account's `tmp` directory and symlinks it from the mailbox's `socks`
//! directory. It then waits until a packet is received. The content of
//! transmitted data is irrelevant; it is used only as a wakeup. On wakeup, the
//! socket is unlinked if it is still there.
//!
//! Sockets are allocated in the `tmp` directory instead of directly under
//! `socks` since the path within the mailbox could easily exceed the maximum
//! length for a UNIX socket pathname on the host OS (e.g., on FreeBSD the
//! limit is 104 bytes; on Linux it is 108 bytes).
//!
//! To notify a listener, the notifier sends a single-byte message, ignores any
//! error, and then unlinks the socket and its symlink. This ensures that
//! sockets left behind by dead processes are cleaned up expediently.
//!
//! To avoid races, stateful idling needs to run by the below procedure:
//!
//! ```ignore
//! while idling {
//!   let listener = mailbox.stateless().prepare_idle()?;
//!   let poll = mailbox.poll()?;
//!   send_poll_results(poll);
//!   listener.idle()?;
//! }
//! ```

use std::fs;
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::Arc;

use log::warn;

use super::defs::*;
use crate::support::error::Error;
use crate::support::file_ops::IgnoreKinds;

static SOCKET_SERNO: AtomicUsize = AtomicUsize::new(0);

/// A handle on a socket that can be used to idle until a change notification
/// is received.
#[derive(Debug)]
pub struct IdleListener {
    sock: Arc<UnixDatagram>,
    sock_path: PathBuf,
    symlink_path: PathBuf,
}

impl IdleListener {
    /// Return an `IdleNotifier` that can be used to awaken this listener.
    pub fn notifier(&self) -> IdleNotifier {
        IdleNotifier {
            sock: Arc::clone(&self.sock),
        }
    }

    /// Block until a notification is received for this listener.
    pub fn idle(self) -> io::Result<()> {
        let mut buf = [0u8];
        // On Linux, recv() on after the notifier closed the socket returns
        // immediately with an empty read.
        // On FreeBSD, it fails with NotConnected.
        match self.sock.recv(&mut buf) {
            Ok(_) => Ok(()),
            Err(e) if io::ErrorKind::NotConnected == e.kind() => Ok(()),
            Err(e) => Err(e),
        }
    }

    #[cfg(test)]
    fn idle_instant(self) -> io::Result<()> {
        self.sock.set_nonblocking(true)?;
        self.idle()
    }
}

impl Drop for IdleListener {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.symlink_path);
        let _ = fs::remove_file(&self.sock_path);
    }
}

/// References a path that can be used to awaken a single `IdleListener`.
///
/// The notifier will work even if the Unix socket itself is removed from the
/// file system.
#[derive(Debug, Clone)]
pub struct IdleNotifier {
    sock: Arc<UnixDatagram>,
}

impl IdleNotifier {
    /// Wake up the corresponding `IdleListener`.
    pub fn notify(self) -> io::Result<()> {
        self.sock.shutdown(std::net::Shutdown::Both)
    }
}

impl StatelessMailbox {
    /// Prepare to idle.
    ///
    /// This ensures that the socks directory exists and binds the UNIX socket
    /// within it.
    pub fn prepare_idle(&self) -> Result<IdleListener, Error> {
        fs::DirBuilder::new()
            .mode(0o770)
            .create(&self.path.socks_path)
            .ignore_already_exists()?;

        let serno = SOCKET_SERNO.fetch_add(1, SeqCst);
        let sock_name = format!("{}.{}", nix::unistd::getpid(), serno);
        let symlink_path = self.path.socks_path.join(&sock_name);
        let sock_path = self.common_paths.tmp.join(&sock_name);

        // Remove any stray socket left over from a prior process that had the
        // same PID.
        let _ = fs::remove_file(&sock_path);
        let _ = fs::remove_file(&symlink_path);

        let listener = IdleListener {
            sock: Arc::new(UnixDatagram::bind(&sock_path)?),
            sock_path,
            symlink_path,
        };

        std::os::unix::fs::symlink(
            &listener.sock_path,
            &listener.symlink_path,
        )?;
        Ok(listener)
    }

    /// Wake all idlers up.
    pub(super) fn notify_all(&self) -> Result<(), Error> {
        let sock = UnixDatagram::unbound()?;

        let dirit = match fs::read_dir(&self.path.socks_path) {
            Ok(d) => d,
            // NotFound = socks directory doesn't exist; nobody's listening
            Err(e) if io::ErrorKind::NotFound == e.kind() => return Ok(()),
            Err(e) => return Err(e.into()),
        };

        for entry in dirit {
            let entry = entry?;

            let path = entry.path();
            if let Ok(destination) = path.canonicalize() {
                let _ = sock.send_to(&[0], &destination);
                let _ = fs::remove_file(&destination);
            }
            let _ = fs::remove_file(&path);
        }

        Ok(())
    }

    /// Wake all idlers up.
    ///
    /// If anything goes wrong, log and carry on.
    pub(super) fn notify_all_best_effort(&self) {
        if let Err(e) = self.notify_all() {
            warn!("{} Failed to send notifications: {}", self.log_prefix, e);
        }
    }
}

#[cfg(test)]
mod test {
    use std::io;

    use super::super::test_prelude::*;
    use crate::account::model::*;

    #[test]
    fn notify_nobody() {
        let setup = set_up();
        setup.stateless.notify_all().unwrap();
    }

    #[test]
    fn listener_would_block_without_notification() {
        let setup = set_up();
        match setup.stateless.prepare_idle().unwrap().idle_instant() {
            Err(e) if io::ErrorKind::WouldBlock == e.kind() => (),
            Err(e) => panic!("Unexpected error: {}", e),
            Ok(_) => panic!("Didn't block"),
        }
    }

    #[test]
    fn notify_self() {
        let setup = set_up();
        let listener = setup.stateless.prepare_idle().unwrap();
        listener.notifier().notify().unwrap();
        // We can't use idle_instant() here since putting the socket in
        // non-blocking mode causes it to still return WouldBlock even after it
        // has been shut down.
        listener.idle().unwrap();
    }

    #[test]
    fn notify_on_message_insert() {
        let setup = set_up();
        let listener = setup.stateless.prepare_idle().unwrap();
        simple_append(&setup.stateless);
        listener.idle_instant().unwrap();
    }

    #[test]
    fn notify_on_blind_flags_set() {
        let setup = set_up();
        let uid = simple_append(&setup.stateless);
        let listener = setup.stateless.prepare_idle().unwrap();
        setup
            .stateless
            .set_flags_blind(vec![(uid, vec![(true, Flag::Flagged)])])
            .unwrap();
        listener.idle_instant().unwrap();
    }

    #[test]
    fn notify_on_multi_message_insert() {
        let setup = set_up();

        let uid1 = simple_append(&setup.stateless);
        let uid2 = simple_append(&setup.stateless);

        let (mut mb1, _) = setup.stateless.clone().select().unwrap();
        let listener = setup.stateless.prepare_idle().unwrap();
        mb1.copy(
            &CopyRequest {
                ids: SeqRange::range(uid1, uid2),
            },
            &setup.stateless,
        )
        .unwrap();

        listener.idle_instant().unwrap();
    }

    #[test]
    fn notify_on_change_tx() {
        let setup = set_up();

        let uid = simple_append(&setup.stateless);

        let (mut mb1, _) = setup.stateless.clone().select().unwrap();
        let listener = setup.stateless.prepare_idle().unwrap();

        mb1.vanquish(&SeqRange::just(uid)).unwrap();

        listener.idle_instant().unwrap();
    }
}
