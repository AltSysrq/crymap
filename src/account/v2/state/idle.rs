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

//! Support for idling, i.e., blocking until the idle is cancelled or a change
//! is discovered. This is used for the IDLE extension, but the functionality
//! here does not alone implement it.
//!
//! Notifications are implemented by watching for modifications on the main
//! database files.
//!
//! To avoid races, stateful idling needs to run by the below procedure:
//!
//! ```ignore
//! while idling {
//!   let mut idle = account.prepare_idle()?;
//!   account.drain_deliveries();
//!   let poll = account.poll(&mut mailbox)?;
//!   send_poll_results(poll);
//!   account.idle(idle)?;
//! }
//! ```

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use super::defs::*;
use crate::support::error::Error;

impl Account {
    /// Prepares to idle.
    ///
    /// Any changes which occur after this call will cause the idle to wake up.
    /// Because there may be as-yet undetected changes from before this call,
    /// it must be followed by a `poll` to check for those updates after
    /// `prepare_idle` succeeds.
    pub fn prepare_idle(&self) -> Result<IdleListener, Error> {
        Ok(IdleListener {
            internal: Arc::new(Mutex::new(IdleInternal {
                metadb_mtime: self.metadb_mtime()?,
                deliverydb_mtime: self.deliverydb_mtime()?,
            })),
        })
    }

    /// Idles.
    ///
    /// This blocks until either a possible change has been detected, an error
    /// occurs, or something invokes `idle.notifier()`.
    pub fn idle(&self, idle: IdleListener) -> Result<(), Error> {
        // TODO Use something other than polling.
        //
        // This is pending a final decision on whether to make the entire
        // system single-threaded. The `notify` crate would be great if we
        // stick with synchronous code, but it doesn't have an async mode and
        // always creates an extra thread. What we need here is pretty
        // simplistic though, so manual implementations with inotify and kqueue
        // would be acceptable.
        //
        // For now, we want this to be as similar as possible to V1 idle to
        // simplify the transition.
        loop {
            {
                let idle = idle.internal.lock().unwrap();
                if self.metadb_mtime()? > idle.metadb_mtime
                    || self.deliverydb_mtime()? > idle.deliverydb_mtime
                {
                    return Ok(());
                }
            }

            std::thread::sleep(Duration::from_secs(1));
        }
    }

    fn metadb_mtime(&self) -> Result<SystemTime, Error> {
        Ok(self.metadb_path.metadata()?.modified()?)
    }

    fn deliverydb_mtime(&self) -> Result<SystemTime, Error> {
        Ok(self.deliverydb_path.metadata()?.modified()?)
    }
}

pub struct IdleListener {
    internal: Arc<Mutex<IdleInternal>>,
}

impl IdleListener {
    /// Creates an `IdleNotifier` which can be used to wake this `Idle` up.
    pub fn notifier(&self) -> IdleNotifier {
        IdleNotifier {
            internal: Arc::clone(&self.internal),
        }
    }
}

/// Handle which allows interrupting an `Idle` from within the process.
pub struct IdleNotifier {
    internal: Arc<Mutex<IdleInternal>>,
}

impl IdleNotifier {
    pub fn notify(self) -> Result<(), Error> {
        self.internal.lock().unwrap().metadb_mtime = SystemTime::UNIX_EPOCH;
        Ok(())
    }
}

struct IdleInternal {
    metadb_mtime: SystemTime,
    deliverydb_mtime: SystemTime,
}
