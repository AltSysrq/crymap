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

use std::io;
use std::path::Path;
use std::time::{Duration, SystemTime};

use super::defs::*;
use crate::{account::model::*, support::error::Error};

impl Account {
    /// Idles.
    ///
    /// This blocks (asynchronously) until there is a non-trivial poll response
    /// to return or an error occurs.
    ///
    /// The idle is cancelled by simply dropping the future. `mailbox` is only
    /// mutated upon a non-trivial poll.
    #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
    pub async fn idle(
        &mut self,
        mailbox: &mut Mailbox,
    ) -> Result<PollResponse, Error> {
        self.idle_poll(mailbox).await
    }

    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    pub async fn idle(
        &mut self,
        mailbox: &mut Mailbox,
    ) -> Result<PollResponse, Error> {
        use std::os::unix::io::RawFd;
        use tokio::io::unix::AsyncFd;

        #[cfg(target_os = "linux")]
        fn init(
            metadb_path: &Path,
            deliverydb_path: &Path,
        ) -> io::Result<(nix::sys::inotify::Inotify, AsyncFd<RawFd>)> {
            use nix::sys::inotify;
            use std::os::fd::{AsFd, AsRawFd};

            let handle = inotify::Inotify::init(
                inotify::InitFlags::IN_CLOEXEC
                    | inotify::InitFlags::IN_NONBLOCK,
            )?;
            handle.add_watch(metadb_path, inotify::AddWatchFlags::IN_MODIFY)?;
            handle.add_watch(
                deliverydb_path,
                inotify::AddWatchFlags::IN_MODIFY,
            )?;
            let asyncfd = tokio::io::unix::AsyncFd::with_interest(
                handle.as_fd().as_raw_fd(),
                tokio::io::Interest::READABLE,
            )
            .unwrap();
            Ok((handle, asyncfd))
        }

        #[cfg(target_os = "linux")]
        fn clear_events(inotify: &nix::sys::inotify::Inotify) {
            while inotify.read_events().ok().is_some_and(|v| !v.is_empty()) {}
        }

        #[cfg(target_os = "freebsd")]
        struct Handle {
            kqueue: nix::sys::event::Kqueue,
            metadb: std::fs::File,
            deliverydb: std::fs::File,
        }

        #[cfg(target_os = "freebsd")]
        fn init(
            metadb_path: &Path,
            deliverydb_path: &Path,
        ) -> io::Result<(nix::sys::event::Kqueue, AsyncFd<RawFd>)> {
            use nix::sys::event;
            use std::mem;

            let metadb = std::fs::File::open(metadb_path)?;
            let deliverydb = std::fs::File::open(deliverydb_path)?;

            let kqueue = event::Kqueue::new();
            handle.kevent(
                &[
                    event::KEvent::new(
                        metadb.as_raw_fd(),
                        event::EventFilter::EVFILT_VNODE,
                        event::EventFlag::NOTE_EXTEND
                            | event::EventFlag::NOTE_WRITE,
                        event::FilterFlag::EVFILT_ADD
                            | event::FilterFlag::EVFILT_ENABLE,
                        0, // nullptr, no system data
                        0, // nullptr, no user data
                    ),
                    event::KEvent::new(
                        deliverydb.as_raw_fd(),
                        event::EventFilter::EVFILT_VNODE,
                        event::EventFlag::NOTE_EXTEND
                            | event::EventFlag::NOTE_WRITE,
                        event::FilterFlag::EVFILT_ADD
                            | event::FilterFlag::EVFILT_ENABLE,
                        0, // nullptr, no system data
                        0, // nullptr, no user data
                    ),
                ],
                &mut [],
                Some(nix::libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                }),
            )?;

            // XXX Kqueue strangely doesn't give access to its file descriptor.
            // As of nix 0.27.1, it is just a #[repr(transparent)] wrapper
            // struct around RawFd.
            //
            // SAFETY: The assertions make this memory-safe. If, somehow,
            // Kqueue turns into a struct with the same size and alignment as
            // RawFd but contains something else, we'll end up polling some
            // other value instead of a file descriptor, but it won't cause a
            // memory safety issue.
            let fd: RawFd = unsafe {
                assert_eq!(
                    mem::size_of::<RawFd>(),
                    mem::size_of::<event::Kqueue>(),
                );
                assert_eq!(
                    mem::align_of::<RawFd>(),
                    mem::align_of::<event::Kqueue>(),
                );
                mem::transmute_copy(&handle)
            };

            let asyncfd = tokio::io::unix::AsyncFd::with_interest(
                fd,
                tokio::io::Interest::READABLE,
            )
            .unwrap();

            Ok(
                Handle {
                    kqueue,
                    metadb,
                    deliverydb,
                },
                asyncfd,
            )
        }

        #[cfg(target_os = "freebsd")]
        fn clear_events(handle: &Handle) {
            use nix::sys::event;
            let mut buf = [event::KEvent; 4];
            let zero = nix::libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            while handle
                .kqueue
                .kevent(&[], &mut buf, Some(zero))
                .ok()
                .is_some_and(|n| n > 0)
            {}
        }

        let (handle, asyncfd) = init(&self.metadb_path, &self.deliverydb_path)?;
        loop {
            self.drain_deliveries();
            let poll = self.poll(mailbox)?;
            if PollResponse::default() != poll {
                return Ok(poll);
            }

            let mut readable = asyncfd.readable().await?;
            clear_events(&handle);
            readable.clear_ready();
        }
    }

    // Always compiled to verify it builds.
    #[allow(dead_code)]
    async fn idle_poll(
        &mut self,
        mailbox: &mut Mailbox,
    ) -> Result<PollResponse, Error> {
        let mut last_metadb = SystemTime::UNIX_EPOCH;
        let mut last_deliverydb = SystemTime::UNIX_EPOCH;
        loop {
            let metadb = self.metadb_mtime()?;
            let deliverydb = self.deliverydb_mtime()?;
            if (last_metadb, last_deliverydb) != (metadb, deliverydb) {
                last_metadb = metadb;
                last_deliverydb = deliverydb;
                self.drain_deliveries();
                let poll = self.poll(mailbox)?;
                if PollResponse::default() != poll {
                    return Ok(poll);
                }
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    fn metadb_mtime(&self) -> Result<SystemTime, Error> {
        Ok(self.metadb_path.metadata()?.modified()?)
    }

    fn deliverydb_mtime(&self) -> Result<SystemTime, Error> {
        Ok(self.deliverydb_path.metadata()?.modified()?)
    }
}
