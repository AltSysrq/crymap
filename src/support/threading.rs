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

//! Utilities for working with threads.
//!
//! Crymap once used Rayon for all these tasks. However, this approach was
//! found to result in excess memory usage, primarily due to the way Rayon
//! keeps all its threads around all the time, which is not necessary or
//! helpful in Crymap, which spends most of its life as an idle process.
//!
//! The implementations here are geared more to simplicity and keeping memory
//! usage low rather than raw performance.

use std::sync::Mutex;

use lazy_static::lazy_static;

lazy_static! {
    /// The current background work queue.
    ///
    /// If `None`, no background worker thread is currently running.
    static ref BACKGROUND_WORK: Mutex<Option<Vec<Box<dyn FnMut () + Send>>>> =
        Mutex::new(None);
}

const MAX_BACKGROUND_WORK: usize = 256;

/// Run the given task in the background.
///
/// In ideal cases, this call returns immediately. `task` is invoked at some
/// point in the future. Tasks are not run in any particular order.
///
/// If too much work is already queued, the task is run synchronously.
///
/// The background work system is optimised for very sporadic tasks with
/// occasional bursts, and should only be used if spinning up a thread just for
/// the one task is acceptable from a CPU time perspective. The advantage
/// of this system instead of just using thread::spawn() is that the at most
/// one background thread exists at any given time, and there is back-pressure
/// if too much work accumulates.
pub fn run_in_background(task: impl FnOnce() + Send + 'static) {
    {
        let mut work = BACKGROUND_WORK.lock().unwrap();
        let work = work.get_or_insert_with(|| {
            std::thread::spawn(run_background_work);
            Vec::new()
        });

        if work.len() < MAX_BACKGROUND_WORK {
            let mut taskopt = Some(task);
            work.push(Box::new(move || taskopt.take().unwrap()()));
            return;
        }
    }

    // Too much work queued, run synchronously
    task();
}

fn run_background_work() {
    loop {
        let mut task = {
            let mut work = BACKGROUND_WORK.lock().unwrap();

            let popped = work.as_mut().and_then(|w| w.pop());
            match popped {
                Some(task) => task,
                None => {
                    *work = None;
                    break;
                },
            }
        };

        task()
    }
}
