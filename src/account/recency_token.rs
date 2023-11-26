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

//! Implements a system for dealing with the \Recent "flag".
//!
//! RFC 3501 is pretty poorly worded here. The semantics it seems to be trying
//! to describe are thus: \Recent is an *immutable* flag associated to each
//! message, which has an independent value between different sessions. \Recent
//! is set on a session if and only if no read-write session has previously
//! assigned a sequence number to the message. All read-only sessions up to
//! that point, and the first read-write session itself, set \Recent on the
//! message, and all other sessions do not.
//!
//! How is this useful? Only Crispin knows, but he's no longer available for
//! comment. It's part of the standard so we implement it anyway.
//!
//! This is implemented by a "recency token". A `recent` directory in the
//! mailbox directory is expected to contain exactly one file, whose name is
//! the greatest UID that any read-write session has marked \Recent.
//!
//! Recency is claimed in a range-based system. One queries with the greatest
//! UID currently known to the claimant, and if successful, the claimant marks
//! \Recent on all UIDs between the old recency token (exclusive) and the new
//! recency token (inclusive).
//!
//! In a read-write session, the claim process is as follows:
//!
//! 1. List the contents of `recent` and find the greatest token within.
//! 2. If `recent` does not exist or there is no token, create `recent` and a
//!    token equal to the greatest UID, and successfully claim the entire UID
//!    range.
//! 3. Attempt to rename the old token to the new greatest UID. On success,
//!    claim the range from the old token (exclusive) to the new token
//!    (inclusive). On `EEXIST`, claim nothing. On `ENOENT`, go to step 1.
//! 4. If there were any superfluous tokens, unlink them.
//!
//! In a read-only session, the claim process is as follows:
//!
//! 1. List the contents of `recent` and find the greatest token within.
//! 2. Claim all UIDs from the current token to the new UID value.
//!
//! In all failure cases, we err on the side of marking the message(s) \Recent.
//! This is required by RFC 3501:
//!
//! > If it is not possible to determine whether or not this
//! > session is the first session to be notified about a message,
//! > then that message SHOULD be considered recent.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use log::error;

use super::model::Uid;
use crate::support::file_ops::IgnoreKinds;

/// Go through the recency claim process.
///
/// If any UIDs should be considered recent, returns the minimum (inclusive)
/// that is recent. The upper bound of that range is `max_uid` itself (also
/// inclusive).
///
/// `min_uid` governs the minimum UID that will be returned.
pub fn claim(
    root: &Path,
    min_uid: Uid,
    max_uid: Uid,
    read_only: bool,
) -> Option<Uid> {
    if read_only {
        read_only_claim(root, max_uid)
    } else {
        read_write_claim(root, max_uid)
    }
    .map(|u| min_uid.max(u))
}

fn read_only_claim(root: &Path, max_uid: Uid) -> Option<Uid> {
    if let Some(last_claimed) = get_current_tokens(&token_dir(root))
        .ok()
        .and_then(|s| s.last().copied().and_then(Uid::of))
    {
        if last_claimed < max_uid {
            last_claimed.next()
        } else {
            None
        }
    } else {
        Some(Uid::MIN)
    }
}

fn read_write_claim(root: &Path, max_uid: Uid) -> Option<Uid> {
    let tdir = token_dir(root);

    loop {
        let current = match get_current_tokens(&tdir) {
            Ok(c) if !c.is_empty() => c,
            Ok(_) => {
                if let Err(err) = init_token_dir(&tdir, max_uid) {
                    error!(
                        "Failed to initialised {}; \
                            all messages will be \\Recent: {}",
                        tdir.display(),
                        err
                    );
                }
                return Some(Uid::MIN);
            },
            Err(e) if io::ErrorKind::NotFound == e.kind() => {
                if let Err(err) = init_token_dir(&tdir, max_uid) {
                    error!(
                        "Failed to initialised {}; \
                            all messages will be \\Recent: {}",
                        tdir.display(),
                        err
                    );
                }
                return Some(Uid::MIN);
            },
            Err(e) => {
                error!(
                    "Failed to list {}; \
                        all messages will be \\Recent: {}",
                    tdir.display(),
                    e
                );
                return Some(Uid::MIN);
            },
        };

        for superfluous in &current[..current.len() - 1] {
            let _ = fs::remove_file(tdir.join(superfluous.to_string()));
        }

        let latest = current[current.len() - 1];
        if latest >= max_uid.0.get() {
            return None;
        }
        let latest_path = tdir.join(latest.to_string());

        // Linux has renameat2() which allows non-clobbering rename, but that's
        // both very recent, filesystem-specific, and non-portable. Instead,
        // we'll link to the new name and then unlink the old one. It's not
        // atomic but won't cause problems; the only failure mode is that we
        // could leave the extra file around, but that will get cleaned up
        // later.
        match nix::unistd::linkat(
            None,
            &latest_path,
            None,
            &tdir.join(max_uid.0.get().to_string()),
            nix::unistd::LinkatFlags::NoSymlinkFollow,
        ) {
            Ok(()) => {
                // Successfully claimed
                // Remove our old link before celebrating
                let _ = fs::remove_file(&latest_path);
                return Uid::of(latest).and_then(Uid::next);
            },
            // ENOENT => we lost the race, try again with updated dir info
            Err(nix::errno::Errno::ENOENT) => continue,
            // EEXIST => we lost the race, and the other process claimed the
            // same range
            Err(nix::errno::Errno::EEXIST) => return None,
            Err(e) => {
                error!(
                    "Failed to update recency token ({}); \
                        all messages will be \\Recent: {}",
                    latest_path.display(),
                    e
                );
                return Some(Uid::MIN);
            },
        }
    }
}

fn token_dir(root: &Path) -> PathBuf {
    root.join("recent")
}

fn get_current_tokens(token_dir: &Path) -> io::Result<Vec<u32>> {
    let mut result = Vec::new();

    for entry in fs::read_dir(token_dir)? {
        let entry = entry?;
        if let Some(val) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        {
            result.push(val);
        }
    }

    result.sort();
    Ok(result)
}

fn init_token_dir(tdir: &Path, max_uid: Uid) -> io::Result<()> {
    fs::DirBuilder::new()
        .mode(0o700)
        .create(tdir)
        .ignore_already_exists()?;
    let mut f = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(tdir.join(max_uid.0.get().to_string()))?;

    // Ignore errors here; if it fails, the file is still useful
    let _ = writeln!(f, "This file is a token that tracks the \\Recent flag.");

    Ok(())
}

#[cfg(test)]
mod test {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn test_recency_token() {
        let root = TempDir::new().unwrap();

        // Read-only operations just return the whole range before the token
        // exists
        assert_eq!(
            Some(Uid::u(5)),
            claim(root.path(), Uid::u(5), Uid::u(10), true)
        );
        assert_eq!(
            Some(Uid::u(2)),
            claim(root.path(), Uid::u(2), Uid::u(7), true)
        );

        // First RW operation claims everything and creates the token
        assert_eq!(
            Some(Uid::u(1)),
            claim(root.path(), Uid::u(1), Uid::u(10), false)
        );
        // Read-only claims to earlier UIDs fail
        assert_eq!(None, claim(root.path(), Uid::u(1), Uid::u(9), true));
        assert_eq!(None, claim(root.path(), Uid::u(1), Uid::u(10), true));
        // So do read-write claims
        assert_eq!(None, claim(root.path(), Uid::u(1), Uid::u(9), false));
        assert_eq!(None, claim(root.path(), Uid::u(1), Uid::u(10), false));

        // A read-only claim to a later UID succeeds but doesn't change
        // anything
        assert_eq!(
            Some(Uid::u(11)),
            claim(root.path(), Uid::u(1), Uid::u(20), true)
        );
        assert_eq!(
            Some(Uid::u(11)),
            claim(root.path(), Uid::u(1), Uid::u(20), true)
        );
        // A read-write claim to a later UID succeeds and advances the token
        assert_eq!(
            Some(Uid::u(11)),
            claim(root.path(), Uid::u(1), Uid::u(20), false)
        );
        // And now attempts to claim that one also fail
        assert_eq!(None, claim(root.path(), Uid::u(1), Uid::u(20), true));
        assert_eq!(None, claim(root.path(), Uid::u(1), Uid::u(20), false));
        // But later claims still work
        assert_eq!(
            Some(Uid::u(21)),
            claim(root.path(), Uid::u(1), Uid::u(30), true)
        );
        assert_eq!(
            Some(Uid::u(21)),
            claim(root.path(), Uid::u(1), Uid::u(30), false)
        );

        // There should still be exactly one file in the recency directory
        assert_eq!(
            1,
            fs::read_dir(root.path().join("recent"))
                .unwrap()
                .map(|v| v.unwrap())
                .count()
        );
    }
}
