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

use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

use log::{error, warn};

/// Given a path to a user directory, drop privileges as appropriate.
///
/// If the current process is not running as root, does nothing.
///
/// If running as root, the process will switch its UID and GID to the owner of
/// that directory and chroot into it. If this happens, `user_dir` is mutated
/// to hold the new path after the chroot.
///
/// Returns whether the operation succeeded. If false, the process is in an
/// indeterminate state and will need to exit soon.
pub fn drop_privileges(
    log_prefix: &str,
    chroot_system: bool,
    user_dir: &mut PathBuf,
) -> bool {
    // Nothing to do if we aren't root
    if nix::unistd::ROOT != nix::unistd::getuid() {
        return true;
    }

    // Before we can chroot, we need to figure out what our groups will be
    // once we drop down to the user, because we won't have access to
    // /etc/group after the chroot
    let md = match user_dir.metadata() {
        Ok(md) => md,
        Err(e) => {
            error!(
                "{} Failed to stat '{}': {}",
                log_prefix,
                user_dir.display(),
                e
            );
            return false;
        }
    };
    let target_uid = nix::unistd::Uid::from_raw(md.uid() as nix::libc::uid_t);
    let (has_user_groups, target_gid) =
        match nix::unistd::User::from_uid(target_uid) {
            Ok(Some(user)) => {
                match nix::unistd::initgroups(
                    &std::ffi::CString::new(user.name.to_owned())
                        .expect("Got UNIX user name with NUL?"),
                    user.gid,
                ) {
                    Ok(()) => (true, user.gid),
                    Err(e) => {
                        warn!(
                            "{} Failed to init groups for user: {}",
                            log_prefix, e
                        );
                        (false, user.gid)
                    }
                }
            }
            Ok(None) => {
                // Failure to access /etc/group is expected if we chroot'ed
                // into the system data directory already
                if !chroot_system {
                    warn!(
                        "{} No passwd entry for UID {}, assuming GID {}",
                        log_prefix,
                        target_uid,
                        md.gid()
                    );
                }
                (
                    false,
                    nix::unistd::Gid::from_raw(md.gid() as nix::libc::gid_t),
                )
            }
            Err(e) => {
                // Failure to access /etc/group is expected if we chroot'ed
                // into the system data directory already
                if !chroot_system {
                    warn!(
                        "{} Failed to look up passwd entry for UID {}, \
                     assuming GID {}: {}",
                        log_prefix,
                        target_uid,
                        md.gid(),
                        e
                    );
                }
                (
                    false,
                    nix::unistd::Gid::from_raw(md.gid() as nix::libc::gid_t),
                )
            }
        };

    if let Err(e) = nix::unistd::chdir(user_dir)
        .and_then(|()| nix::unistd::chroot(user_dir))
    {
        error!(
            "{} Chroot (forced because Crymap is running as root) \
             into '{}' failed: {}",
            log_prefix,
            user_dir.display(),
            e
        );
        return false;
    }

    // Chroot successful, adjust the path to reflect that
    user_dir.push("/"); // Clears everything but '/'

    // Now we can finish dropping privileges
    if let Err(e) = if has_user_groups {
        Ok(())
    } else {
        nix::unistd::setgroups(&[target_gid])
    }
    .and_then(|()| nix::unistd::setgid(target_gid))
    .and_then(|()| nix::unistd::setuid(target_uid))
    {
        error!(
            "{} Failed to drop privileges to {}:{}: {}",
            log_prefix, target_uid, target_gid, e
        );
        return false;
    }

    if nix::unistd::ROOT == nix::unistd::getuid() {
        error!(
            "{} Crymap is still root! You must either \
             (a) Run Crymap as a non-root user; \
             (b) Set [security].system_user in crymap.toml; \
             (c) Ensure that user directories are not owned by root.",
            log_prefix
        );
        return false;
    }

    true
}
