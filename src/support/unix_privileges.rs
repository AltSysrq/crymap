//-
// Copyright (c) 2020, 2024, Jason Lingle
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
use std::path::{Path, PathBuf};

use log::{error, warn};

use crate::support::{file_ops, sysexits::*, system_config::SecurityConfig};

/// If a system user is configured, switch to it if not already that user.
///
/// If a system chroot is configured, enter it. `users_root` is updated to `/`
/// to reflect this.
///
/// On failure, an error message has already been logged, and the appropriate
/// exit code is returned.
pub fn assume_system(
    security: &SecurityConfig,
    users_root: &mut PathBuf,
) -> Result<(), Sysexit> {
    macro_rules! fatal {
        ($sysexit:expr, $($stuff:tt)*) => {{
            error!($($stuff)*);
            return Err($sysexit)
        }}
    }

    let system_user = if security.system_user.is_empty() {
        None
    } else {
        match nix::unistd::User::from_name(&security.system_user) {
            Ok(Some(user)) => Some(user),
            Ok(None) => fatal!(
                EX_NOUSER,
                "system_user '{}' does not exist!",
                security.system_user
            ),
            Err(e) => fatal!(
                EX_OSFILE,
                "Unable to look up system_user '{}': {}",
                security.system_user,
                e
            ),
        }
    };

    if let Some(ref system_user) = system_user {
        if system_user.uid != nix::unistd::getuid() {
            if let Err(e) = nix::unistd::initgroups(
                &std::ffi::CString::new(system_user.name.clone()).unwrap(),
                system_user.gid,
            ) {
                fatal!(
                    EX_OSERR,
                    "Unable to set up groups for system user: {}",
                    e
                );
            }
        }
    }

    if security.chroot_system {
        if let Err(e) = chroot(users_root) {
            fatal!(
                EX_OSERR,
                "Failed to chroot to '{}': {}",
                users_root.display(),
                e
            );
        }

        users_root.push("/");
    }

    if let Some(system_user) = system_user {
        if system_user.uid != nix::unistd::getuid() {
            if let Err(e) = nix::unistd::setgroups(&[system_user.gid]) {
                fatal!(
                    EX_OSERR,
                    "Failed to set groups for UID {}: {}",
                    system_user.uid,
                    e
                );
            }

            if let Err(e) = nix::unistd::setgid(system_user.gid)
                .and_then(|_| nix::unistd::setuid(system_user.uid))
            {
                fatal!(
                    EX_OSERR,
                    "Failed to set UID:GID to {}:{}: {}",
                    system_user.uid,
                    system_user.gid,
                    e
                );
            }
        }
    }

    Ok(())
}

/// Given a path to a user directory, drop privileges as appropriate.
///
/// If the current process is not running as root, does nothing.
///
/// If running as root, the process will switch its UID and GID to the owner of
/// that directory and chroot into it. If this happens, `user_dir` is mutated
/// to hold the new path after the chroot.
///
/// If `effective_only` is true, this will not chroot or reset auxiliary
/// groups, and will only change the effective UID and GID.
///
/// On failure, returns a status code appropriate to use if the process is
/// about to exit in response.
pub fn assume_user_privileges(
    log_prefix: &str,
    chroot_system: bool,
    user_dir: &mut PathBuf,
    effective_only: bool,
) -> Result<(), Sysexit> {
    // Nothing to do if we aren't root
    if nix::unistd::ROOT != nix::unistd::getuid() {
        return Ok(());
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
            return Err(EX_NOUSER);
        },
    };
    let target_uid = nix::unistd::Uid::from_raw(md.uid() as nix::libc::uid_t);
    let (has_user_groups, target_gid) =
        match nix::unistd::User::from_uid(target_uid) {
            Ok(Some(user)) => {
                if effective_only {
                    (false, user.gid)
                } else {
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
                        },
                    }
                }
            },
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
            },
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
            },
        };

    if !effective_only {
        prepare_chroot(user_dir);
        if let Err(e) = chroot(user_dir) {
            error!(
                "{} Chroot (forced because Crymap is running as root) \
                 into '{}' failed: {}",
                log_prefix,
                user_dir.display(),
                e
            );
            return Err(EX_OSERR);
        }

        // Chroot successful, adjust the path to reflect that
        user_dir.push("/"); // Clears everything but '/'
    }

    // Now we can finish dropping privileges
    if let Err(e) = if has_user_groups {
        Ok(())
    } else {
        nix::unistd::setgroups(&[target_gid])
    }
    .and_then(|()| {
        if effective_only {
            nix::unistd::setegid(target_gid)
        } else {
            nix::unistd::setgid(target_gid)
        }
    })
    .and_then(|()| {
        if effective_only {
            nix::unistd::seteuid(target_uid)
        } else {
            nix::unistd::setuid(target_uid)
        }
    }) {
        error!(
            "{} Failed to drop privileges to {}:{}: {}",
            log_prefix, target_uid, target_gid, e
        );
        return Err(EX_OSERR);
    }

    if nix::unistd::ROOT == nix::unistd::geteuid() {
        error!(
            "{} Crymap is still root! You must either \
             (a) Run Crymap as a non-root user; \
             (b) Set [security].system_user in crymap.toml; \
             (c) Ensure that user directories are not owned by root.",
            log_prefix
        );
        return Err(EX_USAGE);
    }

    Ok(())
}

fn chroot(chroot_dir: &Path) -> nix::Result<()> {
    prepare_chroot(chroot_dir);
    // chroot first in case chroot_dir is relative.
    nix::unistd::chroot(chroot_dir).and_then(|()| nix::unistd::chdir("/"))
}

fn prepare_chroot(chroot_dir: &Path) {
    // OpenSSL will want to look into its own files after we chroot if we end
    // up doing outbound SMTP, so make sure the files it wants are actually
    // available in the chroot.
    match get_openssldir() {
        None => {
            error!(
                "Couldn't determine OPENSSLDIR, certificate validation for \
                 outbound SMTP will not work!",
            );
        },

        Some(dir) => {
            if let Err(e) = file_ops::replicate_directory_for_chroot(
                &Path::new("/").join(dir),
                &chroot_dir.join(dir),
            ) {
                error!(
                    "Couldn't replicate OPENSSLDIR /{openssldir} \
                     into chroot at {chroot_dir}/{openssldir}: {e}; \
                     certificate validation for outbound SMTP will not work!",
                    openssldir = dir.display(),
                    chroot_dir = chroot_dir.display(),
                );
            }
        },
    }
}

/// Retrieves the OPENSSL directory, *relative* to the root of the FS.
fn get_openssldir() -> Option<&'static Path> {
    // This is, apparently, the only way to get any inkling of where OpenSSL
    // plans on looking for files. For whatever reason, it's in some
    // human-readable format that we then need to parse.
    //
    // This isn't 100% reliable since it can be overridden by an environment
    // variable, so there's no way to find out exactly what OpenSSL plans to
    // do, but overriding that directory for production Crymap would be very
    // unusual.
    return parse_openssldir(openssl::version::dir());
}

/// Parses the string produced by `openssl::version::dir` to produce a path,
/// *relative* to the root of the FS, of the OpenSSL directory.
fn parse_openssldir(s: &str) -> Option<&Path> {
    s.split('"')
        .nth(1)
        .map(|s| s.strip_prefix('/').unwrap_or(s).as_ref())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_get_openssldir() {
        let rel_dir = get_openssldir().unwrap();
        assert!(
            std::fs::metadata(Path::new("/").join(rel_dir).join("certs"))
                .unwrap()
                .is_dir()
        );
    }

    #[test]
    fn test_parse_openssldir() {
        assert_eq!(None, parse_openssldir("OPENSSLDIR: N/A"));
        assert_eq!(
            Some(Path::new("usr/lib/ssl")),
            parse_openssldir("OPENSSLDIR: \"/usr/lib/ssl\""),
        );
        assert_eq!(
            Some(Path::new("usr/lib/ssl")),
            parse_openssldir("OPENSSLDIR: \"usr/lib/ssl\""),
        );
    }
}
