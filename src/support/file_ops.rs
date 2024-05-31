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

//! Miscellaneous functions for working with files.

use std::collections::HashSet;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::Path;

use log::error;
use rand::{rngs::OsRng, Rng};

use super::error::Error;

/// Write `data` into the file at `path`, atomically.
///
/// The file will first be staged within `tmp`.
///
/// If `overwrite` is true, this will replace anything already at `path`. If
/// false, the call will fail if `path` already exists.
pub fn spit(
    tmp: impl AsRef<Path>,
    path: impl AsRef<Path>,
    overwrite: bool,
    mode: u32,
    data: &[u8],
) -> io::Result<()> {
    let mut tf = tempfile::NamedTempFile::new_in(tmp)?;
    tf.as_file_mut().write_all(data)?;
    chmod(tf.path(), mode)?;
    tf.as_file_mut().sync_all()?;
    if overwrite {
        tf.persist(path)?;
    } else {
        tf.persist_noclobber(path)?;
    }
    Ok(())
}

/// Delete `target` by moving it into the directory given by `garbage` (with a
/// new random name) and recursively removing it.
///
/// This is used to make removal of large directory trees atomic.
pub fn delete_atomically(
    target: impl AsRef<Path>,
    garbage: impl AsRef<Path>,
) -> io::Result<()> {
    let target = target.as_ref();
    let garbage = garbage.as_ref();

    loop {
        let name = format!("garbage.{}", OsRng.gen::<u64>());
        let dst = garbage.join(name);

        match fs::rename(target, &dst) {
            Ok(()) => {
                if let Err(e) = fs::remove_dir_all(&dst) {
                    error!("Failed to remove {}: {}", dst.display(), e);
                }
                break;
            },
            Err(e) if io::ErrorKind::AlreadyExists == e.kind() => continue,
            Err(e) => return Err(e),
        }
    }

    Ok(())
}

/// Recursively replicate directory `src` to `dst` to make it available within
/// a chroot. This does not create an *exact* replica:
///
/// 1. Directories are created with mode 755.
/// 2. Files are hard-linked if possible, and copied if not.
/// 3. Symlinks are traversed, such that the final output has no symlinks at
/// all.
/// 4. Entries which are not world-readable are skipped.
///
/// When `dst` already exists, it will be updated as needed to mirror `src`.
pub fn replicate_directory_for_chroot(
    src: &Path,
    dst: &Path,
) -> io::Result<()> {
    if fs::symlink_metadata(dst)
        .ok()
        .is_some_and(|md| !md.is_dir())
    {
        fs::remove_file(dst).ignore_not_found()?;
    }

    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(dst)
        .ignore_already_exists()?;

    let mut known_files = HashSet::<OsString>::new();

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let file_name = entry.file_name();
        let dst_path = dst.join(&file_name);
        let src_md = match fs::metadata(&src_path) {
            Ok(md) => md,
            Err(e) if io::ErrorKind::NotFound == e.kind() => continue,
            Err(e) => {
                error!("stat {}: {}", src_path.display(), e);
                continue;
            },
        };

        // Treat non-world-readable files as non-existent.
        if 0 == src_md.mode() & 0o004 {
            continue;
        }

        known_files.insert(file_name);

        if src_md.is_dir() {
            // If dst_path already exists and is a non-directory, the recursive
            // call will remove it first.
            replicate_directory_for_chroot(&src_path, &dst_path)?;
        } else if src_md.is_file() {
            if let Ok(dst_md) = fs::symlink_metadata(&dst_path) {
                if !dst_md.is_file() {
                    // If the old file is actually not a regular file, remove
                    // it first to replace it later.
                    if let Err(e) = remove_any(&dst_path) {
                        error!("remove {}: {}", dst_path.display(), e);
                        continue;
                    }
                } else if (src_md.dev(), src_md.ino())
                    == (dst_md.dev(), dst_md.ino())
                    || (src_md.size() == dst_md.size()
                        && src_md.mtime() <= dst_md.mtime())
                {
                    // The source and destination are the same file, or dst is
                    // a copy that is probably still has the same content as
                    // the source.
                    continue;
                } else {
                    // The destination already exists but needs to be replaced.
                    if let Err(e) =
                        fs::remove_file(&dst_path).ignore_not_found()
                    {
                        error!("remove {}: {}", dst_path.display(), e);
                        continue;
                    }
                }
            }

            match nix::unistd::linkat(
                None,
                &src_path,
                None,
                &dst_path,
                nix::unistd::LinkatFlags::SymlinkFollow,
            ) {
                Ok(()) => (),
                Err(nix::errno::Errno::EXDEV) => {
                    if let Err(e) = fs::copy(&src_path, &dst_path) {
                        error!(
                            "copy {} => {}: {}",
                            src_path.display(),
                            dst_path.display(),
                            e,
                        );
                    }
                },
                Err(e) => {
                    error!(
                        "linkat {} => {}: {}",
                        src_path.display(),
                        dst_path.display(),
                        e,
                    );
                },
            }
        }
    }

    for entry in fs::read_dir(dst)? {
        let entry = entry?;
        if !known_files.contains(&entry.file_name()) {
            let path = entry.path();
            if let Err(e) = remove_any(&path) {
                error!("remove {}: {}", path.display(), e);
            }
        }
    }

    Ok(())
}

fn remove_any(path: &Path) -> io::Result<()> {
    fs::remove_file(path).or_else(|_| fs::remove_dir_all(path))
}

pub fn chmod(path: impl AsRef<Path>, mode: u32) -> io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

pub trait IgnoreKinds {
    fn ignore_already_exists(self) -> Self;
    fn ignore_not_found(self) -> Self;
}

impl<R: Default> IgnoreKinds for Result<R, io::Error> {
    fn ignore_already_exists(self) -> Self {
        match self {
            Ok(r) => Ok(r),
            Err(e) if io::ErrorKind::AlreadyExists == e.kind() => {
                Ok(R::default())
            },
            Err(e) => Err(e),
        }
    }

    fn ignore_not_found(self) -> Self {
        match self {
            Ok(r) => Ok(r),
            Err(e) if io::ErrorKind::NotFound == e.kind() => Ok(R::default()),
            Err(e) => Err(e),
        }
    }
}

pub trait ErrorTransforms {
    type Coerced;
    fn on_exists(self, error: Error) -> Self::Coerced;
    fn on_not_found(self, error: Error) -> Self::Coerced;
}

impl<R, E: Into<Error>> ErrorTransforms for Result<R, E> {
    type Coerced = Result<R, Error>;

    fn on_exists(self, error: Error) -> Result<R, Error> {
        match self.map_err(|e| e.into()) {
            Err(Error::Io(e)) if io::ErrorKind::AlreadyExists == e.kind() => {
                Err(error)
            },
            Err(Error::Nix(nix::errno::Errno::EEXIST)) => Err(error),
            s => s,
        }
    }

    fn on_not_found(self, error: Error) -> Result<R, Error> {
        match self.map_err(|e| e.into()) {
            Err(Error::Io(e)) if io::ErrorKind::NotFound == e.kind() => {
                Err(error)
            },
            Err(Error::Nix(nix::errno::Errno::ENOENT)) => Err(error),
            s => s,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use tempfile::TempDir;

    #[test]
    fn test_replicate_directory_for_chroot() {
        let root = TempDir::new().unwrap();
        let root = root.path();

        // Things that won't get changed
        fs::create_dir_all(root.join("src/real")).unwrap();
        fs::create_dir_all(root.join("src/alt")).unwrap();
        fs::write(root.join("src/real/target.txt"), "hello world\n").unwrap();
        std::os::unix::fs::symlink("../real", root.join("src/alt/up")).unwrap();
        std::os::unix::fs::symlink(
            "target.txt",
            root.join("src/real/link.txt"),
        )
        .unwrap();
        fs::write(root.join("src/secret"), "hunter2").unwrap();
        chmod(root.join("src/secret"), 0o660).unwrap();

        // Things that will be changed
        fs::create_dir_all(root.join("src/deleted-dir")).unwrap();
        fs::write(root.join("src/deleted-dir/foo"), "foo").unwrap();
        fs::write(root.join("src/deleted-file"), "bye").unwrap();
        fs::create_dir_all(root.join("src/becomes-file")).unwrap();
        fs::write(root.join("src/becomes-file/bar"), "bar").unwrap();
        fs::write(root.join("src/becomes-dir"), "plugh").unwrap();
        fs::write(root.join("src/content-changes"), "old-content").unwrap();

        replicate_directory_for_chroot(
            &root.join("src"),
            &root.join("sub/dst"),
        )
        .unwrap();
        assert_eq!(
            "hello world\n",
            fs::read_to_string(&root.join("sub/dst/real/target.txt")).unwrap(),
        );
        assert_eq!(
            "hello world\n",
            fs::read_to_string(&root.join("sub/dst/real/link.txt")).unwrap(),
        );
        assert_eq!(
            "hello world\n",
            fs::read_to_string(&root.join("sub/dst/alt/up/link.txt")).unwrap(),
        );
        assert_eq!(
            io::ErrorKind::NotFound,
            fs::read_to_string(&root.join("sub/dst/secret"))
                .unwrap_err()
                .kind(),
        );

        // Ensure the clock ticks over since detecting the content-changes
        // change involves mtime.
        std::thread::sleep(std::time::Duration::from_secs(1));

        // Make our changes
        fs::remove_dir_all(root.join("src/deleted-dir")).unwrap();
        fs::remove_file(root.join("src/deleted-file")).unwrap();
        fs::remove_dir_all(root.join("src/becomes-file")).unwrap();
        fs::write(root.join("src/becomes-file"), "now a file").unwrap();
        fs::remove_file(root.join("src/becomes-dir")).unwrap();
        fs::create_dir_all(root.join("src/becomes-dir")).unwrap();
        fs::write(root.join("src/becomes-dir/qux"), "qux").unwrap();
        fs::remove_file(root.join("src/content-changes")).unwrap();
        fs::write(root.join("src/content-changes"), "new-content").unwrap();

        replicate_directory_for_chroot(
            &root.join("src"),
            &root.join("sub/dst"),
        )
        .unwrap();
        assert_eq!(
            io::ErrorKind::NotFound,
            fs::read_to_string(&root.join("sub/dst/deleted-dir/foo"))
                .unwrap_err()
                .kind(),
        );
        assert_eq!(
            io::ErrorKind::NotFound,
            fs::read_to_string(&root.join("sub/dst/deleted-file"))
                .unwrap_err()
                .kind(),
        );
        assert_eq!(
            "now a file".to_owned(),
            fs::read_to_string(&root.join("sub/dst/becomes-file")).unwrap(),
        );
        assert_eq!(
            "qux".to_owned(),
            fs::read_to_string(&root.join("sub/dst/becomes-dir/qux")).unwrap(),
        );
        assert_eq!(
            "new-content".to_owned(),
            fs::read_to_string(&root.join("sub/dst/content-changes")).unwrap(),
        );
    }
}
