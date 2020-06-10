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

//! Miscellaneous functions for working with files.

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use log::error;
use rand::{rngs::OsRng, Rng};

use crate::support::error::Error;

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
/// new random name) and recursively removing it in the background.
///
/// This is used to make removal of large directory trees both fast and atomic.
pub fn delete_async(
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
                std::thread::spawn(move || {
                    if let Err(e) = fs::remove_dir_all(&dst) {
                        error!("Failed to remove {}: {}", dst.display(), e);
                    }
                });
                break;
            }
            Err(e) if io::ErrorKind::AlreadyExists == e.kind() => continue,
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

pub fn chmod(path: impl AsRef<Path>, mode: u32) -> io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

pub trait ReadUninterruptibly: Read {
    fn read_uninteruptibly(&mut self, dst: &mut [u8]) -> io::Result<usize>;
}

impl<R: Read> ReadUninterruptibly for R {
    /// Read bytes into `dst` until `dst` is full or EOF is reached.
    ///
    /// `Interrupted` errors are ignored and retried. Other errors are
    /// propagated.
    fn read_uninteruptibly(&mut self, mut dst: &mut [u8]) -> io::Result<usize> {
        let mut total = 0;
        while 0 != dst.len() {
            match self.read(dst) {
                Ok(0) => break,
                Ok(n) => {
                    total += n;
                    dst = &mut dst[n..];
                }
                Err(e) if io::ErrorKind::Interrupted == e.kind() => continue,
                Err(e) => return Err(e),
            }
        }

        Ok(total)
    }
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
            }
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
            }
            Err(Error::Nix(nix::Error::Sys(nix::errno::Errno::EEXIST))) => {
                Err(error)
            }
            s => s,
        }
    }

    fn on_not_found(self, error: Error) -> Result<R, Error> {
        match self.map_err(|e| e.into()) {
            Err(Error::Io(e)) if io::ErrorKind::NotFound == e.kind() => {
                Err(error)
            }
            Err(Error::Nix(nix::Error::Sys(nix::errno::Errno::ENOENT))) => {
                Err(error)
            }
            s => s,
        }
    }
}
