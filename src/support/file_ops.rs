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
