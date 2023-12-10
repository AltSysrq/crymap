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

use std::fmt::Write as _;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use chrono::prelude::*;
use nix::errno::Errno;
use tiny_keccak::{Hasher, Sha3};

use crate::support::error::Error;

pub struct MessageStore {
    root: PathBuf,
}

impl MessageStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// Computes the canonical relative path for the given data.
    ///
    /// The canonical path should be used for all automated insertions into the
    /// message store. Non-canonical paths are tolerated to support
    /// administrative use cases such as dropping a file from `lost+found` into
    /// the owning user's message store.
    ///
    /// The canonical path is a two-level structure based on the 256-bit SHA-3
    /// of the raw data (that is, the data of the message file itself, post
    /// encryption and so forth --- so this leaks no information about the
    /// original cleartext contents), consisting of the first octet of the hash
    /// as a directory, and the rest of the octets as the file name, all in
    /// lowercase hex.
    pub fn canonical_path(mut data: impl Read) -> io::Result<PathBuf> {
        let mut buf = [0u8; 4096];
        let mut sha3 = Sha3::v256();

        loop {
            let nread = data.read(&mut buf)?;
            if 0 == nread {
                break;
            }

            sha3.update(&buf[..nread]);
        }

        let mut hash = [0u8; 32];
        sha3.finalize(&mut hash);

        let mut path = String::with_capacity(2 * hash.len() + 1);
        let _ = write!(path, "{:02x}/", hash[0]);
        for &b in &hash[1..] {
            let _ = write!(path, "{:02x}", b);
        }

        Ok(path.into())
    }

    /// Inserts `src` into the message store at `dst`, where `dst` is the
    /// relative path (and preferably the canonical path for the file).
    ///
    /// If the destination already exists, this has no effect.
    pub fn insert(&self, src: &Path, dst: &Path) -> Result<(), Error> {
        let dst = self.root.join(dst);
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }

        match nix::unistd::linkat(
            None,
            src,
            None,
            &dst,
            nix::unistd::LinkatFlags::SymlinkFollow,
        ) {
            Ok(()) | Err(Errno::EEXIST) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Opens the message with the given relative path.
    ///
    /// This will refuse to open absolute paths.
    pub fn open(&self, path: &Path) -> io::Result<fs::File> {
        if path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "unexpected absolute path",
            ));
        }

        fs::File::open(self.root.join(path))
    }

    /// Deletes the message with the given relative path.
    ///
    /// This will refuse to delete absolute paths.
    pub fn delete(&self, path: &Path) -> io::Result<()> {
        if path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "unexpected absolute path",
            ));
        }

        fs::remove_file(self.root.join(path))
    }

    /// Lists the relative paths within the message store which were modified
    /// before `modified_before`.
    ///
    /// This is used to identify messages in the message store that are not
    /// accounted for in the main database. The modification time threshold is
    /// used to ensure files that were recently externally delivered are not
    /// marked as such and can instead go through the normal delivery
    /// mechanism.
    ///
    /// When a message is removed, it is first removed from the message store
    /// and then from the database. When recovering a message through this
    /// mechanism, the message must first be added as an orphan, then tested to
    /// see if the file still exists before actually adding it to the inbox, to
    /// prevent a race condition between recovery and message removal.
    pub fn list(
        &self,
        modified_before: DateTime<Utc>,
    ) -> impl Iterator<Item = PathBuf> + '_ {
        walkdir::WalkDir::new(&self.root)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(move |e| {
                e.metadata().ok().is_some_and(|md| {
                    md.is_file()
                        && md.modified().ok().is_some_and(|mt| {
                            DateTime::<Utc>::from(mt) < modified_before
                        })
                })
            })
            .map(move |e| e.path().strip_prefix(&self.root).unwrap().to_owned())
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_message_store() {
        let root = TempDir::new().unwrap();
        let store = MessageStore::new(root.path().join("messages"));
        let tmp = root.path().join("tmp");

        fs::create_dir(&tmp).unwrap();

        let foo_path = tmp.join("foo");
        fs::write(&foo_path, b"foo").unwrap();
        let bar_path = tmp.join("bar");
        fs::write(&bar_path, b"bar").unwrap();
        let baz_path = tmp.join("baz");
        fs::write(&baz_path, b"baz").unwrap();

        let foo_canonical =
            MessageStore::canonical_path(fs::File::open(&foo_path).unwrap())
                .unwrap();
        let bar_canonical =
            MessageStore::canonical_path(fs::File::open(&bar_path).unwrap())
                .unwrap();
        let baz_canonical =
            MessageStore::canonical_path(fs::File::open(&baz_path).unwrap())
                .unwrap();

        store.insert(&foo_path, &foo_canonical).unwrap();
        store.insert(&bar_path, &bar_canonical).unwrap();
        store.insert(&baz_path, &baz_canonical).unwrap();

        let mut buf = Vec::<u8>::new();
        store
            .open(&foo_canonical)
            .unwrap()
            .read_to_end(&mut buf)
            .unwrap();
        assert_eq!(b"foo", &buf[..]);

        buf.clear();
        store
            .open(&bar_canonical)
            .unwrap()
            .read_to_end(&mut buf)
            .unwrap();
        assert_eq!(b"bar", &buf[..]);

        // Ensure insert() doesn't overwrite but does succeed if the file is
        // already there.
        store.insert(&baz_path, &foo_canonical).unwrap();
        buf.clear();
        store
            .open(&foo_canonical)
            .unwrap()
            .read_to_end(&mut buf)
            .unwrap();
        assert_eq!(b"foo", &buf[..]);

        let mut listed = store
            .list(Utc::now() + Duration::from_secs(5))
            .collect::<Vec<_>>();
        assert_eq!(3, listed.len());
        assert!(listed.contains(&foo_canonical));
        assert!(listed.contains(&bar_canonical));
        assert!(listed.contains(&baz_canonical));

        listed = store
            .list(DateTime::from_timestamp(0, 0).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(0, listed.len());

        store.delete(&bar_canonical).unwrap();
        assert!(store.open(&bar_canonical).is_err());
        listed = store
            .list(Utc::now() + Duration::from_secs(5))
            .collect::<Vec<_>>();
        assert_eq!(2, listed.len());
        assert!(listed.contains(&foo_canonical));
        assert!(listed.contains(&baz_canonical));
    }
}
