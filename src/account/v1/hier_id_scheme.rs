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

//! Implementation of the _hierarchical identifier scheme_ described in
//! `mailbox/mod.rs`.

use std::fs;
use std::io::{self, Seek};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::str;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use rand::{rngs::OsRng, Rng};

use crate::support::error::Error;
use crate::support::file_ops::{self, IgnoreKinds};

/// A scheme for storing files in a hierarchy organised by identity.
///
/// This is a lightweight, stateless value that functions more as a "bundle of
/// parameters" than a resource.
#[derive(Debug, Clone, Copy)]
pub struct HierIdScheme<'a> {
    /// The one-ASCII-character prefix to apply to files managed by this
    /// hierarchy.
    pub prefix: u8,
    /// The extension added to files representing items.
    pub extension: &'a str,
    /// The root directory of the hierarchy.
    pub root: &'a Path,
}

/// A path into a `HierIdScheme` which is used to allocate new IDs or to check
/// whether IDs are allocated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocationPath(PathBuf);

impl AllocationPath {
    /// Return the path to the `alloc` symlink in this path.
    fn alloc_path(&self) -> &Path {
        self.0.parent().unwrap()
    }

    /// Return the path to the bottom directory level in this path.
    fn containing_directory(&self) -> &Path {
        self.alloc_path().parent().unwrap()
    }
}

/// A path into a `HierIdScheme` which is used to access IDs known to already
/// be allocated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessPath(PathBuf);

impl AccessPath {
    pub fn assume_exists(self) -> PathBuf {
        self.0
    }
}

impl<'a> HierIdScheme<'a> {
    /// Return the raw path that is assigned to the given id.
    fn path_for_id(&self, id: u32, for_allocation: bool) -> PathBuf {
        let first_octet: u32;

        let mut first_name = [self.prefix, 0];
        if id < 1 << 8 {
            first_name[1] = b'0';
            first_octet = 3;
        } else if id < 1 << 16 {
            first_name[1] = b'1';
            first_octet = 2;
        } else if id < 1 << 24 {
            first_name[1] = b'2';
            first_octet = 1;
        } else {
            first_name[1] = b'3';
            first_octet = 0;
        }

        let mut buf = self.root.join(str::from_utf8(&first_name).unwrap());

        for octet in first_octet..3 {
            buf.push(format!("{:02x}", (id >> (8 * (3 - octet))) & 0xFF));
        }

        if for_allocation {
            buf.push("alloc");
        }

        buf.push(format!("{:02x}.{}", id & 0xFF, self.extension));
        buf
    }

    /// Return the allocation path that is assigned to the given id.
    pub fn allocation_path_for_id(&self, id: u32) -> AllocationPath {
        AllocationPath(self.path_for_id(id, true))
    }

    /// Return the access path that is assigned to the given id.
    pub fn access_path_for_id(&self, id: u32) -> AccessPath {
        AccessPath(self.path_for_id(id, false))
    }

    /// Link `src` into this scheme at the given destination identifier.
    ///
    /// Returns whether any change was made.
    pub fn emplace(&self, src: &Path, dst_id: u32) -> Result<bool, Error> {
        let dst = self.allocation_path_for_id(dst_id);
        // We only need to try allocating the directory for the first item in
        // each branch.
        if 1 == dst_id || 0 == dst_id % 256 {
            self.mkdirs(&dst)?;
        }

        match nix::unistd::linkat(
            None,
            src,
            None,
            &dst.0,
            nix::unistd::LinkatFlags::SymlinkFollow,
        ) {
            Ok(_) => Ok(true),
            Err(nix::errno::Errno::EEXIST) | Err(nix::errno::Errno::ELOOP) => {
                Ok(false)
            },
            Err(e) => Err(e.into()),
        }
    }

    /// Atomically emplace many (2 to 65536) paths into this hierarchy, such
    /// that no item has an id greater than `max_id`.
    ///
    /// This process will create gravestones where no item existed previously;
    /// the store built on top of it must be able to tolerate that.
    ///
    /// On success, returns the id of the first item. Subsequent items have
    /// successive ids.
    ///
    /// This currently handles mapping most errors to semantic error values and
    /// assumes it is used for emplacing messages.
    pub fn emplace_many(
        &self,
        srcs: &[&Path],
        tmp: &Path,
        max_id: u32,
    ) -> Result<u32, Error> {
        const BASE: u32 = 256 * 256 * 256;

        let (allocation_size, levels) = match srcs.len() {
            0 => panic!("emplace_many with 0 items"),
            1 => panic!("emplace_many with 1 item"),
            2..=256 => (256, 1),
            257..=65536 => (65536, 2),
            _ => return Err(Error::BatchTooBig),
        };

        let tmp_root = tempfile::TempDir::new_in(tmp)?;
        let isolated = HierIdScheme {
            prefix: self.prefix,
            extension: self.extension,
            root: tmp_root.path(),
        };

        // Emplace everything into our isolated hierarchy with aligned ids
        for (ix, src) in srcs.iter().enumerate() {
            if !isolated.emplace(src, BASE + (ix as u32))? {
                match fs::metadata(src) {
                    Ok(_) => return Err(Error::GaveUpInsertion),
                    Err(e) if io::ErrorKind::NotFound == e.kind() => {
                        return Err(Error::NxMessage);
                    },
                    Err(e) if Some(nix::libc::ELOOP) == e.raw_os_error() => {
                        return Err(Error::ExpungedMessage);
                    },
                    Err(e) => return Err(e.into()),
                }
            }
        }

        // Determine the first ID we'll be allocating, and the base ID for an
        // actual item.
        let first_id = self.first_unallocated_id();
        if max_id.saturating_sub(first_id) < allocation_size {
            return Err(Error::MailboxFull);
        }

        let target_id = (first_id + allocation_size - 1) / allocation_size
            * allocation_size;
        if max_id.saturating_sub(first_id) < srcs.len() as u32 {
            return Err(Error::MailboxFull);
        }

        // Create gravestones between the nominal next ID and the alignment
        // target
        let mut to_allocate = first_id;
        while to_allocate < target_id {
            let id = to_allocate;
            let gravestone = self.allocation_path_for_id(id);
            if 0 == id % 256 {
                // Try to allocate all 256 ids at once
                let parent = gravestone.containing_directory();
                self.mkdirs_bare(parent)?;
                let success = match std::os::unix::fs::symlink(
                    parent.file_name().unwrap(),
                    parent,
                ) {
                    Ok(_) => true,
                    Err(e) if Some(nix::libc::ELOOP) == e.raw_os_error() => {
                        true
                    },

                    // Ignore other problems; anything fatal we'll encounter
                    // again below.
                    _ => false,
                };

                if success {
                    to_allocate += 256;
                    continue;
                }

                // We only need to create directories for items evenly
                // divisible by 256...
                self.mkdirs(&gravestone)?;
            }

            // ... or for id 1
            if 1 == id {
                self.mkdirs(&gravestone)?;
            }

            // Mark the whole directory as allocated and increment the current
            // id to the next multiple of 256.
            //
            // We don't need to consider the case where target_id is within
            // that range since target_id is always aligned at least to a
            // multiple of 256.
            self.expunge_path(id, gravestone.alloc_path(), tmp)?;
            to_allocate = (id + 256) / 256 * 256;
        }

        // Now to move the whole aligned directory
        let mut atomic_src = isolated.path_for_id(BASE, false);
        let mut atomic_dst = self.path_for_id(target_id, false);
        for _ in 0..levels {
            atomic_src.pop();
            atomic_dst.pop();
        }

        atomic_src.set_extension("d");
        let atomic_dst_nominal = atomic_dst.clone();
        atomic_dst.set_extension("d");

        self.mkdirs_bare(&atomic_dst)?;
        fs::rename(&atomic_src, &atomic_dst).map_err(|e| {
            // ENOTEMPTY: Someone else made the directory first
            // ELOOP: The directory was created and expunged by GC before we
            // got here
            // AlreadyExists: Not entirely expected, but something else was put
            // here first
            if Some(nix::libc::ENOTEMPTY) == e.raw_os_error()
                || Some(nix::libc::ELOOP) == e.raw_os_error()
                || io::ErrorKind::AlreadyExists == e.kind()
            {
                Error::GaveUpInsertion
            } else {
                e.into()
            }
        })?;
        std::os::unix::fs::symlink(
            atomic_dst.file_name().unwrap(),
            atomic_dst_nominal,
        )
        .ignore_already_exists()?;

        Ok(target_id)
    }

    /// Expunge the item with the given identifier.
    ///
    /// The gravestone is staged in a random file in `tmp`.
    pub fn expunge(&self, target: u32, tmp: &Path) -> Result<(), Error> {
        let path = self.allocation_path_for_id(target);
        self.expunge_path(target, &path.0, tmp)
    }

    fn expunge_path(
        &self,
        target: u32,
        path: &Path,
        tmp: &Path,
    ) -> Result<(), Error> {
        let mut stage: PathBuf;

        // To avoid making a bunch of redundant writes to the FS, see if the
        // file is already a gravestone and short-circuit if it is.
        match fs::metadata(path) {
            Err(e) if Some(nix::libc::ELOOP) == e.raw_os_error() => {
                return Ok(())
            },
            _ => (),
        }

        loop {
            stage =
                tmp.join(format!("expunge.{}.{}", target, OsRng.gen::<u64>()));
            match std::os::unix::fs::symlink(path.file_name().unwrap(), &stage)
            {
                Ok(_) => break,
                Err(e) if io::ErrorKind::AlreadyExists == e.kind() => continue,
                Err(e) => return Err(e.into()),
            }
        }

        let rename_res = fs::rename(&stage, path);
        if rename_res.is_err() {
            let _ = fs::remove_file(&stage);
        }

        match rename_res {
            Ok(_) => Ok(()),
            // ELOOP can happen if we were expunging something already expunged
            // and the parent directory got garbage collected first
            Err(e) if Some(nix::libc::ELOOP) == e.raw_os_error() => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Return whether the given identifier is already allocated.
    pub fn is_allocated(&self, id: u32) -> bool {
        // Follow symlinks here to get ELOOP for expunged individual item
        match fs::metadata(self.allocation_path_for_id(id).0) {
            Ok(_) => true,
            Err(e) if Some(nix::libc::ELOOP) == e.raw_os_error() => true,
            _ => false,
        }
    }

    /// Return the first unallocated id.
    ///
    /// This is best-effort, and may return an allocated id in the presence of
    /// concurrent modifications.
    ///
    /// The `X-guess` file is created if it does not exist. It is used, if
    /// possible, to guess the next allocated id, and updated once a result is
    /// available.
    pub fn first_unallocated_id(&self) -> u32 {
        let mut guess_file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o660)
            .open(self.root.join(format!("{}-guess", self.prefix as char)))
            .ok();

        let guess = guess_file
            .as_mut()
            .and_then(|f| f.read_u32::<LittleEndian>().ok())
            .unwrap_or(1)
            .max(1);

        let result = probe_for_first_id(guess, |id| self.is_allocated(id));

        if let Some(mut f) = guess_file {
            let _ = f
                .seek(io::SeekFrom::Start(0))
                .and_then(|_| f.write_u32::<LittleEndian>(result));
        }

        result
    }

    /// Create the file system to contain the given `AllocationPath`, including
    /// the `self` symlink.
    fn mkdirs(&self, path: &AllocationPath) -> io::Result<()> {
        self.mkdirs_bare(path.alloc_path())?;
        match std::os::unix::fs::symlink(".", path.alloc_path()) {
            Ok(_) => (),
            Err(e) if io::ErrorKind::AlreadyExists == e.kind() => (),
            Err(e) if Some(nix::libc::ELOOP) == e.raw_os_error() => (),
            Err(e) => return Err(e),
        }
        Ok(())
    }

    /// Create the file system above `path`, where `path` must be a value
    /// produced by one of the `*path_for_id()` functions.
    ///
    /// This does not create the bottom-level `self` symlink.
    ///
    /// This will silently succeed if a part of the path is already expunged.
    fn mkdirs_bare(&self, path: &Path) -> io::Result<()> {
        // 255/256th of the time, everything already exists
        match fs::symlink_metadata(path.parent().unwrap()) {
            Ok(_) => return Ok(()),
            Err(e) if Some(nix::libc::ELOOP) == e.raw_os_error() => {
                return Ok(())
            },
            _ => (),
        }

        let path = path.strip_prefix(self.root).unwrap();
        let mut iter = path.parent().unwrap().iter();

        let mut cur_path =
            self.root.join(iter.next().expect("No path components?"));
        fs::DirBuilder::new()
            .mode(0o770)
            .create(&cur_path)
            .ignore_already_exists()?;

        for component in iter {
            cur_path.push(component);
            match fs::symlink_metadata(&cur_path) {
                // If we get anything, this is already set up or expunged
                Ok(_) => continue,
                // ELOOP means something garbage collected this path meanwhile,
                // so there's nothing left to do.
                Err(e) if Some(nix::libc::ELOOP) == e.raw_os_error() => {
                    return Ok(());
                },

                Err(e) if io::ErrorKind::NotFound == e.kind() => {
                    cur_path.set_extension("d");
                    match fs::DirBuilder::new()
                        .mode(0o770)
                        .create(&cur_path)
                        .ignore_already_exists()
                    {
                        Ok(_) => (),
                        // ELOOP = someone garbage collected a parent directory
                        // away
                        Err(e)
                            if Some(nix::libc::ELOOP) == e.raw_os_error() =>
                        {
                            return Ok(());
                        },
                        // Other errors unexpected (we already ignored EEXIST)
                        Err(e) => return Err(e),
                    }

                    let target = cur_path.file_name().unwrap().to_owned();
                    cur_path.set_file_name(component);
                    match std::os::unix::fs::symlink(&target, &cur_path) {
                        Ok(()) => (),
                        Err(e) if
                            // Lost race with another process to create the
                            // same file
                            io::ErrorKind::AlreadyExists == e.kind() ||
                            // Parent directory was expunged
                            Some(nix::libc::ELOOP) == e.raw_os_error() => (),
                        Err(e) => return Err(e),
                    }
                },

                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    /// Garbage-collect this scheme.
    ///
    /// All items with an id less than `expunge_less_than` will be expunged
    /// implicitly. `tmp` is used as a staging directory for gravestones.
    ///
    /// Besides expunging individual items, this will also expunge entire
    /// branches of the file system tree which are fully populated but contain
    /// no existing items.
    ///
    /// `garbage` is used as a staging area for recursive directory deletion.
    pub fn gc(
        &self,
        tmp: &Path,
        garbage: &Path,
        expunge_less_than: u32,
    ) -> Result<(), Error> {
        let mut path = self.root.to_owned();
        for i in 0..=3 {
            path.push(str::from_utf8(&[self.prefix, b'0' + i]).unwrap());
            if path.is_dir() {
                if 0 == i {
                    self.gc_leaf(&mut path, tmp, 0, expunge_less_than, true)?;
                } else {
                    self.gc_branch(
                        &mut path,
                        tmp,
                        garbage,
                        0,
                        8 * (i as u32),
                        expunge_less_than,
                        true,
                    )?;
                }
            }
            path.pop();
        }

        Ok(())
    }

    /// For each item under `path`, recursively continue garbage collection,
    /// and remove branches that are full but have no existing items.
    ///
    /// `shift` gives the bit-shift to the byte this call is to iterate over.
    ///
    /// All items below `expunge_less_than` are to be expunged.
    ///
    /// If `top` is true, this will not short-circuit if the entire branch is
    /// below `expunge_less_than`.
    fn gc_branch(
        &self,
        path: &mut PathBuf,
        tmp: &Path,
        garbage: &Path,
        id_prefix: u32,
        shift: u32,
        expunge_less_than: u32,
        top: bool,
    ) -> Result<bool, Error> {
        // If this entire branch is to be pruned, allow expungement, and no
        // need to expunge individual items.
        if !top && (id_prefix | ((256 << shift) - 1)) < expunge_less_than {
            return Ok(true);
        }

        let mut any_exist = false;
        let mut all_allocated = true;

        for i in 0..=255 {
            let name = format!("{:02x}", i);
            path.push(&name);

            // See what the status of the symlink is
            let (allocated, mut exists) = match fs::metadata(&path) {
                Ok(_) => (true, true),
                Err(e) if Some(nix::libc::ELOOP) == e.raw_os_error() => {
                    (true, false)
                },
                Err(e) if io::ErrorKind::NotFound == e.kind() => (false, false),
                Err(e) => return Err(e.into()),
            };

            if exists {
                path.set_extension("d");

                let subprefix = id_prefix | (i << shift);

                // Recur into the directory to see if we can remove it
                // completely.
                let can_remove = if 8 == shift {
                    self.gc_leaf(
                        path,
                        tmp,
                        subprefix,
                        expunge_less_than,
                        false,
                    )?
                } else {
                    self.gc_branch(
                        path,
                        tmp,
                        garbage,
                        subprefix,
                        shift - 8,
                        expunge_less_than,
                        false,
                    )?
                };
                path.set_file_name(&name);

                if can_remove {
                    self.expunge_path(subprefix, path, tmp)?;
                    exists = false;
                }
            }

            // If the path is allocated but non-existent, make sure the
            // directory itself has been removed.
            if allocated && !exists {
                path.set_extension("d");
                file_ops::delete_atomically(&path, garbage)
                    .ignore_not_found()?;
            }

            path.pop();
            any_exist |= exists;
            all_allocated &= allocated;

            // Slot 0 of top-level is never allocated (since it would go into a
            // different tree).
            if !allocated && (i != 0 || !top) {
                break;
            }
        }

        Ok(!any_exist && all_allocated)
    }

    /// For each item under `path`, expunge it if its id is less than
    /// `expunge_less_than`.
    ///
    /// On success, return whether the directory is fully populated and all
    /// items are expunged.
    ///
    /// If `top` is true, this will not short-circuit if the entire branch is
    /// below `expunge_less_than`.
    fn gc_leaf(
        &self,
        path: &mut PathBuf,
        tmp: &Path,
        id_prefix: u32,
        expunge_less_than: u32,
        top: bool,
    ) -> Result<bool, Error> {
        // If this entire branch is to be pruned, allow expungement, and no
        // need to expunge individual items.
        if !top && (id_prefix | 0xFF) < expunge_less_than {
            return Ok(true);
        }

        path.push("alloc");
        let fully_allocated = match fs::metadata(&path) {
            Err(e) => Some(nix::libc::ELOOP) == e.raw_os_error(),
            Ok(_) => false,
        };
        path.pop();

        let mut expunged_paths = Vec::new();
        let mut all_gone = true;

        // Iterate descending so that we find unallocated items more quickly
        for i in (0..=255).rev() {
            path.push(format!("{:02x}.{}", i, self.extension));
            let (allocated, mut exists) = match fs::metadata(&path) {
                Ok(_) => (true, true),
                Err(e) if Some(nix::libc::ELOOP) == e.raw_os_error() => {
                    (true, false)
                },
                Err(e) if io::ErrorKind::NotFound == e.kind() => (false, false),
                Err(e) => return Err(e.into()),
            };

            if exists && (id_prefix | i) < expunge_less_than {
                self.expunge_path(id_prefix | i, path, tmp)?;
                exists = false;
            }

            if allocated && !exists {
                expunged_paths.push(path.clone());
            }

            path.pop();

            // If the slot is unallocated or still holds an existing item, we
            // can't GC this leaf at all.
            //
            // ID 0 is never allocated, but we don't need to special-case that
            // since the top-level "X0" directory cannot be garbage-collected
            // anyway.
            if !allocated && !fully_allocated {
                return Ok(false);
            }

            all_gone &= !exists;
        }

        if !all_gone && !expunged_paths.is_empty() {
            // We can't fully GC this branch, but we can prune the dead leaves
            // at least.

            // Ensure the whole directory is marked allocated
            if !fully_allocated {
                path.push("alloc");
                self.expunge_path(id_prefix, path, tmp)?;
                path.pop();
            }

            for path in expunged_paths {
                let _ = fs::remove_file(path);
            }
        }

        Ok(all_gone)
    }
}

/// Search for the first free ID.
///
/// `guess` is a ID which is believed to be the last allocated ID, or 1 if no
/// IDs are allocated. The algorithm produces the same result regardless of
/// the value of `guess`, but it is most efficient when it is correct.
///
/// `exists` tests whether the ID is currently allocated. It does not need to
/// return consistent results, though the algorithm assumes it at least has the
/// monotonic properties of IMAP IDs.
///
/// The returned ID is a suggested starting point for linear probing. In the
/// presence of concurrent modification to the ID allocations, it may well
/// already be allocated.
fn probe_for_first_id(guess: u32, exists: impl Fn(u32) -> bool) -> u32 {
    let mut maximum_used = 0u32;
    let mut minimum_free = u32::MAX;

    // Exponentially probe to find a better "free" endpoint than u32::MAX and
    // do discover more allocated UIDs along the way
    let mut exp_probe = 1u32;
    while exp_probe != 0 {
        let probe = guess.saturating_add(exp_probe);
        if u32::MAX == probe {
            // Further probing is useless since we've hit the end of the id space
            break;
        }

        exp_probe <<= 1;

        if exists(probe) {
            maximum_used = probe;
        } else {
            minimum_free = probe;
            break;
        }
    }

    // If probing didn't find any used slots, see if the guess was exactly
    // right
    if 0 == maximum_used && exists(guess) {
        maximum_used = guess;
    }

    // Binary search until we find the ID frontier
    while maximum_used < minimum_free - 1 {
        let mid = ((maximum_used as u64 + minimum_free as u64) / 2) as u32;
        if exists(mid) {
            maximum_used = mid;
        } else {
            minimum_free = mid;
        }
    }

    // Suggest starting one beyond the maximum existing ID found to be more
    // conservative in the presence of concurrent modification
    maximum_used.saturating_add(1)
}

#[cfg(test)]
mod test {
    use proptest::prelude::*;

    use super::*;

    fn test_probe_for_first_id(guess: u32, last_used: u32) -> u32 {
        probe_for_first_id(guess, |u| u <= last_used)
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 65536,
            ..ProptestConfig::default()
        })]
        #[test]
        fn id_probing_fuzz(guess in 1u32.., last_used in 0u32..) {
            prop_assert_eq!(last_used.saturating_add(1),
                            test_probe_for_first_id(guess, last_used));
        }
    }

    #[test]
    fn id_probing_special_cases() {
        assert_eq!(1, test_probe_for_first_id(1, 0));
        assert_eq!(2, test_probe_for_first_id(1, 1));
        assert_eq!(3, test_probe_for_first_id(1, 2));
        assert_eq!(1001, test_probe_for_first_id(1000, 1000));
        assert_eq!(1002, test_probe_for_first_id(1000, 1001));
        assert_eq!(1011, test_probe_for_first_id(1000, 1010));
        assert_eq!(u32::MAX, test_probe_for_first_id(1, u32::MAX));
    }

    #[test]
    fn test_path_for_id() {
        let scheme = HierIdScheme {
            root: "".as_ref(),
            prefix: b'z',
            extension: "eml",
        };

        assert_eq!(
            ["z0", "01.eml"].iter().collect::<PathBuf>(),
            scheme.access_path_for_id(1).0
        );
        assert_eq!(
            ["z0", "ff.eml"].iter().collect::<PathBuf>(),
            scheme.access_path_for_id(255).0
        );
        assert_eq!(
            ["z1", "30", "39.eml"].iter().collect::<PathBuf>(),
            scheme.access_path_for_id(12345).0
        );
        assert_eq!(
            ["z2", "01", "e2", "40.eml"].iter().collect::<PathBuf>(),
            scheme.access_path_for_id(123456).0
        );
        assert_eq!(
            ["z3", "01", "00", "00", "00.eml"]
                .iter()
                .collect::<PathBuf>(),
            scheme.access_path_for_id(16777216).0
        );
        assert_eq!(
            ["z3", "ff", "ff", "ff", "ff.eml"]
                .iter()
                .collect::<PathBuf>(),
            scheme.access_path_for_id(4294967295).0
        );
    }

    #[test]
    fn test_hier_id_scheme() {
        let root = tempfile::TempDir::new().unwrap();
        let dummy = root.path().join("dummy");

        let scheme = HierIdScheme {
            prefix: b'x',
            extension: "foo",
            root: root.path(),
        };

        const N: u32 = 70_000;

        for i in 1..N {
            if 1 == i % 1024 {
                // Recreate the dummy file every 1024 messages since some file
                // systems have link count limits we'll run into otherwise.
                let _ = fs::remove_file(&dummy);
                file_ops::spit(
                    root.path(),
                    &dummy,
                    false,
                    0o600,
                    "dummy".as_bytes(),
                )
                .unwrap();
            }

            assert_eq!(i, scheme.first_unallocated_id());
            assert!(scheme.emplace(&dummy, i).unwrap());
        }

        for i in 1..N {
            assert!(scheme.is_allocated(i));
        }
        assert!(!scheme.is_allocated(N));

        assert!(root.path().join("x1/02/00.foo").is_file());
        scheme.expunge(512, root.path()).unwrap();
        assert!(!root.path().join("x1/02/00.foo").is_file());
        // The gravestone is still there
        assert!(fs::symlink_metadata(root.path().join("x1/02/00.foo")).is_ok());

        assert!(root.path().join("x1/0b/b8.foo").is_file());
        scheme.expunge(3000, root.path()).unwrap();
        assert!(!root.path().join("x1/0b/b8.foo").is_file());
        // The gravestone is still there
        assert!(fs::symlink_metadata(root.path().join("x1/0b/b8.foo")).is_ok());

        scheme.expunge(N - 1, root.path()).unwrap();

        // Expunge the whole page starting at 1024 (x1/04/*)
        for i in 1024..1024 + 256 {
            scheme.expunge(i, root.path()).unwrap();
        }

        // x1/04 and x1/01 should get remove entirely. The contents of x0 and
        // some of x1/02 get expunged. 01/0b/b8.foo's gravestone is removed,
        // but the directory containing it is marked fully allocated. N-1's
        // gravestone *must not* be removed since that branch is not completely
        // allocated.
        scheme.gc(root.path(), root.path(), 550).unwrap();
        assert!(!root.path().join("x0/80.foo").is_file());
        assert!(!root.path().join("x1/02/00.foo").is_file());
        assert!(!root.path().join("x1/01").is_dir());
        assert!(!root.path().join("x1/01.d").is_dir());
        assert!(!root.path().join("x1/04").is_dir());
        assert!(!root.path().join("x1/04.d").is_dir());
        // Cross-check that the above assertions make sense
        assert!(root.path().join("x1/02").is_dir());
        assert!(root.path().join("x1/02.d").is_dir());
        assert!(fs::symlink_metadata(root.path().join("x1/0b/b8.foo")).is_err());

        assert!(scheme.is_allocated(1));
        assert!(scheme.is_allocated(256));
        assert!(scheme.is_allocated(512));
        assert!(scheme.is_allocated(513));
        assert!(scheme.is_allocated(1024));
        assert!(scheme.is_allocated(3000));
        assert!(scheme.is_allocated(N - 1));
        assert!(!scheme.is_allocated(N));

        // Test that overwriting fails in a variety of cases
        assert!(!scheme.emplace(&dummy, N - 1).unwrap());
        assert!(!scheme.emplace(&dummy, 549).unwrap());
        assert!(!scheme.emplace(&dummy, 256).unwrap());

        // Re-expunging the expunged values doesn't fail
        scheme.expunge(N - 1, root.path()).unwrap();
        scheme.expunge(549, root.path()).unwrap();
        scheme.expunge(256, root.path()).unwrap();

        // Ensure we didn't leak any staging files
        for entry in fs::read_dir(root.path()).unwrap() {
            let entry = entry.unwrap();
            assert!(!entry
                .file_name()
                .to_string_lossy()
                .starts_with("expunge"));
        }
    }

    #[test]
    fn test_emplace_many() {
        use rayon::prelude::*;

        [
            0u32, 1, 128, 254, 255, 256, 257, 510, 511, 512, 513, 65534, 65535,
            65536, 131071, 131072,
        ]
        .par_iter()
        .for_each(|&num_prefix_messages| {
            for &num_new_messages in &[2u32, 255, 256, 257, 1024, 65536] {
                do_test_emplace_many(num_prefix_messages, num_new_messages);
            }
        });
    }

    fn do_test_emplace_many(num_prefix_messages: u32, num_new_messages: u32) {
        let root = tempfile::TempDir::new().unwrap();
        let scheme = HierIdScheme {
            prefix: b'x',
            extension: "foo",
            root: root.path(),
        };

        for i in 1..=num_prefix_messages {
            let dummy = root.path().join(format!("dummy{}", i));
            fs::File::create(&dummy).unwrap();
            assert!(scheme.emplace(&dummy, i).unwrap());
        }

        let mut path_bufs = Vec::new();
        for i in 0..num_new_messages {
            let dummy = root.path().join(format!("newdummy{}", i));
            fs::File::create(&dummy).unwrap();
            path_bufs.push(dummy);
        }

        let paths: Vec<&Path> =
            path_bufs.iter().map(|pb| pb as &Path).collect();

        let base = scheme.emplace_many(&paths, root.path(), 1 << 30).unwrap();

        // All values from 1 to base + num_new_messages should be allocated now
        let fast_verify_end = base.saturating_sub(500).max(1);
        for i_100 in 1..(fast_verify_end / 100).max(1) {
            let i = i_100 * 100;
            assert!(scheme.is_allocated(i), "ID {} not allocated", i);
        }

        for i in fast_verify_end..base + num_new_messages {
            assert!(scheme.is_allocated(i), "ID {} not allocated", i);
        }
    }

    // #[ignored] --- this test takes a really long time since it creates over
    // 40 million files over the course of its life. Run the test manually if
    // interesting changes are made to the implementation.
    //
    // This also takes up a huge amount of space so manually setting TMPDIR to
    // something appropriate for the test is also advisable.
    //
    // In development, this required using a separate disk with the XFS
    // filesystem (since ext4 runs out of inodes) and took around an hour to
    // run, peaking at over 24GB of disk usage. On XFS, even after deleting all
    // the files, 14GB of usage remained, presumably in inode tables or extents
    // or something.
    //
    // Also note that the test process exits before the tempdir can be cleaned
    // up, so doing so is manual.
    #[test]
    #[ignore]
    fn test_hier_id_scheme_huge() {
        let root = tempfile::TempDir::new().unwrap();
        let dummy = root.path().join("dummy");

        let scheme = HierIdScheme {
            prefix: b'x',
            extension: "foo",
            root: root.path(),
        };

        const N: u32 = 20_000_000;

        for i in 1..N {
            if 1 == i % 1024 {
                // Recreate the dummy file every 1024 messages since some file
                // systems have link count limits we'll run into otherwise.
                let _ = fs::remove_file(&dummy);
                file_ops::spit(
                    root.path(),
                    &dummy,
                    false,
                    0o600,
                    "dummy".as_bytes(),
                )
                .unwrap();
            }

            assert_eq!(i, scheme.first_unallocated_id());
            assert!(scheme.emplace(&dummy, i).unwrap());
        }

        for i in 1..N {
            assert!(scheme.is_allocated(i));
        }

        // Expunge everything but powers of 7 and the last 100 items
        for i in 1..N - 100 {
            if !is_power_of_7(i) {
                scheme.expunge(i, root.path()).unwrap();
            }
        }

        scheme.gc(root.path(), root.path(), 0).unwrap();

        // Ensure we kept exactly the messages we wanted
        for i in 1..N {
            assert_eq!(
                i >= N - 100 || is_power_of_7(i),
                scheme.access_path_for_id(i).assume_exists().is_file(),
                "Unexpected value for {}",
                i
            );
        }
    }

    fn is_power_of_7(mut n: u32) -> bool {
        while n > 1 && n % 7 == 0 {
            n /= 7;
        }

        1 == n
    }
}
