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

//! Support for storing message flags.
//!
//! Flag storage is totally transparent. Each flag is simply a cleartext bitset
//! in its own file named exactly after the flag, with one byte per message
//! (which makes updates trivially atomic). Flags beyond the end of the file
//! are implicitly 0. The \Recent flag is inverted, with 0 indicating set and 1
//! indicating clear.
//!
//! Only permanent flags are supported. RFC 3501 describes \Recent as a
//! "session flag", which implies that it is not shared between sessions or
//! persisted, but does so immediately after describing how it is shared
//! between sessions and persisted, so we treat it as a normal permanent flag.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::{self, Seek, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::str::FromStr;

const PAGE_SIZE: u32 = 1024;
const PAGE_USIZE: usize = PAGE_SIZE as usize;
const FLAG_TOGGLED: u8 = 1;
const FLAG_DEFAULT: u8 = 0;
const FLAG_UNKNOWN: u8 = 2;
const REFRESH_INTERVAL_SECS: u64 = 5;

use super::message_store::Uid;
use crate::support::error::Error;
use crate::support::file_ops::ReadUninterruptibly;
use crate::support::safe_name::is_safe_name;

/// A message flag.
///
/// System flags are represented as top-level enum values. Keywords are in the
/// `Keyword` case.
///
/// The `Display` format of this type is the exact string value that would be
/// sent over the wire. `FromStr` does the reverse conversion, and also
/// understands non-standard casing of the system flags.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Flag {
    Answered,
    Deleted,
    Draft,
    Flagged,
    Recent,
    Seen,
    Keyword(String),
}

impl fmt::Display for Flag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Flag::Answered => write!(f, "\\Answered"),
            &Flag::Deleted => write!(f, "\\Deleted"),
            &Flag::Draft => write!(f, "\\Draft"),
            &Flag::Flagged => write!(f, "\\Flagged"),
            &Flag::Recent => write!(f, "\\Recent"),
            &Flag::Seen => write!(f, "\\Seen"),
            &Flag::Keyword(ref kw) => write!(f, "{}", kw),
        }
    }
}

impl fmt::Debug for Flag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        <Flag as fmt::Display>::fmt(self, f)
    }
}

impl FromStr for Flag {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        if s.eq_ignore_ascii_case("\\answered") {
            Ok(Flag::Answered)
        } else if s.eq_ignore_ascii_case("\\deleted") {
            Ok(Flag::Deleted)
        } else if s.eq_ignore_ascii_case("\\draft") {
            Ok(Flag::Draft)
        } else if s.eq_ignore_ascii_case("\\flagged") {
            Ok(Flag::Flagged)
        } else if s.eq_ignore_ascii_case("\\recent") {
            Ok(Flag::Recent)
        } else if s.eq_ignore_ascii_case("\\seen") {
            Ok(Flag::Seen)
        } else if s.starts_with("\\") {
            Err(Error::NxFlag)
        } else if is_safe_name(s) {
            Ok(Flag::Keyword(s.to_owned()))
        } else {
            Err(Error::UnsafeName)
        }
    }
}

/// Stores an association between message UIDs and flags applied to them.
pub struct FlagStore {
    root: PathBuf,
    read_only: bool,
    flags: HashMap<Flag, Box<FlagTable>>,
}

impl FlagStore {
    /// Create a new `FlagStore` whose flags are stored in files under `root`.
    pub fn new(root: PathBuf, read_only: bool) -> Self {
        let mut store = FlagStore {
            root,
            read_only,
            flags: HashMap::new(),
        };
        // Always load Recent in since it needs to default to positive
        let _ = store.get_flag(&Flag::Recent);
        store
    }

    /// Scan the flags directory for flag files that haven't been seen yet.
    ///
    /// Any new files found are added as flags (assuming their names are
    /// understood) and become candidates for return values from
    /// `get_flags_on_message()`.
    pub fn refresh_flags(&mut self) -> Result<(), Error> {
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let flag = entry.file_name().to_str().and_then(|s| s.parse().ok());
            if let Some(flag) = flag {
                let _ = self.get_flag(&flag);
            }
        }

        Ok(())
    }

    /// Returns an iterator to the flags currently known to the store.
    pub fn iter_flags<'a>(&'a self) -> impl Iterator<Item = &'a Flag> + 'a {
        self.flags.keys()
    }

    /// Clear all flag caches.
    pub fn clear_cache(&mut self) {
        for tab in self.flags.values_mut() {
            tab.clear_cache();
        }
    }

    /// Return an iterator over all flags on the given message.
    ///
    /// Only flags that have been discovered through direct interaction with
    /// this `FlagStore` or by `refresh_flags()` can be found by this call.
    pub fn get_flags_on_message<'a>(
        &'a mut self,
        uid: Uid,
    ) -> impl Iterator<Item = &'a Flag> + 'a {
        self.flags.iter_mut().filter_map(move |(k, tab)| {
            if tab.test_d(uid).unwrap_or(false) {
                Some(k)
            } else {
                None
            }
        })
    }

    /// Set the status of each flag in `flags` to `val` for the given message.
    pub fn write_flags_on_message<'a>(
        &mut self,
        uid: Uid,
        flags: impl IntoIterator<Item = &'a Flag>,
        val: bool,
    ) -> Result<(), Error> {
        for flag in flags {
            self.get_flag(flag).set(uid, val)?;
        }

        Ok(())
    }

    /// Write a new value of the chosen flag for every message in `uids`.
    pub fn write_flag(
        &mut self,
        flag: &Flag,
        val: bool,
        uids: impl IntoIterator<Item = Uid>,
    ) -> Result<(), Error> {
        let flag = self.get_flag(flag);
        for uid in uids {
            flag.set(uid, val)?;
        }
        Ok(())
    }

    /// Return a predicate which tests whether arbitrary UIDs have the given
    /// flag.
    pub fn flag_predicate<'a>(
        &'a mut self,
        flag: &Flag,
    ) -> impl FnMut(Uid) -> bool + 'a {
        let flag = self.get_flag(flag);
        move |uid| flag.test_d(uid).unwrap_or(false)
    }

    fn get_flag(&mut self, flag: &Flag) -> &mut FlagTable {
        let root = &self.root;
        let read_only = self.read_only;
        self.flags.entry(flag.to_owned()).or_insert_with(|| {
            Box::new(FlagTable::new(
                root.join(flag.to_string()),
                read_only,
                &Flag::Recent == flag,
            ))
        })
    }
}

/// A file-backed table for a single flag.
///
/// Each message is classified into "flag set", "flag clear", or "unknown", the
/// last indicating that the message is not represented in the file.
///
/// Internally, this maintains a write-through cache of a single page of size
/// `PAGE_SIZE` which is always aligned to a multiple of `PAGE_SIZE` bytes.
/// `clear_cache()` must be called as needed to ensure that it does not fall
/// out of date.
///
/// The backing file is not opened until needed, and will not be created until
/// something writes to it. In the non-created state, a read which encounters a
/// missing file caches that miss for the whole table until the table is
/// written or the cache is cleared.
struct FlagTable {
    default: bool,
    path: PathBuf,
    read_only: bool,
    backing: Option<fs::File>,
    cached_nx: bool,
    current_page: [u8; PAGE_USIZE],
    page_offset: u32,
}

impl FlagTable {
    /// Open a new table.
    ///
    /// `read_only` controls whether any kind of modifications are permitted.
    ///
    /// The file is opened until it is needed.
    fn new(path: PathBuf, read_only: bool, default: bool) -> Self {
        FlagTable {
            default,
            path,
            read_only,
            backing: None,
            cached_nx: false,
            current_page: [FLAG_UNKNOWN; PAGE_USIZE],
            // Indicate nothing is loaded
            page_offset: u32::MAX,
        }
    }

    fn ensure_backing(
        &mut self,
        handle_nx: bool,
        create: bool,
    ) -> Result<bool, Error> {
        if self.backing.is_none() {
            match fs::OpenOptions::new()
                .create(!self.read_only && create)
                .read(true)
                .write(!self.read_only)
                .mode(0o600)
                .open(&self.path)
            {
                Ok(f) => self.backing = Some(f),
                Err(e) if io::ErrorKind::NotFound == e.kind() && handle_nx => {
                    return Ok(false)
                }
                Err(e) => return Err(e.into()),
            }
        }

        Ok(true)
    }

    /// Obtain the status of the given UID.
    fn test(&mut self, uid: Uid) -> Result<Option<bool>, Error> {
        if self.cached_nx {
            return Ok(None);
        }

        if !self.ensure_backing(true, false)? {
            self.cached_nx = true;
            return Ok(None);
        }

        let page = uid.0.get() / PAGE_SIZE * PAGE_SIZE;
        let backing = self.backing.as_mut().unwrap();
        if self.page_offset != page {
            backing.seek(io::SeekFrom::Start(page.into()))?;
            let nread = backing.read_uninteruptibly(&mut self.current_page)?;
            for x in &mut self.current_page[nread..] {
                *x = FLAG_UNKNOWN as u8;
            }
            self.page_offset = page;
        }

        match self.current_page[(uid.0.get() % PAGE_SIZE) as usize] {
            FLAG_DEFAULT => Ok(Some(self.default)),
            FLAG_TOGGLED => Ok(Some(!self.default)),
            FLAG_UNKNOWN => Ok(None),
            _ => Err(Error::CorruptFlag),
        }
    }

    /// Obtain the status of the given UID, replacing the unknown status with
    /// the default.
    fn test_d(&mut self, uid: Uid) -> Result<bool, Error> {
        self.test(uid).map(|opt| opt.unwrap_or(self.default))
    }

    /// Set the UID to the given status.
    fn set(&mut self, uid: Uid, val: bool) -> Result<(), Error> {
        if self.read_only {
            return Err(Error::MailboxReadOnly);
        }

        self.ensure_backing(false, true)?;
        self.cached_nx = false;

        let val = if val ^ self.default {
            FLAG_TOGGLED
        } else {
            FLAG_DEFAULT
        };

        let page = uid.0.get() / PAGE_SIZE * PAGE_SIZE;
        if self.page_offset == page {
            let ix = (uid.0.get() % PAGE_SIZE) as usize;
            self.current_page[ix] = val;
            // Nothing below this point is unknown now
            for x in &mut self.current_page[..ix] {
                *x = FLAG_DEFAULT;
            }
        }

        let backing = self.backing.as_mut().unwrap();
        backing.seek(io::SeekFrom::Start(uid.0.get().into()))?;
        backing.write_all(&[val])?;
        Ok(())
    }

    /// Invalidate the cache so that further operations will read the latest
    /// data.
    fn clear_cache(&mut self) {
        self.page_offset = u32::MAX;
        self.cached_nx = false;
    }
}

#[cfg(test)]
mod test {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn flag_table_ops() {
        let tmpdir = TempDir::new().unwrap();
        let path = tmpdir.path().join("flag");

        let mut fta = FlagTable::new(path.clone(), false, false);
        let mut ftb = FlagTable::new(path.clone(), true, false);

        // ftb is read only and won't create the file
        assert_eq!(None, ftb.test(Uid::u(42)).unwrap());
        assert_eq!(None, fta.test(Uid::u(42)).unwrap());

        fta.set(Uid::u(42), true).unwrap();
        assert_eq!(Some(true), fta.test(Uid::u(42)).unwrap());
        assert_eq!(Some(false), fta.test(Uid::u(1)).unwrap());

        // File non-existence is cached until we clear the cache
        assert_eq!(None, ftb.test(Uid::u(42)).unwrap());
        ftb.clear_cache();
        assert_eq!(Some(true), ftb.test(Uid::u(42)).unwrap());
        assert_eq!(Some(false), ftb.test(Uid::u(1)).unwrap());

        fta.set(Uid::u(1), true).unwrap();
        assert_eq!(Some(true), fta.test(Uid::u(1)).unwrap());
        assert_eq!(Some(false), ftb.test(Uid::u(1)).unwrap());
        ftb.clear_cache();
        assert_eq!(Some(true), ftb.test(Uid::u(1)).unwrap());
    }

    #[test]
    fn inverted_table_store() {
        let tmpdir = TempDir::new().unwrap();
        let path = tmpdir.path().join("flag");

        let mut fta = FlagTable::new(path, false, true);
        assert_eq!(None, fta.test(Uid::u(42)).unwrap());
        assert_eq!(true, fta.test_d(Uid::u(42)).unwrap());

        fta.set(Uid::u(1_000_000), false).unwrap();
        fta.set(Uid::u(1_000_001), true).unwrap();
        assert_eq!(Some(false), fta.test(Uid::u(1_000_000)).unwrap());
        assert_eq!(Some(true), fta.test(Uid::u(1_000_001)).unwrap());
        assert_eq!(Some(true), fta.test(Uid::u(42)).unwrap());
        assert_eq!(None, fta.test(Uid::u(2_000_000)).unwrap());
        assert_eq!(true, fta.test_d(Uid::u(2_000_000)).unwrap());
    }

    #[test]
    fn test_flag_store() {
        fn get_flags_on_message(store: &mut FlagStore, uid: u32) -> Vec<Flag> {
            let mut v = store
                .get_flags_on_message(Uid::u(uid))
                .cloned()
                .collect::<Vec<_>>();
            v.sort();
            v
        }

        let tmpdir = TempDir::new().unwrap();

        let mut storea = FlagStore::new(tmpdir.path().to_owned(), false);
        let mut storeb = FlagStore::new(tmpdir.path().to_owned(), true);

        assert_eq!(vec![Flag::Recent], get_flags_on_message(&mut storea, 1));
        assert_eq!(vec![Flag::Recent], get_flags_on_message(&mut storea, 3));

        storea
            .write_flag(&Flag::Recent, false, vec![Uid::u(1), Uid::u(3)])
            .unwrap();
        assert_eq!(Vec::<Flag>::new(), get_flags_on_message(&mut storea, 1));
        assert_eq!(vec![Flag::Recent], get_flags_on_message(&mut storea, 2));
        assert_eq!(Vec::<Flag>::new(), get_flags_on_message(&mut storea, 3));

        storea
            .write_flags_on_message(
                Uid::u(3),
                vec![&Flag::Flagged, &Flag::Keyword("plugh".to_owned())],
                true,
            )
            .unwrap();
        assert_eq!(
            vec![Flag::Flagged, Flag::Keyword("plugh".to_owned())],
            get_flags_on_message(&mut storea, 3)
        );

        storeb.refresh_flags().unwrap();
        assert_eq!(
            vec![Flag::Flagged, Flag::Keyword("plugh".to_owned())],
            get_flags_on_message(&mut storeb, 3)
        );

        {
            let mut pred = storeb.flag_predicate(&Flag::Recent);
            assert!(pred(Uid::u(2)));
            assert!(!pred(Uid::u(3)));
        }
    }
}
