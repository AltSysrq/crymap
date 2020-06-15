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

use std::convert::TryInto;
use std::fmt;
use std::num::{NonZeroU32, NonZeroU64};
use std::path::PathBuf;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::support::error::Error;
use crate::support::safe_name::is_safe_name;

/// A change identifier.
///
/// Change identifiers are assigned sequentially, starting from 1, for all
/// metadata changes in a mailbox. They are one of two components of a
/// `Modseq`.
///
/// Cid 0, while not assigned to any specific change, represents the creation
/// of a message.
///
/// Though this contains a `u32`, only values between `MIN` and `MAX` are valid
/// (and `GENESIS` when referring to the instant a UID is allocated) since RFC
/// 5162 felt the need to accommodate defective environments lacking proper
/// 64-bit integers.
#[derive(
    Deserialize,
    Serialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
#[serde(transparent)]
pub struct Cid(pub u32);

impl Cid {
    pub const GENESIS: Self = Cid(0);
    pub const MIN: Self = Cid(1);
    /// This could be increased to `(1 << 32)`, but the overhead of using
    /// real multiplication and division is pretty small, and this way the
    /// base-10 integers IMAP sends over the wire are readable (in combination
    /// with a `Uid` to form a `Modseq`).
    pub const END: Self = Cid(4_000_000_000);
    pub const MAX: Self = Cid(Cid::END.0 - 1);

    pub fn next(self) -> Option<Self> {
        if self < Cid::MAX {
            Some(Cid(self.0 + 1))
        } else {
            None
        }
    }
}

/// Uniquely identifies a message within a single mailbox.
///
/// UIDs start at 1 and increase monotonically as messages are added to the
/// mailbox. UIDs are never reused.
///
/// RFC 3501 does not actually require them to start at 1. The benefits of
/// starting from 0 are pretty minimal though and doing so has the potential to
/// break clients that assume UIDs start from 1 like sequence numbers.
///
/// In this implementation, UIDs are assigned strictly sequentially.
#[derive(
    Deserialize,
    Serialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
#[serde(transparent)]
pub struct Uid(pub NonZeroU32);

impl Uid {
    // Unsafe because new() isn't const for some reason
    pub const MIN: Self = unsafe { Uid(NonZeroU32::new_unchecked(1)) };
    // The maximum possible UID value is limited by the 63-bit `Modseq` space
    // and the value the UID is multiplied with.
    pub const MAX: Self = unsafe {
        Uid(NonZeroU32::new_unchecked(
            (((1u64 << 63) - 1) / (Cid::END.0 as u64)) as u32,
        ))
    };

    pub fn of(uid: u32) -> Option<Self> {
        NonZeroU32::new(uid).map(Uid).filter(|&u| u <= Uid::MAX)
    }

    pub fn next(self) -> Option<Self> {
        if Uid::MAX == self {
            None
        } else {
            Some(Uid(NonZeroU32::new(self.0.get() + 1).unwrap()))
        }
    }

    pub fn saturating_next(self) -> Self {
        self.next().unwrap_or(Uid::MAX)
    }

    #[cfg(test)]
    pub fn u(uid: u32) -> Self {
        Uid::of(uid).unwrap()
    }
}

/// An abomination.
///
/// The sequence number of a message is one plus the number of non-expunged
/// messages that have a UID less than it, counting based on a point-in-time
/// snapshot instead of the real message state.
#[derive(
    Deserialize,
    Serialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
#[serde(transparent)]
pub struct Seqnum(pub NonZeroU32);

impl Seqnum {
    // Unsafe because new() isn't const for some reason
    pub const MIN: Self = unsafe { Seqnum(NonZeroU32::new_unchecked(1)) };
    pub const MAX: Self =
        unsafe { Seqnum(NonZeroU32::new_unchecked(u32::MAX)) };

    pub fn of(seqnum: u32) -> Option<Self> {
        NonZeroU32::new(seqnum).map(Seqnum)
    }

    #[cfg(test)]
    pub fn u(seqnum: u32) -> Self {
        Seqnum::of(seqnum).unwrap()
    }

    pub fn to_index(self) -> usize {
        let u: Result<usize, _> = self.0.get().try_into();
        u.unwrap() - 1
    }

    pub fn from_index(ix: usize) -> Self {
        Seqnum::of((ix + 1).try_into().unwrap()).unwrap()
    }
}

/// A CONDSTORE/QRESYNC "modifier sequence" number.
///
/// In this implementation, this is a 2-element vector clock of a UID and a
/// CID, which allows message insertions to be more weakly-ordered with respect
/// to metadata changes (which is important so that mail delivery does not need
/// to deal with loading the metadata just to add its message).
///
/// A message with a given UID is said to come into existence at the moment
/// identified by `Modseq::new(uid, Cid::GENESIS)`. Each change takes place
/// with a UID equalling the largest known UID at the time and the CID assigned
/// to that particular change.
///
/// While this is modelled as a vector clock, it is actually strictly ordered
/// with respect to its integer value, as required by QRESYNC. That is, given
/// any two `Modseq` values in the same mailbox, there will never be a case
/// where `a.uid() > b.uid()` but `a.cid() < b.cid()`, except for the case of
/// message insertions whose CID is 0. While those are technically "concurrent"
/// with all metadata updates, we do not need to handle that according to
/// vector clock interpretation because the client will never be given a
/// `HIGHESTMODSEQ` with a CID of 0 unless there have been no metadata
/// operations at all.
///
/// The reported `HIGHESTMODSEQ` always has the UID of the last seen message
/// and the CID of the last seen metadata operation.
///
/// The "primordial" modifier sequence number, used for a brand new mailbox, is
/// not representable by this structure. It is sent over the wire as 1.
#[derive(
    Deserialize,
    Serialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
#[serde(transparent)]
pub struct Modseq(NonZeroU64);

impl Modseq {
    // Unsafe because NonZeroU64::new() is non-const.
    pub const MIN: Self =
        unsafe { Modseq(NonZeroU64::new_unchecked(Cid::END.0 as u64)) };

    pub fn of(raw: u64) -> Option<Self> {
        NonZeroU64::new(raw)
            .map(Modseq)
            .filter(|&m| m >= Modseq::MIN)
    }

    pub fn new(uid: Uid, cid: Cid) -> Self {
        Modseq(
            NonZeroU64::new(
                (uid.0.get() as u64) * (Cid::END.0 as u64) + cid.0 as u64,
            )
            .unwrap(),
        )
    }

    pub fn raw(self) -> NonZeroU64 {
        self.0
    }

    pub fn uid(self) -> Uid {
        Uid::of((self.0.get() / (Cid::END.0 as u64)) as u32).unwrap()
    }

    pub fn cid(self) -> Cid {
        Cid((self.0.get() % (Cid::END.0 as u64)) as u32)
    }

    pub fn combine(self, other: Self) -> Self {
        Modseq::new(self.uid().max(other.uid()), self.cid().max(other.cid()))
    }

    pub fn with_uid(self, uid: Uid) -> Self {
        Modseq::new(uid, self.cid())
    }

    pub fn with_cid(self, cid: Cid) -> Self {
        Modseq::new(self.uid(), cid)
    }

    pub fn next(self) -> Option<Self> {
        self.cid().next().map(|cid| self.with_cid(cid))
    }
}

/// A message flag.
///
/// System flags are represented as top-level enum values. Keywords are in the
/// `Keyword` case.
///
/// The `Display` format of this type is the exact string value that would be
/// sent over the wire. `FromStr` does the reverse conversion, and also
/// understands non-standard casing of the system flags.
///
/// `\Recent` is not represented by this enum since it isn't _really_ a flag.
#[derive(
    Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum Flag {
    Answered,
    Deleted,
    Draft,
    Flagged,
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

/// Holder for common paths used pervasively through a process.
#[derive(Clone, Debug)]
pub struct CommonPaths {
    /// The per-user temporary directory.
    ///
    /// This directory is used to stage files before moving them into their
    /// final home. Files orphaned for over 24hr are cleaned up automatically.
    pub tmp: PathBuf,
    /// The per-user garbage directory.
    ///
    /// Whole directory trees are moved here to simulate an atomic, instant
    /// deletion. Usually, the process that does that move also deletes the
    /// directory tree from here itself. Orphans are cleaned up aggressively.
    pub garbage: PathBuf,
}
