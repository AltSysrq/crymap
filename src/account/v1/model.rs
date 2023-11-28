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

use std::fmt;
use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};

use crate::account::model::{Modseq, Uid};

/// A change identifier.
///
/// Change identifiers are assigned sequentially, starting from 1, for all
/// metadata changes in a mailbox. They are one of two components of a
/// `V1Modseq`.
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

/// The slightly quirky variant of `Modseq` used by the V1 implementation.
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
    Deserialize, Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
#[serde(transparent)]
pub struct V1Modseq(NonZeroU64);

impl V1Modseq {
    // Unsafe because NonZeroU64::new() is non-const.
    pub const MIN: Self =
        unsafe { Self(NonZeroU64::new_unchecked(Cid::END.0 as u64)) };

    pub fn of(raw: u64) -> Option<Self> {
        NonZeroU64::new(raw).map(Self).filter(|&m| m >= Self::MIN)
    }

    pub fn import(modseq: Modseq) -> Option<Self> {
        Self::of(modseq.raw())
    }

    pub fn new(uid: Uid, cid: Cid) -> Self {
        Self(
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
        Self::new(self.uid().max(other.uid()), self.cid().max(other.cid()))
    }

    pub fn with_uid(self, uid: Uid) -> Self {
        Self::new(uid, self.cid())
    }

    pub fn with_cid(self, cid: Cid) -> Self {
        Self::new(self.uid(), cid)
    }

    pub fn next(self) -> Option<Self> {
        self.cid().next().map(|cid| self.with_cid(cid))
    }
}

impl fmt::Debug for V1Modseq {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Modseq({}:{}={})",
            self.uid().0.get(),
            self.cid().0,
            self.0.get()
        )
    }
}

impl From<V1Modseq> for Modseq {
    fn from(m: V1Modseq) -> Self {
        Self::of(m.raw().get())
    }
}

impl From<Option<V1Modseq>> for Modseq {
    fn from(m: Option<V1Modseq>) -> Self {
        Self::of(m.map(|m| m.raw().get()).unwrap_or(1))
    }
}
