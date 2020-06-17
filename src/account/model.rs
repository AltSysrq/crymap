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

use std::collections::BTreeMap;
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::marker::PhantomData;
use std::num::{NonZeroU32, NonZeroU64};
use std::ops::Bound::{Excluded, Included, Unbounded};
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
    Deserialize, Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
#[serde(transparent)]
pub struct Uid(pub NonZeroU32);

impl fmt::Debug for Uid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Uid({})", self.0.get())
    }
}

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

impl TryFrom<u32> for Uid {
    type Error = ();

    fn try_from(v: u32) -> Result<Self, ()> {
        Self::of(v).ok_or(())
    }
}

impl Into<u32> for Uid {
    fn into(self) -> u32 {
        self.0.get()
    }
}

/// An abomination.
///
/// The sequence number of a message is one plus the number of non-expunged
/// messages that have a UID less than it, counting based on a point-in-time
/// snapshot instead of the real message state.
///
/// (Rant) Sequence numbers are an abomination. They should have been EXPUNGEd
/// with the IMAP4 revision, compatibility with IMAP2 be damned. It's
/// inconvenient for the client as it forces the client to keep track of a set
/// of ever-changing identifiers. It's inconvenient for the server, which has
/// to emulate these ever-changing identifiers even though any practical server
/// implementation will have the messages stored by some fixed identifier. The
/// shifting of sequence numbers happens based on events in the protocol and
/// not in real time, so you can't even off-load it to a shared database since
/// each process needs to track the sequence numbers independently. The one and
/// only model where it is convenient for the server is in a system which
/// doesn't allow concurrent mailbox access and stores a list of message
/// references in a naïve list in memory, or which simply does a linear
/// iteration over an `mbox` file for every operation. UIDs should have wholly
/// replace sequence numbers and IMAP2 clients connecting to IMAP4 be left to
/// deal with the resulting holes in the sequence in whatever failure mode that
/// bring. (/Rant)
#[derive(
    Deserialize, Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash,
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

impl TryFrom<u32> for Seqnum {
    type Error = ();

    fn try_from(v: u32) -> Result<Self, ()> {
        Self::of(v).ok_or(())
    }
}

impl Into<u32> for Seqnum {
    fn into(self) -> u32 {
        self.0.get()
    }
}

impl fmt::Debug for Seqnum {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Seqnum({})", self.0.get())
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
    Deserialize, Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash,
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

impl fmt::Debug for Modseq {
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

/// A "sequence set range" of sequence numbers or UIDs.
///
/// Internally, this is maintained as a minimal sorted set of inclusive ranges.
/// It does not maintain information on the original fragmentation, ordering,
/// or duplication.
///
/// There is no support for removal.
///
/// The `Display` format puts this into minimal IMAP wire format. Note that
/// IMAP does not have a way to represent an empty sequence set. `Display`
/// produces an empty string in that case, which is invalid.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SeqRange<T> {
    parts: BTreeMap<u32, u32>,
    _t: PhantomData<T>,
}

impl<T: TryFrom<u32> + Into<u32> + PartialOrd> SeqRange<T> {
    /// Create a new, empty range.
    pub fn new() -> Self {
        SeqRange {
            parts: BTreeMap::new(),
            _t: PhantomData,
        }
    }

    /// Create a range containing just the given item.
    pub fn just(item: T) -> Self {
        let mut this = SeqRange::new();
        this.append(item);
        this
    }

    /// Create a range containing just a single, simple range.
    pub fn range(start: T, end: T) -> Self {
        let mut this = SeqRange::new();
        this.insert(start, end);
        this
    }

    /// Return whether this range is empty (invalid for IMAP wire format).
    pub fn is_empty(&self) -> bool {
        self.parts.is_empty()
    }

    /// Append a single item to this range.
    ///
    /// The item must be strictly greater than all other items already
    /// inserted.
    pub fn append(&mut self, item: T) {
        let item: u32 = item.into();

        if let Some(end) = self.parts.values_mut().next_back() {
            assert!(item > *end);

            if item == *end + 1 {
                *end = item;
                return;
            }
        }

        self.parts.insert(item, item);
    }

    /// Insert the given inclusive range (which must be in the correct order)
    /// into this sequence set.
    pub fn insert(&mut self, start_incl: T, end_incl: T) {
        assert!(end_incl >= start_incl);
        self.insert_raw(start_incl.into(), end_incl.into());
    }

    fn insert_raw(&mut self, start_incl: u32, mut end_incl: u32) {
        // If this range overlaps any later ranges, fuse them.
        loop {
            let following = self
                .parts
                .range((Excluded(start_incl), Unbounded))
                .next()
                .map(|(&start, &end)| (start, end));

            if let Some((following_start, following_end)) = following {
                if following_start - 1 <= end_incl {
                    end_incl = end_incl.max(following_end);
                    self.parts.remove(&following_start);
                    continue;
                }
            }

            break;
        }

        let preceding = self
            .parts
            .range((Unbounded, Included(end_incl)))
            .next_back()
            .map(|(&start, &end)| (start, end));
        if let Some((preceding_start, preceding_end)) = preceding {
            if preceding_end + 1 >= start_incl {
                // Overlap with the new range
                if start_incl < preceding_start {
                    self.parts.remove(&preceding_start);
                    self.parts.insert(start_incl, end_incl.max(preceding_end));
                } else {
                    self.parts
                        .insert(preceding_start, end_incl.max(preceding_end));
                }
                return;
            }
        }

        // No overlap
        self.parts.insert(start_incl, end_incl);
    }

    /// Return whether the given item is present in this set.
    pub fn contains(&self, v: T) -> bool {
        let v: u32 = v.into();
        self.parts
            .range(..=v)
            .next_back()
            .filter(|&(_, &end)| end >= v)
            .is_some()
    }

    /// Return an iterator to the items in this set.
    ///
    /// Invalid items are silently excluded.
    ///
    /// Items are delivered in strictly ascending order.
    pub fn items<'a>(&'a self) -> impl Iterator<Item = T> + 'a {
        self.parts
            .iter()
            .map(|(&start, &end)| (start, end))
            .flat_map(|(start, end)| (start..=end).into_iter())
            .filter_map(|v| T::try_from(v).ok())
    }

    /// Parse the IMAP-format of the sequence set.
    ///
    /// `splat` is used as the value of elements which specify `*`.
    pub fn parse(raw: &str, splat: T) -> Option<Self> {
        fn do_parse(r: &str, splat: u32) -> Option<u32> {
            if "*" == r {
                Some(splat)
            } else {
                r.parse().ok()
            }
        }

        let splat = splat.into();

        let mut this = Self::new();
        for part in raw.split(',') {
            let mut subs = part.split(':');
            match (subs.next(), subs.next(), subs.next()) {
                (Some(only), None, None) => {
                    let only = do_parse(only, splat)?;
                    this.insert_raw(only, only);
                }
                (Some(start), Some(end), None) => {
                    let start = do_parse(start, splat)?;
                    let end = do_parse(end, splat)?;
                    // RFC 3501 allows the endpoints to be in either order for
                    // some reason
                    this.insert_raw(start.min(end), end.max(start));
                }
                _ => return None,
            }
        }

        Some(this)
    }
}

impl<T> fmt::Display for SeqRange<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (ix, (&start, &end)) in self.parts.iter().enumerate() {
            let delim = if 0 == ix { "" } else { "," };

            if start == end {
                write!(f, "{}{}", delim, start)?;
            } else {
                write!(f, "{}{}:{}", delim, start, end)?;
            }
        }

        Ok(())
    }
}

impl fmt::Debug for SeqRange<Seqnum> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[Seqnum {}]", self)
    }
}

impl fmt::Debug for SeqRange<Uid> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[Uid {}]", self)
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

/// All information needed to produce a response to a `SELECT` or `EXAMINE`
/// command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectResponse {
    // ==================== RFC 3501 ====================
    /// The currently-defined flags. Used for both the `FLAGS` response and the
    /// `PERMANENTFLAGS` response-code. For the latter, `\*` must also be
    /// added.
    /// `* FLAGS (flags...)`
    /// `* OK [PERMANENTFLAGS (flags... \*)]`
    pub flags: Vec<Flag>,
    /// The number of messages that currently exist.
    /// `* exists EXISTS`
    pub exists: usize,
    /// The number of messages with the `\Recent` pseudo-flag.
    /// `* recent RECENT`
    pub recent: usize,
    /// The sequence number of the first message without the `\Seen` flag.
    /// `None` if all messages are seen. IMAP offers no way to indicate the
    /// latter state.
    /// `* OK [UNSEEN unseen]`
    pub unseen: Option<Seqnum>,
    /// The probable next UID.
    /// `* OK [UIDNEXT uidnext]`
    pub uidnext: Uid,
    /// The current UID validity.
    /// `* OK [UIDVALIDITY uidvalidity]`
    pub uidvalidity: u32,
    /// Whether the mailbox is read-only.
    /// `TAG OK [READ-WRITE|READ-ONLY]`
    pub read_only: bool,
    // ==================== RFC 7162 ====================
    /// The greatest `Modseq` currently in the mailbox, or `None` if
    /// primordial.
    ///
    /// `* OK [HIGHESTMODSEQ max_modseq.unwrap_or(1)]`
    pub max_modseq: Option<Modseq>,
}

/// Unsolicited responses that can be sent after commands (other than `FETCH`,
/// `STORE`, `SEARCH`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PollResponse {
    /// Any messages to report as expunged.
    ///
    /// This is sorted ascending. For QRESYNC clients, this should be sent
    /// as a `VANISHED` response:
    ///
    /// ```
    /// * VANISHED expunge[0],expunge[1],...
    /// ```
    ///
    /// For non-QRESYNC clients, this must be sent as `EXPUNGED` responses in
    /// *reverse* order.
    ///
    /// ```
    /// * expunge[99] EXPUNGE
    /// * expunge[98] EXPUNGE
    /// ...
    /// ```
    pub expunge: Vec<(Seqnum, Uid)>,
    /// If the mailbox size has changed, the new size.
    /// `* exists EXISTS`
    pub exists: Option<usize>,
    /// If there are new messages, the new recent count.
    /// `* recent RECENT`
    pub recent: Option<usize>,
    /// UIDs of messages that should be sent in unsolicited `FETCH` responses
    /// because their metadata changed or they recently came into existence.
    pub fetch: Vec<Uid>,
    /// The new `HIGHESTMODSEQ`, or `None` if still primordial.
    pub max_modseq: Option<Modseq>,
}

/// The result from a `QRESYNC` operation.
#[derive(Clone, Debug)]
pub struct QresyncResponse {
    /// Messages that have been expunged since the reference point or best
    /// guess thereof.
    ///
    /// ```
    /// * VANISHED (EARLIER) uid,uid,...
    /// ```
    pub expunged: Vec<Uid>,
    /// Messages that have been changed or created since the reference time.
    ///
    /// ```
    /// * seqnum FETCH (UID uid FLAGS (...) MODSEQ (...))
    /// ...
    /// ```
    pub changed: Vec<Uid>,
}

/// Request information for `STORE` and `UID_STORE`.
#[derive(Clone, Debug)]
pub struct StoreRequest<'a, ID>
where
    SeqRange<ID>: fmt::Debug,
{
    // ==================== RFC 3501 ====================
    /// The message(s) to affect.
    pub ids: &'a SeqRange<ID>,
    /// The flags to control.
    pub flags: &'a [Flag],
    /// If false, add any flag within `ids` which is not set. This is used for
    /// `FLAGS` and `+FLAGS`.
    ///
    /// If true, remove any flag within `ids` which is set. This is used for
    /// `-FLAGS`.
    pub remove_listed: bool,
    /// If true, remove any flag on a message which is not present in `ids`.
    ///
    /// This is used for `FLAGS`.
    pub remove_unlisted: bool,
    /// If true, mark all entries in `ids` as having changed flags, even if
    /// they haven't been changed.
    ///
    /// This is used for the `.SILENT` modifier, or rather, its absence.
    ///
    /// RFC 3501 indicates that, given `.SILENT`, the server SHOULD assume that
    /// the client isn't interested in a `FETCH` response indicating a change
    /// which it made itself. However, RFC 7162 specifies:
    ///
    /// > An untagged `FETCH` response MUST be sent, even if the
    /// > `.SILENT` suffix is specified, and the response MUST include the
    /// > MODSEQ message data item.
    ///
    /// For simplicity, we adopt the RFC 7162 behaviour in all cases, which
    /// means that `.SILENT` only suppresses `FETCH` responses for messages
    /// that were totally unchanged.
    pub loud: bool,
    // ==================== RFC 7162 ====================
    /// If set, do not change messages which were modified after this point.
    ///
    /// This corresponds to `UNCHANGEDSINCE`.
    pub unchanged_since: Option<Modseq>,
}

/// Response information for `STORE` and `UID STORE`.
///
/// This does not include which UIDs to fetch for the follow-up `FETCH`
/// response(s). Those must be found by a `mini_poll()` call after the store
/// operation.
#[derive(Clone, Debug)]
pub struct StoreResponse<ID>
where
    SeqRange<ID>: fmt::Debug,
{
    // ==================== RFC 3501 ====================
    /// Whether to return OK or NO.
    ///
    /// The semantics of trying to do a `STORE` against a message which has
    /// since been expunged are murky. RFC 3501 provides absolutely no
    /// guidance. RFC 7162 incidentally shows an example (Example 10 on Page
    /// 14) in which the server executes the request as much as it can, then
    /// returns NO and leaves the client to figure out what actually happened
    /// on its own. Existing implementations vary wildly according to
    /// https://imapwiki.org/ImapTest/ServerStatus (see "Expunge store"
    /// column).
    ///
    /// The IMAP wiki describes the most compliant servers as actually allowing
    /// a `STORE` to an expunged message to succeed. It's unclear whether that
    /// column is informative or expresses an opinion that it _should_ work
    /// that way. But RFC 7162 does make it clear enough that it's _not_
    /// supposed to work that way since the client needs to see that
    /// _something_ went wrong so that it knows to update its state.
    ///
    /// Strangely, RFC 7162 doesn't permit a `VANISHED (EARLIER)` response to
    /// `UID STORE` which would make this whole thing more graceful.
    pub ok: bool,
    // ==================== RFC 7162 ====================
    /// If empty, the operation completed successfully.
    ///
    /// ```
    /// tag OK
    /// ```
    ///
    /// If non-empty, one or more messages could not be updated because the
    /// `unchanged_since` requirement failed.
    ///
    /// ```
    /// tag OK [MODIFIED modified]
    /// ```
    pub modified: SeqRange<ID>,
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

#[cfg(test)]
mod test {
    use proptest::prelude::*;

    use super::*;

    fn assert_sr(
        expected_content: &[u32],
        expected_string: &str,
        seqrange: SeqRange<Uid>,
    ) {
        let actual: Vec<u32> = seqrange.items().map(|u| u.0.get()).collect();
        assert_eq!(expected_content, &actual[..]);
        assert_eq!(expected_string, &seqrange.to_string());
    }

    #[test]
    fn seqrange_parsing() {
        assert_sr(&[1], "1", SeqRange::parse("1", Uid::u(10)).unwrap());
        assert_sr(&[10], "10", SeqRange::parse("*", Uid::u(10)).unwrap());
        assert_sr(&[1, 2], "1:2", SeqRange::parse("1:2", Uid::u(10)).unwrap());
        assert_sr(&[1, 2], "1:2", SeqRange::parse("2:1", Uid::u(10)).unwrap());
        assert_sr(
            &[9, 10],
            "9:10",
            SeqRange::parse("9:*", Uid::u(10)).unwrap(),
        );
        assert_sr(
            &[9, 10],
            "9:10",
            SeqRange::parse("*:9", Uid::u(10)).unwrap(),
        );

        assert_sr(
            &[1, 3, 5],
            "1,3,5",
            SeqRange::parse("1,3,5", Uid::u(10)).unwrap(),
        );
        assert_sr(
            &[1, 3, 5],
            "1,3,5",
            SeqRange::parse("3,1,5", Uid::u(10)).unwrap(),
        );
        assert_sr(
            &[1, 3, 5],
            "1,3,5",
            SeqRange::parse("3,5,1", Uid::u(10)).unwrap(),
        );
        assert_sr(
            &[1, 2, 9, 10],
            "1:2,9:10",
            SeqRange::parse("1:2,9:*", Uid::u(10)).unwrap(),
        );
        assert_sr(
            &[1, 2, 9, 10],
            "1:2,9:10",
            SeqRange::parse("*:9,2:1", Uid::u(10)).unwrap(),
        );

        // Adjacent ranges
        assert_sr(
            &[1, 2, 3, 4],
            "1:4",
            SeqRange::parse("1,2,3,4", Uid::u(10)).unwrap(),
        );
        assert_sr(
            &[1, 2, 3, 4],
            "1:4",
            SeqRange::parse("1:2,3,4", Uid::u(10)).unwrap(),
        );
        assert_sr(
            &[1, 2, 3, 4],
            "1:4",
            SeqRange::parse("1:3,4", Uid::u(10)).unwrap(),
        );
        assert_sr(
            &[1, 2, 3, 4],
            "1:4",
            SeqRange::parse("1,2:3,4", Uid::u(10)).unwrap(),
        );
        assert_sr(
            &[1, 2, 3, 4],
            "1:4",
            SeqRange::parse("1,2:4", Uid::u(10)).unwrap(),
        );
        assert_sr(
            &[1, 2, 3, 4],
            "1:4",
            SeqRange::parse("1:2,3:4", Uid::u(10)).unwrap(),
        );
        // Overlapping ranges, one strictly inside another
        assert_sr(
            &[1, 2, 3, 4],
            "1:4",
            SeqRange::parse("1:4,2:3", Uid::u(10)).unwrap(),
        );
        assert_sr(
            &[1, 2, 3, 4],
            "1:4",
            SeqRange::parse("2:3,1:4", Uid::u(10)).unwrap(),
        );
        // Overlapping ranges with shared endpoint(s)
        assert_sr(
            &[1, 2, 3, 4],
            "1:4",
            SeqRange::parse("1:4,2,4", Uid::u(10)).unwrap(),
        );
        assert_sr(
            &[1, 2, 3, 4],
            "1:4",
            SeqRange::parse("2:4,1,4", Uid::u(10)).unwrap(),
        );
        assert_sr(
            &[1, 2, 3, 4],
            "1:4",
            SeqRange::parse("1:4,1:2", Uid::u(10)).unwrap(),
        );
        assert_sr(
            &[1, 2, 3, 4],
            "1:4",
            SeqRange::parse("1:2,1:4", Uid::u(10)).unwrap(),
        );
        assert_sr(
            &[1, 2, 3, 4],
            "1:4",
            SeqRange::parse("1:4,1:4", Uid::u(10)).unwrap(),
        );
        // Overlapping ranges, neither a subset of the other, no shared
        // endpoints
        assert_sr(
            &[1, 2, 3, 4],
            "1:4",
            SeqRange::parse("1,3:2,4", Uid::u(10)).unwrap(),
        );
        assert_sr(
            &[1, 2, 3, 4],
            "1:4",
            SeqRange::parse("2,4:1,3", Uid::u(10)).unwrap(),
        );
    }

    #[test]
    fn seqrange_append() {
        let mut seqrange = SeqRange::new();
        seqrange.append(Uid::u(1));
        assert_eq!("1", &seqrange.to_string());
        seqrange.append(Uid::u(2));
        assert_eq!("1:2", &seqrange.to_string());
        seqrange.append(Uid::u(3));
        assert_eq!("1:3", &seqrange.to_string());
        seqrange.append(Uid::u(5));
        assert_eq!("1:3,5", &seqrange.to_string());
        seqrange.append(Uid::u(6));
        assert_eq!("1:3,5:6", &seqrange.to_string());
    }

    proptest! {
        #[test]
        fn seqrange_properties(
            ranges in prop::collection::vec((1u32..30, 1u32..=10), 1..=5)
        ) {
            let mut expected = Vec::new();
            let mut seqrange = SeqRange::new();

            for &(start, extent) in &ranges {
                seqrange.insert(Uid::u(start), Uid::u(start + extent));
                expected.extend((start..=start + extent).into_iter());
            }

            expected.sort();
            expected.dedup();

            // Ensure we built the correct set
            let actual: Vec<u32> = seqrange.items().map(
                |u| u.0.get()).collect();
            assert_eq!(expected, actual);

            // contains() works
            for i in 1..50 {
                assert_eq!(
                    expected.contains(&i),
                    seqrange.contains(Uid::u(i)),
                    "Bad contains result for {}",
                    i
                );
            }

            // It can be stringified and parsed back into the same value
            assert_eq!(
                seqrange,
                SeqRange::parse(&seqrange.to_string(), Uid::MAX).unwrap());
        }
    }
}
