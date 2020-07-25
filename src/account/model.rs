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

use chrono::prelude::*;
use serde::{Deserialize, Serialize};

use crate::account::mailbox::BufferedMessage;
use crate::mime::fetch;
use crate::support::error::Error;

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

// This isn't a useful default implementation, but is here so that things
// containing SeqRange<ID> can still derive Default.
impl Default for Uid {
    fn default() -> Self {
        Uid::MIN
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

// This isn't a useful default implementation, but is here so that things
// containing SeqRange<ID> can still derive Default.
impl Default for Seqnum {
    fn default() -> Self {
        Seqnum::MIN
    }
}

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
#[derive(Clone, PartialEq, Eq)]
pub struct SeqRange<T> {
    parts: BTreeMap<u32, u32>,
    _t: PhantomData<T>,
}

impl<T> SeqRange<T> {
    /// Create a new, empty range.
    pub fn new() -> Self {
        SeqRange {
            parts: BTreeMap::new(),
            _t: PhantomData,
        }
    }
}

impl<T: TryFrom<u32> + Into<u32> + PartialOrd + Send + Sync> SeqRange<T> {
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
    /// Invalid items and items greater than `max`. are silently excluded.
    ///
    /// Items are delivered in strictly ascending order.
    pub fn items<'a>(
        &'a self,
        max: impl Into<u32>,
    ) -> impl Iterator<Item = T> + 'a {
        let max: u32 = max.into();
        self.parts
            .iter()
            .map(|(&start, &end)| (start, end))
            .filter(move |&(start, _)| start <= max)
            .flat_map(move |(start, end)| (start..=end.min(max)).into_iter())
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

    /// Return the total size of the sequence set.
    pub fn len(&self) -> usize {
        self.parts
            .iter()
            .map(|(start, end)| end - start + 1)
            .sum::<u32>() as usize
    }

    /// Return the maximum value in this sequence set, raw.
    pub fn max(&self) -> Option<u32> {
        self.parts.values().rev().copied().next()
    }
}

impl<T> SeqRange<T> {
    /// Return whether this range is empty (invalid for IMAP wire format).
    pub fn is_empty(&self) -> bool {
        self.parts.is_empty()
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

impl<T> Default for SeqRange<T> {
    fn default() -> Self {
        SeqRange::new()
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
#[derive(Clone, Serialize, Deserialize)]
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
        } else if s.eq_ignore_ascii_case("\\seen") {
            Ok(Flag::Seen)
        } else if s.starts_with("\\") {
            Err(Error::NxFlag)
        } else if s.as_bytes().iter().copied().all(is_atom_char) {
            Ok(Flag::Keyword(s.to_owned()))
        } else {
            Err(Error::UnsafeName)
        }
    }
}

fn is_atom_char(ch: u8) -> bool {
    match ch {
        0..=b' ' => false,
        127..=255 => false,
        b'(' | b')' | b'{' | b'*' | b'%' | b'\\' | b'"' | b']' => false,
        _ => true,
    }
}

impl PartialEq for Flag {
    fn eq(&self, other: &Flag) -> bool {
        match (self, other) {
            (&Flag::Answered, &Flag::Answered) => true,
            (&Flag::Deleted, &Flag::Deleted) => true,
            (&Flag::Draft, &Flag::Draft) => true,
            (&Flag::Flagged, &Flag::Flagged) => true,
            (&Flag::Seen, &Flag::Seen) => true,
            // Apparently the expectation is that keywords are
            // case-insensitive, despite RFC 3501 not requiring that. We only
            // do ASCII case-insensitivity to limit the insanity (there's no
            // way to get Unicode flags within RFC 3501 anyway).
            (&Flag::Keyword(ref a), &Flag::Keyword(ref b)) => {
                a.eq_ignore_ascii_case(b)
            }
            _ => false,
        }
    }
}

impl Eq for Flag {}

/// Attributes that may be applied to mailboxes.
///
/// This includes the RFC 6154 special-use markers.
#[derive(
    Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord,
)]
pub enum MailboxAttribute {
    // RFC 3501
    // We never do anything with \Marked or \Unmarked, so they are not defined
    // here.
    Noselect,
    Noinferiors,
    // RFC 3348
    HasChildren,
    HasNoChildren,
    // RFC 5258
    NonExistent,
    Subscribed,
    // RFC 6154
    // \All is not supported
    Archive,
    Drafts,
    Flagged,
    Junk,
    Sent,
    Trash,
    // RFC 8457
    Important,
}

impl MailboxAttribute {
    pub fn name(&self) -> &'static str {
        match self {
            &MailboxAttribute::Noselect => "\\Noselect",
            &MailboxAttribute::Noinferiors => "\\Noinferiors",
            &MailboxAttribute::HasChildren => "\\HasChildren",
            &MailboxAttribute::HasNoChildren => "\\HasNoChildren",
            &MailboxAttribute::NonExistent => "\\NonExistent",
            &MailboxAttribute::Subscribed => "\\Subscribed",
            &MailboxAttribute::Archive => "\\Archive",
            &MailboxAttribute::Drafts => "\\Drafts",
            &MailboxAttribute::Flagged => "\\Flagged",
            &MailboxAttribute::Junk => "\\Junk",
            &MailboxAttribute::Sent => "\\Sent",
            &MailboxAttribute::Trash => "\\Trash",
            &MailboxAttribute::Important => "\\Important",
        }
    }
}

impl fmt::Display for MailboxAttribute {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl fmt::Debug for MailboxAttribute {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        <MailboxAttribute as fmt::Display>::fmt(self, f)
    }
}

/// The RFC 3501 `CREATE` command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateRequest {
    /// The name of the new mailbox.
    ///
    /// RFC 3501
    pub name: String,
    /// If non-empty, imbue the mailbox with the given special use(s).
    ///
    /// RFC 6154
    pub special_use: Vec<String>,
}

/// The RFC 3501 `RENAME` command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenameRequest {
    /// The mailbox to rename.
    pub existing_name: String,
    /// The new name for the mailbox.
    pub new_name: String,
}

/// The `STATUS` command and its various extensions.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StatusRequest {
    /// The mailbox to query.
    pub name: String,

    // ==================== RFC 3501 ====================
    /// Return the number of messages.
    pub messages: bool,
    /// Return the number of \Recent messages.
    pub recent: bool,
    /// Return the next UID value
    pub uidnext: bool,
    /// Return the UID validity
    pub uidvalidity: bool,
    /// Return the number of not-\Seen messages.
    pub unseen: bool,

    // ==================== RFC 7162 ====================
    /// Return the greatest Modseq value
    pub max_modseq: bool,
}

/// The `STATUS` response
///
/// Fields are only set if requested in the request. Those fields' meanings
/// correspond exactly to the fields of the same name in `StatusRequest`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StatusResponse {
    /// The mailbox being reported
    pub name: String,

    // ==================== RFC 3501 ====================
    pub messages: Option<usize>,
    pub recent: Option<usize>,
    pub uidnext: Option<Uid>,
    pub uidvalidity: Option<u32>,
    pub unseen: Option<usize>,
    // ==================== RFC 7162 ====================
    pub max_modseq: Option<u64>,
}

/// Request used for implementing `LIST` and `LSUB`.
///
/// This includes the extended options from RFC 5258, the `LIST-EXTENDED`
/// extension. This extension is fairly pointless and adds a large amount of
/// complexity to the `LIST` command, but IMAP4rev2 is going to bring it into
/// the baseline, so we might as well implement it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ListRequest {
    /// The "reference" of the list.
    ///
    /// If non-empty, a `/` is added to the end (if not there already) and this
    /// is prepended to every pattern.
    ///
    /// RFC 3501
    pub reference: String,
    /// Only match mailboxes whose name matches any of these patterns.
    ///
    /// RFC 3501, extended by RFC 5258
    pub patterns: Vec<String>,
    /// Only match mailboxes which are subscribed, and include mailboxes which
    /// don't exist.
    ///
    /// If set, RFC 5258 requires that `return_subscribed` also be set.
    ///
    /// RFC 5258
    pub select_subscribed: bool,
    /// Only match mailboxes which have a special-use attribute.
    ///
    /// If set, RFC 6154 requires that `return_special_use` also be set.
    ///
    /// RFC 6154
    pub select_special_use: bool,
    /// If true, and this mailbox does match `patterns` but fails one of the
    /// selection criteria, and a direct or indirect child does match one of
    /// the selection criteria, but does not match `patterns`, and no
    /// intermediate parents satisfy these conditions, include this mailbox in
    /// the results with the `\NonExistent` attribute.
    ///
    /// This also causes the `child_info` field of the output to be populated.
    ///
    /// RFC 3501 (`LSUB`), RFC 5258
    pub recursive_match: bool,
    /// Determine whether each mailbox is subscribed.
    ///
    /// RFC 5258
    pub return_subscribed: bool,
    /// Determine whether each mailbox has children.
    ///
    /// RFC 5258, XLIST (implicit)
    pub return_children: bool,
    /// Return the special use flags for each mailbox.
    ///
    /// RFC 6154, XLIST (implicit)
    pub return_special_use: bool,
    /// If true, return flags as per `LSUB` --- `\Noselect` instead of
    /// `\NonExistent` for the special `recursive_match` behaviour, and no flag
    /// at all for mailboxes that don't exist.
    ///
    /// RFC 3501
    pub lsub_style: bool,
}

/// A `LIST` or `LSUB` response.
///
/// The structure does not include the second term, the hierarchy delimiter,
/// since it is always `"/"`.
///
/// The fields in this struct are sorted to permit deriving `Ord` and are not
/// in the order they are sent over the wire.
#[derive(Debug, Clone, PartialEq, Eq, Default, PartialOrd, Ord)]
pub struct ListResponse {
    /// The canonical name of this mailbox.
    ///
    /// RFC 3501
    pub name: String,
    /// Any attributes on this mailbox.
    ///
    /// RFC 3501
    pub attributes: Vec<MailboxAttribute>,
    /// If non-empty, return a `("CHILDINFO" (child_info ...))` extended info
    /// block with these values.
    ///
    /// Not returned for LSUB, but it is still computed for that case anyway.
    ///
    /// RFC 5258
    pub child_info: Vec<&'static str>,
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
    /// The new `HIGHESTMODSEQ`, or `None` if still primordial or hasn't
    /// changed since the last poll.
    pub max_modseq: Option<Modseq>,
}

/// The `QRESYNC` part of `SELELCT` or `EXPUNGE`.
#[derive(Clone, Debug)]
pub struct QresyncRequest {
    /// The last known UID validity value for the mailbox.
    pub uid_validity: u32,
    /// If set, only consider changes that may have occurred after this point.
    ///
    /// If clear, consider changes from all time.
    pub resync_from: Option<Modseq>,
    /// If set, only return information for UIDs in this set.
    pub known_uids: Option<SeqRange<Uid>>,
    /// If set and `resync_from` is earlier than the last known expungement,
    /// use these parallel seqnum and UID sets to estimate which expungements
    /// the client already knows about.
    pub mapping_reference: Option<(SeqRange<Seqnum>, SeqRange<Uid>)>,
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
    ///
    /// This is a raw value that nominally should be a `Modseq`. This is
    /// because we must allow clients to submit values less than `Modseq::MIN`,
    /// even though they are doomed to failure. At that, RFC 7162 *requires*
    /// that an `UNCHANGEDSINCE` of 0 MUST fail (Page 12, Example 6):
    ///
    /// > Use of UNCHANGEDSINCE with a modification sequence of 0 always fails
    /// > if the metadata item exists.  A system flag MUST always be considered
    /// > existent, whether it was set or not.
    ///
    /// (Hooray for novel hard requirements set out in examples...)
    pub unchanged_since: Option<u64>,
}

/// Response information for `STORE` and `UID STORE`.
///
/// This does not include which UIDs to fetch for the follow-up `FETCH`
/// response(s). Those must be found by a `mini_poll()` call after the store
/// operation.
#[derive(Clone, Debug, PartialEq, Eq)]
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
    /// RFC 2180, which predates IMAP4rev1, does provide some guidance:
    ///
    /// > 4.2.1 If the ".SILENT" suffix is used, and the STORE completed
    /// > successfully for all the non-expunged messages, the server SHOULD
    /// > return a tagged OK.
    /// >
    /// > 4.2.2. If the ".SILENT" suffix is not used, and only expunged
    /// > messages are referenced, the server SHOULD return only a tagged NO.
    /// >
    /// > 4.2.3. If the ".SILENT" suffix is not used, and a mixture of expunged
    /// > and non-expunged messages are referenced, the server MAY set the
    /// > flags and return a FETCH response for the non-expunged messages
    /// > along with a tagged NO.
    /// >
    /// > 4.2.4. If the ".SILENT" suffix is not used, and a mixture of expunged
    /// > and non-expunged messages are referenced, the server MAY return
    /// > an untagged NO and not set any flags.
    ///
    /// Strangely, RFC 7162 doesn't permit a `VANISHED (EARLIER)` response to
    /// `UID STORE` which would make this whole thing more graceful at least
    /// for QRESYNC clients.
    ///
    /// Section 6.4.8 of RFC 3501 would appear to suggest that a `UID STORE`
    /// referencing an expunged UID should silently ignore the expunged UID
    /// regardless:
    ///
    /// > Note: in the above example, the UID range 443:557
    /// > appears.  The same comment about a non-existent unique
    /// > identifier being ignored without any error message also
    /// > applies here.  Hence, even if neither UID 443 or 557
    /// > exist, this range is valid and would include an existing
    /// > UID 495.
    ///
    /// The term "existent" here probably refers to "is assigned a sequence
    /// number" rather than a present/expunged status, since IMAP4rev1
    /// extensively disregards the possibility of concurrent access and
    /// pervasively assumes that a message exists if and only if it has a
    /// sequence number.
    ///
    /// Though not discussed in any RFC, it appears that a number of mail
    /// stores allow STORE to keep working on expunged messages that are still
    /// in the current snapshot. That is what this implementation does as well.
    /// We return NO only if the request is loud and references no existing
    /// messages (as defined by its snapshot) at all.
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

/// Request information for `FETCH` and `UID FETCH`.
#[derive(Clone, Debug, Default)]
pub struct FetchRequest<ID>
where
    SeqRange<ID>: fmt::Debug,
{
    // ==================== RFC 3501 ====================
    /// The ids to fetch.
    pub ids: SeqRange<ID>,
    /// Return UIDs?
    pub uid: bool,
    /// Return flags?
    pub flags: bool,
    /// Return "RFC 822 size"?
    pub rfc822size: bool,
    /// Return internal date?
    pub internal_date: bool,
    /// Return envelope?
    pub envelope: bool,
    /// Return bodystructure?
    pub bodystructure: bool,
    /// Any sections to be fetched
    pub sections: Vec<fetch::section::BodySection>,
    // ==================== RFC 7162 ====================
    /// Return `Modseq`s?
    pub modseq: bool,
    /// If set, filter out messages which have not been changed since the given
    /// time.
    ///
    /// If the client requests a `Modseq` less than `Modseq::MIN`, pass `None`.
    pub changed_since: Option<Modseq>,
    /// Should the fetch process gather UIDs which were expunged for a
    /// `VANISHED` response? If `changed_since` is greater than the earliest
    /// known expunged message, only messages which were expunged after that
    /// point are gathered. Otherwise, all expunged UIDs requested will be
    /// gathered.
    pub collect_vanished: bool,
}

/// What the tagged response from a `FETCH` should be.
///
/// This is a particularly nasty aspect of IMAP4, owing to its original
/// development being targeted at systems that don't allow concurrent mailbox
/// access.
///
/// The issue is this: The IMAP data model is that the current sequence numbers
/// exactly represent the set of messages that exist. However, since sequence
/// numbers are volatile, we cannot send updates about that set to the client
/// in realtime, since that would break commands that use sequence numbers for
/// addressing (and fetch responses, which are weirdly addressed by sequence
/// number even for `UID FETCH`). What, then, do we do if the client attempts
/// to FETCH a message which is still addressable in its snapshot, but has been
/// expunged by another session?
///
/// RFC 2180 provides some suggestions:
///
/// > 4.1.1 The server MAY allow the EXPUNGE of a multi-accessed mailbox but
/// > keep the messages available to satisfy subsequent FETCH commands until it
/// > is able to send an EXPUNGE response to each client.
/// >
/// >
/// > 4.1.2 The server MAY allow the EXPUNGE of a multi-accessed mailbox, and
/// > on subsequent FETCH commands return FETCH responses only for non-expunged
/// > messages and a tagged NO.
/// >
/// > 4.1.3 The server MAY allow the EXPUNGE of a multi-accessed mailbox, and
/// > on subsequent FETCH commands return the usual FETCH responses for
/// > non-expunged messages, "NIL FETCH Responses" for expunged messages, and a
/// > tagged OK response.
/// >
/// > 4.1.4 To avoid the situation altogether, the server MAY fail the EXPUNGE
/// > of a multi-accessed mailbox.
///
/// The author of the Dovecot server also has
/// [suggestions](https://imapwiki.org/MultiAccessPractices):
///
/// 1. 4.1.1
/// 2. 4.1.3
/// 3. 4.1.2
/// 4. Kill the connection when this situation arises
/// 5. 4.1.4
///
/// Apparently nobody thinks of "silently return OK without the expunged
/// messages missing" as a viable option, even though that's how a number of
/// other commands (e.g. `STORE`) behave in some implementations.
///
/// Crispin believed that 4.1.2 was the worst possible option:
///
/// > I think that 4.1.2 is a bug, and servers that do it are broken.
///
/// He preferred even 4.1.4 over it, even though 4.1.2 is how essentially any
/// other protocol would handle an access to a deleted item. RFC 3501 also
/// explicitly permits this behaviour:
///
/// > Result: ... NO - fetch error: can't fetch that data
///
/// 4.1.2 sounds like what Courier (a maildir-based implementation) would have
/// implemented, and the intensely bad relations between Crispin and Courier's
/// author would have had an influence on that sentiment.
///
/// Crispin was a proponent of 4.1.1, but that is unnecessarily complex to
/// implement for such a fringe case; we'd need some mechanism for all sessions
/// to discover an impending expunge in real time, and have some kind of grace
/// period before the message was actually expunged.
///
/// 4.1.4 is utterly unacceptable. Making it impossible to delete things is
/// *not OK*. Besides, we have no way to know if there are other sessions.
///
/// 4.1.3 is doable, but it's not great. Apparently Cyrus does this. It forces
/// clients to guess what happened.
///
/// The main concern with 4.1.2 is apparently insane clients that think it
/// somehow makes sense to immediately retry a request that resulted in `NO`
/// immediately. Arnt Gulbrandsen in the IMAP mailing list wrote about a hybrid
/// approach on 2006-09-15:
///
/// > (Btw, I changed our code today to use 4.1.2+loopbreaker. The first time
/// > a client fetches a message which another client has expunged, but whose
/// > expunge has not yet been reported in this session, the server issues a
/// > NO as in 4.1.2, and makes a note of the UID(s). If any of those UIDs
/// > are fetched again before the server can report the expunge, the server
/// > issues a BYE. When it reports expunges, it clears its UID set. I think
/// > that's as good as 4.1.1+period.)
///
/// ("4.1.1+period" refers to a scheme of using 4.1.1 by way of a 5-minute or
/// more grace period, followed by Dovecot 4 for attempts that happen later.)
///
/// On 2006-12-31, Gulbrandsen provided an update that this 4.1.2+loopbreaker
/// worked well with clients.
///
/// 4.1.2+loopbreaker is what we implement here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FetchResponseKind {
    /// Return OK.
    ///
    /// This happens in one of two situations:
    ///
    /// - The FETCH request did not reference any expunged messages.
    ///
    /// - The request indicated that the client is prepared to deal with
    /// missing messages. This means that either `collect_vanished` was
    /// specified, or `changed_since` was given and had a UID greater than any
    /// expunged UID encountered.
    Ok,
    /// Return NO.
    ///
    /// This is returned for any case where `Ok` is not returned, unless the
    /// client attempts to fetch the same expunged UID more than once before
    /// the next poll.
    No,
    /// Return the results, then kill the connection.
    ///
    /// This is returned if `No` would be returned, but the client already made
    /// another FETCH request since the last poll and got a `No` for one or
    /// more of the same UIDs.
    Bye,
}

impl Default for FetchResponseKind {
    fn default() -> Self {
        FetchResponseKind::Ok
    }
}

/// The part of a `FETCH` response that must be sent before the fetched items.
#[derive(Debug, Default)]
pub struct PrefetchResponse {
    /// UIDs to report in a `VANISHED (EARLIER)` response.
    ///
    /// RFC 7162 has this curious line:
    ///
    /// > Any VANISHED (EARLIER) responses
    /// > MUST be returned before any FETCH responses, otherwise the client
    /// > might get confused about how message numbers map to UIDs.
    ///
    /// It's unclear what the intent is here, since `VANISHED (EARLIER)` does
    /// not affect the sequence number mapping, so a client could only become
    /// confused if it modified the sequence number mapping anyway, in which
    /// case it would be better to send the `VANISHED (EARLIER)` *after* the
    /// `FETCH` responses. There's also the simple fact that 3501 permits the
    /// server to send any `FETCH` response whenever it wants, so this
    /// requirement overall seems like it should be moot.
    ///
    /// Nonetheless, we order this first since it's a "MUST" requirement.
    pub vanished: SeqRange<Uid>,

    /// If non-empty, send a `FLAGS` response with these flags before the
    /// `FETCH` responses.
    ///
    /// RFC 3501 does not require this, but Crispin indicates on the mailing
    /// list that it is "common sense" that this must be sent if new flags have
    /// been created since the last `FLAGS` response and one cannot expect a
    /// client to determine that the presence of a flag in a `FETCH` implies
    /// that that flag now exists.
    pub flags: Vec<Flag>,
}

/// Response from a `FETCH` or `UID FETCH` command.
///
/// Fields are in transmission order.
///
/// Note that the fetched data itself is *not* in this structure. The caller of
/// the `fetch` implementation must handle that itself. Those responses are
/// placed immediately before the contents of this struct.
#[derive(Debug, Default)]
pub struct FetchResponse {
    /// What type of tagged response to return.
    ///
    /// RFC 3501, RFC 2180, and mailing list discussion (see
    /// `FetchResponseKind`).
    pub kind: FetchResponseKind,
}

/// The `SEARCH` and `UID SEARCH` commands.
#[derive(Clone, Debug, Default)]
pub struct SearchRequest {
    /// The top-level queries, which get ANDed together.
    pub queries: Vec<SearchQuery>,
}

/// The query for the `SEARCH` command and related commands.
///
/// Unlike most request types in these models, this is a very direct
/// representation of the IMAP search query as an AST. This is because only
/// some of the quirks (such as the "Un$flag" queries) are purely syntactic,
/// and keeping all the translation logic in one place makes it easier to
/// manage.
#[derive(Clone, Debug)]
pub enum SearchQuery {
    // ==================== RFC 3501 ====================
    SequenceSet(SeqRange<Seqnum>),
    All,
    Answered,
    Bcc(String),
    Before(NaiveDate),
    Body(String),
    Cc(String),
    Deleted,
    Draft,
    Flagged,
    From(String),
    Header(String, String),
    Keyword(String),
    Larger(u32),
    New,
    Not(Box<SearchQuery>),
    Old, // NB "NOT RECENT", not "NOT NEW"
    On(NaiveDate),
    Or(Box<SearchQuery>, Box<SearchQuery>),
    Recent,
    Seen,
    SentBefore(NaiveDate),
    SentOn(NaiveDate),
    SentSince(NaiveDate),
    Since(NaiveDate),
    Smaller(u32),
    Subject(String),
    Text(String),
    To(String),
    UidSet(SeqRange<Uid>), // RFC 3501 calls it "UID"; "Set" for disambiguation
    Unanswered,
    Undeleted,
    Undraft,
    Unflagged,
    Unkeyword(String),
    Unseen,
    And(Vec<SearchQuery>),
    Modseq(u64),
}

/// The response from the `SEARCH` (`ID` = `Seqnum`) or `UID SEARCH`
/// (`ID` = `Uid`) commands.
#[derive(Clone, Debug)]
pub struct SearchResponse<ID> {
    /// The ids to return in the untagged `* SEARCH` response.
    ///
    /// For some reason, the ids are returned as a naked list instead of using
    /// IMAP's list syntax or sequence-set syntax.
    pub hits: Vec<ID>,
    /// The maximum `Modseq` of any hit, or `None` if there were no hits.
    pub max_modseq: Option<Modseq>,
}

/// The `APPEND` request.
#[derive(Debug, Default)]
pub struct AppendRequest {
    /// The items to append.
    ///
    /// Specified by RFC 3501, extended by RFC 3502 to support multiple inputs.
    pub items: Vec<AppendItem>,
}

/// A single item to be processed by the `APPEND` command.
#[derive(Debug)]
pub struct AppendItem {
    /// The message itself.
    pub buffer_file: BufferedMessage,
    /// Any flags to set on the newly-inserted message.
    pub flags: Vec<Flag>,
}

/// The response for the `APPEND` command.
///
/// All fields are from RFC 4315.
#[derive(Debug, Clone)]
pub struct AppendResponse {
    /// The UID validity value of the destination mailbox.
    pub uid_validity: u32,
    /// The UID(s) of any inserted message.
    pub uids: SeqRange<Uid>,
}

/// The `COPY` and `UID COPY` commands.
#[derive(Debug, Clone)]
pub struct CopyRequest<ID>
where
    SeqRange<ID>: fmt::Debug,
{
    /// The IDs to copy.
    pub ids: SeqRange<ID>,
}

/// The response from the `COPY` and `UID COPY` commands.
#[derive(Debug, Clone, Default)]
pub struct CopyResponse {
    /// The UID validity value of the destination mailbox.
    pub uid_validity: u32,
    /// The UID(s) of any copied message.
    pub from_uids: SeqRange<Uid>,
    /// The UID(s) of the new messages, parallel to `from_uids`.
    pub to_uids: SeqRange<Uid>,
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

/// Metadata about a message which is stored encrypted in the message file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageMetadata {
    /// The uncompressed, unencrypted size of the message.
    ///
    /// In storage, this is actually a random value that must be XORed with
    /// `size_xor`.
    #[serde(alias = "s")]
    pub size: u32,
    /// The `INTERNALDATE` of the message.
    ///
    /// We need to keep the timezone to correctly handle RFC 3501's odd
    /// day-based comparisons.
    #[serde(alias = "d")]
    pub internal_date: DateTime<FixedOffset>,
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
        let actual: Vec<u32> =
            seqrange.items(u32::MAX).map(|u| u.0.get()).collect();
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
            let actual: Vec<u32> = seqrange.items(u32::MAX).map(
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
