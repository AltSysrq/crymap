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

//! Bindings for our model types to `rusqlite`, plus model types specific to
//! the database itself.

use std::convert::TryFrom;
use std::str::FromStr;

use chrono::prelude::*;
use rusqlite::types::{
    FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, ValueRef,
};

use crate::{
    account::model::*,
    crypt::AES_BLOCK,
    support::{error::Error, small_bitset::SmallBitset},
};

macro_rules! transparent_to_sql {
    ($t:ident) => {
        impl ToSql for $t {
            fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
                self.0.to_sql()
            }
        }
    };
}

macro_rules! transparent_from_sql {
    ($t:ident) => {
        impl FromSql for $t {
            fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
                FromSql::column_result(value).map(Self)
            }
        }
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MailboxId(pub i64);
transparent_to_sql!(MailboxId);
transparent_from_sql!(MailboxId);

impl MailboxId {
    /// ID for the root pseudo-mailbox.
    ///
    /// This is used for the parent link of mailboxes under the root solely so
    /// that `(parent_id, name)` still works as a uniqueness constraint for
    /// top-level mailboxes.
    pub const ROOT: Self = Self(0);

    pub fn as_uid_validity(self) -> Result<u32, Error> {
        u32::try_from(self.0)
            .ok()
            .filter(|&u| u != 0)
            .ok_or(Error::MailboxIdOutOfRange)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageId(pub i64);
transparent_to_sql!(MessageId);
transparent_from_sql!(MessageId);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlagId(pub usize);
transparent_to_sql!(FlagId);
transparent_from_sql!(FlagId);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnixTimestamp(pub DateTime<Utc>);

impl UnixTimestamp {
    pub fn now() -> Self {
        Self(Utc::now())
    }

    pub fn zero() -> Self {
        Self(DateTime::<Utc>::from_timestamp(0, 0).unwrap())
    }
}

impl ToSql for UnixTimestamp {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        let ToSqlOutput::Owned(v) = self.0.timestamp().to_sql()? else {
            unreachable!()
        };
        Ok(ToSqlOutput::Owned(v))
    }
}

impl FromSql for UnixTimestamp {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        let inner = i64::column_result(value)?;
        DateTime::<Utc>::from_timestamp(inner, 0)
            .ok_or(FromSqlError::OutOfRange(inner))
            .map(Self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionKey(pub [u8; AES_BLOCK]);

impl ToSql for SessionKey {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::Borrowed(ValueRef::Blob(&self.0)))
    }
}

impl FromSql for SessionKey {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        let ValueRef::Blob(value) = value else {
            return Err(FromSqlError::InvalidType);
        };

        if AES_BLOCK != value.len() {
            return Err(FromSqlError::InvalidBlobSize {
                expected_size: AES_BLOCK,
                blob_size: value.len(),
            });
        }

        let mut block = [0u8; AES_BLOCK];
        block.copy_from_slice(value);
        Ok(Self(block))
    }
}

impl ToSql for Uid {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        let ToSqlOutput::Owned(v) = u32::from(*self).to_sql()? else {
            unreachable!()
        };
        Ok(ToSqlOutput::Owned(v))
    }
}

impl FromSql for Uid {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        let inner = u32::column_result(value)?;
        Self::of(inner).ok_or(FromSqlError::OutOfRange(inner as i64))
    }
}

impl ToSql for Modseq {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        // We don't need to account for values greater than i64::MAX since
        // QRESYNC bars us from actually using that range anyway.
        let ToSqlOutput::Owned(v) = self.raw().to_sql()? else {
            unreachable!()
        };
        Ok(ToSqlOutput::Owned(v))
    }
}

impl FromSql for Modseq {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        u64::column_result(value).map(Self::of)
    }
}

impl ToSql for Flag {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::Borrowed(ValueRef::Text(
            self.as_str().as_bytes(),
        )))
    }
}

impl FromSql for Flag {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        let ValueRef::Text(as_str) = value else {
            return Err(FromSqlError::InvalidType);
        };
        let Ok(as_str) = std::str::from_utf8(as_str) else {
            return Err(FromSqlError::InvalidType);
        };
        Self::from_str(as_str).map_err(|e| FromSqlError::Other(Box::new(e)))
    }
}

impl ToSql for MailboxAttribute {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::Borrowed(ValueRef::Text(
            self.name().as_bytes(),
        )))
    }
}

impl FromSql for MailboxAttribute {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        let ValueRef::Text(as_str) = value else {
            return Err(FromSqlError::InvalidType);
        };
        let Ok(as_str) = std::str::from_utf8(as_str) else {
            return Err(FromSqlError::InvalidType);
        };
        Self::from_str(as_str).map_err(|e| FromSqlError::Other(Box::new(e)))
    }
}

/// All data pertaining to a particular mailbox.
#[derive(Debug, Clone)]
pub struct Mailbox {
    pub id: MailboxId,
    pub parent_id: MailboxId,
    pub name: String,
    pub selectable: bool,
    pub special_use: Option<MailboxAttribute>,
    pub next_uid: Uid,
    pub recent_uid: Uid,
    pub max_modseq: Modseq,
}

impl FromRow for Mailbox {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get("id")?,
            parent_id: row.get("parent_id")?,
            name: row.get("name")?,
            selectable: row.get("selectable")?,
            special_use: row.get("special_use")?,
            next_uid: row.get("next_uid")?,
            recent_uid: row.get("recent_uid")?,
            max_modseq: row.get("max_modseq")?,
        })
    }
}

/// Core status information about a mailbox.
#[derive(Debug, Clone, Copy)]
pub struct MailboxStatus {
    pub selectable: bool,
    pub next_uid: Uid,
    pub recent_uid: Uid,
    pub max_modseq: Modseq,
}

impl FromRow for MailboxStatus {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            selectable: row.get("selectable")?,
            next_uid: row.get("next_uid")?,
            recent_uid: row.get("recent_uid")?,
            max_modseq: row.get("max_modseq")?,
        })
    }
}

/// All data pertaining to a single message.
#[derive(Debug, Clone)]
pub struct RawMessage {
    pub id: MessageId,
    pub path: String,
    pub session_key: Option<SessionKey>,
    pub rfc822_size: Option<u64>,
    pub last_activity: UnixTimestamp,
}

impl FromRow for RawMessage {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get("id")?,
            path: row.get("path")?,
            session_key: row.get("session_key")?,
            rfc822_size: row.get("rfc822_size")?,
            last_activity: row.get("last_activity")?,
        })
    }
}

/// The first-level data pertaining to a message instance in a mailbox.
#[derive(Debug, Clone)]
pub struct RawMailboxMessage {
    pub mailbox_id: MailboxId,
    pub uid: Uid,
    pub message_id: MessageId,
    pub near_flags: i64,
    pub savedate: UnixTimestamp,
    pub append_modseq: Modseq,
    pub flags_modseq: Modseq,
}

impl FromRow for RawMailboxMessage {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            mailbox_id: row.get("mailbox_id")?,
            uid: row.get("uid")?,
            message_id: row.get("message_id")?,
            near_flags: row.get("near_flags")?,
            savedate: row.get("savedate")?,
            append_modseq: row.get("append_modseq")?,
            flags_modseq: row.get("flags_modseq")?,
        })
    }
}

/// The initial snapshot loaded from the database.
///
/// This is essentially `SELECT` + `QRESYNC`.
#[derive(Debug, Clone)]
pub struct InitialSnapshot {
    /// The full set of defined flags, sorted ascending by ID.
    pub flags: Vec<(FlagId, Flag)>,
    /// All messages currently present in the mailbox, sorted ascending by UID.
    pub messages: Vec<InitialMessageStatus>,
    /// The `next_uid` field of the mailbox.
    pub next_uid: Uid,
    /// The greatest modseq of the mailbox.
    pub max_modseq: Modseq,
    /// Any `QRESYNC` response to send.
    pub qresync: Option<QresyncResponse>,
}

/// Information about a message in the mailbox which is being newly introduced
/// to the snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct InitialMessageStatus {
    /// The mailbox-specific UID of the message.
    pub uid: Uid,
    /// The global ID of the message.
    pub id: MessageId,
    /// The flags on the message.
    pub flags: SmallBitset,
    /// The greatest modseq of the message.
    pub last_modified: Modseq,
    /// Whether this message should be marked `\Recent`.
    pub recent: bool,
    /// The `SAVEDATE` attribute of the message.
    pub savedate: UnixTimestamp,
}

/// Information to update a snapshot between the cursed non-UID read-only
/// commands.
#[derive(Debug, Clone, PartialEq)]
pub struct MiniPoll {
    /// New flags that were created, sorted ascending by ID.
    pub new_flags: Vec<(FlagId, Flag)>,
    /// Updates to already-known messages, sorted ascending by UID.
    pub updated_messages: Vec<UpdatedMessageStatus>,
    /// The `HIGHESTMODSEQ` to report. This may be less than the maximum
    /// `Modseq` of any message (including those in `updated_messages`) if
    /// there have been append or expunge operations that are being delayed.
    pub snapshot_modseq: Modseq,
    /// Whether `snapshot_modseq` is less than `max_modseq` on the mailbox.
    pub diverged: bool,
}

/// Full information to update a snapshot to the latest state.
#[derive(Debug, Clone, PartialEq)]
pub struct FullPoll {
    /// New flags that were created.
    pub new_flags: Vec<(FlagId, Flag)>,
    /// Updates to already-known messages, sorted ascending by UID.
    pub updated_messages: Vec<UpdatedMessageStatus>,
    /// Status on newly appended messages, sorted ascending by UID.
    pub new_messages: Vec<InitialMessageStatus>,
    /// UIDs which have been expunged, sorted ascending.
    ///
    /// This may include UIDs which were not in the current snapshot.
    pub expunged: Vec<Uid>,
    /// The current modification sequence number.
    pub snapshot_modseq: Modseq,
}

/// Information about an already-known message which can be updated by polling.
#[derive(Debug, Clone, PartialEq)]
pub struct UpdatedMessageStatus {
    /// The mailbox-specific UID of the message.
    pub uid: Uid,
    /// The flags on the message.
    pub flags: SmallBitset,
    /// The greatest modseq of the message.
    pub last_modified: Modseq,
}

/// Data retrieved when a message is accessed for reading.
#[derive(Debug, Clone, PartialEq)]
pub struct MessageAccessData {
    /// The path to the message relative to the message store.
    pub path: String,
    /// The cached session key (still encrypted), if available.
    pub session_key: Option<SessionKey>,
    /// The value of RFC822.SIZE, if available.
    pub rfc822_size: Option<u64>,
}

impl FromRow for MessageAccessData {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            path: row.get("path")?,
            session_key: row.get("session_key")?,
            rfc822_size: row.get("rfc822_size")?,
        })
    }
}

/// An entry in the delivery database describing a message to be delivered.
#[derive(Debug, Clone, PartialEq)]
pub struct Delivery {
    /// The path to the message, relative to the message store.
    pub path: String,
    /// The path to the mailbox that will receive the message.
    pub mailbox: String,
    /// The flags to set on the message.
    pub flags: Vec<Flag>,
    /// The SAVEDATE for the message.
    pub savedate: UnixTimestamp,
}

impl FromRow for Delivery {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            path: row.get("path")?,
            mailbox: row.get("mailbox")?,
            flags: row.get::<_, String>("flags").map(|flags| {
                flags
                    .split(' ')
                    .filter_map(|flag| Flag::from_str(flag).ok())
                    .collect::<Vec<_>>()
            })?,
            savedate: row.get("savedate")?,
        })
    }
}

pub fn from_row<T: FromRow>(row: &rusqlite::Row<'_>) -> rusqlite::Result<T> {
    T::from_row(row)
}

pub fn from_single<T: FromSql>(row: &rusqlite::Row<'_>) -> rusqlite::Result<T> {
    row.get(0)
}

pub trait FromRow: Sized {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self>;
}

macro_rules! from_row_tuple {
    ($($ix:tt: $t:ident),*) => {
        impl<$($t: FromSql,)*> FromRow
        for ($($t,)*) {
            fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
                Ok(($(row.get($ix)?,)*))
            }
        }
    }
}

from_row_tuple!(0: A);
from_row_tuple!(0: A, 1: B);
from_row_tuple!(0: A, 1: B, 2: C);
from_row_tuple!(0: A, 1: B, 2: C, 3: D);
from_row_tuple!(0: A, 1: B, 2: C, 3: D, 4: E);
from_row_tuple!(0: A, 1: B, 2: C, 3: D, 4: E, 5: F);
from_row_tuple!(0: A, 1: B, 2: C, 3: D, 4: E, 5: F, 6: G);
from_row_tuple!(0: A, 1: B, 2: C, 3: D, 4: E, 5: F, 6: G, 7: H);
from_row_tuple!(0: A, 1: B, 2: C, 3: D, 4: E, 5: F, 6: G, 7: H, 8: I);
from_row_tuple!(0: A, 1: B, 2: C, 3: D, 4: E, 5: F, 6: G, 7: H, 8: I, 9: J);
