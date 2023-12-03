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

use std::num::{NonZeroI64, NonZeroUsize};
use std::str::FromStr;

use chrono::prelude::*;
use rusqlite::types::{
    FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, ValueRef,
};

use crate::{account::model::*, crypt::AES_BLOCK};

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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageId(pub NonZeroI64);
transparent_to_sql!(MessageId);
transparent_from_sql!(MessageId);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlagId(pub NonZeroUsize);
transparent_to_sql!(FlagId);
transparent_from_sql!(FlagId);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnixTimestamp(pub DateTime<Utc>);

impl UnixTimestamp {
    pub fn now() -> Self {
        Self(Utc::now())
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
