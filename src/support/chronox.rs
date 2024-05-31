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

//! Helper traits which restore non-deprecated panicking methods (with 'x'
//! appended to disambiguate) and non-panicking wrappers for things that are
//! obviously infallible, since Chrono decided to make everything super noisy
//! instead.

use chrono::prelude::*;

pub trait FixedOffsetX {
    fn zero() -> Self;
    fn eastx(secs: i32) -> Self;
}

pub trait NaiveDateX {
    fn from_ymdx(y: i32, m: u32, d: u32) -> Self;
    fn and_hmsx(&self, h: u32, m: u32, s: u32) -> NaiveDateTime;
    fn and_hmsx_utc(&self, h: u32, m: u32, s: u32) -> DateTime<Utc>;
}

pub trait OffsetX {
    type DateTime;

    fn ymd_hmsx(
        &self,
        y: i32,
        m: u32,
        d: u32,
        h: u32,
        min: u32,
        s: u32,
    ) -> Self::DateTime;
    fn timestamp0(&self) -> Self::DateTime;
}

impl FixedOffsetX for FixedOffset {
    fn zero() -> Self {
        Self::eastx(0)
    }

    fn eastx(secs: i32) -> Self {
        Self::east_opt(secs).unwrap()
    }
}

impl NaiveDateX for NaiveDate {
    fn from_ymdx(y: i32, m: u32, d: u32) -> Self {
        Self::from_ymd_opt(y, m, d).unwrap()
    }

    fn and_hmsx(&self, h: u32, m: u32, s: u32) -> NaiveDateTime {
        self.and_hms_opt(h, m, s).unwrap()
    }

    fn and_hmsx_utc(&self, h: u32, m: u32, s: u32) -> DateTime<Utc> {
        self.and_hmsx(h, m, s).and_utc()
    }
}

impl<T: chrono::TimeZone + chrono::Offset> OffsetX for T {
    type DateTime = DateTime<T>;

    fn timestamp0(&self) -> Self::DateTime {
        self.timestamp_millis_opt(0).unwrap()
    }

    fn ymd_hmsx(
        &self,
        y: i32,
        m: u32,
        d: u32,
        h: u32,
        min: u32,
        s: u32,
    ) -> Self::DateTime {
        self.with_ymd_and_hms(y, m, d, h, min, s).unwrap()
    }
}
