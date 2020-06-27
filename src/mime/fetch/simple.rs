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

//! Various simple fetchers which just obtain some part of the message
//! metadata.

use std::mem;

use chrono::prelude::*;

use crate::account::model::*;
use crate::mime::grovel::Visitor;

#[derive(Clone, Copy, Debug, Default)]
pub struct UidFetcher;

impl Visitor for UidFetcher {
    type Output = Uid;

    fn uid(&mut self, uid: Uid) -> Result<(), Uid> {
        Err(uid)
    }

    fn end(&mut self) -> Uid {
        panic!("UidFetcher.end()")
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ModseqFetcher;

impl Visitor for ModseqFetcher {
    type Output = Modseq;

    fn last_modified(&mut self, modseq: Modseq) -> Result<(), Modseq> {
        Err(modseq)
    }

    fn end(&mut self) -> Modseq {
        panic!("ModseqFetcher.end()")
    }
}

#[derive(Clone, Debug, Default)]
pub struct FlagsInfo {
    pub flags: Vec<Flag>,
    pub recent: bool,
}

#[derive(Clone, Debug, Default)]
pub struct FlagsFetcher {
    info: FlagsInfo,
}

impl FlagsFetcher {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Visitor for FlagsFetcher {
    type Output = FlagsInfo;

    fn want_flags(&self) -> bool {
        true
    }

    fn flags(&mut self, flags: &[Flag]) -> Result<(), FlagsInfo> {
        self.info.flags = flags.to_owned();
        Ok(())
    }

    fn recent(&mut self) -> Result<(), FlagsInfo> {
        self.info.recent = true;
        Ok(())
    }

    fn end_flags(&mut self) -> Result<(), FlagsInfo> {
        Err(self.end())
    }

    fn end(&mut self) -> FlagsInfo {
        mem::replace(&mut self.info, FlagsInfo::default())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Rfc822SizeFetcher;

impl Visitor for Rfc822SizeFetcher {
    type Output = u32;

    fn metadata(&mut self, md: &MessageMetadata) -> Result<(), u32> {
        Err(md.size)
    }

    fn end(&mut self) -> u32 {
        panic!("Rfc822SizeFetcher.end()")
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct InternalDateFetcher;

impl Visitor for InternalDateFetcher {
    type Output = DateTime<FixedOffset>;

    fn metadata(
        &mut self,
        md: &MessageMetadata,
    ) -> Result<(), DateTime<FixedOffset>> {
        Err(md.internal_date)
    }

    fn end(&mut self) -> DateTime<FixedOffset> {
        panic!("InternalDateFetcher.end()")
    }
}
