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

mod condstore_basics;
mod condstore_enable;
mod condstore_fetch;
mod condstore_flags;
mod condstore_search;
mod condstore_status;
mod qresync;

use super::defs::*;

fn extract_highest_modseq(responses: &[s::ResponseLine<'_>]) -> u64 {
    has_untagged_response_matching! {
        s::Response::Cond(s::CondResponse {
            code: Some(s::RespTextCode::HighestModseq(mm)),
            ..
        }) in responses => mm
    }
}
