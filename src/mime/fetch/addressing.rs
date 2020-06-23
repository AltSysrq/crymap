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

/// Describes which portion of a part to process.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LeafSectionType {
    /// Process the entire part, headers and all.
    Full,
    /// Process only the headers.
    Headers,
    /// Process only the content.
    Content,
}

/// Identifies a particular portion of the body to fetch.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BodySection {
    /// Which subscripts to traverse to find the part in question.
    pub subscripts: Vec<u32>,
    /// Which subsection of the part to read.
    pub leaf_type: LeafSectionType,
    /// When a non-continuation line is encountered, stop copying output until
    /// the next non-continuation line.
    ///
    /// Blank lines are always copied.
    pub header_filter: Vec<String>,
    /// If true, default to dropping data and invert the meaning of
    /// `header_filter`.
    ///
    /// Blank lines are still always copied.
    pub default_discard: bool,
    /// If set, slice the binary data produced by the above to this range,
    /// clamping each endpoint.
    pub partial: Option<(u64, u64)>,
}
