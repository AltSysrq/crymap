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

use std::fmt;
use std::io;

/// A data source for literal items that aren't strings.
///
/// This is often backed by a `BufferReader` but can take any `io::Read`.
///
/// This struct has a `Clone` implementation so that it fits in with the stuff
/// the macros in `syntax` generates, but the implementation always panics.
///
/// For similar reasons, it has `PartialEq` and `Eq` implementations. These
/// only compare the non-data fields.
pub struct LiteralSource {
    /// The data for the literal.
    pub data: Box<dyn io::Read>,
    /// The actual length of the literal.
    pub len: u64,
    /// Whether to use the binary syntax for the literal.
    pub binary: bool,
}

impl Clone for LiteralSource {
    fn clone(&self) -> Self {
        panic!("LiteralSource::clone")
    }
}

impl PartialEq for LiteralSource {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len && self.binary == other.binary
    }
}

impl Eq for LiteralSource {}

impl fmt::Debug for LiteralSource {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("LiteralSource")
            .field("data", &"<data>")
            .field("len", &self.len)
            .field("binary", &self.binary)
            .finish()
    }
}

impl LiteralSource {
    #[cfg(test)]
    pub fn of_data(data: &'static [u8], binary: bool) -> Self {
        LiteralSource {
            data: Box::new(data),
            len: data.len() as u64,
            binary,
        }
    }

    pub fn of_reader(
        reader: impl io::Read + 'static,
        len: u64,
        binary: bool,
    ) -> Self {
        LiteralSource {
            data: Box::new(reader),
            len,
            binary,
        }
    }
}
