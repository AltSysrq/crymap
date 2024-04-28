//-
// Copyright (c) 2024, Jason Lingle
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
use std::io::{self, Write};
use std::sync::Arc;

use chrono::prelude::*;

use crate::{
    account::model::CommonPaths,
    support::buffer::{BufferReader, BufferWriter},
};

pub struct Transcript {
    buffer: BufferWriter,
    last_entry: Option<DateTime<Utc>>,
}

impl Transcript {
    pub fn new(common_paths: Arc<CommonPaths>) -> Self {
        Self {
            buffer: BufferWriter::new(common_paths),
            last_entry: None,
        }
    }

    pub fn line(&mut self, args: fmt::Arguments<'_>) {
        let now = Utc::now();
        let now_fmt = now.format("%Y-%m-%d %H:%M:%S");
        if let Some(last_entry) = self.last_entry {
            let delta =
                now.signed_duration_since(last_entry).num_milliseconds();
            let _ = writeln!(self.buffer, "{now_fmt} ({delta:+5}ms) {args}\r");
        } else {
            let _ = writeln!(self.buffer, "{now_fmt} {args}\r");
        }

        self.last_entry = Some(now);
    }

    pub fn finish(self) -> io::Result<BufferReader> {
        self.buffer.flip()
    }
}
