//-
// Copyright (c) 2020, 2023, Jason Lingle
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

use std::io;

use super::defs::*;
use crate::mime::fetch::zstd_train::ZstdTrainFetcher;
use crate::mime::grovel::grovel;
use crate::support::error::Error;

impl Account {
    pub fn zstd_train(&mut self, mb: &Mailbox) -> Result<Vec<u8>, Error> {
        let samples = mb
            .messages
            .iter()
            .map(|m| {
                let mut accessor = self.access_message(mb, m.uid)?;
                grovel(&mut accessor, ZstdTrainFetcher::default())
            })
            .collect::<Result<Vec<_>, Error>>()?;

        zstd::dict::from_samples(&samples, 4096)
            .map_err(|e| Error::Io(io::Error::new(io::ErrorKind::Other, e)))
    }
}
