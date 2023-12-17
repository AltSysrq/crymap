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

//! Internal utility for fetching inputs from header blocks that can be used to
//! train zstd.
//!
//! Basically, this will accumulate all headers in the header block. With a
//! couple exceptions, the header values are replaced with a few random
//! characters, both to prevent personal data from ending up in the dictionary,
//! and to ensure the dictionary is generally applicable. (This does cause zstd
//! to "learn" some of the random values, but this is OK since the dictionary
//! also matches substrings. The random values are still needed to prevent it
//! from "learning" things like both `From: \r\nTo: \r\n` and
//! `To: \r\nFrom: \r\n`.

use std::io::Write;

use rand::{rngs::OsRng, Rng};

use crate::{mime::grovel, support::un64};

#[derive(Debug, Clone, Default)]
pub struct ZstdTrainFetcher(Vec<u8>);

impl grovel::Visitor for ZstdTrainFetcher {
    type Output = Vec<u8>;

    fn header(
        &mut self,
        raw: &[u8],
        name: &str,
        _value: &[u8],
    ) -> Result<(), Self::Output> {
        if name.eq_ignore_ascii_case("Content-Type")
            || name.eq_ignore_ascii_case("Content-Transfer-Encoding")
            || name.eq_ignore_ascii_case("Date")
            || name.eq_ignore_ascii_case("Precedence")
            || name.eq_ignore_ascii_case("MIME-Version")
        {
            self.0.extend_from_slice(raw);
        } else {
            let rand: [u8; 3] = OsRng.gen();

            self.0.extend_from_slice(name.as_bytes());
            self.0.extend_from_slice(b": ");
            self.0.extend_from_slice(base64::encode(&rand).as_bytes());
            self.0.extend_from_slice(b"\r\n");
        }
        Ok(())
    }

    fn start_content(&mut self) -> Result<(), Self::Output> {
        Err(self.end())
    }

    fn end(&mut self) -> Self::Output {
        // We need to feed what we've accumulated into un64 compression since
        // that's what zstd will actually see, and some header names are longer
        // to be recognised as "base64" and "decoded" by un64.
        let mut compressed = Vec::<u8>::with_capacity(self.0.len());
        {
            let mut writer = un64::Writer::new(&mut compressed);
            writer
                .write_all(&self.0)
                .expect("writing to vec never fails");
            writer.flush().expect("writing to vec never fails");
        }
        self.0.clear();
        compressed
    }
}
