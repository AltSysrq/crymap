//-
// Copyright (c) 2023, 2024, Jason Lingle
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

mod canonicalisation;
mod error;
mod hash;
mod header;
mod sign;
mod verify;

#[cfg(test)]
mod test_domain_keys;

pub use canonicalisation::{
    BodyCanonicalisation, BodyCanonicaliser, Canonicalisation,
    HeaderCanonicalisation,
};
pub use error::*;
#[allow(unused_imports)]
pub use header::{
    Algorithm, HashAlgorithm, Header, SignatureAlgorithm, TxtFlags, TxtRecord,
    HEADER_NAME,
};
#[allow(unused_imports)]
pub use sign::{KeyPair, Signer};
#[allow(unused_imports)]
pub use verify::{Outcome, TxtRecordEntry, VerificationEnvironment, Verifier};

#[cfg(test)]
fn split_message(message: &[u8]) -> (&[u8], &[u8]) {
    let blank_line = memchr::memmem::find(message, b"\r\n\r\n")
        .expect("no CRLF-CRLF in message");
    (&message[..blank_line], &message[blank_line + 4..])
}
