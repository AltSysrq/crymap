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

use std::io;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Unsafe key or mailbox name")]
    UnsafeName,
    #[error("Master key unavailable")]
    MasterKeyUnavailable,
    #[error("Named key not found")]
    NamedKeyNotFound,
    #[error("Encrypted key malformed")]
    BadEncryptedKey,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Ssl(#[from] openssl::error::ErrorStack),
    #[error(transparent)]
    Cbor(#[from] serde_cbor::error::Error),
}
