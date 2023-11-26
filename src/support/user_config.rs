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

use serde::{Deserialize, Serialize};

use crate::account::key_store::KeyStoreConfig;
use crate::crypt::master_key::MasterKeyConfig;

#[allow(clippy::ptr_arg)]
pub mod b64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        bytes: &Vec<u8>,
        ser: S,
    ) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&base64::encode(bytes))
    }

    pub fn deserialize<'a, D: Deserializer<'a>>(
        de: D,
    ) -> Result<Vec<u8>, D::Error> {
        use serde::de::Error;
        String::deserialize(de).and_then(|s| {
            base64::decode(s).map_err(|err| Error::custom(err.to_string()))
        })
    }
}

/// The user configuration.
///
/// This is the root of the TOML file stored in "config.toml" at the root of
/// the user directory.
///
/// Everything inside here is assumed to be mutable by the user.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserConfig {
    pub master_key: MasterKeyConfig,
    pub key_store: KeyStoreConfig,
}
