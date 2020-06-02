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

mod b64 {
    use base64;
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
            base64::decode(&s).map_err(|err| Error::custom(err.to_string()))
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum PasswordType {
    Argon2i_V13_M16384_T10_L1,
}

/// The user configuration.
///
/// This is the root of the TOML file stored in "config.toml" at the root of
/// the user directory.
///
/// Everything inside here is assumed to be mutable by the user.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserConfig {
    pub credentials: CredConfig,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CredConfig {
    #[serde(with = "b64")]
    pub password_hash: Vec<u8>,
    #[serde(with = "b64")]
    pub password_salt: Vec<u8>,
    pub password_type: PasswordType,
    #[serde(with = "b64")]
    pub master_key_xor: Vec<u8>,
}
