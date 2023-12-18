//-
// Copyright (c) 2023, Jason Lingle
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

use std::fs;
use std::io::{Read, Write};

use chrono::prelude::*;

use super::{super::account_config_file, defs::*};
use crate::{
    account::model::*,
    support::{error::Error, safe_name::is_safe_name, user_config::UserConfig},
};

// Like format!, but returns None if the formatter fails instead of panicking.
macro_rules! try_format {
    ($($stuff:tt)*) => {{
        use std::io::Write as _;
        let mut buf = Vec::new();
        write!(&mut buf, $($stuff)*).ok()
            .and_then(|_| String::from_utf8(buf).ok())
    }}
}

impl Account {
    /// Load and return the user's current configuration.
    ///
    /// This may not be the exact configuration currently applied.
    pub fn load_config(&self) -> Result<UserConfig, Error> {
        let config_file = account_config_file(&self.root);
        let mut data = Vec::new();
        fs::File::open(&config_file)?.read_to_end(&mut data)?;

        let config: UserConfig = toml::from_slice(&data)?;
        Ok(config)
    }

    /// Update the user's configuration.
    ///
    /// The changes do not apply to the current connection.
    ///
    /// Returns the location of the backup file this creates.
    pub fn update_config(
        &self,
        request: SetUserConfigRequest,
    ) -> Result<String, Error> {
        let config_file = account_config_file(&self.root);
        let mut config = self.load_config()?;
        let now = Utc::now();

        if let Some(internal_key_pattern) = request.internal_key_pattern {
            // We need to format the keys with some date to check the patterns
            // for validity. This is both because they contain % in raw form,
            // which makes for an unsafe name, and because format!() will
            // result in a panic if the date format is not understood by
            // chrono.
            if !is_safe_name(
                &try_format!("{}", now.format(&internal_key_pattern))
                    .unwrap_or_default(),
            ) {
                return Err(Error::UnsafeName);
            }

            config.key_store.internal_key_pattern = internal_key_pattern;
        }

        if let Some(external_key_pattern) = request.external_key_pattern {
            if !is_safe_name(
                &try_format!("{}", now.format(&external_key_pattern))
                    .unwrap_or_default(),
            ) {
                return Err(Error::UnsafeName);
            }

            config.key_store.external_key_pattern = external_key_pattern;
        }

        if let Some(password) = request.password {
            config.master_key = self
                .master_key
                .make_config(password.as_bytes())
                .expect("argon2 hash failed");
            config.master_key.last_changed = Some(now.into());
        }

        let config_toml =
            toml::to_vec(&config).expect("TOML serialisation failed");

        let mut tmpfile =
            tempfile::NamedTempFile::new_in(&self.common_paths.tmp)?;
        tmpfile.write_all(&config_toml)?;

        let backup_name = format!("config-backup-{}.toml", now.to_rfc3339());
        let backup_file = self.common_paths.tmp.join(&backup_name);
        nix::unistd::linkat(
            None,
            &config_file,
            None,
            &backup_file,
            nix::unistd::LinkatFlags::NoSymlinkFollow,
        )?;
        tmpfile.persist(&config_file).map_err(|e| e.error)?;

        Ok(backup_name)
    }
}
