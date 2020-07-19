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

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The system-wide configuration for Crymap.
///
/// This is stored in a file named `crymap.toml` under the Crymap system root,
/// which is typically `/usr/local/etc/crymap` or `/etc/crymap`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SystemConfig {
    /// Options relating to operational security of Crymap.
    #[serde(default)]
    pub security: SecurityConfig,

    /// Configuration for TLS.
    pub tls: TlsConfig,

    /// Extra values to report in the ID command.
    /// The main useful value here is `support-url`.
    #[serde(default)]
    pub identification: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SecurityConfig {
    /// If true, chroot into the system data directory before communicating
    /// with the client.
    ///
    /// If enabled and Crymap is started as root, it will load the
    /// configuration and TLS keys, then immediately chroot into the system
    /// data directory before doing any communication with the client.
    ///
    /// This option must be disabled if the user directories are symlinks to
    /// other locations, as is typical with a "UNIX-style" setup.
    ///
    /// In conjunction with `system_user`, this supports "black box" style
    /// setups where all the user directories are in one place and under the
    /// same UNIX user, as it allows Crymap to be isolated from the rest of the
    /// file system while still being able to load its shared libraries and
    /// keys.
    #[serde(default)]
    pub chroot_system: bool,
    /// If non-empty, set the process UID to this value after initialisation
    /// but before doing any communication with the client. The name must refer
    /// to a non-root user.
    ///
    /// This should be set for "black box" style setups where mail users are
    /// not mapped to UNIX users, but Crymap must be started as root for some
    /// other reason (such as for `chroot_system`).
    ///
    /// When used in conjunction with `chroot_system`, the UID change is done
    /// after the chroot operation.
    ///
    /// If this is not set, and Crymap is run as root, it will continue running
    /// as root until a successful login, at which point it will drop its
    /// privileges to those of the user that owns the user directory. If it is
    /// still running as root at that point, it will refuse further operation.
    #[serde(default)]
    pub system_user: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TlsConfig {
    /// The path to the TLS private key, which must be in PEM format.
    pub private_key: PathBuf,
    /// The path to the TLS certificate chain, which must be in PEM format.
    pub certificate_chain: PathBuf,
}
