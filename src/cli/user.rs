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

use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::sync::Arc;

use rand::{rngs::OsRng, Rng};

use super::main::ServerUserAddSubcommand;
use crate::account::v1::account::Account;
use crate::crypt::master_key::MasterKey;
use crate::support::safe_name::is_safe_name;

pub(super) fn add(cmd: ServerUserAddSubcommand, users_root: PathBuf) {
    if !is_safe_name(&cmd.name) {
        die!(EX_USAGE, "Invalid user name: {}", cmd.name);
    }

    let nominal_path = users_root.join(&cmd.name);
    let data_path_configured = cmd.data_path.is_some();
    let actual_path = cmd.data_path.unwrap_or_else(|| nominal_path.clone());

    if (users_root.starts_with("/etc")
        || users_root.starts_with("/usr/local/etc"))
        && !data_path_configured
    {
        die!(
            EX_USAGE,
            "This would put the user data under {}, which is probably not\n\
             what you want. Explicit specification of the data-path is\n\
             required.",
            actual_path.display()
        );
    }

    if nominal_path.symlink_metadata().is_ok() {
        die!(EX_CANTCREAT, "User '{}' already exists", cmd.name);
    }

    if actual_path.is_dir() {
        die!(
            EX_CANTCREAT,
            "'{}' is already a directory. If you want to link an existing\n\
             account as a new user in the system, you can run a command like\n\
             \n\
             \tln -s '{}' '{}'",
            actual_path.display(),
            actual_path.display(),
            nominal_path.display()
        );
    }

    let user = if nix::unistd::ROOT == nix::unistd::getuid() {
        let user_result = if let Some(uid) = cmd.uid {
            (
                format!("{}", uid),
                nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid)),
            )
        } else {
            (
                format!("'{}'", cmd.name),
                nix::unistd::User::from_name(&cmd.name),
            )
        };

        match user_result {
            (q, Err(e)) => {
                die!(EX_OSFILE, "Unable to look up UNIX user {}: {}", q, e)
            },
            (q, Ok(None)) => die!(EX_NOUSER, "{} is not a UNIX user", q),
            (_, Ok(Some(user))) if user.uid == nix::unistd::ROOT => {
                die!(EX_USAGE, "Creating account for root not allowed")
            },
            (_, Ok(Some(user))) => Some(user),
        }
    } else if cmd.uid.is_some() {
        die!(EX_NOPERM, "`-u` can only be used as root.")
    } else {
        None
    };

    let password = if cmd.prompt_password {
        match rpassword::prompt_password("Password: ").and_then(|a| {
            rpassword::prompt_password("Confirm: ").map(|b| (a, b))
        }) {
            Err(e) => die!(EX_NOINPUT, "Failed to read password: {}", e),
            Ok((a, b)) if a != b => die!(EX_DATAERR, "Passwords don't match"),
            Ok((a, _)) if a.is_empty() => die!(EX_NOINPUT, "No password given"),
            Ok((a, _)) => a,
        }
    } else {
        let data: [u8; 8] = OsRng.gen();
        base64::encode(data)
    };

    if let Err(e) = fs::DirBuilder::new().mode(0o770).create(&actual_path) {
        die!(
            EX_CANTCREAT,
            "Failed to create '{}': {}",
            actual_path.display(),
            e
        );
    }

    if actual_path != nominal_path {
        if let Err(e) = std::os::unix::fs::symlink(&actual_path, &nominal_path)
        {
            die!(
                EX_CANTCREAT,
                "Failed to link '{}' to '{}': {}",
                nominal_path.display(),
                actual_path.display(),
                e
            );
        }
    }

    if let Some(ref user) = user {
        if let Err(e) =
            nix::unistd::chown(&actual_path, Some(user.uid), Some(user.gid))
        {
            die!(
                EX_OSERR,
                "Failed to change ownership of '{}' to ({},{}): {}",
                actual_path.display(),
                user.uid,
                user.gid,
                e
            );
        }

        if let Err(e) = nix::unistd::initgroups(
            &std::ffi::CString::new(user.name.to_owned()).unwrap(),
            user.gid,
        )
        .and_then(|_| nix::unistd::setgid(user.gid))
        .and_then(|_| nix::unistd::setuid(user.uid))
        {
            die!(
                EX_OSERR,
                "Failed to switch to UNIX user {}: {}",
                user.name,
                e
            );
        }
    }

    let account = Account::new(
        "account-setup".to_owned(),
        actual_path,
        Some(Arc::new(MasterKey::new())),
    );

    if let Err(e) = account.provision(password.as_bytes()) {
        die!(EX_SOFTWARE, "Error provisioning account: {}", e);
    }

    if !cmd.prompt_password {
        println!("Password: {}", password);
    }
}
