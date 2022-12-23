//-
// Copyright (c) 2022, Jason Lingle
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

use std::path::Path;

use log::error;

use super::sysexits::*;
use super::system_config::DiagnosticConfig;

/// Apply the diagnostic configuration.
///
/// On failure, an error message has already been logged, and the appropriate
/// exit code is returned.
pub fn apply_diagnostics(
    root: &Path,
    config: &DiagnosticConfig,
) -> Result<(), Sysexit> {
    if let Some(ref stderr_path) = config.stderr {
        redirect_stderr(&root.join(stderr_path))?;
    }

    Ok(())
}

fn redirect_stderr(stderr_path: &Path) -> Result<(), Sysexit> {
    if let Err(e) = nix::unistd::close(2) {
        error!("failed to redirect stderr: close(stderr): {:?}", e);
        return Err(EX_IOERR);
    }

    match nix::fcntl::open(
        stderr_path,
        nix::fcntl::OFlag::O_APPEND
            | nix::fcntl::OFlag::O_WRONLY
            | nix::fcntl::OFlag::O_CREAT,
        nix::sys::stat::Mode::from_bits(0o640).unwrap(),
    ) {
        Err(e) => {
            error!(
                "failed to redirect stderr: open({}): {:?}",
                stderr_path.display(),
                e,
            );
            Err(EX_CANTCREAT)
        }

        Ok(2) => Ok(()),
        Ok(fd) => {
            error!("failed to redirect stderr: got fd {} instead of 2", fd);
            Err(EX_OSERR)
        }
    }
}
