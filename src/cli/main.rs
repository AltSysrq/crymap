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
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::exit;

use structopt::StructOpt;

use crate::support::system_config::SystemConfig;

#[derive(StructOpt)]
#[structopt(max_term_width = 80)]
enum Command {
    /// Commands to be run on the Crymap server system.
    Server(ServerCommand),
    /// Commands used in the development or testing of Crymap.
    Dev(DevSubcommand),
}

#[derive(StructOpt)]
enum DevSubcommand {
    /// Run Crymap in a scratch environment for testing.
    ///
    /// This subcommand is intended only for use in running IMAP compliance
    /// testers which either are unable to connect over TLS or where running
    /// Crymap under inetd or similar is not desired (e.g. on a developer
    /// machine).
    ///
    /// In this mode, Crymap will listen for TCP connections on port 14143
    /// without TLS support. All connections will be handled in one process,
    /// unlike the intended production environment. A new system root will
    /// automatically be created and populated with a single test user.
    ///
    /// There is no way to configure this.
    ImapTest,
}

#[derive(StructOpt)]
struct ServerCommand {
    /// The directory containing `crymap.toml` etc.
    /// Default: `/etc/crymap` or `/usr/local/etc/crymap`
    #[structopt(long, parse(from_os_str))]
    root: Option<PathBuf>,

    #[structopt(subcommand)]
    subcommand: ServerSubcommand,
}

#[derive(StructOpt)]
enum ServerSubcommand {
    /// Manage user accounts.
    User(ServerUserSubcommand),
    /// Serve a single IMAPS session over standard IO.
    ///
    /// This is intended to be used with inetd, xinetd, etc. It is the main way
    /// to run Crymap in production.
    ServeImaps,
}

#[derive(StructOpt)]
enum ServerUserSubcommand {
    /// Create a new user account.
    Add(ServerUserAddSubcommand),
}

#[derive(StructOpt)]
pub(super) struct ServerUserAddSubcommand {
    /// Prompt for the password instead of generating one.
    #[structopt(long)]
    pub(super) prompt_password: bool,

    /// UNIX UID of the user.
    /// If not given but running as root, the user name will be used for this
    #[structopt(short, long)]
    pub(super) uid: Option<nix::libc::uid_t>,

    /// Name of the user to create.
    pub(super) name: String,

    /// The actual data path for the user. If not given, the user is just
    /// placed under `users/` in the Crymap root.
    #[structopt(parse(from_os_str))]
    pub(super) data_path: Option<PathBuf>,
}

pub fn main() {
    let cmd = Command::from_args();

    match cmd {
        Command::Dev(DevSubcommand::ImapTest) => super::imap_test::imap_test(),
        Command::Server(cmd) => server(cmd),
    }
}

fn server(cmd: ServerCommand) {
    let root = cmd.root.unwrap_or_else(|| {
        if Path::new("/etc/crymap/crymap.toml").is_file() {
            "/etc/crymap".to_owned().into()
        } else if Path::new("/usr/local/etc/crymap/crymap.toml").is_file() {
            "/usr/local/etc/crymap".to_owned().into()
        } else {
            eprintln!(
                "Neither /etc/crymap nor /usr/local/etc/crymap looks like\n\
                 the Crymap root; use --root=/path/to/crymap if your\n\
                 installation is elsewhere."
            );
            exit(1)
        }
    });

    let system_config_path = root.join("crymap.toml");
    let mut system_config_toml = Vec::new();
    if let Err(e) = fs::File::open(&system_config_path)
        .and_then(|mut f| f.read_to_end(&mut system_config_toml))
    {
        eprintln!("Error reading '{}': {}", system_config_path.display(), e);
        exit(1);
    }

    let system_config: SystemConfig =
        match toml::from_slice(&system_config_toml) {
            Ok(config) => config,
            Err(e) => {
                eprintln!(
                    "Error in config file at '{}': {}",
                    system_config_path.display(),
                    e
                );
                exit(1)
            }
        };

    let users_root = root.join("users");
    if !users_root.is_dir() {
        eprintln!("'{}' seems to be missing", users_root.display());
    }

    let users_root = match users_root.canonicalize() {
        Ok(ur) => ur,
        Err(e) => {
            eprintln!(
                "Unable to canonicalise '{}': {}",
                users_root.display(),
                e
            );
            exit(1)
        }
    };

    match cmd.subcommand {
        ServerSubcommand::User(ServerUserSubcommand::Add(cmd)) => {
            super::user::add(cmd, users_root);
        }
        ServerSubcommand::ServeImaps => unimplemented!(),
    }
}
