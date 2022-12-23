//-
// Copyright (c) 2020, 2022, Jason Lingle
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
use std::mem;
use std::path::{Path, PathBuf};

use structopt::StructOpt;

use crate::support::diagnostic;
use crate::support::sysexits::*;
use crate::support::system_config::SystemConfig;

#[derive(StructOpt)]
#[structopt(max_term_width = 80)]
enum Command {
    /// Commands which connect to a remote Crymap server system.
    Remote(RemoteSubcommand),
    /// Commands to be run on the Crymap server system.
    Server(ServerSubcommand),
    /// Commands used in the development or testing of Crymap.
    #[cfg(feature = "dev-tools")]
    Dev(DevSubcommand),
}

#[cfg(feature = "dev-tools")]
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

#[derive(StructOpt, Default)]
pub(super) struct ServerCommonOptions {
    /// The directory containing `crymap.toml` etc
    /// [default: /etc/crymap or /usr/local/etc/crymap]
    #[structopt(long, parse(from_os_str))]
    root: Option<PathBuf>,
}

#[derive(StructOpt)]
enum ServerSubcommand {
    Deliver(ServerDeliverSubcommand),
    /// Manage user accounts.
    User(ServerUserSubcommand),
    /// Serve a single IMAPS session over standard IO.
    ///
    /// This is intended to be used with inetd, xinetd, etc. It is the main way
    /// to run Crymap in production.
    ServeImaps(ServerCommonOptions),
    /// Serve a single LMTP session over standard IO.
    ///
    /// This is intended to be used with inetd, xinetd, etc.
    ServeLmtp(ServerCommonOptions),
}

impl ServerSubcommand {
    fn common_options(&mut self) -> ServerCommonOptions {
        match *self {
            ServerSubcommand::Deliver(ref mut c) => mem::take(&mut c.common),
            ServerSubcommand::User(ServerUserSubcommand::Add(ref mut c)) => {
                mem::take(&mut c.common)
            }
            ServerSubcommand::ServeImaps(ref mut c) => mem::take(c),
            ServerSubcommand::ServeLmtp(ref mut c) => mem::take(c),
        }
    }
}

#[derive(StructOpt)]
enum ServerUserSubcommand {
    /// Create a new user account.
    Add(ServerUserAddSubcommand),
}

#[derive(StructOpt)]
pub(super) struct ServerUserAddSubcommand {
    #[structopt(flatten)]
    pub(super) common: ServerCommonOptions,

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

/// Deliver or import mail.
///
/// By default, this will read from standard input and deliver it to the INBOX
/// of the Crymap user whose name matches the current UNIX user.
///
/// Delivering to another user can be accomplished by setting `--user`. This
/// requires having sufficient privilege to write into the user's mail
/// directory.
///
/// If this command is run as root, it will automatically change its UID to
/// that of the recipient before delivering the message and will chroot into
/// the user's directory. This happens BEFORE any input files are opened. In
/// general, this command should be run as the UNIX user that normally would
/// process the user's mail when not acting as a stdio-based MDA.
///
/// If the first line of an input ends with a UNIX line endings, all line feeds
/// in that input are converted into DOS line endings. If the first line ends
/// with a DOS line ending, the input is passed through bit-for-bit.
///
/// A maildir mailbox can be imported by simply passing all the files into this
/// command individually. For example:
///
/// ls Maildir/cur/* | xargs -d'\n' crymap server deliver --maildir-flags
///
/// This command cannot be used to import mbox files.
#[derive(StructOpt)]
pub(super) struct ServerDeliverSubcommand {
    #[structopt(flatten)]
    pub(super) common: ServerCommonOptions,

    /// Deliver to this user instead of yourself.
    #[structopt(short, long)]
    pub(super) user: Option<String>,

    /// Deliver to this mailbox. This must be an IMAP mailbox name, not a UNIX
    /// path.
    #[structopt(short, long, default_value = "INBOX")]
    pub(super) mailbox: String,

    /// Create the destination mailbox if it does not already exist.
    #[structopt(short, long)]
    pub(super) create: bool,

    /// Add this IMAP flag (e.g., '\Flagged') or keyword to the delivered
    /// message(s). Can be passed multiple times.
    #[structopt(parse(try_from_str), short, long, number_of_values(1))]
    pub(super) flag: Vec<crate::account::model::Flag>,

    /// Extract maildir-style flags from the file name(s).
    #[structopt(long)]
    pub(super) maildir_flags: bool,

    /// The files to import/deliver. "-" will read from stdin.
    #[structopt(parse(from_os_str), default_value = "-")]
    pub(super) inputs: Vec<PathBuf>,
}

#[derive(StructOpt, Default)]
pub(super) struct RemoteCommonOptions {
    /// The user name to log in as [default: current UNIX user name]
    #[structopt(long, short)]
    pub(super) user: Option<String>,
    /// The host to connect to
    #[structopt(long, short)]
    pub(super) host: String,
    /// The port to connect to
    #[structopt(long, short, default_value = "993")]
    pub(super) port: u16,
    /// Allow insecure TLS connections
    #[structopt(long)]
    pub(super) allow_insecure_tls_connections: bool,
    /// Dump a trace of the IMAP connection to standard error.
    #[structopt(long)]
    pub(super) trace: bool,
}

#[derive(StructOpt)]
pub(super) enum RemoteSubcommand {
    /// Connect and log in to a remote Crymap server, then disconnect.
    ///
    /// If this succeeds, it means that the following are working properly:
    ///
    /// - TLS (assuming --allow-insecure-tls-connections was not passed)
    ///
    /// - inetd or whatever else is responsible for running Crymap
    ///
    /// - User login
    ///
    /// - Any proxy in front of Crymap
    ///
    /// This cannot detect problems that require deeper inspection of the user
    /// account, such as file system corruption.
    Test(RemoteCommonOptions),
    /// Change the user's Crymap password.
    ///
    /// The change takes effect immediately; the old password will no longer be
    /// accepted. However, a backup file containing the information needed for
    /// the old password to work is created and retained until the next
    /// successful login at least 24 hours later. If you want to undo this
    /// change, you or an administrator can simply replace the user
    /// configuration file with the backup file.
    ///
    /// There is no way to change a user's password without knowing the current
    /// password. If a user's password is forgotten, their data is lost
    /// forever.
    Chpw(RemoteCommonOptions),
    Config(RemoteConfigSubcommand),
}

impl RemoteSubcommand {
    pub(super) fn common_options(&mut self) -> RemoteCommonOptions {
        match *self {
            RemoteSubcommand::Test(ref mut c)
            | RemoteSubcommand::Chpw(ref mut c) => mem::take(c),

            RemoteSubcommand::Config(ref mut c) => mem::take(&mut c.common),
        }
    }
}

/// Get or set Crymap user configuration.
///
/// Without any configuration options, fetch and display the current
/// configuration. Otherwise, update the requested options.
///
/// Options that are date patterns use the pattern syntax supported by the Rust
/// crate "chrono". Refer to this URL for a table of supported formatting
/// specifiers:
/// https://docs.rs/chrono/0.4.13/chrono/format/strftime/index.html
#[derive(StructOpt)]
pub(super) struct RemoteConfigSubcommand {
    #[structopt(flatten)]
    pub(super) common: RemoteCommonOptions,

    /// Change the pattern used to derive the names of keys used for encrypting
    /// messages and operations originating from the logged in user.
    #[structopt(long)]
    pub(super) internal_key_pattern: Option<String>,

    /// Change the pattern used to derive the names of keys used for encrypting
    /// messages and operations originating from the system.
    #[structopt(long)]
    pub(super) external_key_pattern: Option<String>,
}

pub fn main() {
    // Clap exits with status 1 instead of EX_USAGE if we use the more concise
    // API
    let cmd = Command::from_clap(&match Command::clap().get_matches_safe() {
        Ok(matches) => matches,
        Err(
            e @ clap::Error {
                kind: clap::ErrorKind::HelpDisplayed,
                ..
            },
        )
        | Err(
            e @ clap::Error {
                kind: clap::ErrorKind::VersionDisplayed,
                ..
            },
        ) => {
            println!("{}", e.message);
            return;
        }
        Err(e) => {
            eprintln!("{}", e.message);
            EX_USAGE.exit()
        }
    });

    match cmd {
        #[cfg(feature = "dev-tools")]
        Command::Dev(DevSubcommand::ImapTest) => super::imap_test::imap_test(),
        Command::Remote(cmd) => super::remote::main(cmd),
        Command::Server(cmd) => server(cmd),
    }
}

fn server(mut cmd: ServerSubcommand) {
    let common = cmd.common_options();
    let root = common.root.unwrap_or_else(|| {
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
            EX_CONFIG.exit()
        }
    });

    let system_config_path = root.join("crymap.toml");
    let mut system_config_toml = Vec::new();
    if let Err(e) = fs::File::open(&system_config_path)
        .and_then(|mut f| f.read_to_end(&mut system_config_toml))
    {
        eprintln!("Error reading '{}': {}", system_config_path.display(), e);
        EX_CONFIG.exit();
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
                EX_CONFIG.exit()
            }
        };

    if matches!(
        cmd,
        ServerSubcommand::Deliver(..)
            | ServerSubcommand::ServeLmtp(..)
            | ServerSubcommand::ServeImaps(..),
    ) {
        if let Err(exit) =
            diagnostic::apply_diagnostics(&root, &system_config.diagnostic)
        {
            exit.exit();
        }
    }

    let users_root = root.join("users");
    if !users_root.is_dir() {
        eprintln!("'{}' seems to be missing", users_root.display());
        EX_CONFIG.exit();
    }

    let users_root = match users_root.canonicalize() {
        Ok(ur) => ur,
        Err(e) => {
            eprintln!(
                "Unable to canonicalise '{}': {}",
                users_root.display(),
                e
            );
            EX_IOERR.exit()
        }
    };

    if Ok(true) == nix::unistd::isatty(2) {
        // Running interactively; ignore logging configuration and just write
        // to stderr.
        crate::init_simple_log();
    } else {
        // Right now we have this awkward situation where you can use log4rs *or*
        // syslog, because log4rs-syslog hasn't been updated in quite a while.
        //
        // If anything goes wrong, we don't really have a way to recover since
        // inetd sends even stderr back to the client.
        let log_config_file = root.join("logging.toml");
        if log_config_file.is_file() {
            log4rs::init_file(
                log_config_file,
                log4rs::config::Deserializers::new(),
            )
            .expect("Failed to initialise logging");
        } else {
            let formatter = syslog::Formatter3164 {
                facility: syslog::Facility::LOG_MAIL,
                hostname: None,
                process: env!("CARGO_PKG_NAME").to_owned(),
                pid: nix::unistd::getpid().as_raw(),
            };

            let logger =
                syslog::unix(formatter).expect("Failed to connect to syslog");
            log::set_boxed_logger(Box::new(syslog::BasicLogger::new(logger)))
                .map(|_| log::set_max_level(log::LevelFilter::Info))
                .expect("Failed to initialise logging");
        }
    }

    match cmd {
        ServerSubcommand::Deliver(cmd) => {
            super::deliver::deliver(system_config, cmd, users_root);
        }
        ServerSubcommand::User(ServerUserSubcommand::Add(cmd)) => {
            super::user::add(cmd, users_root);
        }
        ServerSubcommand::ServeImaps(_) => {
            super::serve::imaps(system_config, root, users_root);
        }
        ServerSubcommand::ServeLmtp(_) => {
            super::serve::lmtp(system_config, root, users_root);
        }
    }
}
