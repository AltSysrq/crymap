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

use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(max_term_width = 80)]
enum Command {
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

pub fn main() {
    let cmd = Command::from_args();

    match cmd {
        Command::Dev(DevSubcommand::ImapTest) => super::imap_test::imap_test(),
    }
}
