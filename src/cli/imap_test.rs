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
use std::io;
use std::net::TcpListener;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::sync::Arc;

use log::{info, warn};

use crate::account::account::Account;
use crate::crypt::master_key::MasterKey;
use crate::imap::command_processor::CommandProcessor;
use crate::imap::server::Server;
use crate::support::system_config::*;

pub fn imap_test() {
    crate::init_simple_log();

    let system_root: PathBuf =
        format!("/tmp/crymaptest.{}", nix::unistd::getpid()).into();
    let user_dir = system_root.join("user");

    let system_config = Arc::new(SystemConfig {
        security: SecurityConfig::default(),
        tls: TlsConfig {
            private_key: PathBuf::new(),
            certificate_chain: PathBuf::new(),
        },
        identification: std::collections::BTreeMap::new(),
    });

    fs::DirBuilder::new()
        .mode(0o700)
        .create(&system_root)
        .expect(&format!("Failed to create {}", system_root.display()));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&user_dir)
        .expect(&format!("Failed to create {}", user_dir.display()));

    {
        let account = Account::new(
            "initial-setup".to_owned(),
            user_dir,
            Some(Arc::new(MasterKey::new())),
        );
        account
            .provision(b"hunter2")
            .expect("Failed to set user account up");
    }

    let listener = TcpListener::bind("127.0.0.1:14143")
        .expect("Failed to bind listener socket");

    info!("Initialised successfully.");
    info!("Connect to: localhost:14143, username 'user', password 'hunter2'");

    loop {
        let (stream_in, origin) =
            listener.accept().expect("Failed to listen for connections");

        let processor = CommandProcessor::new(
            origin.to_string(),
            Arc::clone(&system_config),
            system_root.clone(),
        );

        let stream_out = stream_in
            .try_clone()
            .expect("Failed to duplicate socket handle");
        let mut server = Server::new(
            io::BufReader::new(stream_in),
            io::BufWriter::new(stream_out),
            processor,
        );

        std::thread::spawn(move || {
            info!("{} Accepted connection from", origin);

            match server.run() {
                Ok(_) => info!("{} Connection closed normally", origin),
                Err(e) => warn!("{} Connection error: {}", origin, e),
            }
        });
    }
}
