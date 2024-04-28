//-
// Copyright (c) 2020, 2023, Jason Lingle
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

use log::info;
use tokio::net::TcpListener;

use crate::account::v2::Account;
use crate::crypt::master_key::MasterKey;
use crate::imap::command_processor::CommandProcessor;
use crate::support::{
    async_io::ServerIo, log_prefix::LogPrefix, system_config::*,
};

#[tokio::main(flavor = "current_thread")]
pub async fn imap_test() {
    let local = tokio::task::LocalSet::new();
    local.run_until(imap_test_impl()).await
}

async fn imap_test_impl() {
    crate::init_simple_log();

    let system_root: PathBuf =
        format!("/tmp/crymaptest.{}", nix::unistd::getpid()).into();
    let user_dir = system_root.join("user");

    let system_config = Arc::new(SystemConfig {
        security: SecurityConfig::default(),
        ..SystemConfig::default()
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
        let mut account = Account::new(
            LogPrefix::new("initial-setup".to_owned()),
            user_dir,
            Arc::new(MasterKey::new()),
        )
        .expect("failed to open account");
        account
            .provision(b"hunter2")
            .expect("Failed to set user account up");
    }

    let listener = TcpListener::bind("127.0.0.1:14143")
        .await
        .expect("Failed to bind listener socket");

    info!("Initialised successfully.");
    info!("Connect to: localhost:14143, username 'user', password 'hunter2'");

    loop {
        let (tcp_sock, origin) = listener
            .accept()
            .await
            .expect("Failed to listen for connections");
        // Convert to the std type so that the FD is deregistered from the
        // tokio runtime.
        let tcp_sock = tcp_sock.into_std().unwrap();
        let io = ServerIo::new_owned_socket(tcp_sock)
            .expect("Failed to make socket non-blocking");

        let processor = CommandProcessor::new(
            LogPrefix::new(origin.to_string()),
            Arc::clone(&system_config),
            system_root.clone(),
            None,
        );

        tokio::task::spawn_local(crate::imap::server::run(io, processor));
    }
}
