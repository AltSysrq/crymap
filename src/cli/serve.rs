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

use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use log::{error, info, warn};
use nix::sys::time::TimeValLike;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslStream};

use crate::imap::command_processor::CommandProcessor;
use crate::imap::server::Server;
use crate::support::system_config::SystemConfig;

// Need to use a this and not die! so that errors go to syslog/etc
macro_rules! fatal {
    ($($stuff:tt)*) => {{
        error!($($stuff)*);
        std::process::exit(1)
    }}
}

pub fn serve(
    system_config: SystemConfig,
    system_root: PathBuf,
    mut users_root: PathBuf,
) {
    let system_config = Arc::new(system_config);

    // TODO CONFIGURE LOGGING PROPERLY
    crate::init_simple_log();

    let mut acceptor =
        match SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()) {
            Ok(a) => a,
            Err(e) => fatal!("Failed to initialise OpenSSL acceptor: {}", e),
        };

    let private_key_path = system_root.join(&system_config.tls.private_key);
    if let Err(e) =
        acceptor.set_private_key_file(&private_key_path, SslFiletype::PEM)
    {
        fatal!(
            "Unable to load TLS private key from '{}': {}",
            private_key_path.display(),
            e
        );
    }

    let certificate_path =
        system_root.join(&system_config.tls.certificate_chain);
    if let Err(e) =
        acceptor.set_certificate_file(&certificate_path, SslFiletype::PEM)
    {
        fatal!(
            "Unable to load TLS certificate chain from '{}': {}",
            certificate_path.display(),
            e
        );
    }

    if let Err(e) = acceptor.check_private_key() {
        fatal!("TLS key seems to be invalid: {}", e);
    }

    // We've opened access to everything on the main system we need; now we can
    // apply chroot and privilege deescalation.

    let system_user = if system_config.security.system_user.is_empty() {
        None
    } else {
        match nix::unistd::User::from_name(&system_config.security.system_user)
        {
            Ok(Some(user)) => Some(user),
            Ok(None) => fatal!(
                "system_user '{}' does not exist!",
                system_config.security.system_user
            ),
            Err(e) => fatal!(
                "Unable to look up system_user '{}': {}",
                system_config.security.system_user,
                e
            ),
        }
    };

    if let Some(ref system_user) = system_user {
        if let Err(e) = nix::unistd::initgroups(
            &std::ffi::CString::new(system_user.name.clone()).unwrap(),
            system_user.gid,
        ) {
            fatal!("Unable to set up groups for system user: {}", e);
        }
    }

    if system_config.security.chroot_system {
        if let Err(e) =
            // chroot, then chdir, since users_root could be relative
            nix::unistd::chroot(&users_root)
            .and_then(|_| nix::unistd::chdir("/"))
        {
            fatal!("Failed to chroot to '{}': {}", users_root.display(), e);
        }

        users_root.push("/");
    }

    if let Some(system_user) = system_user {
        if let Err(e) = nix::unistd::setgid(system_user.gid)
            .and_then(|_| nix::unistd::setuid(system_user.uid))
        {
            fatal!(
                "Failed to set UID:GID to {}:{}: {}",
                system_user.uid,
                system_user.gid,
                e
            );
        }
    }

    // We've dropped all privileges we can; it's now safe to start talking to
    // the client.
    match (nix::unistd::isatty(0), nix::unistd::isatty(1)) {
        (Ok(true), _) | (_, Ok(true)) => {
            fatal!("stdin and stdout must not be a terminal")
        }
        _ => (),
    }

    let peer_name = match nix::sys::socket::getpeername(0) {
        Ok(addr) => addr.to_string(),
        Err(e) => fatal!("Unable to determine peer name: {}", e),
    };

    if let Err(e) = nix::sys::socket::setsockopt(
        0,
        nix::sys::socket::sockopt::ReceiveTimeout,
        &nix::sys::time::TimeVal::minutes(30),
    )
    .and_then(|_| {
        nix::sys::socket::setsockopt(
            1,
            nix::sys::socket::sockopt::SendTimeout,
            &nix::sys::time::TimeVal::minutes(30),
        )
    }) {
        warn!("{} Unable to configure timeouts: {}", peer_name, e);
    }

    if let Err(e) = nix::sys::socket::setsockopt(
        1,
        nix::sys::socket::sockopt::TcpNoDelay,
        &true,
    ) {
        warn!(
            "{} Unable to configure TCP NODELAY on stdout: {}",
            peer_name, e
        );
    }

    info!("{} Connection established", peer_name);

    let ssl_stream = match acceptor.build().accept(Stdio) {
        Ok(ss) => ss,
        Err(e) => {
            warn!("{} SSL handshake failed: {}", peer_name, e);
            std::process::exit(0)
        }
    };

    info!("{} SSL handshake succeeded", peer_name);

    // This mutex is pretty unfortunate, but needed right now to split
    // SslStream into two pieces.
    let ssl_stream = Arc::new(Mutex::new(ssl_stream));

    let processor =
        CommandProcessor::new(peer_name.clone(), system_config, users_root);

    let mut server = Server::new(
        io::BufReader::new(WrappedIo(Arc::clone(&ssl_stream))),
        io::BufWriter::new(WrappedIo(Arc::clone(&ssl_stream))),
        processor,
    );

    if let Err(e) =
        nix::fcntl::fcntl(0, nix::fcntl::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK))
            .and_then(|_| {
                nix::fcntl::fcntl(
                    1,
                    nix::fcntl::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK),
                )
            })
    {
        fatal!(
            "{} Unable to put input/output into non-blocking mode: {}",
            peer_name,
            e
        );
    }

    match server.run() {
        Ok(_) => info!("{} Normal client disconnect", peer_name),
        Err(e) => warn!("{} Abnormal client disconnect: {}", peer_name, e),
    }
}

// Read and write to the stdio FDs without buffering
#[derive(Debug)]
struct Stdio;

impl Read for Stdio {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        nix::unistd::read(0, buf).map_err(|e| {
            io::Error::from_raw_os_error(e.as_errno().unwrap() as i32)
        })
    }
}

impl Write for Stdio {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        nix::unistd::write(1, buf).map_err(|e| {
            io::Error::from_raw_os_error(e.as_errno().unwrap() as i32)
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Wraps SslStream to implement Read and Write over this structure in the
/// mutex, and also to deal with non-blocking IO.
///
/// We need to use non-blocking IO to allow writes to proceed even when read is
/// blocking on getting data from the client, as when doing IDLE.
struct WrappedIo(Arc<Mutex<SslStream<Stdio>>>);

impl Read for WrappedIo {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let res = {
                let mut lock = self.0.lock().unwrap();
                lock.ssl_read(buf)
            };

            match res {
                Ok(n) => return Ok(n),
                Err(e) => self.on_error(e)?,
            }
        }
    }
}

impl Write for WrappedIo {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        loop {
            let res = {
                let mut lock = self.0.lock().unwrap();
                lock.ssl_write(buf)
            };

            match res {
                Ok(n) => return Ok(n),
                Err(e) => self.on_error(e)?,
            };
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut lock = self.0.lock().unwrap();
        lock.flush()
    }
}

impl WrappedIo {
    fn on_error(&mut self, e: openssl::ssl::Error) -> io::Result<()> {
        match e.code() {
            openssl::ssl::ErrorCode::WANT_READ => {
                let mut stdin = nix::sys::select::FdSet::new();
                stdin.insert(0);
                nix::sys::select::select(
                    None,
                    Some(&mut stdin.clone()),
                    None,
                    Some(&mut stdin),
                    Some(&mut nix::sys::time::TimeVal::minutes(30)),
                )
                .map_err(nix_to_io)?;
                Ok(())
            }
            openssl::ssl::ErrorCode::WANT_WRITE => {
                let mut stdout = nix::sys::select::FdSet::new();
                stdout.insert(1);
                nix::sys::select::select(
                    None,
                    None,
                    Some(&mut stdout.clone()),
                    Some(&mut stdout.clone()),
                    Some(&mut nix::sys::time::TimeVal::minutes(30)),
                )
                .map_err(nix_to_io)?;
                Ok(())
            }
            _ => Err(e
                .into_io_error()
                .unwrap_or_else(|e| io::Error::new(io::ErrorKind::Other, e))),
        }
    }
}

fn nix_to_io(e: nix::Error) -> io::Error {
    io::Error::from_raw_os_error(e.as_errno().unwrap() as i32)
}
