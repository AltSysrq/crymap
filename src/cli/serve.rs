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

use std::io::{self, Read, Write};
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use log::{error, info, warn};
use nix::poll::{poll, PollFd, PollFlags};
use nix::sys::time::TimeValLike;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslStream};

use crate::{
    imap::command_processor::CommandProcessor,
    support::{
        async_io::ServerIo, log_prefix::LogPrefix, system_config::SystemConfig,
        unix_privileges,
    },
};

const STDIN: RawFd = 0;
const STDOUT: RawFd = 1;

// Need to use a this and not die! so that errors go to syslog/etc
macro_rules! fatal {
    ($ex:ident, $($stuff:tt)*) => {{
        error!($($stuff)*);
        crate::support::sysexits::$ex.exit()
    }}
}

#[tokio::main(flavor = "current_thread")]
pub async fn imaps(
    system_config: SystemConfig,
    system_root: PathBuf,
    mut users_root: PathBuf,
) {
    let system_config = Arc::new(system_config);

    let acceptor = create_ssl_acceptor(&system_config, &system_root);

    // We've opened access to everything on the main system we need; now we can
    // apply chroot and privilege deescalation.
    let (log_prefix, _) =
        configure_system("imaps", &system_config, &mut users_root);

    let io = ServerIo::new_stdio().unwrap_or_else(|e| {
        fatal!(
            EX_OSERR,
            "{} Unable to put input/output into non-blocking mode: {}",
            log_prefix,
            e
        )
    });

    match tokio::time::timeout(
        Duration::from_secs(30),
        io.ssl_accept(&acceptor),
    )
    .await
    {
        Ok(Ok(())) => {},
        Ok(Err(e)) => {
            warn!("{} SSL handshake failed: {}", log_prefix, e);
            std::process::exit(0)
        },
        Err(_timeout) => {
            warn!("{} SSL handshake timed out", log_prefix);
            std::process::exit(0)
        },
    }

    // Get the key material out of memory.
    drop(acceptor);

    info!("{} SSL handshake succeeded", log_prefix);

    let processor =
        CommandProcessor::new(log_prefix.clone(), system_config, users_root);
    crate::imap::server::run(io, processor).await;
}

#[tokio::main(flavor = "current_thread")]
pub async fn lmtp(
    system_config: SystemConfig,
    system_root: PathBuf,
    mut users_root: PathBuf,
) {
    let host_name = if system_config.smtp.host_name.is_empty() {
        let host_name_cstr = nix::unistd::gethostname().unwrap_or_else(|e| {
            fatal!(
                EX_OSERR,
                "Failed to determine host name; you may \
                     need to explicitly configure it: {}",
                e
            )
        });
        host_name_cstr
            .to_str()
            .unwrap_or_else(|| {
                fatal!(EX_OSERR, "System host name is not UTF-8")
            })
            .to_owned()
    } else {
        system_config.smtp.host_name.clone()
    };

    let ssl_acceptor = create_ssl_acceptor(&system_config, &system_root);

    // We've opened access to everything on the main system we need; now we can
    // apply chroot and privilege deescalation.
    let (log_prefix, peer_name) =
        configure_system("lmtp", &system_config, &mut users_root);

    let io = ServerIo::new_stdio().unwrap_or_else(|e| {
        fatal!(
            EX_OSERR,
            "Failed to put stdio into non-blocking mode: {e:?}",
        )
    });

    let result = crate::smtp::inbound::serve_lmtp(
        io,
        Arc::new(system_config),
        log_prefix.clone(),
        ssl_acceptor,
        users_root,
        host_name,
        peer_name,
    )
    .await;

    match result {
        Ok(()) => info!("{} Normal client disconnect", log_prefix),
        Err(e) => warn!("{} Abnormal client disconnect: {}", log_prefix, e),
    }
}

fn create_ssl_acceptor(
    system_config: &SystemConfig,
    system_root: &Path,
) -> SslAcceptor {
    let mut acceptor =
        match SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()) {
            Ok(a) => a,
            Err(e) => fatal!(
                EX_SOFTWARE,
                "Failed to initialise OpenSSL acceptor: {}",
                e
            ),
        };

    let private_key_path = system_root.join(&system_config.tls.private_key);
    if let Err(e) =
        acceptor.set_private_key_file(&private_key_path, SslFiletype::PEM)
    {
        fatal!(
            EX_CONFIG,
            "Unable to load TLS private key from '{}': {}",
            private_key_path.display(),
            e
        );
    }

    let certificate_path =
        system_root.join(&system_config.tls.certificate_chain);
    if let Err(e) = acceptor.set_certificate_chain_file(&certificate_path) {
        fatal!(
            EX_CONFIG,
            "Unable to load TLS certificate chain from '{}': {}",
            certificate_path.display(),
            e
        );
    }

    if let Err(e) = acceptor.check_private_key() {
        fatal!(EX_CONFIG, "TLS key seems to be invalid: {}", e);
    }

    acceptor.build()
}

fn configure_system(
    protocol: &str,
    system_config: &SystemConfig,
    users_root: &mut PathBuf,
) -> (LogPrefix, String) {
    if let Err(exit) =
        unix_privileges::assume_system(&system_config.security, users_root)
    {
        exit.exit();
    }

    // We've dropped all privileges we can; it's now safe to start talking to
    // the client.
    match (nix::unistd::isatty(STDIN), nix::unistd::isatty(STDOUT)) {
        (Ok(true), _) | (_, Ok(true)) => {
            // In this case, we *do* want to use die!() since we're on a
            // terminal.
            die!(EX_USAGE, "stdin and stdout must not be a terminal")
        },
        _ => (),
    }

    let mut peer_name = nix::sys::socket::getpeername::<
        nix::sys::socket::UnixAddr,
    >(STDIN)
    .map(|addr| addr.to_string())
    .or_else(|_| {
        nix::sys::socket::getpeername::<nix::sys::socket::SockaddrIn>(STDIN)
            .map(|addr| addr.to_string())
    })
    .or_else(|_| {
        nix::sys::socket::getpeername::<nix::sys::socket::SockaddrIn6>(STDIN)
            .map(|addr| addr.to_string())
    })
    .unwrap_or_else(|_| "unknown-socket".to_owned());

    // On FreeBSD, getpeername() on a UNIX socket returns "@\0", which breaks
    // syslog if we log that.
    if peer_name.contains('\0') {
        peer_name = "unknown-socket".to_owned();
    }
    let log_prefix = LogPrefix::new(format!("{protocol}:{peer_name}"));

    if let Err(e) = nix::sys::socket::setsockopt(
        &std::io::stdin(),
        nix::sys::socket::sockopt::ReceiveTimeout,
        &nix::sys::time::TimeVal::minutes(30),
    )
    .and_then(|_| {
        nix::sys::socket::setsockopt(
            &std::io::stdout(),
            nix::sys::socket::sockopt::SendTimeout,
            &nix::sys::time::TimeVal::minutes(30),
        )
    }) {
        warn!("{} Unable to configure timeouts: {}", log_prefix, e);
    }

    // It is not unusual for stdio to be UNIX sockets instead of TCP, so don't
    // complain if setting TCP_NODELAY fails.
    let _ = nix::sys::socket::setsockopt(
        &std::io::stdout(),
        nix::sys::socket::sockopt::TcpNoDelay,
        &true,
    );

    info!("{} Connection established", log_prefix);
    (log_prefix, peer_name)
}

/// Provides read and write implementations to stdio without taking ownership
/// and without buffering or locking.
///
/// Async implementations assume the stdio file descriptors have already been
/// put into non-blocking mode.
#[derive(Debug)]
struct Stdio;

impl Read for Stdio {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        nix::unistd::read(STDIN, buf)
            .map_err(|e| io::Error::from_raw_os_error(e as i32))
    }
}

impl Write for Stdio {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        nix::unistd::write(STDOUT, buf)
            .map_err(|e| io::Error::from_raw_os_error(e as i32))
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
                let stdin = std::io::stdin();
                let mut stdin = [PollFd::new(
                    &stdin,
                    PollFlags::POLLIN | PollFlags::POLLERR,
                )];

                handle_poll_result(poll(&mut stdin, 30 * 60_000))
            },
            openssl::ssl::ErrorCode::WANT_WRITE => {
                let stdout = std::io::stdout();
                let mut stdout = [PollFd::new(
                    &stdout,
                    PollFlags::POLLOUT | PollFlags::POLLERR,
                )];

                handle_poll_result(poll(&mut stdout, 30 * 60_000))
            },
            _ => Err(e
                .into_io_error()
                .unwrap_or_else(|e| io::Error::new(io::ErrorKind::Other, e))),
        }
    }
}

fn handle_poll_result(
    result: Result<nix::libc::c_int, nix::Error>,
) -> io::Result<()> {
    match result {
        Ok(0) => {
            Err(io::Error::new(io::ErrorKind::TimedOut, "Socket timed out"))
        },
        Ok(_) => Ok(()),
        Err(nix::errno::Errno::EINTR) => Ok(()),
        Err(e) => Err(nix_to_io(e)),
    }
}

fn nix_to_io(e: nix::Error) -> io::Error {
    io::Error::from_raw_os_error(e as i32)
}
