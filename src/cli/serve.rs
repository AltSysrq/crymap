//-
// Copyright (c) 2020, 2023, 2024, Jason Lingle
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

use std::cell::RefCell;
use std::net::IpAddr;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use log::{error, info, warn};
use nix::sys::time::TimeValLike;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};

use crate::{
    imap::command_processor::CommandProcessor,
    support::{
        async_io::ServerIo, dns, log_prefix::LogPrefix,
        system_config::SystemConfig, unix_privileges,
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
    let dns_resolver =
        match hickory_resolver::AsyncResolver::tokio_from_system_conf() {
            Ok(r) => Some(Rc::new(r)),
            Err(e) => {
                error!("Failed to initialise DNS resolver: {e}");
                None
            },
        };

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

    let processor = CommandProcessor::new(
        log_prefix.clone(),
        system_config,
        users_root,
        dns_resolver,
    );
    let local_set = tokio::task::LocalSet::new();
    local_set
        .run_until(crate::imap::server::run(io, processor))
        .await;
}

#[tokio::main(flavor = "current_thread")]
pub async fn lmtp(
    system_config: SystemConfig,
    system_root: PathBuf,
    mut users_root: PathBuf,
) {
    let host_name = smtp_host_name(&system_config);
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

#[tokio::main(flavor = "current_thread")]
pub async fn smtpin(
    system_config: SystemConfig,
    system_root: PathBuf,
    mut users_root: PathBuf,
) {
    let host_name = smtp_host_name(&system_config);
    let ssl_acceptor = create_ssl_acceptor(&system_config, &system_root);

    // We've opened access to everything on the main system we need; now we can
    // apply chroot and privilege deescalation.
    let (log_prefix, _peer_name) =
        configure_system("smtpin", &system_config, &mut users_root);

    let peer_ip = if let Ok(addr) =
        nix::sys::socket::getpeername::<nix::sys::socket::SockaddrIn>(STDIN)
    {
        IpAddr::V4(*std::net::SocketAddrV4::from(addr).ip())
    } else if let Ok(addr) =
        nix::sys::socket::getpeername::<nix::sys::socket::SockaddrIn6>(STDIN)
    {
        let addr = *std::net::SocketAddrV6::from(addr).ip();
        if let Some(v4) = addr.to_ipv4_mapped() {
            IpAddr::V4(v4)
        } else {
            IpAddr::V6(addr)
        }
    } else {
        fatal!(EX_OSERR, "stdin does not seem to be a TCP connection");
    };

    let resolver =
        match hickory_resolver::AsyncResolver::tokio_from_system_conf() {
            Ok(r) => r,
            Err(e) => {
                fatal!(EX_OSERR, "Failed to initialise DNS resolver: {e}")
            },
        };

    let io = ServerIo::new_stdio().unwrap_or_else(|e| {
        fatal!(
            EX_OSERR,
            "Failed to put stdio into non-blocking mode: {e:?}",
        )
    });

    let local_set = tokio::task::LocalSet::new();
    let result = local_set
        .run_until(crate::smtp::inbound::serve_smtpin(
            io,
            Some(Rc::new(resolver)),
            Rc::new(RefCell::new(dns::Cache::default())),
            Arc::new(system_config),
            log_prefix.clone(),
            ssl_acceptor,
            users_root,
            host_name,
            peer_ip,
        ))
        .await;

    match result {
        Ok(()) => info!("{} Normal client disconnect", log_prefix),
        Err(e) => warn!("{} Abnormal client disconnect: {}", log_prefix, e),
    }
}

#[tokio::main(flavor = "current_thread")]
pub async fn smtpsub(
    system_config: SystemConfig,
    system_root: PathBuf,
    mut users_root: PathBuf,
    implicit_tls: bool,
) {
    if system_config.smtp.host_name.is_empty() {
        fatal!(
            EX_CONFIG,
            "smtp.host_name must be explicitly configured for SMTP submission",
        );
    }
    let host_name = system_config.smtp.host_name.clone();
    let ssl_acceptor = create_ssl_acceptor(&system_config, &system_root);

    // We've opened access to everything on the main system we need; now we can
    // apply chroot and privilege deescalation.
    let (log_prefix, _peer_name) = configure_system(
        if implicit_tls { "smtpssub" } else { "smtpsub" },
        &system_config,
        &mut users_root,
    );

    let resolver =
        match hickory_resolver::AsyncResolver::tokio_from_system_conf() {
            Ok(r) => Rc::new(r),
            Err(e) => {
                fatal!(EX_OSERR, "Failed to initialise DNS resolver: {e}",)
            },
        };
    let dns_cache = Rc::new(RefCell::new(dns::Cache::default()));

    let io = ServerIo::new_stdio().unwrap_or_else(|e| {
        fatal!(
            EX_OSERR,
            "Failed to put stdio into non-blocking mode: {e:?}",
        )
    });

    let ssl_acceptor = if implicit_tls {
        match tokio::time::timeout(
            Duration::from_secs(30),
            io.ssl_accept(&ssl_acceptor),
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
        drop(ssl_acceptor);
        None
    } else {
        Some(ssl_acceptor)
    };

    info!("{} SSL handshake succeeded", log_prefix);

    let local_set = tokio::task::LocalSet::new();
    let log_prefix2 = log_prefix.clone();
    let result = local_set
        .run_until(crate::smtp::inbound::serve_smtpsub(
            io,
            Arc::new(system_config),
            log_prefix.clone(),
            ssl_acceptor,
            users_root,
            host_name.clone(),
            Box::new(move |account, id| {
                tokio::task::spawn_local({
                    let log_prefix = log_prefix2.clone();
                    let dns_cache = Rc::clone(&dns_cache);
                    let resolver = Rc::clone(&resolver);
                    let host_name = host_name.clone();
                    async move {
                        let result = crate::smtp::outbound::send_message(
                            dns_cache,
                            Some(resolver),
                            account,
                            id,
                            host_name.clone(),
                            None,
                        )
                        .await;
                        if let Err(e) = result {
                            error!(
                                "{log_prefix} Error setting up \
                                    message delivery: {e}"
                            );
                        }
                    }
                });
            }),
        ))
        .await;

    match result {
        Ok(()) => info!("{} Normal client disconnect", log_prefix),
        Err(e) => warn!("{} Abnormal client disconnect: {}", log_prefix, e),
    }

    // Wait for all mail to be sent.
    local_set.await;
}

fn smtp_host_name(system_config: &SystemConfig) -> String {
    if system_config.smtp.host_name.is_empty() {
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

    // We deliberately want to make things group-writable.
    let _ =
        nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_retain(0o002));

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
        "unknown-socket".clone_into(&mut peer_name);
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
