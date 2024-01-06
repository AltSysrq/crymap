//-
// Copyright (c) 2023, Jason Lingle
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

use std::any::Any;
use std::cell::RefCell;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::io::RawFd;
use std::pin::Pin;
use std::rc::Rc;
use std::task;

use openssl::ssl::SslStream;
use tokio::io::{
    unix::{AsyncFd, AsyncFdReadyGuard},
    AsyncRead, AsyncWrite, ReadBuf,
};

use crate::support::error::Error;

pub const STDIN: RawFd = 0;
pub const STDOUT: RawFd = 1;

/// The main type for doing async I/O for server connections.
///
/// This fulfils three roles:
/// - Working around Tokio's lack of a built-in way to do async IO on stdio.
/// - Supporting switching from cleartext to TLS mid-stream.
/// - Enabling simultaneous read and write even when in TLS mode (which
///   contends for the shared SSL stream).
///
/// Clones of `ServerIo` track the same underlying state. This allows what is
/// initially an `AsyncRead + AsyncWrite` to be split into separate `AsyncRead`
/// and `AsyncWrite` objects which can be used simultaneously.
#[derive(Clone)]
pub struct ServerIo {
    fd_pair: Rc<FdPair>,
    mode: Rc<RefCell<Mode>>,
    _owned: Option<Rc<dyn std::any::Any>>,
}

impl ServerIo {
    /// Sets up a `ServerIo` using stdio.
    ///
    /// This only fails if making stdio non-blocking fails.
    pub fn new_stdio() -> Result<Self, nix::Error> {
        Self::new_pair_raw(STDIN, STDOUT, None)
    }

    /// Sets up a `ServerIo` using separate input and output file descriptors.
    #[cfg(test)]
    pub fn new_owned_pair(
        inf: impl AsRawFd + Any,
        outf: impl AsRawFd + Any,
    ) -> Result<Self, nix::Error> {
        let infd = inf.as_raw_fd();
        let outfd = outf.as_raw_fd();
        Self::new_pair_raw(infd, outfd, Some(Rc::new((inf, outf))))
    }

    fn new_pair_raw(
        infd: RawFd,
        outfd: RawFd,
        owned: Option<Rc<dyn std::any::Any>>,
    ) -> Result<Self, nix::Error> {
        nix::fcntl::fcntl(
            infd,
            nix::fcntl::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK),
        )?;
        nix::fcntl::fcntl(
            outfd,
            nix::fcntl::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK),
        )?;

        let fd_pair = Rc::new(FdPair {
            read: AsyncFd::with_interest(infd, tokio::io::Interest::READABLE)
                .unwrap(),
            write: Some(
                AsyncFd::with_interest(outfd, tokio::io::Interest::WRITABLE)
                    .unwrap(),
            ),
        });

        Ok(Self {
            fd_pair: Rc::clone(&fd_pair),
            mode: Rc::new(RefCell::new(Mode::Cleartext(FdPairRw(fd_pair)))),
            _owned: owned,
        })
    }

    /// Sets up a `ServerIo` which runs over the given socket.
    ///
    /// The `ServerIo` will own the socket, and the socket will be closed when
    /// the last reference is dropped.
    ///
    /// This only fails if making the socket non-blocking fails.
    #[allow(dead_code)]
    pub fn new_owned_socket(
        sock: impl AsRawFd + Any,
    ) -> Result<Self, nix::Error> {
        let fd = sock.as_raw_fd();
        nix::fcntl::fcntl(
            fd,
            nix::fcntl::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK),
        )?;

        let fd_pair = Rc::new(FdPair {
            read: AsyncFd::with_interest(
                fd,
                tokio::io::Interest::READABLE | tokio::io::Interest::WRITABLE,
            )
            .unwrap(),
            write: None,
        });

        Ok(Self {
            fd_pair: Rc::clone(&fd_pair),
            mode: Rc::new(RefCell::new(Mode::Cleartext(FdPairRw(fd_pair)))),
            _owned: Some(Rc::new(sock)),
        })
    }

    pub fn is_ssl(&self) -> bool {
        matches!(*self.mode.borrow(), Mode::Ssl(_))
    }

    pub fn ssl_string(&self) -> Option<String> {
        match *self.mode.borrow() {
            Mode::Cleartext(..) => None,
            Mode::Ssl(ref stream) => {
                let ssl = stream.ssl();
                let cipher = ssl.current_cipher();
                Some(format!(
                    "{tls_version}:{cipher}:{strength}",
                    tls_version = ssl.version_str(),
                    cipher = cipher.map_or("NONE", |c| c.name()),
                    strength = cipher.map_or(0, |c| c.bits().algorithm),
                ))
            },
        }
    }

    /// Performs server-side SSL setup with the given acceptor.
    ///
    /// During the accept flow, concurrent calls to other methods will panic.
    pub async fn ssl_accept(
        &self,
        acceptor: &openssl::ssl::SslAcceptor,
    ) -> Result<(), Error> {
        // Borrow mode immediately so that concurrent access panics.
        #[allow(clippy::await_holding_refcell_ref)] // intentional
        let mode = self.mode.borrow_mut();
        let result = acceptor.accept(FdPairRw(Rc::clone(&self.fd_pair)));
        self.complete_ssl_handshake(mode, result).await
    }

    #[allow(clippy::await_holding_refcell_ref)] // intentional
    async fn complete_ssl_handshake(
        &self,
        mut mode: std::cell::RefMut<'_, Mode>,
        mut result: Result<
            SslStream<FdPairRw>,
            openssl::ssl::HandshakeError<FdPairRw>,
        >,
    ) -> Result<(), Error> {
        // The workflow around the ready guards is awkward because there's no
        // way to tell Tokio "I just saw that it's not ready, block until it's
        // ready again"; there's also no way to know which operation we need
        // without running through one pass of the OpenSSL implementation.
        // Instead, we get the guard when Tokio thinks the operation is ready
        // (but we know it probably isn't, because OpenSSL just told us, but
        // because of the await point it may have become actually ready) and
        // then need to do another round of the loop to test whether it's still
        // blocked. Then, once we do get another WANT_READ/WANT_WRITE while
        // holding the guard, we can finally tell Tokio that it's not ready and
        // drop the guard.
        let mut read_guard = None::<AsyncFdReadyGuard<'_, _>>;
        let mut write_guard = None::<AsyncFdReadyGuard<'_, _>>;

        loop {
            match result {
                Ok(stream) => {
                    *mode = Mode::Ssl(stream);
                    return Ok(());
                },

                Err(openssl::ssl::HandshakeError::SetupFailure(e)) => {
                    return Err(e.into());
                },

                Err(openssl::ssl::HandshakeError::Failure(mhss)) => {
                    return Err(mhss_to_error(mhss));
                },

                Err(openssl::ssl::HandshakeError::WouldBlock(mhss)) => {
                    match mhss.error().code() {
                        openssl::ssl::ErrorCode::WANT_READ => {
                            if let Some(mut read_guard) = read_guard.take() {
                                read_guard.clear_ready();
                            }

                            read_guard =
                                Some(self.fd_pair.read().readable().await?);
                            result = mhss.handshake();
                        },

                        openssl::ssl::ErrorCode::WANT_WRITE => {
                            if let Some(mut write_guard) = write_guard.take() {
                                write_guard.clear_ready();
                            }

                            write_guard =
                                Some(self.fd_pair.write().writable().await?);
                            result = mhss.handshake();
                        },

                        _ => return Err(mhss_to_error(mhss)),
                    }
                },
            }
        }
    }

    /// Called when an error is returned from `ssl_read` or `ssl_write`.
    ///
    /// The main purpose of this function is to handle the cases where OpenSSL
    /// returns `WANT_READ` or `WANT_WRITE`: it arranges a readiness check for
    /// the appropriate FD and clears its readiness status if currently set.
    /// Because of this, it is critical that this *only* be called immediately
    /// after `ssl_read` or `ssl_write`, with no await points in between, so
    /// that we can be certain that the `WANT_READ` or `WANT_WRITE` indicate
    /// that there is absolutely no data on the socket.
    fn on_rw_ssl_error(
        &self,
        ctx: &mut task::Context<'_>,
        e: openssl::ssl::Error,
    ) -> task::Poll<io::Result<()>> {
        match e.code() {
            openssl::ssl::ErrorCode::WANT_READ => {
                futures::ready!(self.fd_pair.read().poll_read_ready(ctx))?
                    .clear_ready();
                // Call again to get tokio to actually watch for more changes.
                futures::ready!(self.fd_pair.read().poll_read_ready(ctx))?
                    .retain_ready();
                // If we get here, the FD has somehow become ready meanwhile.
                task::Poll::Ready(Ok(()))
            },

            openssl::ssl::ErrorCode::WANT_WRITE => {
                futures::ready!(self.fd_pair.write().poll_write_ready(ctx))?
                    .clear_ready();
                // Call again to get tokio to actually watch for more changes.
                futures::ready!(self.fd_pair.write().poll_write_ready(ctx))?
                    .retain_ready();
                // If we get here, the FD has somehow become ready meanwhile.
                task::Poll::Ready(Ok(()))
            },

            // As can be seen in the `fmt::Display` implementation of
            // `openssl::ssl::Error`, EOF is represented by the SYSCALL error
            // code with no associated IO error, and into_io_error() doesn't
            // bother to translate that.
            openssl::ssl::ErrorCode::SYSCALL => task::Poll::Ready(Err(e
                .into_io_error()
                .unwrap_or_else(|_| io::ErrorKind::UnexpectedEof.into()))),

            _ => task::Poll::Ready(Err(e
                .into_io_error()
                .unwrap_or_else(|e| io::Error::new(io::ErrorKind::Other, e)))),
        }
    }
}

enum Mode {
    Cleartext(FdPairRw),
    Ssl(SslStream<FdPairRw>),
}

impl AsyncRead for ServerIo {
    fn poll_read(
        self: Pin<&mut Self>,
        ctx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> task::Poll<io::Result<()>> {
        let mut mode = self.mode.borrow_mut();
        match *mode {
            Mode::Cleartext(ref mut f) => Pin::new(f).poll_read(ctx, buf),
            Mode::Ssl(ref mut ssl) => loop {
                match ssl.ssl_read(buf.initialize_unfilled()) {
                    Ok(n) => {
                        buf.advance(n);
                        return task::Poll::Ready(Ok(()));
                    },

                    Err(e) => futures::ready!(self.on_rw_ssl_error(ctx, e))?,
                }
            },
        }
    }
}

impl AsyncWrite for ServerIo {
    fn poll_write(
        self: Pin<&mut Self>,
        ctx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> task::Poll<io::Result<usize>> {
        let mut mode = self.mode.borrow_mut();
        match *mode {
            Mode::Cleartext(ref mut f) => Pin::new(f).poll_write(ctx, buf),
            Mode::Ssl(ref mut ssl) => loop {
                match ssl.ssl_write(buf) {
                    Ok(n) => return task::Poll::Ready(Ok(n)),
                    Err(e) => futures::ready!(self.on_rw_ssl_error(ctx, e))?,
                }
            },
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _ctx: &mut task::Context<'_>,
    ) -> task::Poll<io::Result<()>> {
        // OpenSSL doesn't buffer anything itself (i.e. SslStream::flush() just
        // delegates to the underlying writer without invoking OpenSSL) and we
        // also have no buffers, so there's nothing to do.
        task::Poll::Ready(Ok(()))
    }

    /// If there is an SSL session, the session is shut down, returning the
    /// sockets to cleartext.
    ///
    /// During the shutdown process, other reads and writes are not
    /// well-defined.
    fn poll_shutdown(
        self: Pin<&mut Self>,
        ctx: &mut task::Context<'_>,
    ) -> task::Poll<io::Result<()>> {
        let mut mode = self.mode.borrow_mut();
        let done = if let Mode::Ssl(ref mut ssl) = *mode {
            loop {
                match ssl.shutdown() {
                    Ok(openssl::ssl::ShutdownResult::Received) => break,
                    Ok(openssl::ssl::ShutdownResult::Sent) => {
                        return task::Poll::Pending;
                    },

                    Err(e) => futures::ready!(self.on_rw_ssl_error(ctx, e))?,
                }
            }

            true
        } else {
            false
        };

        if done {
            *mode = Mode::Cleartext(FdPairRw(Rc::clone(&self.fd_pair)));
        }

        task::Poll::Ready(Ok(()))
    }
}

/// Holds a pair of `AsyncFd`s corresponding to the underlying input and output
/// socket(s).
///
/// This structure is tracked separately from the actual reader/writer as we
/// need to be able to "see through" the SSL stream in order to wait on the
/// underlying FDs to become ready.
struct FdPair {
    read: AsyncFd<RawFd>,
    write: Option<AsyncFd<RawFd>>,
}

impl FdPair {
    fn read(&self) -> &AsyncFd<RawFd> {
        &self.read
    }

    fn write(&self) -> &AsyncFd<RawFd> {
        self.write.as_ref().unwrap_or(&self.read)
    }
}

/// Implements both the synchronous and asynchronous read and write traits atop
/// raw file descriptors.
struct FdPairRw(Rc<FdPair>);

impl io::Read for FdPairRw {
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        let fd = *self.0.read().get_ref();
        nix::unistd::read(fd, dst).map_err(nix_to_io)
    }
}

impl io::Write for FdPairRw {
    fn write(&mut self, src: &[u8]) -> io::Result<usize> {
        let fd = *self.0.write().get_ref();
        nix::unistd::write(fd, src).map_err(nix_to_io)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsyncRead for FdPairRw {
    fn poll_read(
        self: Pin<&mut Self>,
        ctx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> task::Poll<io::Result<()>> {
        let async_read = self.0.read();
        loop {
            let mut guard = futures::ready!(async_read.poll_read_ready(ctx))?;

            match guard.try_io(|fd| {
                nix::unistd::read(*fd.get_ref(), buf.initialize_unfilled())
                    .map_err(nix_to_io)
            }) {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return task::Poll::Ready(Ok(()));
                },

                Ok(Err(e)) => return task::Poll::Ready(Err(e)),

                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for FdPairRw {
    fn poll_write(
        self: Pin<&mut Self>,
        ctx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> task::Poll<io::Result<usize>> {
        let async_write = self.0.write();
        loop {
            let mut guard = futures::ready!(async_write.poll_write_ready(ctx))?;

            if let Ok(result) = guard.try_io(|fd| {
                nix::unistd::write(*fd.get_ref(), buf).map_err(nix_to_io)
            }) {
                return task::Poll::Ready(result);
            }
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _ctx: &mut task::Context<'_>,
    ) -> task::Poll<io::Result<()>> {
        task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _ctx: &mut task::Context<'_>,
    ) -> task::Poll<io::Result<()>> {
        task::Poll::Ready(Ok(()))
    }
}

fn nix_to_io(e: nix::Error) -> io::Error {
    io::Error::from_raw_os_error(e as i32)
}

fn mhss_to_error<S>(mhss: openssl::ssl::MidHandshakeSslStream<S>) -> Error {
    let e = mhss.into_error();
    if let Some(es) = e.ssl_error() {
        Error::Ssl(es.clone())
    } else {
        match e.into_io_error() {
            Ok(io) => Error::Io(io),
            Err(e) if e.code() == openssl::ssl::ErrorCode::SYSCALL => {
                Error::Io(io::ErrorKind::UnexpectedEof.into())
            },
            Err(e) => Error::Io(io::Error::new(io::ErrorKind::Other, e)),
        }
    }
}
