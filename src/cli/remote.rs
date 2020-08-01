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

use std::cell::RefCell;
use std::io::{self, BufRead, Read, Write};
use std::net::{self, ToSocketAddrs};
use std::rc::Rc;

use openssl::ssl::{HandshakeError, SslConnector, SslMethod, SslVerifyMode};
use thiserror::Error;

use super::main::*;
use crate::imap::client::Client;
use crate::imap::syntax as s;

type RemoteClient = Client<Box<dyn BufRead>, Box<dyn Write>>;

#[derive(Error, Debug)]
enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Ssl(#[from] openssl::error::ErrorStack),
    #[error(transparent)]
    Ssl2(#[from] openssl::ssl::Error),
    #[error(transparent)]
    Client(#[from] crate::imap::client::Error),
}

pub(super) fn main(cmd: RemoteSubcommand) {
    if let Err(e) = main_impl(cmd) {
        die!(EX_SOFTWARE, "Error: {}", e);
    }
}

fn main_impl(mut cmd: RemoteSubcommand) -> Result<(), Error> {
    let mut client = connect(cmd.common_options())?;

    match cmd {
        RemoteSubcommand::Test(_) => {
            println!("Server looks OK");
        }
    }

    let mut buffer = Vec::new();
    let _ = client
        .command(s::Command::Simple(s::SimpleCommand::LogOut), &mut buffer);
    Ok(())
}

fn connect(options: RemoteCommonOptions) -> Result<RemoteClient, Error> {
    let user = match options.user {
        Some(user) => user,
        None => match nix::unistd::User::from_uid(nix::unistd::getuid()) {
            Ok(Some(u)) => u.name,
            Ok(None) => die!(EX_NOUSER, "No passwd entry for current user"),
            Err(e) => {
                die!(EX_OSFILE, "Failed to look up current UNIX user: {}", e)
            }
        },
    };

    let mut addresses =
        (&options.host as &str, options.port).to_socket_addrs()?;
    let address = addresses.next().ok_or(Error::Io(io::Error::new(
        io::ErrorKind::Other,
        "Host not found",
    )))?;

    if options.trace {
        eprintln!("Opening connection to {}", address);
    }

    let tcp_stream = net::TcpStream::connect(address)?;

    if options.trace {
        eprintln!("Starting TLS handshake");
    }

    let mut connector = SslConnector::builder(SslMethod::tls())?;
    if options.allow_insecure_tls_connections {
        connector.set_verify(SslVerifyMode::NONE);
    }

    let ssl_stream = connector
        .build()
        .connect(&options.host, tcp_stream)
        .map_err(|e| match e {
            HandshakeError::SetupFailure(es) => Error::Ssl(es),
            HandshakeError::Failure(f) => Error::Ssl2(f.into_error()),
            HandshakeError::WouldBlock(_) => unreachable!(),
        })?;

    let write = RcIo(Rc::new(RefCell::new(ssl_stream)));
    let read = io::BufReader::new(write.clone());

    let mut client: RemoteClient = Client::new(
        Box::new(read),
        Box::new(write),
        if options.trace { Some("") } else { None },
    );

    if options.trace {
        eprintln!("Connection established; reading server greeting");
    }

    let mut buffer = Vec::new();
    let response = client.read_one_response(&mut buffer)?;
    die_if_not_success("Greeting", response);
    buffer.clear();

    check_capabilities(&mut client, &["AUTH=PLAIN"])?;

    client.write_raw(b"A1 AUTHENTICATE PLAIN\r\n")?;
    client.read_logical_line(&mut buffer)?;
    if !buffer.starts_with(b"+") {
        die!(
            EX_PROTOCOL,
            "Server refused AUTHENTICATE: {}",
            String::from_utf8_lossy(&buffer).trim()
        );
    }

    let password = match rpassword::read_password_from_tty(Some("Password: ")) {
        Ok(p) => p,
        Err(e) => die!(EX_NOINPUT, "Failed to read password: {}", e),
    };

    let mut auth_string =
        base64::encode(format!("{}\0{}\0{}", user, user, password));
    auth_string.push_str("\r\n");
    client.write_raw_censored(auth_string.as_bytes())?;

    let mut responses = client.read_responses_until_tagged(&mut buffer)?;
    die_if_not_success("AUTHENTICATE", responses.pop().unwrap());

    check_capabilities(&mut client, &["LITERAL+", "XCRY"])?;

    Ok(client)
}

fn check_capabilities(
    client: &mut RemoteClient,
    required: &[&str],
) -> Result<(), Error> {
    let mut buffer = Vec::new();
    let mut responses = client.command(
        s::Command::Simple(s::SimpleCommand::Capability),
        &mut buffer,
    )?;
    die_if_not_success("CAPABILITY", responses.pop().unwrap());

    for r in responses {
        let r = r.response;
        if let s::Response::Capability(s::CapabilityData { capabilities }) = r {
            for cap in required {
                if !capabilities.iter().any(|c| cap.eq_ignore_ascii_case(c)) {
                    die!(EX_PROTOCOL, "Required capability {} missing", cap);
                }
            }

            return Ok(());
        }
    }

    die!(EX_PROTOCOL, "Missing CAPABILITY response")
}

fn die_if_not_success(what: &str, response: s::ResponseLine<'_>) {
    match response.response {
        s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Ok,
            ..
        }) => (),
        s::Response::Cond(s::CondResponse { cond, quip, .. }) => {
            die!(
                EX_PROTOCOL,
                "{} failed: {:?} {}",
                what,
                cond,
                quip.unwrap_or_default()
            );
        }
        r => {
            die!(
                EX_PROTOCOL,
                "Server returned unexpected response for {}: {:?}",
                what,
                r
            );
        }
    }
}

#[derive(Debug)]
struct RcIo<T>(Rc<RefCell<T>>);

impl<T> Clone for RcIo<T> {
    fn clone(&self) -> Self {
        RcIo(Rc::clone(&self.0))
    }
}

impl<T: Read> Read for RcIo<T> {
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        self.0.borrow_mut().read(dst)
    }
}

impl<T: Write> Write for RcIo<T> {
    fn write(&mut self, src: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().write(src)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.borrow_mut().flush()
    }
}
