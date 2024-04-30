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

use std::io::{self, BufRead, Read, Write};
use std::mem;

use openssl::ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode};

use crate::test_data::{CERTIFICATE, CERTIFICATE_PRIVATE_KEY};

pub fn ssl_acceptor() -> SslAcceptor {
    let mut ssl_acceptor =
        SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
    ssl_acceptor
        .set_private_key(&CERTIFICATE_PRIVATE_KEY)
        .unwrap();
    ssl_acceptor.set_certificate(&CERTIFICATE).unwrap();
    ssl_acceptor.build()
}

pub trait ReadWrite: Read + Write {}
impl<T: Read + Write + ?Sized> ReadWrite for T {}

pub struct SmtpClient {
    name: &'static str,
    io: Box<dyn ReadWrite>,
}

impl SmtpClient {
    pub fn new(name: &'static str, io: impl ReadWrite + 'static) -> Self {
        Self {
            name,
            io: Box::new(io),
        }
    }

    /// Read responses from the client up to and including the final response.
    ///
    /// This creates a `BufReader` over `io` and will lose any data which was
    /// buffered after the last read line. This should be fine since we don't
    /// do pipelining here.
    pub fn read_responses(&mut self) -> Vec<String> {
        let mut ret = Vec::<String>::new();
        let mut r = io::BufReader::new(&mut self.io);

        loop {
            let mut line = String::new();
            r.read_line(&mut line).unwrap();
            println!("[{}] >> {:?}", self.name, line);

            if line.is_empty() {
                panic!("Unexpected EOF");
            }

            let last = " " == &line[3..4];
            ret.push(line);

            if last {
                break;
            }
        }

        ret
    }

    /// Writes the given complete line to the server.
    pub fn write_line(&mut self, s: &str) {
        assert!(s.ends_with('\n'));
        for line in s.split_inclusive('\n') {
            println!("[{}] << {:?}", self.name, line);
        }
        self.io.write_all(s.as_bytes()).unwrap();
    }

    /// Writes the given raw data to the server.
    pub fn write_raw(&mut self, data: &[u8]) {
        println!("[{}] << [{} bytes]", self.name, data.len());
        self.io.write_all(data).unwrap();
    }

    /// Skip the server greeting, then send the given command and consume the
    /// responses. Assert that the command succeeds.
    pub fn skip_pleasantries(&mut self, cmd: &str) {
        self.read_responses();
        self.write_line(&format!("{}\r\n", cmd));
        let responses = self.read_responses();
        assert!(responses.last().unwrap().starts_with("250"));
    }

    /// Send a command which is expected to have one response with the given
    /// prefix.
    pub fn simple_command(&mut self, command: &str, prefix: &str) {
        self.write_line(&format!("{}\r\n", command));
        let responses = self.read_responses();
        assert_eq!(1, responses.len());
        assert!(responses[0].starts_with(prefix));
    }

    /// Like `simple_command`, but omits the CR before the line ending.
    pub fn unix_simple_command(&mut self, command: &str, prefix: &str) {
        self.write_line(&format!("{}\n", command));
        let responses = self.read_responses();
        assert_eq!(1, responses.len());
        assert!(responses[0].starts_with(prefix));
    }

    /// Performs a TLS handshake on the connection.
    pub fn start_tls(&mut self) {
        let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
        connector.set_verify(SslVerifyMode::NONE);

        println!("[{}] <> Start TLS handshake", self.name);
        let cxn = mem::replace(&mut self.io, Box::new(io::empty()));
        let cxn = connector
            .build()
            .connect("localhost", cxn)
            .map_err(|_| "SSL handshake failed")
            .unwrap();
        println!("[{}] <> TLS handshake succeeded", self.name);
        self.io = Box::new(cxn);
    }

    /// Skip the greeting, perform a HELO, STARTTLS, skip the repeated
    /// greeting, and do the second HELO.
    pub fn skip_pleasantries_with_tls(&mut self, command: &str) {
        self.skip_pleasantries(command);
        self.simple_command("STARTTLS", "220 2.0.0");
        self.start_tls();
        self.write_line(&format!("{}\r\n", command));
        let responses = self.read_responses();
        assert!(responses.last().unwrap().starts_with("250"));
    }

    /// Skip the greetings and so forth, enable TLS, and log in with the given
    /// username and password.
    pub fn quick_log_in(&mut self, helo: &str, user: &str, password: &str) {
        self.skip_pleasantries_with_tls(helo);
        let auth = format!(
            "AUTH PLAIN {}",
            base64::encode(format!("{user}\0{user}\0{password}")),
        );
        self.simple_command(&auth, "235 ");
    }
}
