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

//! A simple AST-level Crymap client.
//!
//! **THIS IS NOT A GENERAL-PURPOSE IMAP CLIENT.** It makes many assumptions
//! that rely on implementation details specific to Crymap (see `syntax.rs` for
//! the gory details) and will only reliably work even with other Crymap
//! versions for the subset of the protocol used by the Crymap CLI. Please do
//! not request to extract this to a separate crate.
//!
//! Besides the CLI subset, this is mainly used for internal integration tests.

use std::borrow::Cow;
use std::io::{self, BufRead, Read, Write};
use std::str;

use lazy_static::lazy_static;
use regex::bytes::Regex;
use thiserror::Error;

use super::lex::LexWriter;
use super::syntax as s;

lazy_static! {
    static ref LITERAL_AT_EOL: Regex =
        Regex::new(r#"~?\{([0-9]+)?\}\r\n$"#).unwrap();
}

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("Parse error: {0}")]
    Nom(String),
    #[error("Failed to parse whole response")]
    PartialParse,
}

pub struct Client<R, W> {
    read: R,
    write: W,
    trace_stderr: Option<&'static str>,
    next_tag: u64,
}

impl<R: BufRead, W: Write> Client<R, W> {
    pub fn new(read: R, write: W, trace_stderr: Option<&'static str>) -> Self {
        Client {
            read,
            write,
            trace_stderr,
            next_tag: 0,
        }
    }

    pub fn write_raw(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.trace(true, ">>[raw]", bytes);
        self.write.write_all(bytes)?;
        Ok(())
    }

    pub fn read_line_raw(&mut self, dst: &mut Vec<u8>) -> Result<usize, Error> {
        let start = dst.len();
        let nread = self.read.read_until(b'\n', dst)?;
        self.trace(false, "<<[eol]", &dst[start..]);
        Ok(nread)
    }

    pub fn read_data_raw(
        &mut self,
        dst: &mut Vec<u8>,
        n: u32,
    ) -> Result<usize, Error> {
        let start = dst.len();
        let nread = self.read.by_ref().take(n.into()).read_to_end(dst)?;
        self.trace(true, "<<[lit]", &dst[start..]);
        if n > nread as u32 {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Hit EOF before end of literal",
            )));
        }

        Ok(nread)
    }

    pub fn read_logical_line(
        &mut self,
        dst: &mut Vec<u8>,
    ) -> Result<(), Error> {
        loop {
            let nread = self.read_line_raw(dst)?;
            if !dst.ends_with(b"\r\n") {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Line didn't end with CRLF",
                )));
            }

            let literal_len = LITERAL_AT_EOL
                .captures(&dst[dst.len() - nread..])
                .and_then(|cap| {
                    str::from_utf8(cap.get(1).unwrap().as_bytes())
                        .expect("Matched invalid UTF-8 inside literal start?")
                        .parse::<u32>()
                        .ok()
                });

            if let Some(literal_len) = literal_len {
                self.read_data_raw(dst, literal_len)?;
            } else {
                break;
            }
        }

        Ok(())
    }

    pub fn read_one_response<'a>(
        &mut self,
        dst: &'a mut Vec<u8>,
    ) -> Result<s::ResponseLine<'a>, Error> {
        let start = dst.len();
        self.read_logical_line(dst)?;
        let (remaining, r) = s::ResponseLine::parse(&dst[start..dst.len() - 2])
            .map_err(|e| Error::Nom(e.to_string()))?;

        if !remaining.is_empty() {
            return Err(Error::PartialParse);
        }

        Ok(r)
    }

    pub fn read_commands_until_tagged<'a>(
        &mut self,
        dst: &'a mut Vec<u8>,
    ) -> Result<Vec<s::ResponseLine<'a>>, Error> {
        let mut boundaries = vec![dst.len()];
        loop {
            let start = dst.len();
            self.read_logical_line(dst)?;
            boundaries.push(dst.len());

            if b'*' != dst[start] {
                break;
            }
        }

        let dst: &'a Vec<u8> = &*dst;

        boundaries
            .windows(2)
            .map(|w| &dst[w[0]..w[1] - 2])
            .map(|line| {
                let (remaining, r) = s::ResponseLine::parse(line)
                    .map_err(|e| Error::Nom(e.to_string()))?;
                if !remaining.is_empty() {
                    return Err(Error::PartialParse);
                }

                Ok(r)
            })
            .collect::<Result<Vec<_>, Error>>()
    }

    pub fn command<'a>(
        &mut self,
        command: s::Command<'_>,
        response_buffer: &'a mut Vec<u8>,
    ) -> Result<Vec<s::ResponseLine<'a>>, Error> {
        response_buffer.clear();

        let tag = self.next_tag;
        self.next_tag += 1;

        let mut command_buffer = Vec::<u8>::new();
        {
            s::CommandLine {
                tag: Cow::Owned(format!("{}", tag)),
                cmd: command,
            }
            .write_to(&mut LexWriter::new(&mut command_buffer, true, true))
            .unwrap();
        }

        command_buffer.extend_from_slice(b"\r\n");
        self.trace(false, ">>[cmd]", &command_buffer);
        self.write.write_all(&command_buffer)?;
        self.read_commands_until_tagged(response_buffer)
    }

    fn trace(&self, truncate: bool, what: &str, data: &[u8]) {
        if let Some(prefix) = self.trace_stderr {
            if data.is_empty() {
                eprintln!("{} WIRE {}<empty>", prefix, what);
                return;
            }

            let (data, truncated) = if truncate {
                data.split_at(data.len().min(128))
            } else {
                (data, &[] as &[u8])
            };

            let mut start = 0;
            for split in memchr::memchr_iter(b'\n', data)
                .chain(std::iter::once(data.len() - 1))
            {
                if split < start {
                    continue;
                }

                let data = &data[start..=split];
                start = split + 1;

                let mut vis = String::new();
                for &byte in data {
                    match byte {
                        b' '..=b'~' => vis.push(byte as char),
                        b'\n' => vis.push_str("\\n"),
                        b'\r' => vis.push_str("\\r"),
                        b => vis.push_str(&format!("\\x{:02X}", b)),
                    }
                }

                eprintln!("{} WIRE {} {}", prefix, what, vis);
            }

            if !truncated.is_empty() {
                eprintln!(
                    "{} WIRE {}<{} more bytes>",
                    prefix,
                    what,
                    truncated.len()
                );
            }
        }
    }
}
