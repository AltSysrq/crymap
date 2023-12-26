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

use std::io::{self, Read};
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt as _;

use super::{
    lex::{LexOutput, LexWriter},
    syntax as s,
};
use crate::support::async_io::ServerIo;

/// An event to be sent to the client.
pub enum OutputEvent {
    /// A full response line.
    ResponseLine {
        /// The content to write.
        line: s::ResponseLine<'static>,
        /// Any special handling for this line.
        ctl: OutputControl,
    },
    /// A continuation line (i.e. "+ {message}\r\n").
    ContinuationLine {
        /// The prompt to send.
        prompt: &'static str,
    },
    /// Flush the buffers immediately if non-empty.
    Flush,
    /// Mark the client as Unicode-aware for all further responses.
    EnableUnicode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputControl {
    /// No special handling. Written responses may continue to be buffered.
    Buffer,
    /// Flush all internal buffers after writing this response.
    Flush,
    /// Flush all internal buffers after writing this response, and enable
    /// transparent compression before writing anything further.
    EnableCompression,
    /// Flush all internal buffers and disconnect immediately after writing
    /// this response.
    Disconnect,
}

/// The reason `write_responses` terminated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputDisconnect {
    /// The disconnect was initiated by `OutputControl::Disconnect`.
    ByControl,
    /// The `OutputEvent` receiver was closed.
    InputClosed,
}

/// Actor for writing responses to the client.
///
/// The actor runs until one of the following:
/// - An error occurs.
/// - `outputs` is disconnected. The actor returns no error.
/// - `OutputControl::Disconnect` is processed. The actor returns no error.
pub async fn write_responses(
    mut io: ServerIo,
    mut outputs: tokio::sync::mpsc::Receiver<OutputEvent>,
) -> io::Result<OutputDisconnect> {
    let mut state = State::new();
    while let Some(evt) = outputs.recv().await {
        // Reset last_flush if there's not actually anything pending.
        if state.text.is_empty() {
            state.last_flush = Instant::now();
        }

        let ctl = match evt {
            OutputEvent::ResponseLine { mut line, ctl } => {
                let unicode = state.unicode;
                line.write_to(&mut LexWriter::new(&mut state, unicode, false))?;
                state.text.extend_from_slice(b"\r\n");
                ctl
            },

            OutputEvent::ContinuationLine { prompt } => {
                state.text.extend_from_slice(b"+ ");
                state.text.extend_from_slice(prompt.as_bytes());
                state.text.extend_from_slice(b"\r\n");
                OutputControl::Flush
            },

            OutputEvent::Flush => OutputControl::Flush,

            OutputEvent::EnableUnicode => {
                state.unicode = true;
                continue;
            },
        };

        match ctl {
            OutputControl::Buffer => {
                let flush_due_to_size = state.text.len() >= TEXT_FLUSH_THRESH
                    || state.splices.len() >= SPLICE_FLUSH_THRESH;

                // Since the client can request commands that take a long time
                // but produce little output (e.g. LIST STATUS), force a flush
                // implicitly if we've had data sitting around for a while.
                let flush_due_to_time =
                    state.last_flush.elapsed() >= Duration::from_secs(3);

                if flush_due_to_size || flush_due_to_time {
                    let flush_compress = if flush_due_to_time {
                        flate2::FlushCompress::Sync
                    } else {
                        flate2::FlushCompress::None
                    };
                    state.flush(&mut io, flush_compress).await?;
                }
            },

            OutputControl::Flush => {
                state.flush(&mut io, flate2::FlushCompress::Sync).await?;
            },

            OutputControl::EnableCompression => {
                assert!(state.compress.is_none());
                state.flush(&mut io, flate2::FlushCompress::None).await?;
                state.compress = Some(flate2::Compress::new(
                    flate2::Compression::new(3),
                    false,
                ));
                state.compressed = vec![0u8; TEXT_FLUSH_THRESH];
            },

            OutputControl::Disconnect => {
                state.flush(&mut io, flate2::FlushCompress::Finish).await?;
                return Ok(OutputDisconnect::ByControl);
            },
        }
    }

    state.flush(&mut io, flate2::FlushCompress::Finish).await?;

    Ok(OutputDisconnect::InputClosed)
}

const TEXT_FLUSH_THRESH: usize = 4096;
const SPLICE_FLUSH_THRESH: usize = 4;

struct State {
    /// The buffer into which `LexWriter` writes.
    ///
    /// Splices are stored separately, retaining their original `impl Read`, to
    /// be played back once flushed.
    text: Vec<u8>,
    /// Literals to be spliced into `text`, sorted ascending by offset.
    splices: Vec<LiteralSplice>,
    /// Buffer into which chunks from `splices` are staged.
    splice_read: Vec<u8>,
    /// The compressor, if any.
    compress: Option<flate2::Compress>,
    /// Buffer into which the compressor compresses.
    compressed: Vec<u8>,
    /// The last time a flush was completed.
    last_flush: Instant,
    /// Whether the Unicode output is enabled.
    unicode: bool,
}

struct LiteralSplice {
    /// The offset within `text` of this splice.
    offset: usize,
    data: Box<dyn Read>,
}

impl State {
    fn new() -> Self {
        Self {
            text: Vec::with_capacity(TEXT_FLUSH_THRESH * 5 / 4),
            splices: Vec::with_capacity(SPLICE_FLUSH_THRESH * 2),
            splice_read: vec![0; 4096],
            compress: None,
            compressed: Vec::new(),
            last_flush: Instant::now(),
            unicode: false,
        }
    }

    async fn flush(
        &mut self,
        io: &mut ServerIo,
        flush_compress: flate2::FlushCompress,
    ) -> io::Result<()> {
        #[allow(clippy::collapsible_else_if)] // clearer
        async fn do_write(
            io: &mut ServerIo,
            compress: Option<&mut flate2::Compress>,
            compressed: &mut [u8],
            mut data: &[u8],
        ) -> io::Result<()> {
            if let Some(compress) = compress {
                while !data.is_empty() {
                    let before_in = compress.total_in();
                    let before_out = compress.total_out();
                    compress
                        .compress(data, compressed, flate2::FlushCompress::None)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                    let after_in = compress.total_in();
                    let after_out = compress.total_out();

                    data = &data[(after_in - before_in) as usize..];
                    if after_out != before_out {
                        io.write_all(
                            &compressed[..(after_out - before_out) as usize],
                        )
                        .await?;
                    }
                }
            } else {
                if !data.is_empty() {
                    io.write_all(data).await?;
                }
            }

            Ok(())
        }

        let mut offset = 0usize;
        for mut splice in self.splices.drain(..) {
            if splice.offset > offset {
                do_write(
                    io,
                    self.compress.as_mut(),
                    &mut self.compressed,
                    &self.text[offset..splice.offset],
                )
                .await?;
                offset = splice.offset;
            }

            loop {
                let nread = splice.data.read(&mut self.splice_read)?;
                if 0 == nread {
                    break;
                }

                do_write(
                    io,
                    self.compress.as_mut(),
                    &mut self.compressed,
                    &self.splice_read[..nread],
                )
                .await?;
            }
        }

        if offset < self.text.len() {
            do_write(
                io,
                self.compress.as_mut(),
                &mut self.compressed,
                &self.text[offset..],
            )
            .await?;
        }

        if flate2::FlushCompress::None != flush_compress {
            if let Some(ref mut compress) = self.compress {
                loop {
                    let before_out = compress.total_out();
                    compress
                        .compress(&[], &mut self.compressed, flush_compress)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                    let after_out = compress.total_out();

                    if after_out == before_out {
                        break;
                    }

                    io.write_all(
                        &self.compressed[..(after_out - before_out) as usize],
                    )
                    .await?;
                }
            }
        }

        self.text.clear();
        self.last_flush = Instant::now();
        Ok(())
    }
}

impl io::Write for &mut State {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.text.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // Not supported, we do this async
        Ok(())
    }
}

impl LexOutput for &mut State {
    fn splice<R: Read + 'static>(&mut self, data: R) -> io::Result<()> {
        self.splices.push(LiteralSplice {
            offset: self.text.len(),
            data: Box::new(data),
        });
        Ok(())
    }
}
