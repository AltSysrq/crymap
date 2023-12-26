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

use std::future::Future;
use std::io;
use std::ops::Range;
use std::pin::Pin;
use std::task;

use lazy_static::lazy_static;
use regex::bytes::Regex;
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

use super::{response_writer::OutputEvent, syntax as s};

lazy_static! {
    static ref LITERAL_AT_END: Regex =
        Regex::new(r#"~?\{([0-9]+)\+?\}\r?\n$"#).unwrap();
}

const MAX_CMDLINE: usize = 65536;

/// Manages the state of the network input.
///
/// `RequestReader` cannot be an independent actor like the `request_writer`
/// module because the zero-copy command parser borrows into the internal
/// buffer.
pub struct RequestReader<R> {
    io: R,
    /// The (decompressed) text buffer. The `Vec` itself is used as a
    /// fixed-size array; the size currently in use is given by `text_len`.
    text: Vec<u8>,
    /// The number of initialised bytes in `text`.
    text_len: usize,
    /// The number of bytes in `text` that have been consumed by reading.
    text_consumed: usize,
    /// The decompressor, if decompression is active.
    decompress: Option<flate2::Decompress>,
    /// The staging buffer for compressed data when decompression is active.
    compressed: Vec<u8>,
    /// The range of `compressed` which is yet to be processed.
    compressed_range: Range<usize>,
    /// Whether we've seen an EOF from the reader.
    reader_eof: bool,
}

/// Possible outcomes of trying to read the start of a command line.
pub enum CommandStart<'a> {
    /// A full line was received but it could not even be split into a tag and
    /// a command.
    Incomprehensible,
    /// A full line was received but the command could not be parsed. The value
    /// is the tag.
    Bad(String),
    /// An excessively long command was received but was successfully skipped.
    /// The value is the tag.
    TooLongRecovered(String),
    /// An excessively long command was received and could not be skipped. The
    /// value is the tag.
    TooLongFatal(String),
    /// A complete stand-alone command was received.
    StandAlone(s::CommandLine<'a>),
    /// The start of an `APPEND` was received.
    ///
    /// No continuation line has been sent yet. The append must either be
    /// accepted by sending the continuation line, consuming the literal, then
    /// calling `read_append_continue`, or must be entirely rejected by calling
    /// `abort_append`.
    AppendStart {
        append: s::AppendCommandStart<'a>,
        size: u32,
        literal_plus: bool,
    },
    /// The start of an `AUTHENTICATE` was received.
    ///
    /// No continuation line has been sent.
    AuthenticateStart(s::AuthenticateCommandStart<'a>),
    /// The reader wanted to send a continuation line, but the output channel
    /// was disconnected.
    OutputDisconnected,
}

pub enum AppendContinuation {
    /// There is another part in the `APPEND` sequence.
    NextPart {
        fragment: s::AppendFragment,
        size: u32,
        literal_plus: bool,
    },
    /// The `APPEND` command is done.
    Done,
    /// The continued syntax of the command is invalid. The parser has
    /// recovered and aborted the append.
    SyntaxError,
    /// The line continuation was too long.
    TooLong,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompressionStatus {
    Started,
    AlreadyActive,
    InvalidPipelinedData,
}

impl<R: AsyncRead + Unpin> RequestReader<R> {
    pub fn new(io: R) -> Self {
        Self {
            io,
            text: vec![0u8; MAX_CMDLINE],
            text_len: 0,
            text_consumed: 0,
            decompress: None,
            compressed: Vec::new(),
            compressed_range: 0..0,
            reader_eof: false,
        }
    }

    /// Parses a `CommandStart` from the stream.
    ///
    /// `send_output` is used to send continuation lines for old-fashioned
    /// literals as needed.
    ///
    /// If `recover_overlong` is true, an attempt will be made to resynchronise
    /// the protocol if the command line is too long. If false, any overlong
    /// command line will be fatal. (But rejecting overlong non-LITERAL+
    /// literals is always graceful.)
    pub async fn read_command_start<'a>(
        &'a mut self,
        send_output: &mut tokio::sync::mpsc::Sender<OutputEvent>,
        recover_overlong: bool,
    ) -> io::Result<CommandStart<'_>> {
        self.drop_consumed();

        loop {
            if self.consume_line().await?.is_none() {
                return self
                    .on_command_line_overflow(
                        OverflowState::Line,
                        recover_overlong,
                    )
                    .await;
            }

            let Some((before_literal, literal_length, literal_plus)) =
                self.check_literal()
            else {
                break;
            };

            // APPEND needs to be handled specially since it can be much
            // larger than MAX_CMDLINE.
            if let Ok((b"", append)) =
                s::AppendCommandStart::parse(before_literal)
            {
                return Ok(CommandStart::AppendStart {
                    // Work around https://github.com/rust-lang/rust/issues/54663
                    //
                    // SAFETY: We're transmuting to AppendCommandStart<'b>
                    // (where 'b is the local borrow from self.check_literal())
                    // to AppendCommandStart<'a>. 'a and 'b are both borrows
                    // into `self`.
                    append: unsafe {
                        std::mem::transmute::<
                            s::AppendCommandStart<'_>,
                            s::AppendCommandStart<'a>,
                        >(append)
                    },
                    size: literal_length,
                    literal_plus,
                });
            }

            // Otherwise, just add the literal to the command line if
            // there's space for it.
            if literal_length as usize + self.text_consumed <= MAX_CMDLINE {
                if !literal_plus {
                    if send_output
                        .send(OutputEvent::ContinuationLine { prompt: "go" })
                        .await
                        .is_err()
                    {
                        return Ok(CommandStart::OutputDisconnected);
                    }
                }

                self.consume_exact(literal_length as usize).await?;
            } else if literal_plus {
                // The client's already committed to sending the
                // overlong command line, so we need to either abort or
                // consume it all.
                return self
                    .on_command_line_overflow(
                        OverflowState::LiteralPlus(literal_length),
                        recover_overlong,
                    )
                    .await;
            } else if let Ok((_, frag)) =
                s::UnknownCommandFragment::parse(before_literal)
            {
                // The client is waiting for confirmation to send, so we
                // can just tell them NO.
                return Ok(CommandStart::TooLongRecovered(
                    frag.tag.into_owned(),
                ));
            }
        }

        // No ending literal, so we believe we have a complete command.
        let mut command_line = &self.text[..self.text_consumed - 1]; // exclude \n
        if Some(b'\r') == command_line.last().copied() {
            command_line = &self.text[..self.text_consumed - 2];
        }
        if let Ok((b"", command)) = s::CommandLine::parse(command_line) {
            Ok(CommandStart::StandAlone(command))
        } else if let Ok((b"", command)) =
            s::AuthenticateCommandStart::parse(command_line)
        {
            Ok(CommandStart::AuthenticateStart(command))
        } else if let Ok((_, unknown)) =
            s::UnknownCommandFragment::parse(command_line)
        {
            Ok(CommandStart::Bad(unknown.tag.into_owned()))
        } else {
            Ok(CommandStart::Incomprehensible)
        }
    }

    /// Reads a single line from the input without parsing it.
    ///
    /// If `None` is returned, the line was too long to fit in the buffer.
    pub async fn read_raw_line(&mut self) -> io::Result<Option<&[u8]>> {
        self.drop_consumed();
        self.consume_line().await
    }

    /// Return an `AsyncRead` that can be used to read an `APPEND` literal of
    /// the given length.
    ///
    /// The reader MUST be consumed in its entirety to maintain protocol
    /// consistency.
    pub fn read_append_literal(
        &mut self,
        len: u32,
    ) -> impl AsyncRead + Unpin + '_ {
        self.take(len as u64)
    }

    /// Abort the in-progress `APPEND` command. This must be invoked without
    /// having consumed the `APPEND` literal.
    pub async fn abort_append(
        &mut self,
        len: u32,
        literal_plus: bool,
    ) -> io::Result<()> {
        if !literal_plus {
            return Ok(());
        }

        self.skip_command(OverflowState::LiteralPlus(len)).await
    }

    /// Abort the in-progress `APPEND` command after having read the entire
    /// literal.
    pub async fn abort_append_after_literal(&mut self) -> io::Result<()> {
        match self.continue_append(false).await? {
            AppendContinuation::Done
            | AppendContinuation::SyntaxError
            | AppendContinuation::TooLong => Ok(()),
            AppendContinuation::NextPart {
                size, literal_plus, ..
            } => self.abort_append(size, literal_plus).await,
        }
    }

    /// Continues parsing an `APPEND` command.
    ///
    /// This must be called after the previous `APPEND` literal was completely
    /// consumed. `prev_utf8` is the value of `utf8` from the previous
    /// fragment.
    pub async fn continue_append(
        &mut self,
        prev_utf8: bool,
    ) -> io::Result<AppendContinuation> {
        self.drop_consumed();
        let Some(line) = self.consume_line().await? else {
            self.skip_command(OverflowState::Line).await?;
            return Ok(AppendContinuation::TooLong);
        };

        // A completed APPEND is either the empty string or just ")" (for
        // UTF8).
        match (line, prev_utf8) {
            (b"", false) | (b")", true) => return Ok(AppendContinuation::Done),
            (b"", true) | (b")", false) => {
                return Ok(AppendContinuation::SyntaxError)
            },
            _ => {},
        }

        let Some((before_literal, size, literal_plus)) = self.check_literal()
        else {
            // There's no literal so this is the end of the command line, but
            // we also disqualified the possibility of valid syntax above.
            return Ok(AppendContinuation::SyntaxError);
        };

        let prefix = if prev_utf8 { b")".as_slice() } else { b"" };
        let frag = if !before_literal.starts_with(prefix) {
            None
        } else if let Ok((b"", frag)) =
            s::AppendFragment::parse(&before_literal[prefix.len()..])
        {
            Some(frag)
        } else {
            None
        };

        let Some(frag) = frag else {
            if literal_plus {
                self.skip_command(OverflowState::LiteralPlus(size)).await?;
            }
            return Ok(AppendContinuation::SyntaxError);
        };

        Ok(AppendContinuation::NextPart {
            fragment: frag,
            size,
            literal_plus,
        })
    }

    /// Enables compression on the input.
    pub fn start_compression(&mut self) -> CompressionStatus {
        if self.decompress.is_some() {
            CompressionStatus::AlreadyActive
        } else if self.text_consumed < self.text_len {
            CompressionStatus::InvalidPipelinedData
        } else {
            self.decompress = Some(flate2::Decompress::new(false));
            self.compressed = vec![0u8; 4096];
            CompressionStatus::Started
        }
    }

    /// Check whether the current command line (ending at `text_consumed`) ends
    /// with a literal.
    ///
    /// Returns the text of the command before the literal, the length of the
    /// literal, and whether this is a LITERAL+ literal.
    fn check_literal(&self) -> Option<(&[u8], u32, bool)> {
        LITERAL_AT_END
            .captures(&self.text[..self.text_consumed])
            .and_then(|c| c.get(0).and_then(|m0| c.get(1).map(|m1| (m0, m1))))
            .and_then(|(m0, m1)| {
                std::str::from_utf8(m1.as_bytes())
                    .ok()
                    .and_then(|s| s.parse::<u32>().ok())
                    .map(|len| {
                        (
                            &self.text[..m0.start()],
                            len,
                            m0.as_bytes().contains(&b'+'),
                        )
                    })
            })
    }

    /// Called when the command line has grown too long.
    ///
    /// This attempts to skip the rest of the command and resynchronise the
    /// protocol state, depending on recover_overlong.
    async fn on_command_line_overflow(
        &mut self,
        state: OverflowState,
        recover_overlong: bool,
    ) -> io::Result<CommandStart<'_>> {
        let frag_end = match state {
            // Line indicates text_len is the maximum value and we couldn't
            // find a line break between text_consumed and there, so we need to
            // make sure to scan the entire text buffer to find the tag rather
            // than just the "consumed" part. At the same time, we know all of
            // text through `text_len` is part of this "line".
            OverflowState::Line => self.text_len,
            // For literal plus, the line containing the literal was marked as
            // consumed, so we can find the tag in just the main part of the
            // line. (And bytes beyond `text_consumed` may be garbage.)
            OverflowState::LiteralPlus(_) => self.text_consumed,
        };

        let Ok((_, frag)) =
            s::UnknownCommandFragment::parse(&self.text[..frag_end])
        else {
            self.text_len = 0;
            self.text_consumed = 0;
            return Ok(CommandStart::Incomprehensible);
        };

        let tag = frag.tag.into_owned();
        if !recover_overlong {
            self.text_len = 0;
            self.text_consumed = 0;
            return Ok(CommandStart::TooLongFatal(tag));
        }

        self.skip_command(state).await?;
        Ok(CommandStart::TooLongRecovered(tag))
    }

    /// Skip the rest of the current command.
    ///
    /// `text` must either be full to `text_len` (as in an overlong command
    /// line) or an unconsumed LITERAL+ must be the next thing in the stream.
    async fn skip_command(
        &mut self,
        mut state: OverflowState,
    ) -> io::Result<()> {
        loop {
            match state {
                OverflowState::Line => {
                    // Shift away all but the last 32 bytes we've buffered. If
                    // `text` ends with the start of a literal declaration,
                    // this will let us find that when we continue the line.
                    self.text_consumed = self.text_len - 32;
                },

                OverflowState::LiteralPlus(len) => {
                    // Discard the literal.
                    tokio::io::copy(
                        &mut self.take(u64::from(len)),
                        &mut tokio::io::sink(),
                    )
                    .await?;
                },
            }

            self.drop_consumed();
            // Try again to find a line boundary.
            if self.consume_line().await?.is_none() {
                // No line boundary.
                state = OverflowState::Line;
            } else if let Some((_, len, literal_plus)) = self.check_literal() {
                if literal_plus {
                    // We have to skip this literal too.
                    state = OverflowState::LiteralPlus(len);
                } else {
                    // We can say NO here.
                    return Ok(());
                }
            } else {
                // End of command.
                return Ok(());
            }
        }
    }

    /// Advances `text_consumed` to one byte past the next line boundary.
    ///
    /// If no IO error occurs, this returns the line (excluding the line-ending
    /// character(s)), or `None` if `MAX_CMDLINE` was reached without finding a
    /// line feed. In the latter case, `text_consumed` is not advanced.
    async fn consume_line(&mut self) -> io::Result<Option<&[u8]>> {
        let start = self.text_consumed;
        let mut cursor = start;

        loop {
            if let Some(lf) =
                memchr::memchr(b'\n', &self.text[cursor..self.text_len])
            {
                let end = cursor + lf + 1;
                self.text_consumed = end;

                let mut before_line_end = end - 1; // before '\n'
                if before_line_end > 0
                    && self.text[before_line_end - 1] == b'\r'
                {
                    before_line_end -= 1;
                }
                return Ok(Some(&self.text[start..before_line_end]));
            }

            cursor = self.text_len;
            if self.text_len == MAX_CMDLINE {
                return Ok(None);
            }

            self.grow_text().await?;
        }
    }

    /// Advances `text_consumed` by exactly `n`, returning the slice of bytes
    /// consumed.
    ///
    /// If consuming that many bytes would make the command line larger than
    /// `MAX_CMDLINE`, returns `Ok(None)` without mutating self.
    async fn consume_exact(&mut self, n: usize) -> io::Result<Option<&[u8]>> {
        let start = self.text_consumed;
        let target_len = self.text_consumed + n;
        if target_len > MAX_CMDLINE {
            return Ok(None);
        }

        while self.text_len < target_len {
            self.grow_text().await?;
        }

        self.text_consumed = target_len;
        Ok(Some(&self.text[start..target_len]))
    }

    /// Removes all text marked as consumed from the text buffer.
    fn drop_consumed(&mut self) {
        if self.text_consumed < self.text_len {
            self.text.copy_within(self.text_consumed..self.text_len, 0);
        }

        self.text_len -= self.text_consumed;
        self.text_consumed = 0;
    }

    /// Perform a non-empty read into `text`.
    fn grow_text(&mut self) -> impl Future<Output = io::Result<()>> + '_ {
        struct GrowText<'a, R> {
            this: &'a mut RequestReader<R>,
        }

        impl<R: AsyncRead + Unpin> Future for GrowText<'_, R> {
            type Output = io::Result<()>;

            fn poll(
                mut self: Pin<&mut Self>,
                ctx: &mut task::Context<'_>,
            ) -> task::Poll<io::Result<()>> {
                let this = &mut *self.this;
                let mut buf = ReadBuf::new(&mut this.text[this.text_len..]);

                let poll = if let Some(ref mut decompress) = this.decompress {
                    poll_decompress(
                        ctx,
                        &mut buf,
                        Pin::new(&mut this.io),
                        decompress,
                        &mut this.compressed,
                        &mut this.compressed_range,
                        &mut this.reader_eof,
                    )
                } else {
                    Pin::new(&mut this.io).poll_read(ctx, &mut buf)
                };

                futures::ready!(poll)?;

                let nread = buf.filled().len();
                if 0 == nread {
                    return task::Poll::Ready(Err(
                        io::ErrorKind::UnexpectedEof.into(),
                    ));
                }

                this.text_len += nread;
                task::Poll::Ready(Ok(()))
            }
        }

        GrowText { this: self }
    }
}

#[derive(Clone, Copy)]
enum OverflowState {
    /// `text` is full with no EOL in sight.
    Line,
    /// The consumed part of `text` ends with a LITERAL+ literal start of this
    /// size.
    LiteralPlus(u32),
}

/// The `AsyncRead` implementation directly reads from the logical byte stream
/// of the request reader.
impl<R: AsyncRead + Unpin> AsyncRead for RequestReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        ctx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> task::Poll<io::Result<()>> {
        let this = self.get_mut();

        if this.text_consumed < this.text_len {
            // Data we've already buffered comes first.
            let len = buf.remaining().min(this.text_len - this.text_consumed);
            buf.put_slice(&this.text[this.text_consumed..][..len]);
            this.text_consumed += len;
            task::Poll::Ready(Ok(()))
        } else if let Some(ref mut decompress) = this.decompress {
            poll_decompress(
                ctx,
                buf,
                Pin::new(&mut this.io),
                decompress,
                &mut this.compressed,
                &mut this.compressed_range,
                &mut this.reader_eof,
            )
        } else {
            // No buffered data and no decompression, so just pass through the
            // underlying reader.
            Pin::new(&mut this.io).poll_read(ctx, buf)
        }
    }
}

/// Decompress data into `dst`.
///
/// `compressed` is the staging buffer for compressed data, with
/// `compressed_range` being the range of `compressed` which has unprocessed
/// data.
fn poll_decompress<R: AsyncRead>(
    ctx: &mut task::Context<'_>,
    dst: &mut ReadBuf<'_>,
    mut src: Pin<&mut R>,
    decompress: &mut flate2::Decompress,
    compressed: &mut [u8],
    compressed_range: &mut Range<usize>,
    reader_eof: &mut bool,
) -> task::Poll<io::Result<()>> {
    loop {
        // First, try to squeeze data out of the decompressor even if we have
        // nothing else to give it.
        let before_in = decompress.total_in();
        let before_out = decompress.total_out();
        if let Err(e) = decompress.decompress(
            &compressed[compressed_range.clone()],
            dst.initialize_unfilled(),
            if *reader_eof {
                flate2::FlushDecompress::Finish
            } else {
                flate2::FlushDecompress::Sync
            },
        ) {
            return task::Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                e,
            )));
        }
        let after_in = decompress.total_in();
        let after_out = decompress.total_out();

        compressed_range.start += (after_in - before_in) as usize;
        if after_out != before_out || *reader_eof {
            dst.advance((after_out - before_out) as usize);
            return task::Poll::Ready(Ok(()));
        }

        // We can't get anything more from the compressor with the data we
        // have. If *compressed_range is not yet empty, we'll just make another
        // pass through the decompressor. Otherwise, try to read more data.
        if (*compressed_range).is_empty() {
            if *reader_eof {
                // Neither the decompressor nor the stream has more data for us.
                return task::Poll::Ready(Ok(()));
            }

            let mut compressed_buf = ReadBuf::new(compressed);
            futures::ready!(src.as_mut().poll_read(ctx, &mut compressed_buf))?;

            *compressed_range = 0..compressed_buf.filled().len();
            *reader_eof = (*compressed_range).is_empty();
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn run_test(input: &str, expected_output: &str) {
        use super::super::lex::LexWriter;
        use std::io::Write as _;

        for compression in [false, true] {
            let mut input_data = Vec::<u8>::new();
            if compression {
                let mut w = flate2::write::DeflateEncoder::new(
                    &mut input_data,
                    flate2::Compression::best(),
                );
                w.write_all(input.as_bytes()).unwrap();
                w.flush().unwrap();
            } else {
                input_data.extend_from_slice(input.as_bytes());
            }

            let (mut sender, _receiver) = tokio::sync::mpsc::channel(999);

            let mut reader = RequestReader::new(&input_data[..]);
            if compression {
                assert_eq!(
                    CompressionStatus::Started,
                    reader.start_compression()
                );
            }

            let mut output = Vec::<u8>::new();

            loop {
                let start = match futures::executor::block_on(
                    reader.read_command_start(&mut sender, true),
                ) {
                    Err(e) if io::ErrorKind::UnexpectedEof == e.kind() => break,
                    Err(e) => {
                        panic!(
                            "unexpected error \
                             (compression = {compression:?}): {e}",
                        );
                    },

                    Ok(start) => start,
                };

                match start {
                    CommandStart::Incomprehensible => {
                        writeln!(output, "incomprehensible").unwrap();
                        break;
                    },

                    CommandStart::Bad(tag) => {
                        writeln!(output, "bad: {tag}").unwrap();
                    },

                    CommandStart::TooLongRecovered(tag) => {
                        writeln!(output, "too long, recovered: {tag}").unwrap();
                    },

                    CommandStart::TooLongFatal(tag) => {
                        writeln!(output, "too long, fatal: {tag}").unwrap();
                        break;
                    },

                    CommandStart::StandAlone(mut cmd) => {
                        write!(output, "stand-alone: ").unwrap();
                        cmd.write_to(&mut LexWriter::new(
                            &mut output,
                            true,
                            false,
                        ))
                        .unwrap();
                        output.push(b'\n');
                    },

                    CommandStart::AppendStart {
                        mut append,
                        mut size,
                        mut literal_plus,
                    } => {
                        write!(output, "append ({size} {literal_plus}): ")
                            .unwrap();
                        append
                            .write_to(&mut LexWriter::new(
                                &mut output,
                                true,
                                false,
                            ))
                            .unwrap();
                        output.push(b'\n');

                        let mut prev_utf8 = append.first_fragment.utf8;

                        loop {
                            match futures::executor::block_on(
                                reader.continue_append(prev_utf8),
                            )
                            .unwrap()
                            {
                                AppendContinuation::NextPart {
                                    mut fragment,
                                    size: size2,
                                    literal_plus: literal_plus2,
                                } => {
                                    size = size2;
                                    literal_plus = literal_plus2;
                                    prev_utf8 = fragment.utf8;

                                    write!(
                                        output,
                                        "append cont ({size} {literal_plus}): "
                                    )
                                    .unwrap();
                                    fragment
                                        .write_to(&mut LexWriter::new(
                                            &mut output,
                                            true,
                                            false,
                                        ))
                                        .unwrap();
                                    output.push(b'\n');
                                },

                                AppendContinuation::Done => {
                                    writeln!(output, "append done").unwrap();
                                    break;
                                },

                                AppendContinuation::SyntaxError => {
                                    writeln!(output, "append syntax error")
                                        .unwrap();
                                    break;
                                },

                                AppendContinuation::TooLong => {
                                    writeln!(output, "append too long")
                                        .unwrap();
                                    break;
                                },
                            }
                        }
                    },

                    CommandStart::AuthenticateStart(mut auth) => {
                        write!(output, "authenticate: ").unwrap();
                        auth.write_to(&mut LexWriter::new(
                            &mut output,
                            true,
                            false,
                        ))
                        .unwrap();
                        output.push(b'\n');
                    },

                    CommandStart::OutputDisconnected => {
                        writeln!(output, "output disconnected").unwrap();
                    },
                }
            }

            let output = std::str::from_utf8(&output).unwrap();
            assert!(
                expected_output == output,
                "mismatch for compression = {compression}\n\
                 expected:\n\
                 {expected_output}\n\
                 got:\n\
                 {output}",
            );
        }
    }

    #[test]
    fn simple_commands() {
        run_test(
            "A NOOP\r\n\
             B CHECK\r\n",
            //
            "stand-alone: A NOOP\n\
             stand-alone: B CHECK\n",
        );
        run_test(
            "A NOOP\n\
             B CHECK\n",
            //
            "stand-alone: A NOOP\n\
             stand-alone: B CHECK\n",
        );
        run_test(
            "A AUTHENTICATE PLAIN\n",
            "authenticate: A AUTHENTICATE PLAIN\n",
        );
        run_test(
            "A AUTHENTICATE PLAIN response\n",
            "authenticate: A AUTHENTICATE PLAIN response\n",
        );
    }

    #[test]
    fn bad_syntax() {
        run_test("\r\n", "incomprehensible\n");
        run_test("\n", "incomprehensible\n");
        run_test("foo\r\n", "incomprehensible\n");
        run_test("foo bar\r\n", "bad: foo\n");
        run_test(&format!("{:099999}\r\n", 1), "incomprehensible\n");
        run_test(
            &format!("x {:099999}\r\ny noop\n", 1),
            //
            "too long, recovered: x\n\
             stand-alone: y NOOP\n",
        );
    }

    #[test]
    fn literals() {
        run_test(
            "a CREATE {5}\r\nplugh\r\n\
             a CREATE {5}\nplugh\n\
             a CREATE {5+}\r\nplugh\r\n\
             a CREATE {5+}\nplugh\n",
            //
            "stand-alone: a CREATE plugh\n\
             stand-alone: a CREATE plugh\n\
             stand-alone: a CREATE plugh\n\
             stand-alone: a CREATE plugh\n",
        );

        run_test(
            "a unknown-command {5+}\n\
             plugh\n\
             b LOGOUT\n",
            //
            "bad: a\n\
             stand-alone: b LOGOUT\n",
        );

        run_test(
            "a CREATE {98765}\n\
             b DELETE INBOX\n",
            //
            "too long, recovered: a\n\
             stand-alone: b DELETE INBOX\n",
        );
        run_test(
            &format!(
                "a CREATE {{98765+}}\n\
                 {:098765}\n\
                 b DELETE Trash\n",
                1,
            ),
            //
            "too long, recovered: a\n\
             stand-alone: b DELETE Trash\n",
        );
    }

    #[test]
    fn append() {
        run_test(
            "A APPEND {5+}\r\n\
             INBOX (\\Seen Flag) \" 4-Jul-2020 16:31:00 +0100\" {123}\r\n\
             \r\n",
            //
            "append (123 false): A APPEND INBOX (\\Seen Flag) \
             \" 4-Jul-2020 16:31:00 +0100\" \n\
             append done\n",
        );
        run_test(
            "A APPEND {5+}\r\n\
             INBOX ~{123}\r\n\
             \x20{456+}\r\n\
             \r\n",
            //
            "append (123 false): A APPEND INBOX \n\
             append cont (456 true):  \n\
             append done\n",
        );
        run_test(
            "A APPEND INBOX UTF8 ({123}\r\n\
             ) (Flag) UTF8 (~{456+}\r\n\
             )\r\n",
            //
            "append (123 false): A APPEND INBOX UTF8 (\n\
             append cont (456 true):  (Flag) UTF8 (\n\
             append done\n",
        );
        run_test(
            "A APPEND INBOX {1}\n\
             )\n",
            //
            "append (1 false): A APPEND INBOX \n\
             append syntax error\n",
        );
        run_test(
            "A APPEND INBOX UTF8 ({1}\n\
             \n",
            //
            "append (1 false): A APPEND INBOX UTF8 (\n\
             append syntax error\n",
        );
        run_test(
            "A APPEND INBOX {1}\n\
             \x20({99999}\n\
             B CREATE FOO\n",
            //
            "append (1 false): A APPEND INBOX \n\
             append syntax error\n\
             stand-alone: B CREATE FOO\n",
        );
        run_test(
            "A APPEND INBOX {1}\n\
             \x20({5+}\n\
             plugh\n\
             B CREATE FOO\n",
            //
            "append (1 false): A APPEND INBOX \n\
             append syntax error\n\
             stand-alone: B CREATE FOO\n",
        );
        run_test(
            &format!(
                "A APPEND INBOX {{1}}\n\
                 \x20{:098765}\n\
                 B CREATE FOO\n",
                1,
            ),
            //
            "append (1 false): A APPEND INBOX \n\
             append too long\n\
             stand-alone: B CREATE FOO\n",
        );
    }
}
