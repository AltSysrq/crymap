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

use std::borrow::Cow;
use std::io;
use std::pin::{pin, Pin};
use std::time::Duration;

use log::{info, warn};
use tokio::io::AsyncWriteExt;

use super::{
    command_processor::CommandProcessor,
    request_reader::{
        AppendContinuation, CommandStart, CompressionStatus, RequestReader,
    },
    response_writer::{self, OutputControl, OutputDisconnect, OutputEvent},
};
use crate::{
    imap::syntax as s,
    support::{append_limit::APPEND_SIZE_LIMIT, async_io::ServerIo},
};

/// Runs the IMAPS server over the given I/O socket(s) using the given command
/// processor.
///
/// This logs the final outcome itself.
pub async fn run(mut io: ServerIo, mut processor: CommandProcessor) {
    let (input_result, output_result) =
        run_impl(io.clone(), &mut processor).await;

    // Close the TLS session cleanly if possible.
    let _ = tokio::time::timeout(Duration::from_secs(5), io.shutdown()).await;

    match (input_result, output_result) {
        (Some(Ok(())), _) => {
            info!("{} Normal client disconnect", processor.log_prefix());
        },

        (Some(Err(ProcessError::Protocol)), _) => {
            warn!("{} Unrecoverable protocol error", processor.log_prefix());
        },

        (Some(Err(ProcessError::Loitering)), _) => {
            warn!("{} Disconnected due to loitering", processor.log_prefix());
        },

        (Some(Err(ProcessError::InputIo(e))), _) | (_, Some(Err(e)))
            if io::ErrorKind::UnexpectedEof == e.kind() =>
        {
            info!("{} Client closed connection", processor.log_prefix());
        }

        (Some(Err(ProcessError::InputIo(e))), _) | (_, Some(Err(e)))
            if io::ErrorKind::TimedOut == e.kind() =>
        {
            info!("{} Network timed out", processor.log_prefix());
        }

        (Some(Err(ProcessError::InputIo(e))), _) => {
            warn!(
                "{} Disconnected due to input I/O error: {e}",
                processor.log_prefix(),
            );
        },

        (_, Some(Err(e))) => {
            warn!(
                "{} Disconnected due to output I/O error: {e}",
                processor.log_prefix(),
            );
        },

        (_, Some(Ok(OutputDisconnect::ByControl))) => {
            warn!(
                "{} Connection terminated by server logic",
                processor.log_prefix(),
            );
        },

        // These imply that the other side chose to exit first, so they
        // shouldn't happen.
        (Some(Err(ProcessError::OutputClosed)), _) |
        (_, Some(Ok(OutputDisconnect::InputClosed))) |
        // Doesn't happen since one side always exits.
        (None, None) => {
            warn!(
                "{} Disconnected for unknown reason",
                processor.log_prefix(),
            );
        }
    }
}

async fn run_impl(
    io: ServerIo,
    processor: &mut CommandProcessor,
) -> (
    Option<Result<(), ProcessError>>,
    Option<io::Result<OutputDisconnect>>,
) {
    let (output_tx, output_rx) = tokio::sync::mpsc::channel(16);
    let (ping_tx, ping_rx) = tokio::sync::mpsc::channel(1);
    let inactivity_monitor = inactivity_monitor(ping_rx, output_tx.clone());
    let mut input_processor =
        pin!(process_input(io.clone(), processor, ping_tx, output_tx));
    let mut response_writer =
        pin!(response_writer::write_responses(io, output_rx));

    // Generally, we want both results to best determine why the connection
    // terminated. However, on graceless disconnect, it's not necessarily
    // possible for this to happen, in particular because the output side tries
    // its best to flush before terminating even after noticing its channel has
    // been closed, so we give a few seconds for things to respond, then give
    // up.
    tokio::select! {
        _ = inactivity_monitor => {
            let output_result = tokio::time::timeout(
                Duration::from_secs(5),
                response_writer).await.ok();
            (Some(Err(ProcessError::Loitering)), output_result)
        },

        input_result = &mut input_processor => {
            let output_result = tokio::time::timeout(
                Duration::from_secs(5),
                response_writer).await.ok();
            (Some(input_result), output_result)
        },

        output_result = &mut response_writer => {
            let input_result = tokio::time::timeout(
                Duration::from_secs(5),
                input_processor).await.ok();
            (input_result, Some(output_result))
        },
    }
}

macro_rules! bye {
    ($output_tx:expr, $err:expr, $code:expr, $quip:expr $(,)*) => {
        let _ = $output_tx
            .send(OutputEvent::ResponseLine {
                line: s::ResponseLine {
                    tag: None,
                    response: s::Response::Cond(s::CondResponse {
                        cond: s::RespCondType::Bye,
                        code: $code,
                        quip: Some(Cow::Borrowed($quip)),
                    }),
                },
                ctl: OutputControl::Disconnect,
            })
            .await;
        return Err($err);
    };
}

macro_rules! send_cond {
    ($output_tx:expr, $tag:expr, $cond:ident, $code:expr, $quip:expr $(,)*) => {
        $output_tx
            .send(OutputEvent::ResponseLine {
                line: s::ResponseLine {
                    tag: Some($tag),
                    response: s::Response::Cond(s::CondResponse {
                        cond: s::RespCondType::$cond,
                        code: $code,
                        quip: Some(Cow::Borrowed($quip)),
                    }),
                },
                ctl: OutputControl::Flush,
            })
            .await
            .map_err(|_| ProcessError::OutputClosed)
    };
}

async fn process_input(
    io: ServerIo,
    processor: &mut CommandProcessor,
    ping_tx: tokio::sync::mpsc::Sender<bool>,
    mut output_tx: tokio::sync::mpsc::Sender<OutputEvent>,
) -> Result<(), ProcessError> {
    let mut request_reader = RequestReader::new(io);
    let mut unauthenticated_commands = 0;

    output_tx
        .send(OutputEvent::ResponseLine {
            line: processor.greet(),
            ctl: OutputControl::Flush,
        })
        .await
        .map_err(|_| ProcessError::OutputClosed)?;

    while !processor.logged_out() {
        let authenticated = processor.is_authenticated();
        let _ = ping_tx.send(authenticated).await;

        if !authenticated {
            unauthenticated_commands += 1;
            // Limit the number of commands that can be executed before
            // authenticating. This limits the effectiveness of using COMPRESS
            // to flood the server with NOOPs etc.
            if unauthenticated_commands > 30 {
                bye!(
                    output_tx,
                    ProcessError::Loitering,
                    None,
                    "LOGIN or GET OUT",
                );
            }
        }

        // We only allow overlong line recovery if authenticated. This prevents
        // using COMPRESS to send a deflate bomb to flood the CPU.
        let start = request_reader
            .read_command_start(&mut output_tx, authenticated)
            .await
            .map_err(ProcessError::InputIo)?;

        match start {
            CommandStart::Incomprehensible => {
                bye!(
                    output_tx,
                    ProcessError::Protocol,
                    Some(s::RespTextCode::Parse(())),
                    "That doesn't look anything like an IMAP command!",
                );
            },

            CommandStart::Bad(tag) => {
                send_cond!(
                    output_tx,
                    Cow::Owned(tag),
                    Bad,
                    Some(s::RespTextCode::Parse(())),
                    "Unrecognised command syntax",
                )?;
            },

            CommandStart::TooLongRecovered(tag) => {
                send_cond!(
                    output_tx,
                    Cow::Owned(tag),
                    No,
                    None,
                    "Command line too long",
                )?;
            },

            CommandStart::TooLongFatal(_tag) => {
                bye!(
                    output_tx,
                    ProcessError::Protocol,
                    None,
                    "Command line too long",
                );
            },

            CommandStart::OutputDisconnected => {
                return Err(ProcessError::OutputClosed);
            },

            CommandStart::AppendStart {
                append,
                size,
                literal_plus,
            } => {
                let append = s::AppendCommandStart::<'static> {
                    tag: Cow::Owned(append.tag.into_owned()),
                    mailbox: append.mailbox.into_static(),
                    first_fragment: append.first_fragment,
                };
                handle_append(
                    &mut request_reader,
                    &mut output_tx,
                    processor,
                    append,
                    size,
                    literal_plus,
                )
                .await?;
            },

            CommandStart::AuthenticateStart(auth) => {
                if let Some(line) = processor.authenticate_start(&auth) {
                    output_tx
                        .send(OutputEvent::ResponseLine {
                            ctl: command_end_ctl(&line.response),
                            line,
                        })
                        .await
                        .map_err(|_| ProcessError::OutputClosed)?;
                    continue;
                }

                let auth = s::AuthenticateCommandStart::<'static> {
                    tag: Cow::Owned(auth.tag.into_owned()),
                    auth_type: Cow::Owned(auth.auth_type.into_owned()),
                    initial_response: auth
                        .initial_response
                        .map(|ir| Cow::Owned(ir.into_owned())),
                };
                output_tx
                    .send(OutputEvent::ContinuationLine {
                        // The "prompt" is actually the challenge data, of which
                        // there is none.
                        prompt: "",
                    })
                    .await
                    .map_err(|_| ProcessError::OutputClosed)?;

                let Some(auth_data) = request_reader
                    .read_raw_line()
                    .await
                    .map_err(ProcessError::InputIo)?
                else {
                    bye!(
                        output_tx,
                        ProcessError::Protocol,
                        None,
                        "Auth data too long",
                    );
                };

                let line = processor.authenticate_finish(auth, auth_data);
                output_tx
                    .send(OutputEvent::ResponseLine {
                        ctl: command_end_ctl(&line.response),
                        line,
                    })
                    .await
                    .map_err(|_| ProcessError::OutputClosed)?;
            },

            CommandStart::StandAlone(cmd) => match cmd {
                s::CommandLine {
                    tag,
                    cmd: s::Command::Simple(s::SimpleCommand::Compress),
                } => {
                    let tag = tag.into_owned();
                    handle_compress(&mut request_reader, &mut output_tx, tag)
                        .await?;
                },

                s::CommandLine {
                    tag,
                    cmd: s::Command::Simple(s::SimpleCommand::Idle),
                } => {
                    let tag = tag.into_owned();
                    handle_idle(
                        &mut request_reader,
                        &mut output_tx,
                        processor,
                        tag,
                    )
                    .await?;
                },

                cmd => {
                    let line =
                        processor.handle_command(cmd, output_tx.clone()).await;
                    // Notably, for LOGOUT, this does not actually cause the
                    // final OK to be sent with OutputControl::Disconnect.
                    // Instead, the input loop simply exits when it sees the
                    // processor has logged out.
                    output_tx
                        .send(OutputEvent::ResponseLine {
                            ctl: command_end_ctl(&line.response),
                            line,
                        })
                        .await
                        .map_err(|_| ProcessError::OutputClosed)?;
                },
            },
        }
    }

    Ok(())
}

enum ProcessError {
    InputIo(io::Error),
    Protocol,
    Loitering,
    OutputClosed,
}

async fn handle_append(
    request_reader: &mut RequestReader<ServerIo>,
    output_tx: &mut tokio::sync::mpsc::Sender<OutputEvent>,
    processor: &mut CommandProcessor,
    append: s::AppendCommandStart<'_>,
    mut size: u32,
    mut literal_plus: bool,
) -> Result<(), ProcessError> {
    let tag = append.tag.clone().into_owned();

    if let Err(e) = processor.cmd_append_start(&append) {
        request_reader
            .abort_append(size, literal_plus)
            .await
            .map_err(ProcessError::InputIo)?;
        output_tx
            .send(OutputEvent::ResponseLine {
                ctl: command_end_ctl(&e),
                line: s::ResponseLine {
                    tag: Some(Cow::Owned(tag)),
                    response: e,
                },
            })
            .await
            .map_err(|_| ProcessError::OutputClosed)?;
        return Ok(());
    }

    let mut fragment = append.first_fragment;
    // For each iteration of the loop, we're about to read a
    // literal described by (size, literal_plus, fragment)
    loop {
        // Verify allowable sizes. (0 explicitly cancels but is
        // still a NO.)
        if 0 == size {
            send_cond!(
                output_tx,
                Cow::Owned(tag),
                No,
                None,
                "Zero-size APPEND",
            )?;
            request_reader
                .abort_append(size, literal_plus)
                .await
                .map_err(ProcessError::InputIo)?;
            return Ok(());
        }

        if size > APPEND_SIZE_LIMIT {
            send_cond!(
                output_tx,
                Cow::Owned(tag),
                No,
                Some(s::RespTextCode::TooBig(())),
                "APPEND message too big",
            )?;
            request_reader
                .abort_append(size, literal_plus)
                .await
                .map_err(ProcessError::InputIo)?;
            return Ok(());
        }

        // Ready to read the literal.
        if !literal_plus {
            output_tx
                .send(OutputEvent::ContinuationLine { prompt: "go" })
                .await
                .map_err(|_| ProcessError::OutputClosed)?;
        }

        // Process this item.
        let result = {
            let mut reader = request_reader.read_append_literal(size);
            let result = processor
                .cmd_append_item(&fragment, size, Pin::new(&mut reader))
                .await;
            // Ensure we consume the whole thing
            tokio::io::copy(&mut reader, &mut tokio::io::sink())
                .await
                .map_err(ProcessError::InputIo)?;
            result
        };

        // Back out if this item specifically failed.
        if let Err(response) = result {
            output_tx
                .send(OutputEvent::ResponseLine {
                    ctl: command_end_ctl(&response),
                    line: s::ResponseLine {
                        tag: Some(Cow::Owned(tag)),
                        response,
                    },
                })
                .await
                .map_err(|_| ProcessError::OutputClosed)?;
            processor.cmd_append_abort();
            request_reader
                .abort_append_after_literal()
                .await
                .map_err(ProcessError::InputIo)?;
            return Ok(());
        }

        let next = request_reader
            .continue_append(fragment.utf8)
            .await
            .map_err(ProcessError::InputIo)?;

        match next {
            AppendContinuation::NextPart {
                fragment: f,
                size: s,
                literal_plus: l,
            } => {
                // Ok, keep going
                fragment = f;
                size = s;
                literal_plus = l;
            },

            AppendContinuation::Done => break,

            AppendContinuation::SyntaxError => {
                processor.cmd_append_abort();
                send_cond!(
                    output_tx,
                    Cow::Owned(tag),
                    Bad,
                    Some(s::RespTextCode::Parse(())),
                    "Bad APPEND continuation",
                )?;
                return Ok(());
            },

            AppendContinuation::TooLong => {
                processor.cmd_append_abort();
                send_cond!(
                    output_tx,
                    Cow::Owned(tag),
                    Bad,
                    None,
                    "APPEND continuation line too long",
                )?;
                return Ok(());
            },
        }
    }

    // The last item was prepared, and the parser is beyond the end of the
    // whole APPEND.
    let line = processor
        .cmd_append_commit(Cow::Owned(tag), output_tx.clone())
        .await;
    output_tx
        .send(OutputEvent::ResponseLine {
            ctl: command_end_ctl(&line.response),
            line,
        })
        .await
        .map_err(|_| ProcessError::OutputClosed)?;
    Ok(())
}

async fn handle_compress(
    request_reader: &mut RequestReader<ServerIo>,
    output_tx: &mut tokio::sync::mpsc::Sender<OutputEvent>,
    tag: String,
) -> Result<(), ProcessError> {
    let response = match request_reader.start_compression() {
        CompressionStatus::Started => s::CondResponse {
            cond: s::RespCondType::Ok,
            code: None,
            quip: Some(Cow::Borrowed("Oo.")),
        },

        CompressionStatus::AlreadyActive => s::CondResponse {
            cond: s::RespCondType::No,
            code: Some(s::RespTextCode::CompressionActive(())),
            quip: Some(Cow::Borrowed("Already compressing")),
        },

        CompressionStatus::InvalidPipelinedData => s::CondResponse {
            cond: s::RespCondType::Bad,
            code: Some(s::RespTextCode::ClientBug(())),
            quip: Some(Cow::Borrowed(
                "There is pipelined data behind the \
                     COMPRESS command",
            )),
        },
    };

    output_tx
        .send(OutputEvent::ResponseLine {
            ctl: if s::RespCondType::Ok == response.cond {
                OutputControl::EnableCompression
            } else {
                OutputControl::Flush
            },
            line: s::ResponseLine {
                tag: Some(Cow::Owned(tag)),
                response: s::Response::Cond(response),
            },
        })
        .await
        .map_err(|_| ProcessError::OutputClosed)?;

    Ok(())
}

async fn handle_idle(
    request_reader: &mut RequestReader<ServerIo>,
    output_tx: &mut tokio::sync::mpsc::Sender<OutputEvent>,
    processor: &mut CommandProcessor,
    tag: String,
) -> Result<(), ProcessError> {
    if let Some(line) = processor.cmd_idle_preflight(&tag) {
        output_tx
            .send(OutputEvent::ResponseLine {
                ctl: command_end_ctl(&line.response),
                line,
            })
            .await
            .map_err(|_| ProcessError::OutputClosed)?;
        return Ok(());
    }

    output_tx
        .send(OutputEvent::ContinuationLine { prompt: "idling" })
        .await
        .map_err(|_| ProcessError::OutputClosed)?;

    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
    let mut idle = pin!(processor.cmd_idle(&tag, output_tx.clone(), cancel_rx));
    let read_line = async move {
        let line = request_reader.read_raw_line().await;
        let _ = cancel_tx.send(());
        line
    };

    let fatal_error = tokio::select! {
        idle_error = &mut idle => {
            // IDLE only exits early on error, which is always
            // fatal, so cancelling the non-cancel-safe
            // read_raw_line() is fine.
            Some(idle_error)
        },

        line = read_line => {
            // If we got an IO error, cancel everything because the connection
            // is dead.
            let line = line.map_err(ProcessError::InputIo)?;

            if line.is_some() {
                // Normal case, we got a line (presumably "DONE", but we don't
                // care) which cancels the IDLE gracefully.
                None
            } else {
                // The "DONE" line was somehow too long.
                Some(s::ResponseLine {
                    tag: None,
                    response: s::Response::Cond(s::CondResponse {
                        cond: s::RespCondType::Bye,
                        code: None,
                        quip: Some(Cow::Borrowed(
                            "Expecting 'DONE', got far more than that",
                        )),
                    }),
                })
            }
        },
    };

    if let Some(fatal_error) = fatal_error {
        // This could be cancelling the non-cancel-safe
        // cmd_idle(), but that's fine since we're
        // disconnecting anyway.
        output_tx
            .send(OutputEvent::ResponseLine {
                line: fatal_error,
                ctl: OutputControl::Disconnect,
            })
            .await
            .map_err(|_| ProcessError::OutputClosed)?;
        return Err(ProcessError::Protocol);
    }

    let line = idle.await;
    output_tx
        .send(OutputEvent::ResponseLine {
            ctl: command_end_ctl(&line.response),
            line,
        })
        .await
        .map_err(|_| ProcessError::OutputClosed)?;
    Ok(())
}

/// Monitors for request inactivity.
///
/// Each message on `ping` resets the clock and informs whether the connection
/// is authenticated.
///
/// This only terminates if the inactivity timer elapses.
async fn inactivity_monitor(
    mut ping: tokio::sync::mpsc::Receiver<bool>,
    output_tx: tokio::sync::mpsc::Sender<OutputEvent>,
) {
    let mut authenticated = false;
    loop {
        let timeout = if authenticated {
            // A bit over the required 30 minutes
            Duration::from_secs(31 * 60)
        } else {
            // RFC 3501 requires the timer to be at least 30 minutes, but
            // possibly only intends that to apply to logged in clients. RFC
            // 9051 amends it to explicitly allow shorter timeouts for
            // not-logged-in clients.
            Duration::from_secs(300)
        };

        tokio::select! {
            _ = tokio::time::sleep(timeout) => break,
            auth = ping.recv() => authenticated = auth.unwrap_or(false),
        }
    }

    let _ = output_tx
        .send(OutputEvent::ResponseLine {
            ctl: OutputControl::Disconnect,
            line: s::ResponseLine {
                tag: None,
                response: s::Response::Cond(s::CondResponse {
                    cond: s::RespCondType::Bye,
                    code: None,
                    quip: Some(Cow::Borrowed(if authenticated {
                        "Inactivity timer elapsed"
                    } else {
                        "Authentication timed out"
                    })),
                }),
            },
        })
        .await;
}

fn command_end_ctl(response: &s::Response<'_>) -> OutputControl {
    if matches!(
        *response,
        s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Bye,
            ..
        }),
    ) {
        OutputControl::Disconnect
    } else {
        OutputControl::Flush
    }
}
