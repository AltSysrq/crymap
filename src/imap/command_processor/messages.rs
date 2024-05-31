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

use std::borrow::Cow;

use chrono::prelude::*;

use super::defs::*;
use crate::account::model::*;
use crate::account::v2::{Account, Mailbox};
use crate::imap::mailbox_name::MailboxName;
use crate::support::error::Error;

impl CommandProcessor {
    /// Start an append command.
    ///
    /// This call performs the initial sanity checks.
    ///
    /// Items are added by calling `cmd_append_item()` one or more times. Once
    /// everything is done, `cmd_append_commit()` is called to actually run the
    /// commit.
    ///
    /// If `cmd_append_start()` or `cmd_append_item()` fails,
    /// `cmd_append_abort()` must be called, and then the error response from
    /// the failing command returned with the tag matching the original
    /// request.
    pub fn cmd_append_start(
        &mut self,
        cmd: &s::AppendCommandStart<'_>,
    ) -> PartialResult<()> {
        // This version shall not include an append_item call!
        let mailbox = cmd.mailbox.get_utf8(self.unicode_aware);
        account!(self)?
            .probe_mailbox(&mailbox)
            .map_err(map_error! {
                self,
                NxMailbox =>
                    (No, Some(s::RespTextCode::TryCreate(()))),
                MailboxUnselectable =>
                    (No, Some(s::RespTextCode::Nonexistent(()))),
                UnsafeName =>
                    (No, Some(s::RespTextCode::Cannot(()))),
            })?;
        self.multiappend = Some(Multiappend {
            dst: mailbox.into_owned(),
            request: AppendRequest { items: vec![] },
        });
        Ok(())
    }

    pub async fn cmd_append_item(
        &mut self,
        cmd: &s::AppendFragment,
        item_size: u32,
        item_data: std::pin::Pin<&mut impl tokio::io::AsyncRead>,
    ) -> PartialResult<()> {
        if 0 == item_size {
            return Err(s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::No,
                code: None,
                quip: Some(Cow::Borrowed("APPEND aborted by empty payload")),
            }));
        }

        // UTF8 literals are nothing but syntax salt and a waste of everyone's
        // time, but we enforce the requirement that they can't be used without
        // ENABLE UTF8=ACCEPT anyway.
        if cmd.utf8 && !self.utf8_enabled {
            return Err(s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::No,
                code: None,
                quip: Some(Cow::Borrowed(
                    "UTF8 literal not allowed until ENABLE UTF8=ACCEPT",
                )),
            }));
        }

        let append = self
            .multiappend
            .as_mut()
            .expect("cmd_append_item with no append in progress");

        if append.request.items.len() >= 65536 {
            return Err(s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::No,
                code: Some(s::RespTextCode::Limit(())),
                quip: Some(Cow::Borrowed(
                    "Maximum message count for MULTIAPPEND is 65536",
                )),
            }));
        }

        let buffered = account!(self)?
            .buffer_message_async(
                cmd.internal_date.unwrap_or_else(|| Utc::now().into()),
                item_data,
            )
            .await
            .map_err(map_error!(self))?;
        append.request.items.push(AppendItem {
            buffer_file: buffered,
            flags: cmd.flags.clone().unwrap_or_default(),
        });

        Ok(())
    }

    pub async fn cmd_append_commit(
        &mut self,
        tag: Cow<'static, str>,
        sender: SendResponse,
    ) -> s::ResponseLine<'static> {
        let account = account!(self)
            .expect("APPEND couldn't have started if there were no account");

        let append = self
            .multiappend
            .take()
            .expect("cmd_append_commit with no append in progress");
        let response =
            match account.multiappend(&append.dst, append.request).map_err(map_error! {
                self,
                MailboxFull => (No, Some(s::RespTextCode::Limit(()))),
                GaveUpInsertion => (No, Some(s::RespTextCode::Unavailable(()))),
                BatchTooBig => (No, Some(s::RespTextCode::Limit(()))),
                NxMailbox => (No, Some(s::RespTextCode::TryCreate(()))),
                MailboxUnselectable => (No, Some(s::RespTextCode::Nonexistent(()))),
            }) {
                Ok(appended) => appended,
                Err(response) => {
                    return s::ResponseLine {
                        tag: Some(tag),
                        response,
                    };
                },
            };

        // Fall through to a NOOP to get the rest of the post-command
        // semantics.
        self.handle_command(
            s::CommandLine {
                tag: tag.clone(),
                cmd: s::Command::Simple(s::SimpleCommand::XAppendFinishedNoop),
            },
            sender,
        )
        .await;

        s::ResponseLine {
            tag: Some(tag),
            response: s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::Ok,
                code: Some(s::RespTextCode::AppendUid(s::AppendUidData {
                    uid_validity: response.uid_validity,
                    uids: Cow::Owned(response.uids.to_string()),
                })),
                quip: None,
            }),
        }
    }

    pub fn cmd_append_abort(&mut self) {
        self.multiappend = None;
    }

    pub(super) fn cmd_expunge(&mut self) -> CmdResult {
        // As with NOOP, the unsolicited responses that go with this are part
        // of the natural poll cycle.
        account!(self)?
            .expunge_all_deleted(selected!(self)?)
            .map_err(map_error! {
                self,
                MailboxReadOnly => (No, Some(s::RespTextCode::Cannot(()))),
            })?;
        success()
    }

    pub(super) fn cmd_uid_expunge(&mut self, uids: Cow<'_, str>) -> CmdResult {
        let uids = self.parse_uid_range(&uids)?;
        account!(self)?
            .expunge_deleted(selected!(self)?, &uids)
            .map_err(map_error! {
                self,
                MailboxReadOnly =>
                    (No, Some(s::RespTextCode::Cannot(()))),
                NxMessage =>
                    (No, Some(s::RespTextCode::Nonexistent(()))),
                UnaddressableMessage =>
                    (No, Some(s::RespTextCode::ClientBug(()))),
            })?;
        // If QRESYNC is enabled, the *tagged* OK response is supposed to have
        // the HIGHESTMODSEQ as its response code. This is awkward since we
        // don't know what that value is yet, since the poll output occurs
        // before our tagged response in the stream but is computed later.
        // This is handled as a special case by `handle_command()`.
        success()
    }

    pub(super) fn cmd_vanquish(&mut self, uids: Cow<'_, str>) -> CmdResult {
        let uids = self.parse_uid_range(&uids)?;
        account!(self)?.vanquish(selected!(self)?, &uids).map_err(map_error! {
            self,
            MailboxReadOnly => (No, Some(s::RespTextCode::Cannot(()))),
            NxMessage => (No, Some(s::RespTextCode::Nonexistent(()))),
            UnaddressableMessage => (No, Some(s::RespTextCode::ClientBug(()))),
        })?;
        success()
    }

    pub(super) fn cmd_xcry_purge(&mut self) -> CmdResult {
        let n = account!(self)?.purge_all().map_err(map_error!(self))?;
        Ok(s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Ok,
            code: None,
            quip: Some(Cow::Owned(format!("{} messages purged", n))),
        }))
    }

    pub(super) async fn cmd_copy(
        &mut self,
        cmd: s::CopyCommand<'_>,
        sender: &mut SendResponse,
    ) -> CmdResult {
        let messages = self.parse_seqnum_range(&cmd.messages)?;
        let request = CopyRequest { ids: messages };
        self.copy_or_move(
            &cmd.dst,
            request,
            sender,
            false,
            Account::seqnum_copy,
        )
        .await
    }

    pub(super) async fn cmd_move(
        &mut self,
        cmd: s::MoveCommand<'_>,
        sender: &mut SendResponse,
    ) -> CmdResult {
        let messages = self.parse_seqnum_range(&cmd.messages)?;
        let request = CopyRequest { ids: messages };
        self.copy_or_move(
            &cmd.dst,
            request,
            sender,
            true,
            Account::seqnum_moove,
        )
        .await
    }

    pub(super) async fn cmd_uid_copy(
        &mut self,
        cmd: s::CopyCommand<'_>,
        sender: &mut SendResponse,
    ) -> CmdResult {
        let messages = self.parse_uid_range(&cmd.messages)?;
        let request = CopyRequest { ids: messages };
        self.copy_or_move(&cmd.dst, request, sender, false, Account::copy)
            .await
    }

    pub(super) async fn cmd_uid_move(
        &mut self,
        cmd: s::MoveCommand<'_>,
        sender: &mut SendResponse,
    ) -> CmdResult {
        let messages = self.parse_uid_range(&cmd.messages)?;
        let request = CopyRequest { ids: messages };
        self.copy_or_move(&cmd.dst, request, sender, true, Account::moove)
            .await
    }

    async fn copy_or_move<T>(
        &mut self,
        dst: &MailboxName<'_>,
        request: T,
        sender: &mut SendResponse,
        copyuid_in_separate_response: bool,
        f: impl FnOnce(
            &mut Account,
            &Mailbox,
            &T,
            &str,
        ) -> Result<CopyResponse, Error>,
    ) -> CmdResult {
        let account = account!(self)?;
        let selected = selected!(self)?;

        let dst = dst.get_utf8(self.unicode_aware);
        let response = f(account, selected, &request, &dst).map_err(map_error! {
            self,
            MailboxFull => (No, Some(s::RespTextCode::Limit(()))),
            NxMessage => (No, Some(s::RespTextCode::Nonexistent(()))),
            ExpungedMessage => (No, Some(s::RespTextCode::ExpungeIssued(()))),
            GaveUpInsertion => (No, Some(s::RespTextCode::Unavailable(()))),
            UnaddressableMessage => (No, Some(s::RespTextCode::ClientBug(()))),
            BatchTooBig => (No, Some(s::RespTextCode::Limit(()))),
            NxMailbox => (No, Some(s::RespTextCode::TryCreate(()))),
            MailboxUnselectable => (No, Some(s::RespTextCode::Nonexistent(()))),
            MoveIntoSelf => (No, Some(s::RespTextCode::Cannot(()))),
        })?;

        if response.from_uids.is_empty() {
            return Ok(s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::No,
                code: None,
                quip: Some(Cow::Borrowed("No messages matched")),
            }));
        }

        let mut copyuid_code = Some(s::RespTextCode::CopyUid(s::CopyUidData {
            uid_validity: response.uid_validity,
            from_uids: Cow::Owned(response.from_uids.to_string()),
            to_uids: Cow::Owned(response.to_uids.to_string()),
        }));

        if copyuid_in_separate_response {
            // RFC 6851 recommends sending the COPYUID response in an untagged
            // response before any EXPUNGE responses.
            send_response(
                sender,
                s::Response::Cond(s::CondResponse {
                    cond: s::RespCondType::Ok,
                    code: copyuid_code.take(),
                    quip: None,
                }),
            )
            .await;
        }

        Ok(s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Ok,
            code: copyuid_code,
            quip: None,
        }))
    }
}
