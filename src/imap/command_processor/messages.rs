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

use std::borrow::Cow;
use std::io::Read;

use chrono::prelude::*;

use super::defs::*;
use crate::account::mailbox::{StatefulMailbox, StatelessMailbox};
use crate::account::model::*;
use crate::imap::mailbox_name::MailboxName;
use crate::support::error::Error;

impl CommandProcessor {
    /// Start an append command.
    ///
    /// This call adds the first item to the append. Further items are added by
    /// subsequent calls to `cmd_append_item()`. Once everything is done,
    /// `cmd_append_commit()` is called to actually run the commit.
    ///
    /// If `cmd_append_start()` or `cmd_append_item()` fails,
    /// `cmd_append_abort()` must be called, and then the error response from
    /// the failing command returned with the tag matching the original
    /// request.
    pub fn cmd_append_start(
        &mut self,
        cmd: s::AppendCommandStart<'_>,
        item_size: u32,
        item_data: impl Read,
    ) -> PartialResult<()> {
        let mailbox = cmd.mailbox.get_utf8(self.unicode_aware);
        let dst =
            account!(self)?
                .mailbox(&mailbox, false)
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
            dst,
            request: AppendRequest { items: vec![] },
        });
        self.cmd_append_item(cmd.first_fragment, item_size, item_data)
    }

    pub fn cmd_append_item(
        &mut self,
        cmd: s::AppendFragment<'_>,
        item_size: u32,
        item_data: impl Read,
    ) -> PartialResult<()> {
        if 0 == item_size {
            return Err(s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::No,
                code: None,
                quip: Some(Cow::Borrowed("APPEND aborted by empty payload")),
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

        let buffered = append
            .dst
            .buffer_message(
                cmd.internal_date.unwrap_or_else(|| {
                    FixedOffset::east(0)
                        .from_utc_datetime(&Utc::now().naive_local())
                }),
                item_data,
            )
            .map_err(map_error!(self))?;
        append.request.items.push(AppendItem {
            buffer_file: buffered,
            flags: cmd.flags.unwrap_or_default(),
        });

        Ok(())
    }

    pub fn cmd_append_commit(
        &mut self,
        tag: Cow<'static, str>,
        sender: SendResponse<'_>,
    ) -> s::ResponseLine<'static> {
        let append = self
            .multiappend
            .take()
            .expect("cmd_append_commit with no append in progress");
        match append.dst.multiappend(append.request).map_err(map_error! {
            self,
            MailboxFull => (No, Some(s::RespTextCode::Limit(()))),
            GaveUpInsertion => (No, Some(s::RespTextCode::Unavailable(()))),
            BatchTooBig => (No, Some(s::RespTextCode::Limit(()))),
        }) {
            Ok(_appended) => { /* TODO UIDPLUS */ }
            Err(response) => {
                return s::ResponseLine {
                    tag: Some(tag),
                    response,
                };
            }
        }

        // Fall through to a NOOP to get the rest of the post-command
        // semantics.
        self.handle_command(
            s::CommandLine {
                tag,
                cmd: s::Command::Simple(s::SimpleCommand::XAppendFinishedNoop),
            },
            sender,
        )
    }

    pub fn cmd_append_abort(&mut self) {
        self.multiappend = None;
    }

    pub(super) fn cmd_expunge(
        &mut self,
        _sender: SendResponse<'_>,
    ) -> CmdResult {
        // As with NOOP, the unsolicited responses that go with this are part
        // of the natural poll cycle.
        selected!(self)?.expunge_all_deleted().map_err(map_error! {
            self,
            MailboxReadOnly => (No, Some(s::RespTextCode::Cannot(()))),
        })?;
        success()
    }

    pub(super) fn cmd_uid_expunge(
        &mut self,
        uids: Cow<'_, str>,
        _sender: SendResponse<'_>,
    ) -> CmdResult {
        let uids = self.parse_uid_range(&uids)?;
        selected!(self)?
            .expunge_deleted(&uids)
            .map_err(map_error! {
                self,
                MailboxReadOnly =>
                    (No, Some(s::RespTextCode::Cannot(()))),
                NxMessage =>
                    (No, Some(s::RespTextCode::Nonexistent(()))),
                UnaddressableMessage =>
                    (No, Some(s::RespTextCode::ClientBug(()))),
            })?;
        success()
    }

    pub(super) fn cmd_vanquish(
        &mut self,
        uids: Cow<'_, str>,
        _sender: SendResponse<'_>,
    ) -> CmdResult {
        let uids = self.parse_uid_range(&uids)?;
        let uids = uids.items(u32::MAX).take(65536).collect::<Vec<_>>();
        selected!(self)?.vanquish(uids).map_err(map_error! {
            self,
            MailboxReadOnly => (No, Some(s::RespTextCode::Cannot(()))),
            NxMessage => (No, Some(s::RespTextCode::Nonexistent(()))),
            UnaddressableMessage => (No, Some(s::RespTextCode::ClientBug(()))),
        })?;
        success()
    }

    pub(super) fn cmd_purge(&mut self) -> CmdResult {
        let n = selected!(self)?.purge_all();
        Ok(s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Ok,
            code: None,
            quip: Some(Cow::Owned(format!("{} messages purged", n))),
        }))
    }

    pub(super) fn cmd_copy(
        &mut self,
        cmd: s::CopyCommand<'_>,
        _sender: SendResponse<'_>,
    ) -> CmdResult {
        let messages = self.parse_seqnum_range(&cmd.messages)?;
        let request = CopyRequest { ids: messages };
        self.copy(&cmd.dst, request, StatefulMailbox::seqnum_copy)
    }

    pub(super) fn cmd_uid_copy(
        &mut self,
        cmd: s::CopyCommand<'_>,
        _sender: SendResponse<'_>,
    ) -> CmdResult {
        let messages = self.parse_uid_range(&cmd.messages)?;
        let request = CopyRequest { ids: messages };
        self.copy(&cmd.dst, request, StatefulMailbox::copy)
    }

    fn copy<T>(
        &mut self,
        dst: &MailboxName<'_>,
        request: T,
        f: impl FnOnce(
            &StatefulMailbox,
            &T,
            &StatelessMailbox,
        ) -> Result<AppendResponse, Error>,
    ) -> CmdResult {
        let account = account!(self)?;
        let selected = selected!(self)?;
        let dst = dst.get_utf8(self.unicode_aware);
        let dst = account.mailbox(&dst, false).map_err(map_error! {
            self,
            NxMailbox =>
                (No, Some(s::RespTextCode::TryCreate(()))),
            UnsafeName =>
                (No, Some(s::RespTextCode::Cannot(()))),
            MailboxUnselectable =>
                (No, Some(s::RespTextCode::Nonexistent(()))),
        })?;
        f(selected, &request, &dst).map_err(map_error! {
            self,
            MailboxFull => (No, Some(s::RespTextCode::Limit(()))),
            NxMessage => (No, Some(s::RespTextCode::Nonexistent(()))),
            ExpungedMessage => (No, Some(s::RespTextCode::ExpungeIssued(()))),
            GaveUpInsertion => (No, Some(s::RespTextCode::Unavailable(()))),
            UnaddressableMessage => (No, Some(s::RespTextCode::ClientBug(()))),
            BatchTooBig => (No, Some(s::RespTextCode::Limit(()))),
        })?;
        success()
    }
}
