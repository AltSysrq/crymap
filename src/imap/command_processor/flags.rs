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
use std::fmt;

use super::defs::*;
use crate::account::{
    model::*,
    v2::{Account, Mailbox},
};
use crate::support::error::Error;

impl CommandProcessor {
    pub(crate) async fn cmd_store(
        &mut self,
        cmd: s::StoreCommand<'_>,
        sender: &mut SendResponse,
    ) -> CmdResult {
        let ids = self.parse_seqnum_range(&cmd.messages)?;
        self.store(ids, cmd, sender, Account::seqnum_store).await
    }

    pub(crate) async fn cmd_uid_store(
        &mut self,
        cmd: s::StoreCommand<'_>,
        sender: &mut SendResponse,
    ) -> CmdResult {
        let ids = self.parse_uid_range(&cmd.messages)?;
        self.store(ids, cmd, sender, Account::store).await
    }

    async fn store<ID>(
        &mut self,
        ids: SeqRange<ID>,
        cmd: s::StoreCommand<'_>,
        sender: &mut SendResponse,
        f: impl FnOnce(
            &mut Account,
            &mut Mailbox,
            &StoreRequest<ID>,
        ) -> Result<StoreResponse<ID>, Error>,
    ) -> CmdResult
    where
        SeqRange<ID>: fmt::Debug,
    {
        if cmd.unchanged_since.is_some() {
            self.enable_condstore(sender, true).await;
        }

        let request = StoreRequest {
            ids: &ids,
            flags: &cmd.flags,
            remove_listed: s::StoreCommandType::Minus == cmd.typ,
            remove_unlisted: s::StoreCommandType::Eq == cmd.typ,
            loud: !cmd.silent,
            unchanged_since: cmd.unchanged_since.map(Modseq::of),
        };

        let resp = f(account!(self)?, selected!(self)?, &request).map_err(map_error! {
            self,
            MailboxFull => (No, Some(s::RespTextCode::Limit(()))),
            NxMessage => (No, Some(s::RespTextCode::Nonexistent(()))),
            ExpungedMessage => (No, Some(s::RespTextCode::ExpungeIssued(()))),
            MailboxReadOnly => (No, Some(s::RespTextCode::Cannot(()))),
            UnaddressableMessage => (No, Some(s::RespTextCode::ClientBug(()))),
            GaveUpInsertion => (No, Some(s::RespTextCode::Unavailable(()))),
        })?;

        if !resp.modified.is_empty() {
            Ok(s::Response::Cond(s::CondResponse {
                cond: if resp.ok {
                    s::RespCondType::Ok
                } else {
                    s::RespCondType::No
                },
                code: Some(s::RespTextCode::Modified(Cow::Owned(
                    resp.modified.to_string(),
                ))),
                quip: None,
            }))
        } else if resp.ok {
            success()
        } else {
            Ok(s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::No,
                code: None,
                quip: Some(Cow::Borrowed("No messages matched")),
            }))
        }
    }
}
