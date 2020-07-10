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

use super::defs::*;
use crate::account::mailbox::{StatefulMailbox, StatelessMailbox};
use crate::account::model::*;
use crate::support::error::Error;

impl CommandProcessor {
    pub(super) fn cmd_expunge(
        &mut self,
        _sender: SendResponse<'_>,
    ) -> CmdResult {
        // As with NOOP, the unsolicited responses that go with this are part
        // of the natural poll cycle.
        selected!(self)?.expunge_all_deleted().map_err(map_error! {
            self,
            MailboxReadOnly => (No, None),
        })?;
        success()
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
        dst: &str,
        request: T,
        f: impl FnOnce(
            &StatefulMailbox,
            &T,
            &StatelessMailbox,
        ) -> Result<AppendResponse, Error>,
    ) -> CmdResult {
        let account = account!(self)?;
        let selected = selected!(self)?;
        let dst = account.mailbox(&dst, false).map_err(map_error! {
            self,
            NxMailbox => (No, Some(s::RespTextCode::TryCreate(()))),
            UnsafeName | MailboxUnselectable => (No, None),
        })?;
        f(selected, &request, &dst).map_err(map_error! {
           self,
            MailboxFull | NxMessage | ExpungedMessage | GaveUpInsertion |
            UnaddressableMessage => (No, None),
        })?;
        success()
    }
}
