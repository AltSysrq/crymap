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

use super::defs::*;
use crate::{account::model::*, support::error::Error};

impl Account {
    /// Perform a `SELECT` or `EXAMINE` of the given mailbox, with an optional
    /// fused `QRESYNC` operation.
    ///
    /// Use `Mailbox::select_response()` on the returned `Mailbox` to get the
    /// actual `SelectResponse`.
    pub fn select(
        &mut self,
        mailbox: &str,
        writable: bool,
        qresync: Option<&QresyncRequest>,
    ) -> Result<(Mailbox, Option<QresyncResponse>), Error> {
        // Implicitly drain deliveries before selecting to ensure new messages
        // show up immediately.
        self.drain_deliveries();

        let mailbox_id = self.metadb.find_mailbox(mailbox)?;
        let snapshot = self.metadb.select(mailbox_id, writable, qresync)?;
        let mailbox = Mailbox {
            id: mailbox_id,
            writable,
            messages: snapshot
                .messages
                .into_iter()
                .map(MessageStatus::from)
                .collect(),
            max_client_known_flag_id: snapshot
                .flags
                .last()
                .expect("there is always at least one flag")
                .0,
            flags: snapshot.flags,
            snapshot_modseq: snapshot.max_modseq,
            polled_snapshot_modseq: snapshot.max_modseq,
            next_uid: snapshot.next_uid,
            changed_flags_uids: Vec::new(),
            fetch_loopbreaker: Default::default(),
        };

        Ok((mailbox, snapshot.qresync))
    }
}

impl Mailbox {
    /// Generates the `SelectResponse` to be produced in response to selecting
    /// the mailbox in this state.
    pub fn select_response(&self) -> Result<SelectResponse, Error> {
        let seen_flag =
            self.flag_id(&Flag::Seen).expect("\\Seen is always defined");

        Ok(SelectResponse {
            flags: self
                .flags
                .iter()
                .map(|&(_, ref flag)| flag.clone())
                .collect(),
            exists: self.messages.len(),
            recent: self.messages.iter().filter(|m| m.recent).count(),
            unseen: self
                .messages
                .iter()
                .position(|m| !m.flags.contains(seen_flag.0))
                .map(Seqnum::from_index),
            uidnext: self.next_uid,
            uidvalidity: self.id.as_uid_validity()?,
            read_only: !self.writable,
            max_modseq: self.snapshot_modseq,
        })
    }
}
