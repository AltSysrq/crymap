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

use std::mem;

use itertools::Itertools;

use super::super::storage;
use super::defs::*;
use crate::{account::model::*, support::error::Error};

impl Account {
    /// Do a "mini" poll on an open mailbox, appropriate for use after a
    /// `FETCH`, `STORE`, or `SEARCH` operation.
    ///
    /// This will not affect the sequence number mapping, and only reports
    /// information that was discovered incidentally since the last poll.
    ///
    /// Errors from this call are not recoverable. If it fails, the client and
    /// server are left in an inconsistent state.
    pub fn mini_poll(
        &mut self,
        mailbox: &mut Mailbox,
    ) -> Result<MiniPollResponse, Error> {
        let mut mini_poll = self.metadb.mini_poll(
            mailbox.id,
            mailbox
                .flags
                .last()
                .expect("there is always at least one flag")
                .0,
            mailbox.messages.last().map(|m| m.uid),
            mailbox.snapshot_modseq,
            mailbox
                .messages
                .iter()
                .map(|m| m.last_modified)
                .max()
                .unwrap_or(mailbox.snapshot_modseq),
        )?;

        mailbox.flags.append(&mut mini_poll.new_flags);
        mailbox.snapshot_modseq = mini_poll.snapshot_modseq;
        mailbox.merge_message_updates(mini_poll.updated_messages);

        Ok(MiniPollResponse {
            fetch: mailbox.take_changed_flags_uids(),
            divergent_modseq: mini_poll
                .diverged
                .then_some(mini_poll.snapshot_modseq),
        })
    }

    /// Do a full poll cycle, appropriate for use after all commands but
    /// `FETCH`, `STORE`, or `SEARCH`, and in response to wake-ups during
    /// `IDLE`.
    ///
    /// New messages and changes are detected, and the sequence number mapping
    /// is updated.
    ///
    /// Returns information that must be sent to the client to inform it of any
    /// changes that were detected.
    ///
    /// Errors from this call are not recoverable. If it fails, the client and
    /// server are left in an inconsistent state.
    pub fn poll(
        &mut self,
        mailbox: &mut Mailbox,
    ) -> Result<PollResponse, Error> {
        let mut poll = self.metadb.full_poll(
            mailbox.id,
            mailbox.writable,
            mailbox
                .flags
                .last()
                .expect("there is always at least one flag")
                .0,
            mailbox.messages.last().map(|m| m.uid),
            mailbox.snapshot_modseq,
            mailbox
                .messages
                .iter()
                .map(|m| m.last_modified)
                .max()
                .unwrap_or(mailbox.snapshot_modseq),
        )?;

        let new_messages = !poll.new_messages.is_empty();
        let messages_changed = !poll.expunged.is_empty() || new_messages;
        let modseq_changed = mailbox.snapshot_modseq != poll.snapshot_modseq;
        mailbox.flags.append(&mut poll.new_flags);
        mailbox.snapshot_modseq = poll.snapshot_modseq;
        mailbox.merge_message_updates(poll.updated_messages);
        let mut changed_uids = mailbox.take_changed_flags_uids();
        changed_uids.extend(poll.new_messages.iter().map(|m| m.uid));
        mailbox
            .messages
            .extend(poll.new_messages.into_iter().map(MessageStatus::from));

        let expunge = poll
            .expunged
            .iter()
            .filter_map(|&uid| {
                mailbox
                    .uid_index(uid)
                    .map(|ix| (Seqnum::from_index(ix), uid))
            })
            .collect::<Vec<_>>();

        let mut expunged_it = poll.expunged.iter().copied().peekable();
        mailbox.messages.retain(|m| {
            while expunged_it.peek().is_some_and(|&uid| uid < m.uid) {
                expunged_it.next();
            }

            !expunged_it.peek().is_some_and(|&uid| uid == m.uid)
        });

        expunged_it = poll.expunged.iter().copied().peekable();
        changed_uids.retain(|&cu| {
            while expunged_it.peek().is_some_and(|&uid| uid < cu) {
                expunged_it.next();
            }

            Some(cu) != expunged_it.peek().copied()
        });

        Ok(PollResponse {
            expunge,
            exists: messages_changed.then_some(mailbox.messages.len()),
            recent: new_messages
                .then(|| mailbox.messages.iter().filter(|m| m.recent).count()),
            fetch: changed_uids,
            max_modseq: modseq_changed.then_some(poll.snapshot_modseq),
        })
    }
}

impl Mailbox {
    fn merge_message_updates(
        &mut self,
        updated_messages: Vec<storage::UpdatedMessageStatus>,
    ) {
        for join in self
            .messages
            .iter_mut()
            .merge_join_by(updated_messages.into_iter(), |a, b| {
                a.uid.cmp(&b.uid)
            })
        {
            if let itertools::EitherOrBoth::Both(old, new) = join {
                old.last_modified = new.last_modified;
                old.flags = new.flags;
                self.changed_flags_uids.push(old.uid);
            }
        }
    }

    fn take_changed_flags_uids(&mut self) -> Vec<Uid> {
        self.changed_flags_uids.sort_unstable();
        self.changed_flags_uids.dedup();
        mem::take(&mut self.changed_flags_uids)
    }
}

// TODO v1/mailbox/poll.rs has a couple tests that could be adapted once we
// support the other mailbox features.
