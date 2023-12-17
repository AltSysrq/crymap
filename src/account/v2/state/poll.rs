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
    /// Clear cache(s) only used for the duration of individual commands.
    pub fn clear_cache(&mut self) {
        self.key_store.clear_cache();
    }

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
        let modseq_changed =
            mailbox.polled_snapshot_modseq != poll.snapshot_modseq;
        mailbox.flags.append(&mut poll.new_flags);
        mailbox.snapshot_modseq = poll.snapshot_modseq;
        mailbox.polled_snapshot_modseq = poll.snapshot_modseq;
        mailbox.merge_message_updates(poll.updated_messages);
        mailbox.next_uid = poll.next_uid;
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

        // Now that the client knows about all the expunges, we can forget the
        // loopbreaker state.
        mailbox.fetch_loopbreaker.clear();

        Ok(PollResponse {
            expunge,
            exists: new_messages.then_some(mailbox.messages.len()),
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn single_client_message_operations() {
        let mut fixture = TestFixture::new();

        let (mut mb, _) = fixture.select("INBOX", true, None).unwrap();
        let select_res = mb.select_response().unwrap();
        assert_eq!(0, select_res.exists);
        assert_eq!(0, select_res.recent);
        assert_eq!(None, select_res.unseen);
        assert_eq!(Uid::MIN, select_res.uidnext);
        assert!(!select_res.read_only);
        assert_eq!(Modseq::MIN, select_res.max_modseq);

        assert_eq!(Uid::u(1), fixture.simple_append("INBOX"));

        let poll = fixture.poll(&mut mb).unwrap();
        assert_eq!(Vec::<(Seqnum, Uid)>::new(), poll.expunge);
        assert_eq!(Some(1), poll.exists);
        assert_eq!(Some(1), poll.recent);
        assert_eq!(vec![Uid::u(1)], poll.fetch);
        assert_eq!(Some(Modseq::of(2)), poll.max_modseq);

        assert_eq!(Uid::u(2), fixture.simple_append("INBOX"));
        assert_eq!(Uid::u(3), fixture.simple_append("INBOX"));

        let poll = fixture.poll(&mut mb).unwrap();
        assert_eq!(Vec::<(Seqnum, Uid)>::new(), poll.expunge);
        assert_eq!(Some(3), poll.exists);
        assert_eq!(Some(3), poll.recent);
        assert_eq!(vec![Uid::u(2), Uid::u(3)], poll.fetch);
        assert_eq!(Some(Modseq::of(4)), poll.max_modseq);

        fixture
            .store(
                &mut mb,
                &StoreRequest {
                    ids: &SeqRange::just(Uid::u(2)),
                    flags: &[Flag::Deleted],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                },
            )
            .unwrap();

        let poll = fixture.mini_poll(&mut mb).unwrap();
        assert_eq!(vec![Uid::u(2)], poll.fetch);
        assert!(mb.test_flag_o(&Flag::Deleted, Uid::u(2)));

        fixture.expunge_all_deleted(&mb).unwrap();

        let poll = fixture.poll(&mut mb).unwrap();
        assert_eq!(vec![(Seqnum::u(2), Uid::u(2))], poll.expunge);
        assert_eq!(None, poll.exists);
        assert_eq!(None, poll.recent);
        assert_eq!(Vec::<Uid>::new(), poll.fetch);
        assert_eq!(Some(Modseq::of(6)), poll.max_modseq);
    }

    #[test]
    fn multi_client_message_operations() {
        let mut fixture = TestFixture::new();

        let (mut mb1, _) = fixture.select("INBOX", true, None).unwrap();
        let (mut mb2, _) = fixture.select("INBOX", true, None).unwrap();

        assert_eq!(Uid::u(1), fixture.simple_append("INBOX"));

        let poll = fixture.poll(&mut mb1).unwrap();
        assert_eq!(Vec::<(Seqnum, Uid)>::new(), poll.expunge);
        assert_eq!(Some(1), poll.exists);
        assert_eq!(Some(1), poll.recent);
        assert_eq!(vec![Uid::u(1)], poll.fetch);
        assert_eq!(Some(Modseq::of(2)), poll.max_modseq);

        let poll = fixture.poll(&mut mb2).unwrap();
        assert_eq!(Vec::<(Seqnum, Uid)>::new(), poll.expunge);
        assert_eq!(Some(1), poll.exists);
        // mb2 is the second to see the message, so it does not get \Recent on
        // UID 1
        assert_eq!(Some(0), poll.recent);
        assert_eq!(vec![Uid::u(1)], poll.fetch);
        assert_eq!(Some(Modseq::of(2)), poll.max_modseq);

        fixture
            .store(
                &mut mb1,
                &StoreRequest {
                    ids: &SeqRange::just(Uid::u(1)),
                    flags: &[Flag::Deleted],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                },
            )
            .unwrap();

        let poll = fixture.poll(&mut mb2).unwrap();
        assert_eq!(Vec::<(Seqnum, Uid)>::new(), poll.expunge);
        assert_eq!(None, poll.exists);
        assert_eq!(None, poll.recent);
        assert_eq!(vec![Uid::u(1)], poll.fetch);
        assert_eq!(Some(Modseq::of(3)), poll.max_modseq);

        fixture.mini_poll(&mut mb1).unwrap();
        assert!(mb1.test_flag_o(&Flag::Deleted, Uid::u(1)));

        fixture.expunge_all_deleted(&mb1).unwrap();

        let poll = fixture.poll(&mut mb2).unwrap();
        assert_eq!(vec![(Seqnum::u(1), Uid::u(1))], poll.expunge);
        assert_eq!(None, poll.exists);
        assert_eq!(None, poll.recent);
        assert_eq!(Vec::<Uid>::new(), poll.fetch);
        assert_eq!(Some(Modseq::of(4)), poll.max_modseq);
    }
}
