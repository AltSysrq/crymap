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

use std::fs;
use std::os::unix::fs::DirBuilderExt;

use log::warn;

use super::defs::*;
use crate::support::error::Error;
use crate::support::file_ops::{self, IgnoreKinds};
use crate::userbox::model::*;
use crate::userbox::recency_token;

impl StatefulMailbox {
    /// Do a "mini" poll, appropriate for use after a `FETCH`, `STORE`, or
    /// `SEARCH` operation.
    ///
    /// This will not affect the sequence number mapping, and only reports
    /// information that was discovered incidentally since the last poll.
    ///
    /// Returns a list of UIDs that should be sent in unsolicited `FETCH`
    /// responses (as per RFC 7162). This only includes UIDs currently mapped
    /// to sequence numbers, but may include UIDs that have since been
    /// expunged. Flag updates on UIDs not yet mapped to sequence numbers are
    /// lost, since those `FETCH` responses are expected to happen when the
    /// full poll announces the new messages to the client.
    pub fn mini_poll(&mut self) -> Vec<Uid> {
        let mut uids = self.state.take_changed_flags_uids();
        uids.retain(|&u| self.state.is_assigned_uid(u));
        uids
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
    pub fn poll(&mut self) -> Result<PollResponse, Error> {
        self.poll_for_new_uids();
        self.poll_for_new_changes(Cid::GENESIS)?;

        let flush = self.state.flush();
        let has_new = !flush.new.is_empty();
        let mut fetch = self.mini_poll();
        fetch.extend(flush.new.into_iter().map(|(_, u)| u));
        fetch.sort_unstable();
        fetch.dedup();

        // If there are new UIDs, see if we can claim \Recent on any of them.
        if let Some(max_recent_uid) = flush.max_modseq.map(Modseq::uid) {
            let min_recent_uid = self
                .recency_frontier
                .and_then(Uid::next)
                .unwrap_or(Uid::MIN);
            if min_recent_uid <= max_recent_uid {
                if let Some(claimed_recent_uid) = recency_token::claim(
                    &self.s.root,
                    min_recent_uid,
                    max_recent_uid,
                    self.s.read_only,
                ) {
                    for uid in
                        claimed_recent_uid.0.get()..=max_recent_uid.0.get()
                    {
                        self.state.set_recent(Uid::of(uid).unwrap());
                    }
                }
            }
        }

        // For any newly expunged messages, ensure they have gravestones.
        if !self.s.read_only {
            let message_scheme = self.s.message_scheme();
            for uid in flush
                .expunged
                .iter()
                .map(|&(_, u)| u)
                .chain(flush.stillborn.into_iter())
            {
                if let Err(e) = message_scheme
                    .expunge(uid.0.get(), &self.s.common_paths.tmp)
                {
                    warn!(
                        "{} Failed to fully expunge {}: {}",
                        self.s.log_prefix,
                        uid.0.get(),
                        e
                    );
                }
            }
        }

        let should_rollup = if self.suggest_rollup == 0 {
            false
        } else {
            self.suggest_rollup -= 1;
            self.suggest_rollup == 0
        };

        if !self.s.read_only && should_rollup {
            if let Err(e) = self.dump_rollup() {
                warn!(
                    "{} Failed to write metadata rollup: {}",
                    self.s.log_prefix, e
                );
            }
        }

        Ok(PollResponse {
            expunge: flush.expunged,
            exists: if has_new {
                Some(self.state.num_messages())
            } else {
                None
            },
            recent: if has_new {
                Some(self.count_recent())
            } else {
                None
            },
            fetch: fetch,
            max_modseq: flush.max_modseq,
        })
    }

    /// Probe for UIDs allocated later than the last known UID.
    fn poll_for_new_uids(&mut self) {
        let messages_scheme = self.s.message_scheme();
        while let Some(next_uid) = self.state.next_uid() {
            if messages_scheme.is_allocated(next_uid.0.get()) {
                self.state.seen(next_uid);
                // Plan to generate a rollup at every multiple of 256 messages
                // discovered by probing. (We don't expend effort to consider
                // messages discovered through change transactions, since some
                // other process already got to that same multiple of 256.) We
                // don't want to do this *immediately* though in order to avoid
                // O(n²) complexity when importing large numbers of messages,
                // so we require a few poll cycles to go by without new
                // messages first.
                //
                // Note that change probing runs after this point, so rollups
                // are forced every 256 change transactions regardless of what
                // we do here.
                self.suggest_rollup = 4;
            } else {
                break;
            }
        }
    }

    /// Probe for and load CIDs later than the last known CID.
    ///
    /// If a transaction with an id of `no_notify_cid` is found, any flag
    /// changes it makes are not added to the list of UIDs that have
    /// outstanding flag changes to report to the client.
    pub(super) fn poll_for_new_changes(
        &mut self,
        no_notify_cid: Cid,
    ) -> Result<(), Error> {
        while let Some(next_cid) = self.state.next_cid() {
            if self.s.change_scheme().is_allocated(next_cid.0) {
                self.apply_change(next_cid, next_cid != no_notify_cid)?;
            } else {
                break;
            }
        }

        Ok(())
    }

    fn apply_change(&mut self, cid: Cid, notify: bool) -> Result<(), Error> {
        self.state.commit(
            cid,
            self.s
                .read_state_file(&self.s.change_scheme().path_for_id(cid.0))?,
            notify,
        );

        if 0 == cid.0 % 256 {
            // Changes are fairly slow to read in, so force rollup at end of
            // poll cycle.
            self.suggest_rollup = 1;
        }

        Ok(())
    }

    fn dump_rollup(&self) -> Result<(), Error> {
        let mut path = self.s.root.join("rollup");

        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .ignore_already_exists()?;

        let buffer_file = self.s.write_state_file(&self.state)?;
        file_ops::chmod(buffer_file.path(), 0o400)?;

        path.push(
            self.state
                .max_modseq()
                .expect("Attempted rollup with no changes")
                .raw()
                .to_string(),
        );

        buffer_file
            .persist_noclobber(&path)
            .map_err(|e| e.error)
            .map(|_| ())
            .ignore_already_exists()?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::super::test_prelude::*;
    use super::*;

    #[test]
    fn single_client_message_operations() {
        let setup = set_up();

        let (mut mb, select_res) = setup.stateless.select().unwrap();
        assert_eq!(0, select_res.exists);
        assert_eq!(0, select_res.recent);
        assert_eq!(None, select_res.unseen);
        assert_eq!(Uid::MIN, select_res.uidnext);
        assert!(!select_res.read_only);
        assert_eq!(None, select_res.max_modseq);

        assert_eq!(Uid::u(1), simple_append(mb.stateless()));

        let poll = mb.poll().unwrap();
        assert_eq!(Vec::<(Seqnum, Uid)>::new(), poll.expunge);
        assert_eq!(Some(1), poll.exists);
        assert_eq!(Some(1), poll.recent);
        assert_eq!(vec![Uid::u(1)], poll.fetch);
        assert_eq!(Some(Modseq::new(Uid::u(1), Cid::GENESIS)), poll.max_modseq);

        assert_eq!(Uid::u(2), simple_append(mb.stateless()));
        assert_eq!(Uid::u(3), simple_append(mb.stateless()));

        let poll = mb.poll().unwrap();
        assert_eq!(Vec::<(Seqnum, Uid)>::new(), poll.expunge);
        assert_eq!(Some(3), poll.exists);
        assert_eq!(Some(3), poll.recent);
        assert_eq!(vec![Uid::u(2), Uid::u(3)], poll.fetch);
        assert_eq!(Some(Modseq::new(Uid::u(3), Cid::GENESIS)), poll.max_modseq);

        mb.store(&StoreRequest {
            ids: &SeqRange::just(Uid::u(2)),
            flags: &[Flag::Deleted],
            remove_listed: false,
            remove_unlisted: false,
            loud: false,
            unchanged_since: None,
        })
        .unwrap();

        assert_eq!(vec![Uid::u(2)], mb.mini_poll());
        assert!(mb.state.test_flag_o(&Flag::Deleted, Uid::u(2)));

        mb.expunge_all_deleted().unwrap();

        let poll = mb.poll().unwrap();
        assert_eq!(vec![(Seqnum::u(2), Uid::u(2))], poll.expunge);
        assert_eq!(None, poll.exists);
        assert_eq!(None, poll.recent);
        assert_eq!(Vec::<Uid>::new(), poll.fetch);
        assert_ne!(Cid::GENESIS, poll.max_modseq.unwrap().cid());
    }

    #[test]
    fn multi_client_message_operations() {
        let setup = set_up();

        let (mut mb1, _) = setup.stateless.clone().select().unwrap();
        let (mut mb2, _) = setup.stateless.clone().select().unwrap();

        assert_eq!(Uid::u(1), simple_append(mb1.stateless()));

        let poll = mb1.poll().unwrap();
        assert_eq!(Vec::<(Seqnum, Uid)>::new(), poll.expunge);
        assert_eq!(Some(1), poll.exists);
        assert_eq!(Some(1), poll.recent);
        assert_eq!(vec![Uid::u(1)], poll.fetch);
        assert_eq!(Some(Modseq::new(Uid::u(1), Cid::GENESIS)), poll.max_modseq);

        let poll = mb2.poll().unwrap();
        assert_eq!(Vec::<(Seqnum, Uid)>::new(), poll.expunge);
        assert_eq!(Some(1), poll.exists);
        // mb2 is the second to see the message, so it does not get \Recent on
        // UID 1
        assert_eq!(Some(0), poll.recent);
        assert_eq!(vec![Uid::u(1)], poll.fetch);
        assert_eq!(Some(Modseq::new(Uid::u(1), Cid::GENESIS)), poll.max_modseq);

        mb1.store(&StoreRequest {
            ids: &SeqRange::just(Uid::u(1)),
            flags: &[Flag::Deleted],
            remove_listed: false,
            remove_unlisted: false,
            loud: false,
            unchanged_since: None,
        })
        .unwrap();

        let poll = mb2.poll().unwrap();
        assert_eq!(Vec::<(Seqnum, Uid)>::new(), poll.expunge);
        assert_eq!(None, poll.exists);
        assert_eq!(None, poll.recent);
        assert_eq!(vec![Uid::u(1)], poll.fetch);
        assert_eq!(Some(Modseq::new(Uid::u(1), Cid(1))), poll.max_modseq);

        assert!(mb1.state.test_flag_o(&Flag::Deleted, Uid::u(1)));

        mb1.expunge_all_deleted().unwrap();

        let poll = mb2.poll().unwrap();
        assert_eq!(vec![(Seqnum::u(1), Uid::u(1))], poll.expunge);
        assert_eq!(None, poll.exists);
        assert_eq!(None, poll.recent);
        assert_eq!(Vec::<Uid>::new(), poll.fetch);
        assert_eq!(Some(Modseq::new(Uid::u(1), Cid(2))), poll.max_modseq);
    }
}
