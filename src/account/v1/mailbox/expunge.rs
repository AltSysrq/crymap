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

use chrono::prelude::*;

use log::warn;

use super::defs::*;
use crate::account::model::*;
use crate::support::{chronox::*, error::Error};

impl StatefulMailbox {
    /// Expunge all messages with the `\Deleted` flag in the current snapshot.
    ///
    /// This is the `EXPUNGE` operation from RFC 3501, and is also used for
    /// `CLOSE`.
    pub fn expunge_all_deleted(&mut self) -> Result<(), Error> {
        self.expunge_deleted(&SeqRange::range(Uid::MIN, Uid::MAX))
    }

    /// Expunge messages with the `\Deleted` flag and which are in the given
    /// UID set and the current snapshot.
    ///
    /// This is the `UID EXPUNGE` operation from RFC 4315.
    ///
    /// There is no error if `uids` includes a non-addressable UID. RFC 4315
    /// does not explicitly describe any particular behaviour when the client
    /// tries to `UID EXPUNGE` an unmapped UID. However, the wording
    ///
    /// > The UID EXPUNGE command permanently removes all messages that both
    /// > have the \Deleted flag set and have a UID that is included in the
    /// > specified sequence set from the currently selected mailbox.
    ///
    /// suggests the appropriate action is to ignore unmapped UIDs, since the
    /// condition is simply "message with \Deleted" AND "UID in set".
    pub fn expunge_deleted(
        &mut self,
        uids: &SeqRange<Uid>,
    ) -> Result<(), Error> {
        self.s.not_read_only()?;

        // Can't start a transaction if no messages have ever existed. And the
        // result is always the same if there are no messages at all, i.e., do
        // nothing.
        if 0 == self.state.num_messages() {
            return Ok(());
        }

        let deadline = expunge_deadline();
        self.change_transaction(|this, tx| {
            let deleted = match this.state.flag_id(&Flag::Deleted) {
                Some(deleted) => deleted,
                // If the flag hasn't been interned yet, no messages have it.
                None => return Ok(()),
            };

            // NB We can't iterate the HashMap<Uid, MessageStatus> directly because
            // we must only consider messages in the current snapshot
            for uid in this.state.uids() {
                if let Some(status) = this.state.message_status(uid) {
                    if status.test_flag(deleted) && uids.contains(uid) {
                        tx.expunge(deadline, uid);
                    }
                }
            }

            Ok(())
        })
    }

    /// Directly expunge the given UIDs, without going through the \Deleted
    /// dance.
    ///
    /// This would make a good extension, but it isn't an official one. It's
    /// used internally as a convenience function.
    pub fn vanquish(&mut self, uids: &SeqRange<Uid>) -> Result<(), Error> {
        self.s.not_read_only()?;

        if 0 == self.state.num_messages() {
            return Ok(());
        }

        let deadline = expunge_deadline();
        self.change_transaction(|this, tx| {
            for uid in uids.items(this.state.max_uid_val()) {
                if !this.state.is_assigned_uid(uid) {
                    continue;
                }

                if this.state.message_status(uid).is_some() {
                    tx.expunge(deadline, uid);
                }
            }

            Ok(())
        })
    }

    /// Immediately purge all pending soft expunges which have a deadline
    /// before the given date.
    ///
    /// This is mainly used for testing cases where a hard expunge occurs while
    /// a client still has a message in its snapshot as well as periodic
    /// maintenance.
    ///
    /// While this is sort of a mutating operation, it is allowed on read-only
    /// mailboxes as well to allow maintenance processes to execute it.
    ///
    /// Returns the number of messages that were purged.
    pub fn purge(&mut self, dt: DateTime<Utc>) -> u32 {
        let message_scheme = self.s.message_scheme();
        let mut count = 0;
        for uid in self.state.drain_soft_expunged(dt) {
            if let Err(e) =
                message_scheme.expunge(uid.0.get(), &self.s.common_paths.tmp)
            {
                warn!(
                    "{} Failed to fully expunge {}: {}",
                    self.s.log_prefix,
                    uid.0.get(),
                    e
                );
            } else {
                // Trigger a rollup so that future maintenance processes
                // don't try to do the expunge over and over again.
                self.suggest_rollup = 1;
                count += 1;
            }
        }

        count
    }

    /// Convenience for calling `purge()` with a date far in the future.
    pub fn purge_all(&mut self) -> u32 {
        self.purge(NaiveDate::from_ymdx(9999, 12, 31).and_hmsx_utc(23, 59, 59))
    }
}

fn expunge_deadline() -> DateTime<Utc> {
    Utc::now() + chrono::Duration::hours(24)
}

#[cfg(test)]
mod test {
    use super::super::test_prelude::*;
    use super::*;

    #[test]
    fn expunge_of_expunged_message_succeeds_quietly() {
        let setup = set_up();

        let (mut mb1, _) = setup.stateless.clone().select().unwrap();
        let (mut mb2, _) = setup.stateless.clone().select().unwrap();

        // Create a message with the \Deleted flag set
        let uid = simple_append(mb1.stateless());
        mb1.poll().unwrap();
        mb1.store(&StoreRequest {
            ids: &SeqRange::just(uid),
            flags: &[Flag::Deleted],
            remove_listed: false,
            remove_unlisted: false,
            loud: false,
            unchanged_since: None,
        })
        .unwrap();
        mb1.poll().unwrap();

        // Let mb2 see it
        mb2.poll().unwrap();

        // Expunge it in mb1, and call poll() and purge_all() to ensure it
        // really gets deleted
        assert!(mb1
            .stateless()
            .message_scheme()
            .access_path_for_id(uid.0.get())
            .assume_exists()
            .is_file());
        mb1.expunge_all_deleted().unwrap();
        mb1.poll().unwrap();
        mb1.purge_all();
        assert!(!mb1
            .stateless()
            .message_scheme()
            .access_path_for_id(uid.0.get())
            .assume_exists()
            .is_file());

        // Expunge via mb2, who thinks the message still exists
        mb2.expunge_all_deleted().unwrap();
        mb2.poll().unwrap();

        // Also ensure that the second expunge doesn't break mb1
        mb1.poll().unwrap();
    }

    #[test]
    fn expunge_empty_mailbox() {
        let setup = set_up();
        let (mut mb1, _) = setup.stateless.select().unwrap();
        mb1.expunge_all_deleted().unwrap();
        mb1.poll().unwrap();
    }

    #[test]
    fn expunge_sees_delete_set_in_other_session() {
        let setup = set_up();

        let (mut mb1, _) = setup.stateless.clone().select().unwrap();
        let (mut mb2, _) = setup.stateless.clone().select().unwrap();

        let uid = simple_append(mb1.stateless());
        mb1.poll().unwrap();
        mb2.poll().unwrap();

        mb1.store(&StoreRequest {
            ids: &SeqRange::just(uid),
            flags: &[Flag::Deleted],
            remove_listed: false,
            remove_unlisted: false,
            loud: false,
            unchanged_since: None,
        })
        .unwrap();

        mb2.expunge_all_deleted().unwrap();

        let poll = mb2.poll().unwrap();
        assert_eq!(vec![(Seqnum::u(1), uid)], poll.expunge);
        mb2.purge_all();
        assert!(!mb2
            .stateless()
            .message_scheme()
            .access_path_for_id(uid.0.get())
            .assume_exists()
            .is_file());
    }

    #[test]
    fn expunge_wont_delete_invisible_messages() {
        let setup = set_up();

        let (mut mb1, _) = setup.stateless.clone().select().unwrap();
        let (mut mb2, _) = setup.stateless.clone().select().unwrap();

        let _uid1 = simple_append(mb1.stateless());
        mb1.poll().unwrap();
        mb2.poll().unwrap();

        let uid2 = simple_append(mb1.stateless());
        mb1.poll().unwrap();
        mb1.store(&StoreRequest {
            ids: &SeqRange::just(uid2),
            flags: &[Flag::Deleted],
            remove_listed: false,
            remove_unlisted: false,
            loud: false,
            unchanged_since: None,
        })
        .unwrap();

        // Polling for changes will cause the \Deleted to be discovered and,
        // implicitly, uid2
        mb2.poll_for_new_changes().unwrap();
        assert!(mb2.state.test_flag_o(&Flag::Deleted, uid2));
        mb2.expunge_all_deleted().unwrap();

        let poll = mb2.poll().unwrap();
        assert!(poll.expunge.is_empty());
        assert!(mb2
            .stateless()
            .message_scheme()
            .access_path_for_id(uid2.0.get())
            .assume_exists()
            .is_file());
    }

    #[test]
    fn uid_delete_only_considers_requested_uids() {
        let setup = set_up();
        let (mut mb, _) = setup.stateless.clone().select().unwrap();

        for _ in 0..10 {
            simple_append(mb.stateless());
        }
        mb.poll().unwrap();

        mb.store(&StoreRequest {
            ids: &SeqRange::range(Uid::u(1), Uid::u(9)),
            flags: &[Flag::Deleted],
            remove_listed: false,
            remove_unlisted: false,
            loud: false,
            unchanged_since: None,
        })
        .unwrap();
        mb.poll().unwrap();

        mb.expunge_deleted(&SeqRange::range(Uid::u(3), Uid::u(5)))
            .unwrap();

        let poll = mb.poll().unwrap();
        assert_eq!(
            vec![
                (Seqnum::u(3), Uid::u(3)),
                (Seqnum::u(4), Uid::u(4)),
                (Seqnum::u(5), Uid::u(5))
            ],
            poll.expunge
        );
    }

    #[test]
    fn no_expunge_on_read_only() {
        let mut setup = set_up();
        setup.stateless.read_only = true;
        let (mut mb, _) = setup.stateless.clone().select().unwrap();

        assert!(matches!(
            mb.expunge_all_deleted(),
            Err(Error::MailboxReadOnly)
        ));
        assert!(matches!(
            mb.expunge_deleted(&SeqRange::just(Uid::u(1))),
            Err(Error::MailboxReadOnly)
        ));
    }

    #[test]
    fn no_error_on_uid_expunge_with_bad_uids() {
        let setup = set_up();
        let (mut mb, _) = setup.stateless.clone().select().unwrap();

        for _ in 0..3 {
            simple_append(mb.stateless());
        }
        mb.poll().unwrap();

        mb.store(&StoreRequest {
            ids: &SeqRange::just(Uid::u(2)),
            flags: &[Flag::Deleted],
            remove_listed: false,
            remove_unlisted: false,
            loud: false,
            unchanged_since: None,
        })
        .unwrap();
        mb.poll().unwrap();

        mb.expunge_all_deleted().unwrap();
        mb.poll().unwrap();

        mb.expunge_deleted(&SeqRange::range(Uid::u(1), Uid::u(5)))
            .unwrap();
    }
}
