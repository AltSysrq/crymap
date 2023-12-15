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

use chrono::prelude::*;
use log::warn;

use super::super::storage;
use super::defs::*;
use crate::{
    account::model::*,
    support::{chronox::*, error::Error},
};

impl Account {
    /// Directly expunge the given UIDs, without going through the \Deleted
    /// dance.
    ///
    /// This is exposed as the `XVANQUISH` extension and the corresponding
    /// `XVANQUISH` command.
    pub fn vanquish(
        &mut self,
        mailbox: &Mailbox,
        uids: &SeqRange<Uid>,
    ) -> Result<(), Error> {
        mailbox.require_writable()?;
        let uids = mailbox.filter_uid_range(uids);
        self.metadb
            .expunge_mailbox_messages(mailbox.id, &mut uids.items(u32::MAX))?;
        Ok(())
    }

    /// Expunge messages named by `uids` which also have the `\Deleted` flag
    /// set.
    ///
    /// This is the `UID EXPUNGE` operation from RFC 4315.
    ///
    /// Checking the `\Deleted` flag is done with respect to the current
    /// snapshot and not the true message state, which makes it easier for the
    /// client to predict what the command will actually do.
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
        mailbox: &Mailbox,
        uids: &SeqRange<Uid>,
    ) -> Result<(), Error> {
        mailbox.require_writable()?;

        let Some(flag_id) = mailbox.flag_id(&Flag::Deleted) else {
            return Ok(());
        };

        let indices = mailbox.uid_range_to_indices(uids, true)?;
        self.metadb.expunge_mailbox_messages(
            mailbox.id,
            &mut indices
                .items(u32::MAX)
                .map(|ix| &mailbox.messages[ix as usize])
                .filter(|m| m.flags.contains(flag_id.0))
                .map(|m| m.uid),
        )?;
        Ok(())
    }

    /// Expunge all messages with the `\Deleted` flag in the current snapshot.
    ///
    /// This is the `EXPUNGE` operation from RFC 3501, and is also used for
    /// `CLOSE`.
    ///
    /// Checking the `\Deleted` flag is done with respect to the current
    /// snapshot and not the true message state.
    pub fn expunge_all_deleted(
        &mut self,
        mailbox: &Mailbox,
    ) -> Result<(), Error> {
        mailbox.require_writable()?;

        let Some(flag_id) = mailbox.flag_id(&Flag::Deleted) else {
            return Ok(());
        };

        self.metadb.expunge_mailbox_messages(
            mailbox.id,
            &mut mailbox
                .messages
                .iter()
                .filter(|m| m.flags.contains(flag_id.0))
                .map(|m| m.uid),
        )?;
        Ok(())
    }

    /// Immediately purge all pending soft expunges which have a
    /// `last_activity` before the given datetime.
    ///
    /// This is normally used as part of periodic messages to remove unused
    /// message files, but is also used for testing what happens when a removed
    /// message is read.
    ///
    /// Returns the number of messages that were purged.
    pub fn purge(&mut self, dt: DateTime<Utc>) -> Result<u32, Error> {
        let orphans = self
            .metadb
            .fetch_orphaned_messages(storage::UnixTimestamp(dt))?;

        let mut removed = 0u32;
        for &(message, ref path) in &orphans {
            // Delete the message itself first so that it will never get
            // "recovered" into the INBOX.
            if let Err(e) = self.message_store.delete(path.as_ref()) {
                // TODO log prefix
                warn!("delete message at {path:?}: {e:?}");
            } else {
                self.metadb.forget_message(message)?;
                removed += 1;
            }
        }

        Ok(removed)
    }

    /// Convenience for calling `purge()` with a date far in the future.
    pub fn purge_all(&mut self) -> Result<u32, Error> {
        self.purge(NaiveDate::from_ymdx(9999, 12, 31).and_hmsx_utc(23, 59, 59))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn expunge_of_expunged_message_succeeds_quietly() {
        let mut fixture = TestFixture::new();
        let (mut mb1, _) = fixture.account.select("INBOX", true, None).unwrap();
        let (mut mb2, _) = fixture.account.select("INBOX", true, None).unwrap();

        // Create a message with the \Deleted flag set
        let uid = fixture.simple_append("INBOX");
        fixture.account.poll(&mut mb1).unwrap();
        fixture
            .account
            .store(
                &mut mb1,
                &StoreRequest {
                    ids: &SeqRange::just(uid),
                    flags: &[Flag::Deleted],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                },
            )
            .unwrap();
        fixture.account.poll(&mut mb1).unwrap();

        // Let mb2 see it too
        fixture.account.poll(&mut mb2).unwrap();

        // Expunge it in mb1 and verify it's gone.
        fixture.account.expunge_all_deleted(&mb1).unwrap();
        let poll = fixture.account.poll(&mut mb1).unwrap();
        assert_eq!(vec![(Seqnum::u(1), uid)], poll.expunge);
        assert_eq!(None, mb1.uid_index(uid));

        // Expunge via mb2, which thinks the message still exists.
        fixture.account.expunge_all_deleted(&mb2).unwrap();
        let poll = fixture.account.poll(&mut mb2).unwrap();
        assert_eq!(vec![(Seqnum::u(1), uid)], poll.expunge);
        assert_eq!(None, mb2.uid_index(uid));

        // Also ensure that the second expunge doesn't break mb1
        fixture.account.poll(&mut mb1).unwrap();
    }

    #[test]
    fn expunge_empty_mailbox() {
        let mut fixture = TestFixture::new();
        let (mut mb1, _) = fixture.account.select("INBOX", true, None).unwrap();
        fixture.account.expunge_all_deleted(&mb1).unwrap();
        fixture.account.poll(&mut mb1).unwrap();
    }

    // v1/mailbox/expunge.rs has a test
    //   fn expunge_sees_delete_set_in_other_session()
    // which sets \Deleted in one session, then invokes EXPUNGE in a second
    // session without first polling to allow that second session to discover
    // the flag. This is an expected behaviour difference in V2.

    #[test]
    fn expunge_doesnt_see_delete_set_in_other_session() {
        let mut fixture = TestFixture::new();
        let uid = fixture.simple_append("INBOX");
        let (mut mb1, _) = fixture.account.select("INBOX", true, None).unwrap();
        let (mut mb2, _) = fixture.account.select("INBOX", true, None).unwrap();

        // Session 1 sets \Deleted
        fixture
            .account
            .store(
                &mut mb1,
                &StoreRequest {
                    ids: &SeqRange::just(uid),
                    flags: &[Flag::Deleted],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                },
            )
            .unwrap();

        // Session 2 runs EXPUNGE without having a chance to see the flag
        // change.
        fixture.account.expunge_all_deleted(&mb2).unwrap();
        // In the end, nothing is expunged.
        let poll = fixture.account.poll(&mut mb2).unwrap();
        assert!(poll.expunge.is_empty());
    }

    #[test]
    fn expunge_wont_delete_invisible_messages() {
        let mut fixture = TestFixture::new();
        let uid1 = fixture.simple_append("INBOX");
        let (mut mb1, _) = fixture.account.select("INBOX", true, None).unwrap();
        let (mut mb2, _) = fixture.account.select("INBOX", true, None).unwrap();

        // A second STORE comes in, and the first session sees that message and
        // sets \Deleted on both messages.
        let uid2 = fixture.simple_append("INBOX");
        fixture.account.poll(&mut mb1).unwrap();
        fixture
            .account
            .store(
                &mut mb1,
                &StoreRequest {
                    ids: &SeqRange::range(uid1, uid2),
                    flags: &[Flag::Deleted],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                },
            )
            .unwrap();

        // The second session does a mini poll, which exposes it to the new
        // \Deleted state.
        assert_eq!(1, fixture.account.mini_poll(&mut mb2).unwrap().fetch.len());
        // When the second session runs EXPUNGE, only the message actually in
        // its snapshot is removed.
        fixture.account.expunge_all_deleted(&mb2).unwrap();

        let poll = fixture.account.poll(&mut mb1).unwrap();
        assert_eq!(vec![(Seqnum::u(1), uid1)], poll.expunge);
    }

    #[test]
    fn uid_expunge_wont_delete_invisible_messages() {
        let mut fixture = TestFixture::new();
        let uid1 = fixture.simple_append("INBOX");
        let (mut mb1, _) = fixture.account.select("INBOX", true, None).unwrap();
        let (mut mb2, _) = fixture.account.select("INBOX", true, None).unwrap();

        // A second STORE comes in, and the first session sees that message and
        // sets \Deleted on both messages.
        let uid2 = fixture.simple_append("INBOX");
        fixture.account.poll(&mut mb1).unwrap();
        fixture
            .account
            .store(
                &mut mb1,
                &StoreRequest {
                    ids: &SeqRange::range(uid1, uid2),
                    flags: &[Flag::Deleted],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                },
            )
            .unwrap();

        // The second session does a mini poll, which exposes it to the new
        // \Deleted state.
        assert_eq!(1, fixture.account.mini_poll(&mut mb2).unwrap().fetch.len());
        // When the second session runs UID EXPUNGE, explicitly requesting both
        // UIDs, only the message actually in its snapshot is removed.
        fixture
            .account
            .expunge_deleted(&mb2, &SeqRange::range(uid1, uid2))
            .unwrap();

        let poll = fixture.account.poll(&mut mb1).unwrap();
        assert_eq!(vec![(Seqnum::u(1), uid1)], poll.expunge);
    }

    #[test]
    fn no_expunge_on_read_only() {
        let mut fixture = TestFixture::new();
        let (mb, _) = fixture.account.select("INBOX", false, None).unwrap();

        assert_matches!(
            Err(Error::MailboxReadOnly),
            fixture
                .account
                .expunge_deleted(&mb, &SeqRange::just(Uid::MIN)),
        );
        assert_matches!(
            Err(Error::MailboxReadOnly),
            fixture.account.expunge_all_deleted(&mb),
        );
        assert_matches!(
            Err(Error::MailboxReadOnly),
            fixture.account.vanquish(&mb, &SeqRange::just(Uid::MIN)),
        );
    }

    #[test]
    fn no_error_on_uid_expunge_with_bad_uids() {
        let mut fixture = TestFixture::new();
        for _ in 0..3 {
            fixture.simple_append("INBOX");
        }
        let (mut mb, _) = fixture.account.select("INBOX", true, None).unwrap();

        fixture
            .account
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
        fixture.account.poll(&mut mb).unwrap();

        fixture.account.expunge_all_deleted(&mb).unwrap();
        fixture.account.poll(&mut mb).unwrap();

        fixture
            .account
            .expunge_deleted(&mb, &SeqRange::range(Uid::u(1), Uid::u(5)))
            .unwrap();
    }
}
