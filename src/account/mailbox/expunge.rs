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

use super::defs::*;
use crate::account::model::*;
use crate::support::error::Error;

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
    pub fn expunge_deleted(
        &mut self,
        uids: &SeqRange<Uid>,
    ) -> Result<(), Error> {
        self.s.not_read_only()?;

        let deleted = match self.state.flag_id(&Flag::Deleted) {
            Some(deleted) => deleted,
            // If the flag hasn't been interned yet, no messages have it.
            None => return Ok(()),
        };

        self.change_transaction(|this, tx| {
            // NB We can't iterate the HashMap<Uid, MessageStatus> directly because
            // we must only consider messages in the current snapshot
            for uid in this.state.uids() {
                if let Some(status) = this.state.message_status(uid) {
                    if status.test_flag(deleted) && uids.contains(uid) {
                        tx.expunge(uid);
                    }
                }
            }

            Ok(())
        })
    }
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

        // Expunge it in mb1, and call poll() to ensure it really gets deleted
        assert!(mb1
            .stateless()
            .message_scheme()
            .path_for_id(uid.0.get())
            .is_file());
        mb1.expunge_all_deleted().unwrap();
        mb1.poll().unwrap();
        assert!(!mb1
            .stateless()
            .message_scheme()
            .path_for_id(uid.0.get())
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
}
