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

use super::super::storage;
use super::defs::*;
use crate::{account::model::*, support::error::Error};

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
    /// snapshot and not the true message state.
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
}

// TODO Adapt tests from v1/mailbox/expunge.rs
