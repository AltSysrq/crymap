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

use log::warn;

use super::defs::*;
use crate::support::error::Error;
use crate::userbox::mailbox_state::*;
use crate::userbox::model::*;

impl StatelessMailbox {
    /// Blindly set and clear the given flags on the given message.
    ///
    /// The caller must already know that `uid` refers to an allocated message.
    ///
    /// On success, returns the CID of the change, or `None` if there were not
    /// actually any changes to make.
    pub(super) fn set_flags_blind(
        &self,
        uid: Uid,
        flags: impl IntoIterator<Item = (bool, Flag)>,
    ) -> Result<Option<Cid>, Error> {
        self.not_read_only()?;

        let mut tx = StateTransaction::new_unordered(uid);
        for (add, flag) in flags {
            if add {
                tx.add_flag(uid, flag);
            } else {
                tx.rm_flag(uid, flag);
            }
        }

        if tx.is_empty() {
            return Ok(None);
        }

        let buffer_file = self.write_state_file(&tx)?;
        let scheme = self.change_scheme();
        for _ in 0..1000 {
            let next_cid = Cid(scheme.first_unallocated_id());
            if next_cid > Cid::MAX {
                return Err(Error::MailboxFull);
            }

            if scheme.emplace(buffer_file.path(), next_cid.0)? {
                return Ok(Some(next_cid));
            }
        }

        Err(Error::GaveUpInsertion)
    }

    /// Try to add all the given flags to `uid`.
    ///
    /// On error, the error is logged.
    pub(super) fn propagate_flags_best_effort(
        &self,
        uid: Uid,
        flags: impl IntoIterator<Item = Flag>,
    ) {
        if let Err(e) =
            self.set_flags_blind(uid, flags.into_iter().map(|f| (true, f)))
        {
            // If APPEND/COPY/MOVE returns an error, the call must have had no
            // effect, so we can't return an error to the client here since we
            // already emplaced the new message. Transferring the flags is only
            // a SHOULD, however, so we're fine to just log the error and carry
            // on if anything failed.
            warn!(
                "{} Failed to set flags on {}: {}",
                self.log_prefix,
                uid.0.get(),
                e
            );
        }
    }
}

impl StatefulMailbox {
    /// Perform a `STORE` operation.
    pub fn seqnum_store(
        &mut self,
        request: &StoreRequest<'_, Seqnum>,
    ) -> Result<StoreResponse<Seqnum>, Error> {
        let ids = self.state.seqnum_range_to_uid(request.ids, false)?;
        self.store(&StoreRequest {
            ids: &ids,
            flags: request.flags,
            remove_listed: request.remove_listed,
            remove_unlisted: request.remove_unlisted,
            loud: request.loud,
            unchanged_since: request.unchanged_since,
        })
        .map(|resp| StoreResponse {
            ok: resp.ok,
            modified: self
                .state
                .uid_range_to_seqnum(&resp.modified, true)
                .unwrap(),
        })
    }

    /// Perform a `UID STORE` operation.
    pub fn store(
        &mut self,
        request: &StoreRequest<'_, Uid>,
    ) -> Result<StoreResponse<Uid>, Error> {
        if self.s.read_only {
            return Err(Error::MailboxReadOnly);
        }

        // Can't start a transaction if no messages have ever existed. And the
        // result is always the same if there are no messages at all.
        if 0 == self.state.num_messages() {
            return Ok(StoreResponse {
                ok: false,
                modified: SeqRange::new(),
            });
        }

        let flags: Vec<FlagId> = request
            .flags
            .iter()
            .map(|f| self.state.flag_id_mut(f.to_owned()))
            .collect();

        let ret = self.change_transaction(|this, tx| {
            let mut modified = SeqRange::new();
            let mut ok = true;

            for uid in request.ids.items() {
                if !this.state.is_assigned_uid(uid) {
                    return Err(Error::NxMessage);
                }

                let status = match this.state.message_status(uid) {
                    Some(status) => status,
                    None => {
                        // RFC 7162 shows an example of a STORE to an expunged
                        // UID as returning NO but otherwise succeeding.
                        ok = false;
                        continue;
                    }
                };

                if request
                    .unchanged_since
                    .map(|uc| uc < status.last_modified())
                    .unwrap_or(false)
                {
                    modified.append(uid);
                    continue;
                }

                for &flag in &flags {
                    if request.remove_listed == status.test_flag(flag) {
                        if let Some(flag_obj) = this.state.flag(flag) {
                            if request.remove_listed {
                                tx.rm_flag(uid, flag_obj.to_owned());
                            } else {
                                tx.add_flag(uid, flag_obj.to_owned());
                            }
                        }
                    }
                }

                if request.remove_unlisted {
                    for flag in status.flags() {
                        if !flags.contains(&flag) {
                            if let Some(flag_obj) = this.state.flag(flag) {
                                tx.rm_flag(uid, flag_obj.to_owned());
                            }
                        }
                    }
                }
            }

            Ok(StoreResponse { ok, modified })
        })?;

        if request.loud {
            for uid in request.ids.items() {
                self.state.add_changed_flags_uid(uid);
            }
        }

        Ok(ret)
    }
}

#[cfg(test)]
mod test {
    use super::super::test_prelude::*;
    use super::*;

    #[test]
    fn store_empty_mailbox() {
        let setup = set_up();
        let (mut mb1, _) = setup.stateless.select().unwrap();
        let res = mb1
            .store(&StoreRequest {
                ids: &SeqRange::just(Uid::MIN),
                flags: &[Flag::Flagged],
                remove_listed: false,
                remove_unlisted: false,
                loud: false,
                unchanged_since: None,
            })
            .unwrap();
        assert!(!res.ok);

        mb1.poll().unwrap();
    }
}
