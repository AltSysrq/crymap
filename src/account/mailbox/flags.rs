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
use crate::account::mailbox_state::*;
use crate::account::model::*;
use crate::support::error::Error;

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
                ok: !request.loud,
                modified: SeqRange::new(),
            });
        }

        // We can intern the flags outside of the transaction safely, since
        // this is an idempotent operation, and even if we end up not modifying
        // any flags, it does not materially change the state.
        let flags: Vec<FlagId> = request
            .flags
            .iter()
            .map(|f| self.state.flag_id_mut(f.to_owned()))
            .collect();

        let (ret, valid) = self.change_transaction(|this, tx| {
            let mut modified = SeqRange::new();
            let mut valid_uids = Vec::new();
            let mut ok = true;

            for uid in request.ids.items() {
                if !this.state.is_assigned_uid(uid) {
                    // Per RFC 3501, section 6.4.8:
                    //
                    // > A non-existent unique identifier is ignored without
                    // > any error message generated. Thus, it is possible for
                    // > a UID > FETCH command to return an OK without any data
                    // > or a UID COPY or UID STORE to return an OK without
                    // > performing any operations.
                    continue;
                }

                let status = match this.state.message_status(uid) {
                    Some(status) => status,
                    None => {
                        // Return no error, instead returning NO error later
                        // See the docs of `StoreResponse.ok`
                        ok = false;
                        continue;
                    }
                };

                // RFC 7162 UNCHANGEDSINCE handling
                //
                // The RFC implies there is some special handling regarding
                if request
                    .unchanged_since
                    .map(|uc| uc < status.last_modified().raw().get())
                    .unwrap_or(false)
                {
                    // Per RFC 7162, we leave it up to the client whether they
                    // want to fetch the modified messages. (Though note that
                    // during concurrent modifications, the regular realtime
                    // change notifications will still happen and provide
                    // unsolicited FETCH responses anyway.)
                    modified.append(uid);
                    continue;
                }

                // This UID is valid enough to consider; queue it for FETCH if
                // loud
                valid_uids.push(uid);

                // Add flags not already set for FLAGS and +FLAGS, and remove
                // set flags for -FLAGS.
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

                // Remove extra set flags for FLAGS.
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

            Ok((
                StoreResponse {
                    ok: ok || !request.loud,
                    modified,
                },
                valid_uids,
            ))
        })?;

        if request.loud {
            for uid in valid {
                self.state.add_changed_flags_uid(uid);
            }
        }

        Ok(ret)
    }
}

#[cfg(test)]
mod test {
    use std::iter;

    use tempfile::TempDir;

    use super::super::test_prelude::*;
    use super::*;

    fn store_set_up() -> (Uid, StatefulMailbox, TempDir) {
        let setup = set_up();
        let (mut mb, _) = setup.stateless.select().unwrap();
        let uid = simple_append(mb.stateless());
        mb.poll().unwrap();
        (uid, mb, setup.root)
    }

    #[test]
    fn store_empty_mailbox_loud() {
        let setup = set_up();
        let (mut mb1, _) = setup.stateless.select().unwrap();
        let res = mb1
            .store(&StoreRequest {
                ids: &SeqRange::just(Uid::MIN),
                flags: &[Flag::Flagged],
                remove_listed: false,
                remove_unlisted: false,
                loud: true,
                unchanged_since: None,
            })
            .unwrap();
        assert!(!res.ok);

        mb1.poll().unwrap();
    }

    #[test]
    fn store_empty_mailbox_silent() {
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
        assert!(res.ok);

        mb1.poll().unwrap();
    }

    #[test]
    fn store_plus_flag_uncond_loud_success() {
        let (uid1, mut mb, _root) = store_set_up();
        let res = mb
            .store(&StoreRequest {
                ids: &SeqRange::just(uid1),
                flags: &[Flag::Flagged],
                remove_listed: false,
                remove_unlisted: false,
                loud: true,
                unchanged_since: None,
            })
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::new()
            },
            res
        );

        assert_eq!(vec![uid1], mb.mini_poll());
        let poll = mb.poll().unwrap();
        assert_eq!(Some(Modseq::new(uid1, Cid(1))), poll.max_modseq);
        assert!(poll.fetch.is_empty());

        assert!(mb.state.test_flag_o(&Flag::Flagged, uid1));
    }

    #[test]
    fn store_plus_flag_uncond_loud_noop() {
        let (uid1, mut mb, _root) = store_set_up();
        mb.store(&StoreRequest {
            ids: &SeqRange::just(uid1),
            flags: &[Flag::Flagged],
            remove_listed: false,
            remove_unlisted: false,
            loud: true,
            unchanged_since: None,
        })
        .unwrap();
        // Flush pending notifications
        mb.poll().unwrap();

        // Second operation does the same thing, so has no effect
        let res = mb
            .store(&StoreRequest {
                ids: &SeqRange::just(uid1),
                flags: &[Flag::Flagged],
                remove_listed: false,
                remove_unlisted: false,
                loud: true,
                unchanged_since: None,
            })
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::new()
            },
            res
        );

        // Due to it being loud, we get a fetch anyway
        assert_eq!(vec![uid1], mb.mini_poll());
        let poll = mb.poll().unwrap();
        // No spurious change inserted
        assert_eq!(Some(Modseq::new(uid1, Cid(1))), poll.max_modseq);
        assert!(poll.fetch.is_empty());

        assert!(mb.state.test_flag_o(&Flag::Flagged, uid1));
    }

    #[test]
    fn store_plus_flag_uncond_loud_nx() {
        let (uid1, mut mb, _root) = store_set_up();
        let res = mb
            .store(&StoreRequest {
                ids: &SeqRange::just(Uid::MAX),
                flags: &[Flag::Flagged],
                remove_listed: false,
                remove_unlisted: false,
                loud: true,
                unchanged_since: None,
            })
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::new()
            },
            res
        );

        assert!(mb.mini_poll().is_empty());
        let poll = mb.poll().unwrap();
        assert_eq!(Some(Modseq::new(uid1, Cid::GENESIS)), poll.max_modseq);
        assert!(poll.fetch.is_empty());

        assert!(!mb.state.test_flag_o(&Flag::Flagged, uid1));
    }

    #[test]
    fn store_plus_flag_uncond_loud_expunged() {
        let (uid1, mut mb, _root) = store_set_up();
        mb.vanquish(iter::once(uid1)).unwrap();
        // Don't poll -- we want uid1 to still be in the snapshot, but do
        // ensure we brought the change into memory
        assert_eq!(Some(Modseq::new(uid1, Cid(1))), mb.state.max_modseq());

        let res = mb
            .store(&StoreRequest {
                ids: &SeqRange::just(uid1),
                flags: &[Flag::Flagged],
                remove_listed: false,
                remove_unlisted: false,
                loud: true,
                unchanged_since: None,
            })
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: false,
                modified: SeqRange::new()
            },
            res
        );

        assert!(mb.mini_poll().is_empty());
        let poll = mb.poll().unwrap();
        // Ensure there was not a spurious transaction
        assert_eq!(Some(Modseq::new(uid1, Cid(1))), poll.max_modseq);
        assert!(poll.fetch.is_empty());
    }

    #[test]
    fn store_plus_flag_uncond_silent_success() {
        let (uid1, mut mb, _root) = store_set_up();
        let res = mb
            .store(&StoreRequest {
                ids: &SeqRange::just(uid1),
                flags: &[Flag::Flagged],
                remove_listed: false,
                remove_unlisted: false,
                loud: false,
                unchanged_since: None,
            })
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::new()
            },
            res
        );

        assert_eq!(vec![uid1], mb.mini_poll());
        let poll = mb.poll().unwrap();
        assert_eq!(Some(Modseq::new(uid1, Cid(1))), poll.max_modseq);
        assert!(poll.fetch.is_empty());

        assert!(mb.state.test_flag_o(&Flag::Flagged, uid1));
    }

    #[test]
    fn store_plus_flag_uncond_silent_noop() {
        let (uid1, mut mb, _root) = store_set_up();
        mb.store(&StoreRequest {
            ids: &SeqRange::just(uid1),
            flags: &[Flag::Flagged],
            remove_listed: false,
            remove_unlisted: false,
            loud: false,
            unchanged_since: None,
        })
        .unwrap();
        // Flush pending notifications
        mb.poll().unwrap();

        // Second operation does the same thing, so has no effect
        let res = mb
            .store(&StoreRequest {
                ids: &SeqRange::just(uid1),
                flags: &[Flag::Flagged],
                remove_listed: false,
                remove_unlisted: false,
                loud: false,
                unchanged_since: None,
            })
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::new()
            },
            res
        );

        // Due to it being silent, we get no change notification
        assert!(mb.mini_poll().is_empty());
        let poll = mb.poll().unwrap();
        // No spurious change inserted
        assert_eq!(Some(Modseq::new(uid1, Cid(1))), poll.max_modseq);
        assert!(poll.fetch.is_empty());

        assert!(mb.state.test_flag_o(&Flag::Flagged, uid1));
    }

    #[test]
    fn store_plus_flag_uncond_silent_nx() {
        let (uid1, mut mb, _root) = store_set_up();
        let res = mb
            .store(&StoreRequest {
                ids: &SeqRange::just(Uid::MAX),
                flags: &[Flag::Flagged],
                remove_listed: false,
                remove_unlisted: false,
                loud: false,
                unchanged_since: None,
            })
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::new()
            },
            res
        );

        assert!(mb.mini_poll().is_empty());
        let poll = mb.poll().unwrap();
        assert_eq!(Some(Modseq::new(uid1, Cid::GENESIS)), poll.max_modseq);
        assert!(poll.fetch.is_empty());

        assert!(!mb.state.test_flag_o(&Flag::Flagged, uid1));
    }

    #[test]
    fn store_plus_flag_uncond_silent_expunged() {
        let (uid1, mut mb, _root) = store_set_up();
        mb.vanquish(iter::once(uid1)).unwrap();
        // Don't poll -- we want uid1 to still be in the snapshot, but do
        // ensure we brought the change into memory
        assert_eq!(Some(Modseq::new(uid1, Cid(1))), mb.state.max_modseq());

        let res = mb
            .store(&StoreRequest {
                ids: &SeqRange::just(uid1),
                flags: &[Flag::Flagged],
                remove_listed: false,
                remove_unlisted: false,
                loud: false,
                unchanged_since: None,
            })
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::new()
            },
            res
        );

        assert!(mb.mini_poll().is_empty());
        let poll = mb.poll().unwrap();
        // Ensure there was not a spurious transaction
        assert_eq!(Some(Modseq::new(uid1, Cid(1))), poll.max_modseq);
        assert!(poll.fetch.is_empty());
    }

    // The nx, expunged, noop results cease to be interesting for other
    // combinations. The loud/silent distinction also does not depend on the
    // operation, so all tests below are silent.

    #[test]
    fn store_plus_flag_cond_silent_success() {
        let (uid1, mut mb, _root) = store_set_up();
        let uid2 = simple_append(mb.stateless());
        mb.poll().unwrap();

        // UNCHANGEDSINCE == last_modified
        let res = mb
            .store(&StoreRequest {
                ids: &SeqRange::just(uid1),
                flags: &[Flag::Flagged],
                remove_listed: false,
                remove_unlisted: false,
                loud: false,
                unchanged_since: Some(
                    Modseq::new(uid2, Cid::GENESIS).raw().get(),
                ),
            })
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::new()
            },
            res
        );

        assert_eq!(vec![uid1], mb.mini_poll());
        let poll = mb.poll().unwrap();
        assert_eq!(Some(Modseq::new(uid2, Cid(1))), poll.max_modseq);

        // UNCHANGEDSINCE > last_modified
        let res = mb
            .store(&StoreRequest {
                ids: &SeqRange::just(uid2),
                flags: &[Flag::Seen],
                remove_listed: false,
                remove_unlisted: false,
                loud: false,
                unchanged_since: Some(poll.max_modseq.unwrap().raw().get()),
            })
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::new()
            },
            res
        );

        assert_eq!(vec![uid2], mb.mini_poll());
        let poll = mb.poll().unwrap();
        assert_eq!(Some(Modseq::new(uid2, Cid(2))), poll.max_modseq);

        assert!(mb.state.test_flag_o(&Flag::Seen, uid2));
    }

    #[test]
    fn store_plus_flag_cond_silent_modified() {
        let (uid1, mut mb, _root) = store_set_up();

        let res = mb
            .store(&StoreRequest {
                ids: &SeqRange::just(uid1),
                flags: &[Flag::Flagged],
                remove_listed: false,
                remove_unlisted: false,
                loud: false,
                unchanged_since: None,
            })
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::new()
            },
            res
        );
        // Discard pending notifications
        mb.poll().unwrap();

        let res = mb
            .store(&StoreRequest {
                ids: &SeqRange::just(uid1),
                flags: &[Flag::Seen],
                remove_listed: false,
                remove_unlisted: false,
                loud: false,
                unchanged_since: Some(
                    Modseq::new(uid1, Cid::GENESIS).raw().get(),
                ),
            })
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::just(uid1)
            },
            res
        );

        // No unsolicited FETCH sent
        assert!(mb.mini_poll().is_empty());

        let poll = mb.poll().unwrap();
        // No transaction happened
        assert_eq!(Some(Modseq::new(uid1, Cid(1))), poll.max_modseq);

        // The flag didn't get set
        assert!(!mb.state.test_flag_o(&Flag::Seen, uid1));
    }

    #[test]
    fn store_plus_flag_cond_silent_modified_mixed() {
        let (uid1, mut mb, _root) = store_set_up();
        let uid2 = simple_append(mb.stateless());
        let uid3 = simple_append(mb.stateless());
        assert_eq!(
            Some(Modseq::new(uid3, Cid::GENESIS)),
            mb.poll().unwrap().max_modseq
        );

        let res = mb
            .store(&StoreRequest {
                ids: &SeqRange::just(uid2),
                flags: &[Flag::Flagged],
                remove_listed: false,
                remove_unlisted: false,
                loud: false,
                unchanged_since: None,
            })
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::new()
            },
            res
        );
        // Discard pending notifications
        assert_eq!(
            Some(Modseq::new(uid3, Cid(1))),
            mb.poll().unwrap().max_modseq
        );

        let res = mb
            .store(&StoreRequest {
                ids: &SeqRange::range(uid1, uid3),
                flags: &[Flag::Seen],
                remove_listed: false,
                remove_unlisted: false,
                loud: false,
                unchanged_since: Some(
                    Modseq::new(uid3, Cid::GENESIS).raw().get(),
                ),
            })
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::just(uid2)
            },
            res
        );

        // Only the two changed messages get unsolicited FETCH responses
        assert_eq!(vec![uid1, uid3], mb.mini_poll());

        mb.poll().unwrap();

        // The flag got set only on the messages that passed the UNCHANGEDSINCE
        // clause
        assert!(mb.state.test_flag_o(&Flag::Seen, uid1));
        assert!(!mb.state.test_flag_o(&Flag::Seen, uid2));
        assert!(mb.state.test_flag_o(&Flag::Seen, uid3));
    }

    #[test]
    fn store_plus_flag_cond_silent_modified_anachronous() {
        let (uid1, mut mb, _root) = store_set_up();
        let uid2 = simple_append(mb.stateless());
        mb.poll().unwrap();

        // Try to edit UID 2 with an UNCHANGEDSINCE before it was created.
        let res = mb
            .store(&StoreRequest {
                ids: &SeqRange::just(uid2),
                flags: &[Flag::Flagged],
                remove_listed: false,
                remove_unlisted: false,
                loud: false,
                unchanged_since: Some(
                    Modseq::new(uid1, Cid::GENESIS).raw().get(),
                ),
            })
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::just(uid2)
            },
            res
        );

        // No unsolicited FETCH since nothing happened
        assert!(mb.mini_poll().is_empty());

        mb.poll().unwrap();

        // No change was made
        assert!(!mb.state.test_flag_o(&Flag::Flagged, uid2));
    }

    #[test]
    fn store_plus_flag_cond_silent_doomed() {
        let (uid1, mut mb, _root) = store_set_up();

        // Try to edit UID 1 with an UNCHANGEDSINCE of 0, something that MUST
        // fail according to RFC 7162, Page 12, Example 6.
        let res = mb
            .store(&StoreRequest {
                ids: &SeqRange::just(uid1),
                flags: &[Flag::Flagged],
                remove_listed: false,
                remove_unlisted: false,
                loud: false,
                unchanged_since: Some(0),
            })
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::just(uid1)
            },
            res
        );

        // No unsolicited FETCH since nothing happened
        assert!(mb.mini_poll().is_empty());

        mb.poll().unwrap();

        // No change was made
        assert!(!mb.state.test_flag_o(&Flag::Flagged, uid1));
    }

    // UNCHANGEDSINCE handling doesn't depend on the operation either, so the
    // rest of the tests are unconditional (and silent success only as noted in
    // the earlier comment).

    #[test]
    fn store_minus_flag_uncond_silent_success() {
        let (uid1, mut mb, _root) = store_set_up();

        mb.store(&StoreRequest {
            ids: &SeqRange::just(uid1),
            flags: &[Flag::Flagged, Flag::Seen],
            remove_listed: false,
            remove_unlisted: false,
            loud: false,
            unchanged_since: None,
        })
        .unwrap();
        mb.poll().unwrap();

        let res = mb
            .store(&StoreRequest {
                ids: &SeqRange::just(uid1),
                flags: &[Flag::Flagged],
                remove_listed: true,
                remove_unlisted: false,
                loud: false,
                unchanged_since: None,
            })
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::new()
            },
            res
        );

        assert_eq!(vec![uid1], mb.mini_poll());

        // Only the \Flagged flag was removed
        assert!(mb.state.test_flag_o(&Flag::Seen, uid1));
        assert!(!mb.state.test_flag_o(&Flag::Flagged, uid1));
    }

    #[test]
    fn store_eq_flag_uncond_silent_success() {
        let (uid1, mut mb, _root) = store_set_up();

        mb.store(&StoreRequest {
            ids: &SeqRange::just(uid1),
            flags: &[Flag::Seen],
            remove_listed: false,
            remove_unlisted: false,
            loud: false,
            unchanged_since: None,
        })
        .unwrap();
        mb.poll().unwrap();

        let res = mb
            .store(&StoreRequest {
                ids: &SeqRange::just(uid1),
                flags: &[Flag::Flagged],
                remove_listed: false,
                remove_unlisted: true,
                loud: false,
                unchanged_since: None,
            })
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::new()
            },
            res
        );

        assert_eq!(vec![uid1], mb.mini_poll());

        // The \Flagged flag was added and the \Seen flag was removed
        assert!(!mb.state.test_flag_o(&Flag::Seen, uid1));
        assert!(mb.state.test_flag_o(&Flag::Flagged, uid1));
    }

    #[test]
    fn seqnum_store_cond_modified() {
        let (uid1, mut mb, _root) = store_set_up();
        let uid2 = simple_append(mb.stateless());
        let uid3 = simple_append(mb.stateless());
        mb.poll().unwrap();
        mb.vanquish(iter::once(uid1)).unwrap();
        assert_eq!(
            Some(Modseq::new(uid3, Cid(1))),
            mb.poll().unwrap().max_modseq
        );

        let res = mb
            .store(&StoreRequest {
                ids: &SeqRange::just(uid2),
                flags: &[Flag::Flagged],
                remove_listed: false,
                remove_unlisted: false,
                loud: false,
                unchanged_since: None,
            })
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::new()
            },
            res
        );
        // Discard pending notifications
        assert_eq!(
            Some(Modseq::new(uid3, Cid(2))),
            mb.poll().unwrap().max_modseq
        );

        let res = mb
            .seqnum_store(&StoreRequest {
                ids: &SeqRange::range(Seqnum::u(1), Seqnum::u(2)),
                flags: &[Flag::Seen],
                remove_listed: false,
                remove_unlisted: false,
                loud: false,
                unchanged_since: Some(Modseq::new(uid3, Cid(1)).raw().get()),
            })
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::just(Seqnum::u(1))
            },
            res
        );

        // Only the changed message get unsolicited FETCH responses
        assert_eq!(vec![uid3], mb.mini_poll());

        mb.poll().unwrap();

        // The flag got set only on the message that passed the UNCHANGEDSINCE
        // clause
        assert!(!mb.state.test_flag_o(&Flag::Seen, uid2));
        assert!(mb.state.test_flag_o(&Flag::Seen, uid3));
    }

    #[test]
    fn store_rejected_when_read_only() {
        let (uid1, mut mb, _root) = store_set_up();
        mb.s.read_only = true;

        assert!(matches!(
            mb.store(&StoreRequest {
                ids: &SeqRange::just(uid1),
                flags: &[Flag::Seen],
                remove_listed: false,
                remove_unlisted: false,
                loud: false,
                unchanged_since: None,
            }),
            Err(Error::MailboxReadOnly)
        ));
    }

    #[test]
    fn seqnum_store_bad_seqnum() {
        let (_, mut mb, _root) = store_set_up();
        assert!(matches!(
            mb.seqnum_store(&StoreRequest {
                ids: &SeqRange::range(Seqnum::u(1), Seqnum::u(2)),
                flags: &[Flag::Seen],
                remove_listed: false,
                remove_unlisted: false,
                loud: false,
                unchanged_since: None,
            }),
            Err(Error::NxMessage)
        ));
    }
}
