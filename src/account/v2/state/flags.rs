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
use crate::{
    account::model::*,
    support::{error::Error, small_bitset::SmallBitset},
};

impl Account {
    /// Perform a `STORE` operation.
    pub fn seqnum_store(
        &mut self,
        mailbox: &mut Mailbox,
        request: &StoreRequest<'_, Seqnum>,
    ) -> Result<StoreResponse<Seqnum>, Error> {
        let ids = mailbox.seqnum_range_to_indices(request.ids, true)?;
        let request = StoreRequest {
            ids: &ids,
            flags: request.flags,
            remove_listed: request.remove_listed,
            remove_unlisted: request.remove_unlisted,
            loud: request.loud,
            unchanged_since: request.unchanged_since,
        };
        let resp = self.store_impl(mailbox, request, true)?;

        Ok(StoreResponse {
            ok: resp.ok,
            modified: mailbox
                .uid_range_to_seqnum(&resp.modified, true)
                .unwrap(),
        })
    }

    /// Perform a `UID STORE` operation.
    pub fn store(
        &mut self,
        mailbox: &mut Mailbox,
        request: &StoreRequest<'_, Uid>,
    ) -> Result<StoreResponse<Uid>, Error> {
        // Per RFC 3501, section 6.4.8:
        //
        // > A non-existent unique identifier is ignored without
        // > any error message generated. Thus, it is possible for
        // > a UID FETCH command to return an OK without any data
        // > or a UID COPY or UID STORE to return an OK without
        // > performing any operations.
        let ids = mailbox.uid_range_to_indices(request.ids, true)?;
        let request = StoreRequest {
            ids: &ids,
            flags: request.flags,
            remove_listed: request.remove_listed,
            remove_unlisted: request.remove_unlisted,
            loud: request.loud,
            unchanged_since: request.unchanged_since,
        };

        self.store_impl(mailbox, request, false)
    }

    /// Perform either kind of `STORE` request, using IDs already turned into
    /// indices.
    ///
    /// The response uses UIDs to name messages which were modified after
    /// `unchanged_since`, since any sensible client will be using UIDs for
    /// such operations. For clients making insensible requests, the UIDs must
    /// be converted.
    ///
    /// `pretend_nonexistent_messages_do_exist` controls whether special
    /// handling should occur for unconditional stores to messages that have
    /// been expunged outside the snapshot by directly mutating the messages
    /// within the snapshot. This needs to be `true` for seqnum `STORE` since
    /// we can't report those expunges to the client, but is not required for
    /// `UID STORE` since the messages will just be reported as expunged after
    /// polling.
    fn store_impl(
        &mut self,
        mailbox: &mut Mailbox,
        request: StoreRequest<u32>,
        pretend_nonexistent_messages_do_exist: bool,
    ) -> Result<StoreResponse<Uid>, Error> {
        mailbox.require_writable()?;

        let mut flags = SmallBitset::new();
        for flag in request.flags {
            flags.insert(self.metadb.intern_flag(flag)?.0);
        }

        let target_ix_uids = request
            .ids
            .items((mailbox.messages.len().saturating_sub(1)) as u32)
            .map(|ix| (ix as usize, mailbox.messages[ix as usize].uid))
            .collect::<Vec<_>>();

        let db_results = self.metadb.modify_mailbox_message_flags(
            mailbox.id,
            &flags,
            request.remove_listed,
            request.remove_unlisted,
            request.unchanged_since.unwrap_or(Modseq::MAX),
            &mut target_ix_uids.iter().map(|&(_, uid)| uid),
        )?;

        let mut successful_uids = target_ix_uids
            .iter()
            .copied()
            .zip(&db_results)
            .filter(|&(_, &r)| storage::StoreResult::Modified == r)
            .map(|((_, uid), _)| uid)
            .collect::<Vec<_>>();

        let mut rejected_uids = SeqRange::<Uid>::new();
        if request.unchanged_since.is_some() {
            // The messages modified since `unchanged_since` are those the
            // database did not update but where the request was not a no-op.
            for uid in target_ix_uids
                .iter()
                .copied()
                .zip(&db_results)
                .filter(|(_, &r)| {
                    storage::StoreResult::PreconditionsFailed == r
                })
                .map(|((_, uid), _)| uid)
            {
                // Per RFC 7162, we leave it up to the client whether they want
                // to fetch the modified messages and so don't add this to the
                // list of UIDs to implicitly fetch. (Though note that during
                // concurrent modifications, the regular realtime change
                // notifications will still happen and provide unsolicited
                // FETCH responses anyway.)
                rejected_uids.append(uid);
            }
        } else if pretend_nonexistent_messages_do_exist {
            // We don't report any rejected UIDs back to the client. However,
            // we do need to write back to our snapshot, inline, the effect
            // that should have happened for any message the database rejected
            // to preserve the illusion that any expunged messages actually
            // still exist.
            for (index, uid) in target_ix_uids
                .iter()
                .copied()
                .zip(&db_results)
                .filter(|&(_, &r)| {
                    storage::StoreResult::PreconditionsFailed == r
                })
                .map(|(a, _)| a)
            {
                let message = &mut mailbox.messages[index];
                let old_flags = message.flags.clone();

                // A peculiarity of this update is that the message doesn't get
                // a new modseq, because there is no modseq that we can
                // sensibly assign the message. In theory, the database layer
                // could generate a modseq even if it updates no messages
                // itself, which we could then use here, but then we'd need
                // extra bookkeeping to avoid making it the
                // `max_message_modseq`.
                //
                // `CONDSTORE` clients using seqnum `STORE` are pathological
                // anyway, and leaving the modseq frozen in time before the
                // expunge modseq could actually be better for compatibility.
                // (This is all speculation, as the author has never seen a
                // `CONDSTORE`-aware client use seqnum `STORE`.)
                apply_flags(
                    &mut message.flags,
                    &flags,
                    request.remove_listed,
                    request.remove_unlisted,
                );

                if old_flags != message.flags {
                    successful_uids.push(uid);
                }
            }
        }

        if request.loud {
            mailbox
                .changed_flags_uids
                .extend(target_ix_uids.iter().map(|&(_, uid)| uid));
        } else {
            mailbox
                .changed_flags_uids
                .extend_from_slice(&successful_uids);
        }

        Ok(StoreResponse {
            ok: !request.loud || !request.ids.is_empty(),
            modified: rejected_uids,
        })
    }
}

fn apply_flags(
    dst: &mut SmallBitset,
    flags: &SmallBitset,
    remove_listed: bool,
    remove_unlisted: bool,
) {
    if remove_listed {
        dst.remove_all(flags);
    } else {
        dst.add_all(flags);
    }
    if remove_unlisted {
        dst.remove_complement(flags);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn store_empty_mailbox_loud() {
        let mut fixture = TestFixture::new();
        let (mut mb1, _) = fixture.account.select("INBOX", true, None).unwrap();
        let res = fixture
            .account
            .store(
                &mut mb1,
                &StoreRequest {
                    ids: &SeqRange::just(Uid::MIN),
                    flags: &[Flag::Flagged],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: true,
                    unchanged_since: None,
                },
            )
            .unwrap();
        assert!(!res.ok);

        fixture.account.poll(&mut mb1).unwrap();
    }

    #[test]
    fn store_empty_mailbox_silent() {
        let mut fixture = TestFixture::new();
        let (mut mb1, _) = fixture.account.select("INBOX", true, None).unwrap();
        let res = fixture
            .account
            .store(
                &mut mb1,
                &StoreRequest {
                    ids: &SeqRange::just(Uid::MIN),
                    flags: &[Flag::Flagged],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                },
            )
            .unwrap();
        assert!(res.ok);

        fixture.account.poll(&mut mb1).unwrap();
    }

    #[test]
    fn store_plus_flag_uncond_loud_success() {
        let mut fixture = TestFixture::new();
        let uid1 = fixture.simple_append("INBOX");
        let (mut mb, _) = fixture.account.select("INBOX", true, None).unwrap();
        let res = fixture
            .account
            .store(
                &mut mb,
                &StoreRequest {
                    ids: &SeqRange::just(uid1),
                    flags: &[Flag::Flagged],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: true,
                    unchanged_since: None,
                },
            )
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::new()
            },
            res
        );

        let mini_poll = fixture.account.mini_poll(&mut mb).unwrap();
        assert_eq!(vec![uid1], mini_poll.fetch);
        let poll = fixture.account.poll(&mut mb).unwrap();
        assert_eq!(Some(Modseq::of(3)), poll.max_modseq,);
        assert!(poll.fetch.is_empty());

        assert!(mb.test_flag_o(&Flag::Flagged, uid1));
    }

    #[test]
    fn store_plus_flag_uncond_loud_noop() {
        let mut fixture = TestFixture::new();
        let uid1 = fixture.simple_append("INBOX");
        let (mut mb, _) = fixture.account.select("INBOX", true, None).unwrap();
        fixture
            .account
            .store(
                &mut mb,
                &StoreRequest {
                    ids: &SeqRange::just(uid1),
                    flags: &[Flag::Flagged],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: true,
                    unchanged_since: None,
                },
            )
            .unwrap();
        // Flush pending notifications
        fixture.account.poll(&mut mb).unwrap();

        // Second operation does the same thing, so has no effect
        let res = fixture
            .account
            .store(
                &mut mb,
                &StoreRequest {
                    ids: &SeqRange::just(uid1),
                    flags: &[Flag::Flagged],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: true,
                    unchanged_since: None,
                },
            )
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::new()
            },
            res
        );

        // Due to it being loud, we get a fetch anyway
        let mini_poll = fixture.account.mini_poll(&mut mb).unwrap();
        assert_eq!(
            MiniPollResponse {
                fetch: vec![uid1],
                divergent_modseq: None
            },
            mini_poll,
        );
        let poll = fixture.account.poll(&mut mb).unwrap();
        // No spurious change inserted
        assert_eq!(None, poll.max_modseq);
        assert!(poll.fetch.is_empty());

        assert!(mb.test_flag_o(&Flag::Flagged, uid1));
    }

    #[test]
    fn store_plus_flag_uncond_loud_nx() {
        let mut fixture = TestFixture::new();
        let uid1 = fixture.simple_append("INBOX");
        let (mut mb, _) = fixture.account.select("INBOX", true, None).unwrap();
        let res = fixture
            .account
            .store(
                &mut mb,
                &StoreRequest {
                    ids: &SeqRange::just(Uid::MAX),
                    flags: &[Flag::Flagged],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: true,
                    unchanged_since: None,
                },
            )
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: false,
                modified: SeqRange::new()
            },
            res
        );

        assert_eq!(
            MiniPollResponse {
                fetch: vec![],
                divergent_modseq: None,
            },
            fixture.account.mini_poll(&mut mb).unwrap(),
        );
        let poll = fixture.account.poll(&mut mb).unwrap();
        assert_eq!(None, poll.max_modseq);
        assert!(poll.fetch.is_empty());

        assert!(!mb.test_flag_o(&Flag::Flagged, uid1));
    }

    // TODO Adapt more unit tests.
    // Next is `store_plus_flag_uncond_loud_expunged`, but we can't do that
    // until we can expunge messages.
}
