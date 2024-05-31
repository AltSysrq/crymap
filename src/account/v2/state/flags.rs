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
        let ids = mailbox.seqnum_range_to_indices(request.ids, false)?;
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
                .filter(|&(_, &r)| {
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
            mailbox
                .changed_flags_uids
                .extend(rejected_uids.items(u32::MAX));
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
        let (mut mb1, _) = fixture.select("INBOX", true, None).unwrap();
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

        fixture.poll(&mut mb1).unwrap();
    }

    #[test]
    fn store_empty_mailbox_silent() {
        let mut fixture = TestFixture::new();
        let (mut mb1, _) = fixture.select("INBOX", true, None).unwrap();
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

        fixture.poll(&mut mb1).unwrap();
    }

    #[test]
    fn store_plus_flag_uncond_loud_success() {
        let mut fixture = TestFixture::new();
        let uid1 = fixture.simple_append("INBOX");
        let (mut mb, _) = fixture.select("INBOX", true, None).unwrap();
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
            res,
        );

        let mini_poll = fixture.mini_poll(&mut mb).unwrap();
        assert_eq!(vec![uid1], mini_poll.fetch);
        let poll = fixture.poll(&mut mb).unwrap();
        assert_eq!(Some(Modseq::of(3)), poll.max_modseq,);
        assert!(poll.fetch.is_empty());

        assert!(mb.test_flag_o(&Flag::Flagged, uid1));
    }

    #[test]
    fn store_plus_flag_uncond_loud_noop() {
        let mut fixture = TestFixture::new();
        let uid1 = fixture.simple_append("INBOX");
        let (mut mb, _) = fixture.select("INBOX", true, None).unwrap();
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
        fixture.poll(&mut mb).unwrap();

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
            res,
        );

        // Due to it being loud, we get a fetch anyway
        let mini_poll = fixture.mini_poll(&mut mb).unwrap();
        assert_eq!(
            MiniPollResponse {
                fetch: vec![uid1],
                divergent_modseq: None
            },
            mini_poll,
        );
        let poll = fixture.poll(&mut mb).unwrap();
        // No spurious change inserted
        assert_eq!(None, poll.max_modseq);
        assert!(poll.fetch.is_empty());

        assert!(mb.test_flag_o(&Flag::Flagged, uid1));
    }

    #[test]
    fn store_plus_flag_uncond_loud_nx() {
        let mut fixture = TestFixture::new();
        let uid1 = fixture.simple_append("INBOX");
        let (mut mb, _) = fixture.select("INBOX", true, None).unwrap();
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
            res,
        );

        assert_eq!(
            MiniPollResponse {
                fetch: vec![],
                divergent_modseq: None,
            },
            fixture.mini_poll(&mut mb).unwrap(),
        );
        let poll = fixture.poll(&mut mb).unwrap();
        assert_eq!(None, poll.max_modseq);
        assert!(poll.fetch.is_empty());

        assert!(!mb.test_flag_o(&Flag::Flagged, uid1));
    }

    #[test]
    fn store_plus_flag_uncond_loud_expunged() {
        let mut fixture = TestFixture::new();
        let uid1 = fixture.simple_append("INBOX");
        let (mut mb, _) = fixture.select("INBOX", true, None).unwrap();
        fixture
            .account
            .vanquish(&mb, &SeqRange::just(uid1))
            .unwrap();
        // Don't poll -- we want uid1 to still be in the snapshot.

        let res = fixture
            .account
            .seqnum_store(
                &mut mb,
                &StoreRequest {
                    ids: &SeqRange::just(Seqnum::from_index(0)),
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
            res,
        );

        // Due to snapshot isolation, the store still "works" and we do affect
        // the flag on the message.
        assert_eq!(
            MiniPollResponse {
                fetch: vec![uid1],
                divergent_modseq: Some(Modseq::of(2)),
            },
            fixture.mini_poll(&mut mb).unwrap(),
        );
        assert!(mb.test_flag_o(&Flag::Flagged, uid1));
        let poll = fixture.poll(&mut mb).unwrap();
        assert_eq!(Some(Modseq::of(3)), poll.max_modseq,);
        assert!(poll.fetch.is_empty());
    }

    #[test]
    fn store_plus_flag_uncond_silent_success() {
        let mut fixture = TestFixture::new();
        let uid1 = fixture.simple_append("INBOX");
        let (mut mb, _) = fixture.select("INBOX", true, None).unwrap();
        let res = fixture
            .account
            .store(
                &mut mb,
                &StoreRequest {
                    ids: &SeqRange::just(uid1),
                    flags: &[Flag::Flagged],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                },
            )
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::new()
            },
            res,
        );

        assert_eq!(vec![uid1], fixture.mini_poll(&mut mb).unwrap().fetch,);
        let poll = fixture.poll(&mut mb).unwrap();
        assert_eq!(Some(Modseq::of(3)), poll.max_modseq);
        assert!(poll.fetch.is_empty());

        assert!(mb.test_flag_o(&Flag::Flagged, uid1));
    }

    #[test]
    fn store_plus_flag_uncond_silent_noop() {
        let mut fixture = TestFixture::new();
        let uid1 = fixture.simple_append("INBOX");
        let (mut mb, _) = fixture.select("INBOX", true, None).unwrap();

        fixture
            .account
            .store(
                &mut mb,
                &StoreRequest {
                    ids: &SeqRange::just(uid1),
                    flags: &[Flag::Flagged],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                },
            )
            .unwrap();
        // Flush pending notifications
        fixture.poll(&mut mb).unwrap();

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
                    loud: false,
                    unchanged_since: None,
                },
            )
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::new()
            },
            res,
        );

        // Due to it being silent, we get no change notification
        assert!(fixture.mini_poll(&mut mb).unwrap().fetch.is_empty());
        let poll = fixture.poll(&mut mb).unwrap();
        // No spurious change inserted
        assert_eq!(None, poll.max_modseq);
        assert!(poll.fetch.is_empty());

        assert!(mb.test_flag_o(&Flag::Flagged, uid1));
    }

    #[test]
    fn store_plus_flag_uncond_silent_nx() {
        let mut fixture = TestFixture::new();
        let uid1 = fixture.simple_append("INBOX");
        let (mut mb, _) = fixture.select("INBOX", true, None).unwrap();

        let res = fixture
            .account
            .store(
                &mut mb,
                &StoreRequest {
                    ids: &SeqRange::just(Uid::MAX),
                    flags: &[Flag::Flagged],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                },
            )
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::new()
            },
            res,
        );

        assert!(fixture.mini_poll(&mut mb).unwrap().fetch.is_empty(),);
        let poll = fixture.poll(&mut mb).unwrap();
        assert_eq!(None, poll.max_modseq);
        assert!(poll.fetch.is_empty());

        assert!(!mb.test_flag_o(&Flag::Flagged, uid1));
    }

    #[test]
    fn store_plus_flag_uncond_silent_expunged() {
        let mut fixture = TestFixture::new();
        let uid1 = fixture.simple_append("INBOX");
        let (mut mb, _) = fixture.select("INBOX", true, None).unwrap();

        fixture
            .account
            .vanquish(&mb, &SeqRange::just(uid1))
            .unwrap();
        // Don't poll -- we want uid1 to still be in the snapshot.

        let res = fixture
            .account
            .seqnum_store(
                &mut mb,
                &StoreRequest {
                    ids: &SeqRange::just(Seqnum::from_index(0)),
                    flags: &[Flag::Flagged],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                },
            )
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::new()
            },
            res,
        );

        // Due to snapshot isolation, the store still "works" and we do affect
        // the flag on the message.
        assert_eq!(
            MiniPollResponse {
                fetch: vec![uid1],
                divergent_modseq: Some(Modseq::of(2)),
            },
            fixture.mini_poll(&mut mb).unwrap(),
        );
        assert!(mb.test_flag_o(&Flag::Flagged, uid1));
        let poll = fixture.poll(&mut mb).unwrap();
        assert_eq!(Some(Modseq::of(3)), poll.max_modseq);
        assert!(poll.fetch.is_empty());
    }

    // The nx, expunged, noop results cease to be interesting for other
    // combinations. The loud/silent distinction also does not depend on the
    // operation, so all tests below are silent.

    #[test]
    fn store_plus_flag_cond_silent_success() {
        let mut fixture = TestFixture::new();
        let uid1 = fixture.simple_append("INBOX");
        let uid2 = fixture.simple_append("INBOX");
        let (mut mb, _) = fixture.select("INBOX", true, None).unwrap();

        // UNCHANGEDSINCE == last_modified
        let res = fixture
            .account
            .store(
                &mut mb,
                &StoreRequest {
                    ids: &SeqRange::just(uid1),
                    flags: &[Flag::Flagged],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: Some(Modseq::of(3)),
                },
            )
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::new()
            },
            res,
        );

        assert_eq!(
            MiniPollResponse {
                fetch: vec![uid1],
                divergent_modseq: None,
            },
            fixture.mini_poll(&mut mb).unwrap(),
        );
        let poll = fixture.poll(&mut mb).unwrap();
        assert_eq!(Some(Modseq::of(4)), poll.max_modseq);
        assert!(mb.test_flag_o(&Flag::Flagged, uid1));

        // UNCHANGEDSINCE > last_modified
        let res = fixture
            .account
            .store(
                &mut mb,
                &StoreRequest {
                    ids: &SeqRange::just(uid2),
                    flags: &[Flag::Seen],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: poll.max_modseq,
                },
            )
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::new()
            },
            res,
        );

        assert_eq!(
            MiniPollResponse {
                fetch: vec![uid2],
                divergent_modseq: None,
            },
            fixture.mini_poll(&mut mb).unwrap(),
        );
        let poll = fixture.poll(&mut mb).unwrap();
        assert_eq!(Some(Modseq::of(5)), poll.max_modseq);
        assert!(mb.test_flag_o(&Flag::Seen, uid2));
    }

    #[test]
    fn store_plus_flag_cond_silent_modified() {
        let mut fixture = TestFixture::new();
        let uid1 = fixture.simple_append("INBOX");
        let (mut mb, _) = fixture.select("INBOX", true, None).unwrap();

        let res = fixture
            .account
            .store(
                &mut mb,
                &StoreRequest {
                    ids: &SeqRange::just(uid1),
                    flags: &[Flag::Flagged],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                },
            )
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::new()
            },
            res,
        );
        // Discard pending notifications
        fixture.poll(&mut mb).unwrap();

        let res = fixture
            .account
            .store(
                &mut mb,
                &StoreRequest {
                    ids: &SeqRange::just(uid1),
                    flags: &[Flag::Seen],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: Some(Modseq::of(2)),
                },
            )
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::just(uid1)
            },
            res,
        );

        // Unsolicited FETCH sent for the message that failed unchanged_since
        assert_eq!(
            MiniPollResponse {
                fetch: vec![uid1],
                divergent_modseq: None,
            },
            fixture.mini_poll(&mut mb).unwrap(),
        );

        let poll = fixture.poll(&mut mb).unwrap();
        // No transaction happened
        assert_eq!(None, poll.max_modseq);

        // The flag didn't get set
        assert!(!mb.test_flag_o(&Flag::Seen, uid1));
    }

    #[test]
    fn store_plus_flag_cond_silent_modified_mixed() {
        let mut fixture = TestFixture::new();
        let uid1 = fixture.simple_append("INBOX");
        let uid2 = fixture.simple_append("INBOX");
        let uid3 = fixture.simple_append("INBOX");
        let (mut mb, _) = fixture.select("INBOX", true, None).unwrap();
        assert_eq!(Modseq::of(4), mb.select_response().unwrap().max_modseq,);

        let res = fixture
            .account
            .store(
                &mut mb,
                &StoreRequest {
                    ids: &SeqRange::just(uid2),
                    flags: &[Flag::Flagged],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                },
            )
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::new()
            },
            res,
        );
        // Discard pending notifications
        assert_eq!(
            Some(Modseq::of(5)),
            fixture.poll(&mut mb).unwrap().max_modseq,
        );

        let res = fixture
            .account
            .store(
                &mut mb,
                &StoreRequest {
                    ids: &SeqRange::range(uid1, uid3),
                    flags: &[Flag::Seen],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: Some(Modseq::of(4)),
                },
            )
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::just(uid2)
            },
            res,
        );

        // The two changed messages and the one that failed unchanged_since get
        // unsolicited FETCH responses
        assert_eq!(
            MiniPollResponse {
                fetch: vec![uid1, uid2, uid3],
                divergent_modseq: None,
            },
            fixture.mini_poll(&mut mb).unwrap(),
        );

        fixture.poll(&mut mb).unwrap();

        // The flag got set only on the messages that passed the UNCHANGEDSINCE
        // clause
        assert!(mb.test_flag_o(&Flag::Seen, uid1));
        assert!(!mb.test_flag_o(&Flag::Seen, uid2));
        assert!(mb.test_flag_o(&Flag::Seen, uid3));
    }

    #[test]
    fn store_plus_flag_cond_silent_modified_anachronous() {
        let mut fixture = TestFixture::new();
        let _uid1 = fixture.simple_append("INBOX");
        let uid2 = fixture.simple_append("INBOX");
        let (mut mb, _) = fixture.select("INBOX", true, None).unwrap();

        // Try to edit UID 2 with an UNCHANGEDSINCE before it was created.
        let res = fixture
            .account
            .store(
                &mut mb,
                &StoreRequest {
                    ids: &SeqRange::just(uid2),
                    flags: &[Flag::Flagged],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: Some(Modseq::of(2)),
                },
            )
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::just(uid2)
            },
            res,
        );

        // Unsolicited FETCH sent for the message that failed unchanged_since
        assert_eq!(
            MiniPollResponse {
                fetch: vec![uid2],
                divergent_modseq: None,
            },
            fixture.mini_poll(&mut mb).unwrap(),
        );

        fixture.poll(&mut mb).unwrap();

        // No change was made
        assert!(!mb.test_flag_o(&Flag::Flagged, uid2));
    }

    #[test]
    fn store_plus_flag_cond_silent_doomed() {
        let mut fixture = TestFixture::new();
        let uid1 = fixture.simple_append("INBOX");
        let (mut mb, _) = fixture.select("INBOX", true, None).unwrap();

        // Try to edit UID 1 with an UNCHANGEDSINCE of 0, something that MUST
        // fail according to RFC 7162, Page 12, Example 6.
        let res = fixture
            .account
            .store(
                &mut mb,
                &StoreRequest {
                    ids: &SeqRange::just(uid1),
                    flags: &[Flag::Flagged],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: Some(Modseq::of(0)),
                },
            )
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::just(uid1)
            },
            res,
        );

        // Unsolicited FETCH for 1 since it failed unchanged_since
        assert_eq!(
            MiniPollResponse {
                fetch: vec![uid1],
                divergent_modseq: None,
            },
            fixture.mini_poll(&mut mb).unwrap(),
        );

        fixture.poll(&mut mb).unwrap();

        // No change was made
        assert!(!mb.test_flag_o(&Flag::Flagged, uid1));
    }

    // UNCHANGEDSINCE handling doesn't depend on the operation either, so the
    // rest of the tests are unconditional (and silent success only as noted in
    // the earlier comment).

    #[test]
    fn store_minus_flag_uncond_silent_success() {
        let mut fixture = TestFixture::new();
        let uid1 = fixture.simple_append("INBOX");
        let (mut mb, _) = fixture.select("INBOX", true, None).unwrap();

        fixture
            .account
            .store(
                &mut mb,
                &StoreRequest {
                    ids: &SeqRange::just(uid1),
                    flags: &[Flag::Flagged, Flag::Seen],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                },
            )
            .unwrap();
        fixture.poll(&mut mb).unwrap();

        let res = fixture
            .account
            .store(
                &mut mb,
                &StoreRequest {
                    ids: &SeqRange::just(uid1),
                    flags: &[Flag::Flagged],
                    remove_listed: true,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                },
            )
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::new()
            },
            res,
        );

        assert_eq!(
            MiniPollResponse {
                fetch: vec![uid1],
                divergent_modseq: None,
            },
            fixture.mini_poll(&mut mb).unwrap(),
        );

        // Only the \Flagged flag was removed
        assert!(mb.test_flag_o(&Flag::Seen, uid1));
        assert!(!mb.test_flag_o(&Flag::Flagged, uid1));
    }

    #[test]
    fn store_eq_flag_uncond_silent_success() {
        let mut fixture = TestFixture::new();
        let uid1 = fixture.simple_append("INBOX");
        let (mut mb, _) = fixture.select("INBOX", true, None).unwrap();

        fixture
            .account
            .store(
                &mut mb,
                &StoreRequest {
                    ids: &SeqRange::just(uid1),
                    flags: &[Flag::Seen],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                },
            )
            .unwrap();
        fixture.poll(&mut mb).unwrap();

        let res = fixture
            .account
            .store(
                &mut mb,
                &StoreRequest {
                    ids: &SeqRange::just(uid1),
                    flags: &[Flag::Flagged],
                    remove_listed: false,
                    remove_unlisted: true,
                    loud: false,
                    unchanged_since: None,
                },
            )
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::new()
            },
            res,
        );

        assert_eq!(
            MiniPollResponse {
                fetch: vec![uid1],
                divergent_modseq: None,
            },
            fixture.mini_poll(&mut mb).unwrap(),
        );

        // The \Flagged flag was added and the \Seen flag was removed
        assert!(!mb.test_flag_o(&Flag::Seen, uid1));
        assert!(mb.test_flag_o(&Flag::Flagged, uid1));
    }

    #[test]
    fn seqnum_store_cond_modified() {
        let mut fixture = TestFixture::new();
        let uid1 = fixture.simple_append("INBOX");
        let uid2 = fixture.simple_append("INBOX");
        let uid3 = fixture.simple_append("INBOX");
        let (mut mb, _) = fixture.select("INBOX", true, None).unwrap();
        fixture
            .account
            .vanquish(&mb, &SeqRange::just(uid1))
            .unwrap();
        assert_eq!(
            Some(Modseq::of(5)),
            fixture.poll(&mut mb).unwrap().max_modseq,
        );

        let res = fixture
            .account
            .store(
                &mut mb,
                &StoreRequest {
                    ids: &SeqRange::just(uid2),
                    flags: &[Flag::Flagged],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                },
            )
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::new()
            },
            res,
        );
        // Discard pending notifications
        assert_eq!(
            Some(Modseq::of(6)),
            fixture.poll(&mut mb).unwrap().max_modseq,
        );

        let res = fixture
            .account
            .seqnum_store(
                &mut mb,
                &StoreRequest {
                    ids: &SeqRange::range(Seqnum::u(1), Seqnum::u(2)),
                    flags: &[Flag::Seen],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: Some(Modseq::of(5)),
                },
            )
            .unwrap();
        assert_eq!(
            StoreResponse {
                ok: true,
                modified: SeqRange::just(Seqnum::u(1)),
            },
            res,
        );

        // The changed message and the one that failed unchanged_since get
        // unsolicited FETCH responses
        assert_eq!(
            MiniPollResponse {
                fetch: vec![uid2, uid3],
                divergent_modseq: None,
            },
            fixture.mini_poll(&mut mb).unwrap(),
        );

        fixture.poll(&mut mb).unwrap();

        // The flag got set only on the message that passed the UNCHANGEDSINCE
        // clause
        assert!(!mb.test_flag_o(&Flag::Seen, uid2));
        assert!(mb.test_flag_o(&Flag::Seen, uid3));
    }

    #[test]
    fn store_rejected_when_read_only() {
        let mut fixture = TestFixture::new();
        let uid1 = fixture.simple_append("INBOX");
        let (mut mb, _) = fixture.select("INBOX", false, None).unwrap();

        assert_matches!(
            Err(Error::MailboxReadOnly),
            fixture.store(
                &mut mb,
                &StoreRequest {
                    ids: &SeqRange::just(uid1),
                    flags: &[Flag::Seen],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                }
            ),
        );
    }

    #[test]
    fn seqnum_store_bad_seqnum() {
        let mut fixture = TestFixture::new();
        let _uid1 = fixture.simple_append("INBOX");
        let (mut mb, _) = fixture.select("INBOX", true, None).unwrap();
        assert_matches!(
            Err(Error::NxMessage),
            fixture.seqnum_store(
                &mut mb,
                &StoreRequest {
                    ids: &SeqRange::range(Seqnum::u(1), Seqnum::u(2)),
                    flags: &[Flag::Seen],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                }
            ),
        );
    }
}
