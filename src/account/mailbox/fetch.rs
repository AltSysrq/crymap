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

use std::collections::HashSet;
use std::io::BufRead;
use std::sync::Arc;

use rayon::prelude::*;

use super::defs::*;
use crate::account::mailbox_state::*;
use crate::account::model::*;
use crate::mime::fetch::multi::*;
use crate::mime::grovel::{grovel, MessageAccessor};
use crate::support::error::Error;

pub struct MailboxMessageAccessor<'a> {
    mailbox: &'a StatefulMailbox,
    uid: Uid,
    message_status: &'a MessageStatus,
}

impl<'a> MessageAccessor for MailboxMessageAccessor<'a> {
    type Reader = Box<dyn BufRead + 'a>;

    fn uid(&self) -> Uid {
        self.uid
    }

    fn last_modified(&self) -> Modseq {
        self.message_status.last_modified()
    }

    fn is_recent(&self) -> bool {
        self.message_status.is_recent()
    }

    fn flags(&self) -> Vec<Flag> {
        self.message_status
            .flags()
            .filter_map(|fid| self.mailbox.state.flag(fid))
            .cloned()
            .collect()
    }

    fn open(&self) -> Result<(MessageMetadata, Self::Reader), Error> {
        self.mailbox.s.open_message(self.uid)
    }
}

impl StatefulMailbox {
    /// Create an accessor that can be passed to `grovel` to access the message
    /// identified by `uid`.
    ///
    /// This does not check that `uid` is in the currently addressable set.
    ///
    /// This fails fast if `uid` is not currently known to exist, but note that
    /// `grovel` could also fail with `ExpungedMessage` if another process
    /// expunges the underlying file before it is accessed.
    pub fn access_message(
        &self,
        uid: Uid,
    ) -> Result<MailboxMessageAccessor<'_>, Error> {
        Ok(MailboxMessageAccessor {
            mailbox: self,
            uid,
            message_status: self
                .state
                .message_status(uid)
                .ok_or_else(|| self.state.missing_uid_error(uid))?,
        })
    }

    /// The `FETCH` command.
    pub fn seqnum_fetch(
        &mut self,
        request: FetchRequest<Seqnum>,
    ) -> Result<FetchResponse, Error> {
        let request = FetchRequest {
            ids: self.state.seqnum_range_to_uid(&request.ids, false)?,
            uid: request.uid,
            flags: request.flags,
            rfc822size: request.rfc822size,
            internal_date: request.internal_date,
            envelope: request.envelope,
            bodystructure: request.bodystructure,
            sections: request.sections,
            modseq: request.modseq,
            changed_since: request.changed_since,
            collect_vanished: request.collect_vanished,
        };
        self.fetch(&request)
    }

    /// The `UID FETCH` command.
    pub fn fetch(
        &mut self,
        request: &FetchRequest<Uid>,
    ) -> Result<FetchResponse, Error> {
        let mut response = FetchResponse::default();

        let precise_expunged = if request.collect_vanished {
            request
                .changed_since
                .and_then(|since| self.state.uids_expunged_since(since))
                .map(|it| it.collect::<HashSet<Uid>>())
        } else {
            None
        };

        let mut fetched: Vec<(Uid, Result<SingleFetchResponse, Error>)> =
            request
                .ids
                .par_items(self.state.max_uid_val())
                .map(|uid| {
                    (uid, self.fetch_single(request, uid, &precise_expunged))
                })
                .collect();

        fetched.sort_unstable_by_key(|&(uid, _)| uid);

        let mut need_flags_response = false;

        for (uid, result) in fetched {
            let result = result?;

            match result {
                SingleFetchResponse::Fetched(seqnum, fetched) => {
                    // See if we're returning a flag the client hasn't seen
                    // yet. If so, we'll need to send a FLAGS response first.
                    if !need_flags_response && request.flags {
                        'outer: for item in &fetched {
                            if let &FetchedItem::Flags(ref flags) = item {
                                for flag in &flags.flags {
                                    if !self.client_known_flags.contains(flag) {
                                        need_flags_response = true;
                                        break 'outer;
                                    }
                                }
                            }
                        }
                    }

                    response.fetched.push((seqnum, fetched));
                }
                SingleFetchResponse::NotModified => continue,
                SingleFetchResponse::SilentExpunge => continue,
                SingleFetchResponse::VanishedEarlier => {
                    response.vanished.append(uid)
                }
                SingleFetchResponse::UnexpectedExpunge => {
                    let r = if self.fetch_loopbreaker.insert(uid) {
                        FetchResponseKind::No
                    } else {
                        FetchResponseKind::Bye
                    };

                    response.kind = response.kind.max(r);
                }
            }
        }

        if need_flags_response {
            response.flags = self.flags_response();
        }

        Ok(response)
    }

    fn fetch_single(
        &self,
        request: &FetchRequest<Uid>,
        uid: Uid,
        precise_expunged: &Option<HashSet<Uid>>,
    ) -> Result<SingleFetchResponse, Error> {
        let seqnum = match self.state.uid_to_seqnum(uid) {
            Ok(s) => s,
            Err(Error::ExpungedMessage) => {
                if request.collect_vanished
                    && precise_expunged
                        .as_ref()
                        .map(|pe| pe.contains(&uid))
                        .unwrap_or(true)
                {
                    return Ok(SingleFetchResponse::VanishedEarlier);
                } else {
                    // If the client didn't request collect_vanished, we
                    // silently drop requests for unaddressable UIDs.
                    return Ok(SingleFetchResponse::SilentExpunge);
                }
            }
            Err(Error::NxMessage) =>
            // Similar to the above, silently drop UIDs outside the
            // addressable range.
            {
                return Ok(SingleFetchResponse::SilentExpunge)
            }
            Err(e) => return Err(e),
        };

        let result = self.access_message(uid).and_then(|accessor| {
            if request
                .changed_since
                .map(|since| accessor.message_status.last_modified() <= since)
                .unwrap_or(false)
            {
                Ok(SingleFetchResponse::NotModified)
            } else {
                let mut fetcher = MultiFetcher::new();
                if request.uid {
                    fetcher.add_uid();
                }
                if request.modseq {
                    fetcher.add_modseq();
                }
                if request.flags {
                    fetcher.add_flags();
                }
                if request.rfc822size {
                    fetcher.add_rfc822size();
                }
                if request.internal_date {
                    fetcher.add_internal_date();
                }
                if request.envelope {
                    fetcher.add_envelope();
                }
                if request.bodystructure {
                    fetcher.add_body_structure();
                }
                for section in &request.sections {
                    fetcher.add_section(section.to_owned().fetcher(
                        Box::new(|v| v),
                        Arc::clone(&self.s.common_paths),
                    ));
                }

                let fetched = grovel(&accessor, fetcher)?;
                Ok(SingleFetchResponse::Fetched(seqnum, fetched))
            }
        });

        if let &Err(Error::ExpungedMessage) = &result {
            if request.collect_vanished {
                // If the client requested collect_vanished and we got here,
                // that means the expunge took place later than the latest
                // Modseq we currently know about, so always treat as
                // VanishedEarlier.
                return Ok(SingleFetchResponse::VanishedEarlier);
            } else {
                // Otherwise, dive into the quagmire that is FetchResponseKind.
                return Ok(SingleFetchResponse::UnexpectedExpunge);
            }
        }

        result
    }
}

#[derive(Debug)]
enum SingleFetchResponse {
    Fetched(Seqnum, Vec<FetchedItem>),
    NotModified,
    VanishedEarlier,
    SilentExpunge,
    UnexpectedExpunge,
}

#[cfg(test)]
mod test {
    use std::iter;

    use tempfile::TempDir;

    use super::super::test_prelude::*;
    use super::*;
    use crate::mime::fetch::section;
    use crate::test_data::*;

    struct FetchSetup {
        root: TempDir,
        mb1: StatefulMailbox,
        mb2: StatefulMailbox,
        uids: Vec<Uid>,
    }

    fn set_up_fetch() -> FetchSetup {
        let setup = set_up();
        let uids = ENRON_SMALL_MULTIPARTS
            .iter()
            .map(|data| simple_append_data(&setup.stateless, data))
            .collect::<Vec<_>>();

        let (mb1, _) = setup.stateless.clone().select().unwrap();
        let (mb2, _) = setup.stateless.select().unwrap();

        FetchSetup {
            root: setup.root,
            mb1,
            mb2,
            uids,
        }
    }

    #[test]
    fn fetch_all_the_things() {
        let mut setup = set_up_fetch();
        let response = setup
            .mb1
            .fetch(&FetchRequest {
                ids: SeqRange::range(
                    *setup.uids.first().unwrap(),
                    *setup.uids.last().unwrap(),
                ),
                uid: true,
                flags: true,
                rfc822size: true,
                internal_date: true,
                envelope: true,
                bodystructure: true,
                sections: vec![section::BodySection::default()],
                modseq: true,
                changed_since: None,
                collect_vanished: false,
            })
            .unwrap();

        assert_eq!(FetchResponseKind::Ok, response.kind);
        assert!(response.flags.is_empty());
        assert!(response.vanished.is_empty());
        assert_eq!(setup.uids.len(), response.fetched.len());

        for (_, fetched) in response.fetched {
            let mut has_uid = false;
            let mut has_flags = false;
            let mut has_rfc822size = false;
            let mut has_internal_date = false;
            let mut has_envelope = false;
            let mut has_bodystructure = false;
            let mut has_section = false;
            let mut has_modseq = false;

            for part in fetched {
                match part {
                    FetchedItem::Uid(_) => has_uid = true,
                    FetchedItem::Flags(_) => has_flags = true,
                    FetchedItem::Rfc822Size(_) => has_rfc822size = true,
                    FetchedItem::InternalDate(_) => has_internal_date = true,
                    FetchedItem::Envelope(_) => has_envelope = true,
                    FetchedItem::BodyStructure(_) => has_bodystructure = true,
                    FetchedItem::BodySection((_, Ok(_))) => has_section = true,
                    FetchedItem::Modseq(_) => has_modseq = true,
                    part => panic!("Unexpected part: {:?}", part),
                }
            }

            assert!(has_uid);
            assert!(has_flags);
            assert!(has_rfc822size);
            assert!(has_internal_date);
            assert!(has_envelope);
            assert!(has_bodystructure);
            assert!(has_section);
            assert!(has_modseq);
        }
    }

    #[test]
    fn fetches_correct_data() {
        let mut setup = set_up_fetch();

        // Make a hole between UIDs 1 and 3
        setup.mb1.vanquish(iter::once(setup.uids[1])).unwrap();
        setup.mb1.poll().unwrap();

        let mut seq = SeqRange::new();
        seq.insert(setup.uids[0], setup.uids[0]);
        seq.insert(setup.uids[2], setup.uids[2]);

        let response = setup
            .mb1
            .fetch(&FetchRequest {
                ids: seq,
                envelope: true,
                ..FetchRequest::default()
            })
            .unwrap();
        assert_eq!(2, response.fetched.len());

        assert_eq!(Seqnum::u(1), response.fetched[0].0);
        match &response.fetched[0].1[0] {
            FetchedItem::Envelope(e) => {
                assert_eq!("Fwd: failure delivery", e.subject.as_ref().unwrap())
            }
            f => panic!("Unexpected item: {:?}", f),
        }

        assert_eq!(Seqnum::u(2), response.fetched[1].0);
        match &response.fetched[1].1[0] {
            FetchedItem::Envelope(e) => {
                assert_eq!("Entex apr 3 noms", e.subject.as_ref().unwrap())
            }
            f => panic!("Unexpected item: {:?}", f),
        }
    }

    #[test]
    fn notify_of_new_flag_on_fetch() {
        let mut setup = set_up_fetch();

        setup
            .mb2
            .store(&StoreRequest {
                ids: &SeqRange::just(setup.uids[2]),
                flags: &[Flag::Keyword("NewKeyword".to_owned())],
                remove_listed: false,
                remove_unlisted: false,
                loud: false,
                unchanged_since: None,
            })
            .unwrap();
        setup.mb1.poll().unwrap();

        let result = setup
            .mb1
            .fetch(&FetchRequest {
                ids: SeqRange::just(setup.uids[2]),
                flags: true,
                ..FetchRequest::default()
            })
            .unwrap();

        assert!(result
            .flags
            .contains(&Flag::Keyword("NewKeyword".to_owned())));

        let result = setup
            .mb1
            .fetch(&FetchRequest {
                ids: SeqRange::just(setup.uids[2]),
                flags: true,
                ..FetchRequest::default()
            })
            .unwrap();

        assert!(result.flags.is_empty());
    }

    #[test]
    fn filter_not_modified() {
        let mut setup = set_up_fetch();

        setup
            .mb1
            .store(&StoreRequest {
                ids: &SeqRange::just(setup.uids[2]),
                flags: &[Flag::Flagged],
                remove_listed: false,
                remove_unlisted: false,
                loud: false,
                unchanged_since: None,
            })
            .unwrap();
        let modseq = setup.mb1.poll().unwrap().max_modseq;

        setup
            .mb1
            .store(&StoreRequest {
                ids: &SeqRange::just(setup.uids[3]),
                flags: &[Flag::Flagged],
                remove_listed: false,
                remove_unlisted: false,
                loud: false,
                unchanged_since: None,
            })
            .unwrap();
        setup.mb1.poll().unwrap();

        let result = setup
            .mb1
            .fetch(&FetchRequest {
                ids: SeqRange::range(Uid::MIN, Uid::MAX),
                uid: true,
                changed_since: modseq,
                ..FetchRequest::default()
            })
            .unwrap();

        assert_eq!(1, result.fetched.len());
        assert_eq!(Seqnum::u(4), result.fetched[0].0);
        match &result.fetched[0].1[0] {
            &FetchedItem::Uid(uid) => assert_eq!(setup.uids[3], uid),
            f => panic!("Unexpected item: {:?}", f),
        }
    }

    #[test]
    fn fetch_vanished_strict() {
        let mut setup = set_up_fetch();

        setup.mb1.vanquish(setup.uids[4..].iter().copied()).unwrap();
        let modseq = setup.mb1.poll().unwrap().max_modseq;
        setup
            .mb1
            .vanquish(setup.uids[2..4].iter().copied())
            .unwrap();
        setup.mb1.poll().unwrap();

        let result = setup
            .mb1
            .fetch(&FetchRequest {
                ids: SeqRange::range(Uid::MIN, Uid::MAX),
                uid: true,
                changed_since: modseq,
                collect_vanished: true,
                ..FetchRequest::default()
            })
            .unwrap();

        assert!(result.fetched.is_empty());
        assert_eq!(
            SeqRange::range(setup.uids[2], setup.uids[3]),
            result.vanished
        );
        assert_eq!(FetchResponseKind::Ok, result.kind);
    }

    #[test]
    fn fetch_vanished_start_point_forgotten() {
        let mut setup = set_up_fetch();

        // Vanquish messages one at a time so that each gets a different CID
        for &uid in &setup.uids[..2] {
            setup.mb1.vanquish(iter::once(uid)).unwrap();
        }
        let modseq = setup.mb1.poll().unwrap().max_modseq;

        for &uid in &setup.uids[4..] {
            setup.mb1.vanquish(iter::once(uid)).unwrap();
        }
        setup.mb1.poll().unwrap();

        let result = setup
            .mb1
            .fetch(&FetchRequest {
                ids: SeqRange::range(Uid::MIN, Uid::MAX),
                uid: true,
                changed_since: modseq,
                collect_vanished: true,
                ..FetchRequest::default()
            })
            .unwrap();

        let mut expected = SeqRange::range(setup.uids[0], setup.uids[1]);
        expected.insert(setup.uids[4], *setup.uids.last().unwrap());
        assert_eq!(expected, result.vanished);
        assert_eq!(FetchResponseKind::Ok, result.kind);
    }

    #[test]
    fn fetch_unexpected_expunged() {
        let mut setup = set_up_fetch();

        setup.mb2.vanquish(iter::once(setup.uids[0])).unwrap();
        setup.mb2.poll().unwrap();

        let result = setup
            .mb1
            .fetch(&FetchRequest {
                ids: SeqRange::just(setup.uids[0]),
                // Need to try to fetch something from the file in order to
                // discover the hard way that someone else expunged the message
                // meanwhile.
                envelope: true,
                ..FetchRequest::default()
            })
            .unwrap();
        assert_eq!(FetchResponseKind::No, result.kind);

        // Happens implicitly after command
        setup.mb1.mini_poll();

        // Buggy client retries without even doing anything that would cause a
        // full poll
        let result = setup
            .mb1
            .fetch(&FetchRequest {
                ids: SeqRange::just(setup.uids[0]),
                envelope: true,
                ..FetchRequest::default()
            })
            .unwrap();
        assert_eq!(FetchResponseKind::Bye, result.kind);
    }

    #[test]
    fn fetch_unexpected_expunged_alread_known() {
        let mut setup = set_up_fetch();

        setup.mb2.vanquish(iter::once(setup.uids[0])).unwrap();
        setup.mb2.poll().unwrap();

        // Cause mb1 to become aware of the expungement, though it does not get
        // applied to the snapshot yet
        setup.mb1.poll_for_new_changes().unwrap();

        let result = setup
            .mb1
            .fetch(&FetchRequest {
                ids: SeqRange::just(setup.uids[0]),
                // Need to try to fetch something from the file in order to
                // discover the hard way that someone else expunged the message
                // meanwhile.
                envelope: true,
                ..FetchRequest::default()
            })
            .unwrap();
        assert_eq!(FetchResponseKind::No, result.kind);

        // Happens implicitly after command
        setup.mb1.mini_poll();

        // Buggy client retries without even doing anything that would cause a
        // full poll
        let result = setup
            .mb1
            .fetch(&FetchRequest {
                ids: SeqRange::just(setup.uids[0]),
                envelope: true,
                ..FetchRequest::default()
            })
            .unwrap();
        assert_eq!(FetchResponseKind::Bye, result.kind);
    }

    #[test]
    fn seqnum_fetch() {
        let mut setup = set_up_fetch();

        setup.mb1.vanquish(setup.uids[..4].iter().copied()).unwrap();
        setup.mb1.poll().unwrap();

        let result = setup
            .mb1
            .seqnum_fetch(FetchRequest {
                ids: SeqRange::just(Seqnum::u(1)),
                uid: true,
                ..FetchRequest::default()
            })
            .unwrap();

        assert_eq!(1, result.fetched.len());
        assert_eq!(Seqnum::u(1), result.fetched[0].0);
        match &result.fetched[0].1[0] {
            &FetchedItem::Uid(uid) => assert_eq!(setup.uids[4], uid),
            f => panic!("Unexpected item: {:?}", f),
        }
    }
}
