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
use std::fmt;
use std::io::BufRead;
use std::mem;
use std::sync::Arc;

use super::super::mailbox_state::*;
use super::defs::*;
use crate::account::model::*;
use crate::mime::fetch::multi::*;
use crate::mime::grovel::{grovel, MessageAccessor};
use crate::support::error::Error;
use crate::support::threading;

pub struct MailboxMessageAccessor<'a> {
    mailbox: &'a StatefulMailbox,
    uid: Uid,
    message_status: &'a MessageStatus,
}

pub type FetchReceiver<'a> =
    &'a (dyn Fn(Seqnum, Vec<FetchedItem>) + Send + Sync + 'a);

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

    /// Obtain pre-responses for the `FETCH` and `UID FETCH` commands.
    ///
    /// For this to produce an output compliant with the standards, no actions
    /// may be taken before this call and the subsequent `seqnum_fetch()` or
    /// `fetch()` call. The separation is merely to allow the pre-responses to
    /// be sent before streaming the real responses.
    ///
    /// Note that `collect_vanished` is handled in terms of `uids` to avoid
    /// needing to leak the UID->Seqnum translation out of the abstraction.
    /// This is fine since `collect_vanished` is invalid on seqnum FETCH
    /// anyway.
    ///
    /// There's still an inherent race between `prefetch()` and `fetch()`:
    /// Another process could expunge messages between our check here and
    /// actually fetching them. There's not much we can do here, since RFC 7162
    /// requires returning `VANISHED` and `FETCH` in the wrong order.
    pub fn prefetch<ID>(
        &mut self,
        request: &FetchRequest<ID>,
        uids: &SeqRange<Uid>,
    ) -> PrefetchResponse
    where
        SeqRange<ID>: fmt::Debug,
    {
        let mut response = PrefetchResponse::default();
        // If we now know of any flags that haven't been sent to the client,
        // update that now
        if request.flags
            && self
                .state
                .flags()
                .any(|(_, f)| !self.client_known_flags.contains(f))
        {
            response.flags = self.flags_response();
        }

        if request.collect_vanished {
            let precise_expunged = request
                .changed_since
                .and_then(|since| self.state.uids_expunged_since(since))
                .map(|it| it.collect::<HashSet<Uid>>());
            for uid in uids.items(self.state.max_uid_val()) {
                if precise_expunged
                    .as_ref()
                    .map(|p| p.contains(&uid))
                    .unwrap_or(true)
                    && self.state.message_status(uid).is_none()
                {
                    response.vanished.append(uid);
                }
            }
        }

        response
    }

    /// The `FETCH` command.
    ///
    /// `receiver` is called with fetched data as it becomes available. The
    /// caller must buffer the fetch responses in a way it deems appropriate,
    /// so that they can be sent out at the appropriate, awkward point half-way
    /// through the fixed-size fetch responses.
    pub fn seqnum_fetch(
        &mut self,
        request: FetchRequest<Seqnum>,
        receiver: FetchReceiver<'_>,
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
            email_id: request.email_id,
            thread_id: request.thread_id,
        };
        self.fetch(&request, receiver)
    }

    /// The `UID FETCH` command.
    pub fn fetch(
        &mut self,
        request: &FetchRequest<Uid>,
        receiver: FetchReceiver<'_>,
    ) -> Result<FetchResponse, Error> {
        static SG: threading::ScatterGather = threading::ScatterGather {
            batch_size: 4,
            escalate: std::time::Duration::from_millis(2),
            buffer_size: 16,
        };

        enum StrippedFetchResponse {
            Nil,
            UnexpectedExpunge(Uid),
        }

        let mut fetched: Vec<Result<StrippedFetchResponse, Error>> = Vec::new();
        SG.run(
            request.ids.items(self.state.max_uid_val()),
            |uid| {
                let full_response = self.fetch_single(request, uid);

                let full_response = match full_response {
                    Ok(f) => f,
                    Err(e) => return Err(e),
                };

                match full_response {
                    SingleFetchResponse::Fetched(seqnum, fetched) => {
                        receiver(seqnum, fetched);
                        Ok(StrippedFetchResponse::Nil)
                    },

                    SingleFetchResponse::NotModified
                    | SingleFetchResponse::SilentExpunge => {
                        Ok(StrippedFetchResponse::Nil)
                    },

                    SingleFetchResponse::UnexpectedExpunge => {
                        Ok(StrippedFetchResponse::UnexpectedExpunge(uid))
                    },
                }
            },
            |r| fetched.push(r),
        );

        let mut response = FetchResponse::default();

        for result in fetched {
            match result? {
                StrippedFetchResponse::Nil => (),
                StrippedFetchResponse::UnexpectedExpunge(uid) => {
                    let r = if self.fetch_loopbreaker.insert(uid) {
                        FetchResponseKind::No
                    } else {
                        FetchResponseKind::Bye
                    };

                    response.kind = response.kind.max(r);
                },
            }
        }

        Ok(response)
    }

    fn fetch_single(
        &self,
        request: &FetchRequest<Uid>,
        uid: Uid,
    ) -> Result<SingleFetchResponse, Error> {
        let seqnum = match self.state.uid_to_seqnum(uid) {
            Ok(s) => s,
            Err(Error::ExpungedMessage) => {
                // Silently drop requests for unaddressable UIDs
                return Ok(SingleFetchResponse::SilentExpunge);
            },
            Err(Error::NxMessage) => {
                // Similar to the above, silently drop UIDs outside the
                // addressable range.
                return Ok(SingleFetchResponse::SilentExpunge);
            },
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
                if request.email_id {
                    fetcher.add_email_id();
                }
                if request.thread_id {
                    fetcher.add_thread_id();
                }
                if request.envelope {
                    fetcher.add_envelope();
                }
                if request.bodystructure {
                    fetcher.add_body_structure();
                }
                for section in &request.sections {
                    fetcher.add_section(
                        section
                            .to_owned()
                            .fetcher(Arc::clone(&self.s.common_paths)),
                    );
                }

                let mut fetched = grovel(&accessor, fetcher)?;

                // Ensure any section parts are OK
                for part in &mut fetched {
                    if let FetchedItem::BodySection((_, ref mut section)) =
                        *part
                    {
                        if section.is_err() {
                            return mem::replace(
                                section,
                                Err(Error::NxMessage),
                            )
                            .map(|_| unreachable!());
                        }
                    }
                }

                Ok(SingleFetchResponse::Fetched(seqnum, fetched))
            }
        });

        if let Err(Error::ExpungedMessage) = result {
            // If the client requested collect_vanished and we got here, that
            // means the expunge took place later than the latest Modseq we
            // currently know about. In a perfect world, we would report this
            // as `VANISHED (EARLIER)`, but due to RFC 7162's odd ordering
            // requirements, that train has already left the station, so we
            // treat this situation the same way we do for non-QRESYNC clients:
            // Dive into the quagmire that is FetchResponseKind.
            return Ok(SingleFetchResponse::UnexpectedExpunge);
        }

        result
    }
}

#[derive(Debug)]
enum SingleFetchResponse {
    Fetched(Seqnum, Vec<FetchedItem>),
    NotModified,
    SilentExpunge,
    UnexpectedExpunge,
}

#[cfg(test)]
mod test {
    use std::sync::{Arc, Mutex};

    use tempfile::TempDir;

    use super::super::test_prelude::*;
    use super::*;
    use crate::mime::fetch::section;
    use crate::test_data::*;

    struct FetchSetup {
        _root: TempDir,
        mb1: StatefulMailbox,
        mb2: StatefulMailbox,
        uids: Vec<Uid>,

        received: Arc<Mutex<Vec<(Seqnum, Vec<FetchedItem>)>>>,
    }

    impl FetchSetup {
        fn receiver(
            &self,
        ) -> impl Fn(Seqnum, Vec<FetchedItem>) + Send + Sync + 'static {
            let received = Arc::clone(&self.received);
            move |seqnum, fetched| {
                let mut lock = received.lock().unwrap();
                lock.push((seqnum, fetched));
            }
        }

        fn received(&self) -> Vec<(Seqnum, Vec<FetchedItem>)> {
            let mut lock = self.received.lock().unwrap();
            mem::replace(&mut *lock, Vec::new())
        }
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
            _root: setup.root,
            mb1,
            mb2,
            uids,
            received: Arc::new(Mutex::new(Vec::new())),
        }
    }

    #[test]
    fn fetch_all_the_things() {
        let mut setup = set_up_fetch();

        let request = FetchRequest {
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
            email_id: true,
            thread_id: true,
        };
        let prefetch = setup.mb1.prefetch(&request, &request.ids);
        let response = setup.mb1.fetch(&request, &setup.receiver()).unwrap();

        let fetched = setup.received();

        assert_eq!(FetchResponseKind::Ok, response.kind);
        assert!(prefetch.flags.is_empty());
        assert!(prefetch.vanished.is_empty());
        assert_eq!(setup.uids.len(), fetched.len());

        for (_, fetched) in fetched {
            let mut has_uid = false;
            let mut has_flags = false;
            let mut has_rfc822size = false;
            let mut has_internal_date = false;
            let mut has_envelope = false;
            let mut has_bodystructure = false;
            let mut has_section = false;
            let mut has_modseq = false;
            let mut has_emailid = false;
            let mut has_threadid = false;

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
                    FetchedItem::EmailId(_) => has_emailid = true,
                    FetchedItem::ThreadIdNil => has_threadid = true,
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
            assert!(has_emailid);
            assert!(has_threadid);
        }
    }

    #[test]
    fn fetches_correct_data() {
        let mut setup = set_up_fetch();

        // Make a hole between UIDs 1 and 3
        setup.mb1.vanquish(&SeqRange::just(setup.uids[1])).unwrap();
        setup.mb1.poll().unwrap();

        let mut seq = SeqRange::new();
        seq.insert(setup.uids[0], setup.uids[0]);
        seq.insert(setup.uids[2], setup.uids[2]);

        let request = FetchRequest {
            ids: seq,
            envelope: true,
            ..FetchRequest::default()
        };
        setup.mb1.prefetch(&request, &request.ids);
        setup.mb1.fetch(&request, &setup.receiver()).unwrap();

        let mut fetched = setup.received();
        fetched.sort_by_key(|&(seqnum, _)| seqnum);
        assert_eq!(2, fetched.len());

        assert_eq!(Seqnum::u(1), fetched[0].0);
        match &fetched[0].1[0] {
            FetchedItem::Envelope(e) => {
                assert_eq!("Fwd: failure delivery", e.subject.as_ref().unwrap())
            },
            f => panic!("Unexpected item: {:?}", f),
        }

        assert_eq!(Seqnum::u(2), fetched[1].0);
        match &fetched[1].1[0] {
            FetchedItem::Envelope(e) => {
                assert_eq!("Entex apr 3 noms", e.subject.as_ref().unwrap())
            },
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

        let request = FetchRequest {
            ids: SeqRange::just(setup.uids[2]),
            flags: true,
            ..FetchRequest::default()
        };
        let prefetch = setup.mb1.prefetch(&request, &request.ids);
        setup.mb1.fetch(&request, &setup.receiver()).unwrap();

        assert!(prefetch
            .flags
            .contains(&Flag::Keyword("NewKeyword".to_owned())));

        let prefetch = setup.mb1.prefetch(&request, &request.ids);
        setup.mb1.fetch(&request, &setup.receiver()).unwrap();

        assert!(prefetch.flags.is_empty());
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

        let request = FetchRequest {
            ids: SeqRange::range(Uid::MIN, Uid::MAX),
            uid: true,
            changed_since: modseq,
            ..FetchRequest::default()
        };
        setup.mb1.prefetch(&request, &request.ids);
        setup.mb1.fetch(&request, &setup.receiver()).unwrap();

        let fetched = setup.received();
        assert_eq!(1, fetched.len());
        assert_eq!(Seqnum::u(4), fetched[0].0);
        match &fetched[0].1[0] {
            &FetchedItem::Uid(uid) => assert_eq!(setup.uids[3], uid),
            f => panic!("Unexpected item: {:?}", f),
        }
    }

    #[test]
    fn vanished_not_collected_if_not_requested() {
        let mut setup = set_up_fetch();

        setup
            .mb1
            .vanquish(&SeqRange::range(
                setup.uids[4],
                setup.uids[setup.uids.len() - 1],
            ))
            .unwrap();
        setup.mb1.poll().unwrap();
        setup
            .mb1
            .vanquish(&SeqRange::range(setup.uids[2], setup.uids[3]))
            .unwrap();
        setup.mb1.poll().unwrap();

        let request = FetchRequest {
            ids: SeqRange::range(Uid::MIN, Uid::MAX),
            uid: true,
            collect_vanished: false,
            ..FetchRequest::default()
        };
        let prefetch = setup.mb1.prefetch(&request, &request.ids);
        assert!(prefetch.vanished.is_empty());
    }

    #[test]
    fn fetch_vanished_strict() {
        let mut setup = set_up_fetch();

        setup
            .mb1
            .vanquish(&SeqRange::range(
                setup.uids[4],
                setup.uids[setup.uids.len() - 1],
            ))
            .unwrap();
        let modseq = setup.mb1.poll().unwrap().max_modseq;
        setup
            .mb1
            .vanquish(&SeqRange::range(setup.uids[2], setup.uids[3]))
            .unwrap();
        setup.mb1.poll().unwrap();

        let request = FetchRequest {
            ids: SeqRange::range(Uid::MIN, Uid::MAX),
            uid: true,
            changed_since: modseq,
            collect_vanished: true,
            ..FetchRequest::default()
        };
        let prefetch = setup.mb1.prefetch(&request, &request.ids);
        let result = setup.mb1.fetch(&request, &setup.receiver()).unwrap();

        assert!(setup.received().is_empty());
        assert_eq!(
            SeqRange::range(setup.uids[2], setup.uids[3]),
            prefetch.vanished
        );
        assert_eq!(FetchResponseKind::Ok, result.kind);
    }

    #[test]
    fn fetch_vanished_start_point_forgotten() {
        let mut setup = set_up_fetch();

        // Vanquish messages one at a time so that each gets a different CID
        for &uid in &setup.uids[..2] {
            setup.mb1.vanquish(&SeqRange::just(uid)).unwrap();
        }
        let modseq = setup.mb1.poll().unwrap().max_modseq;

        for &uid in &setup.uids[4..] {
            setup.mb1.vanquish(&SeqRange::just(uid)).unwrap();
        }
        setup.mb1.poll().unwrap();

        let request = FetchRequest {
            ids: SeqRange::range(Uid::MIN, Uid::MAX),
            uid: true,
            changed_since: modseq,
            collect_vanished: true,
            ..FetchRequest::default()
        };
        let prefetch = setup.mb1.prefetch(&request, &request.ids);
        let result = setup.mb1.fetch(&request, &setup.receiver()).unwrap();

        let mut expected = SeqRange::range(setup.uids[0], setup.uids[1]);
        expected.insert(setup.uids[4], *setup.uids.last().unwrap());
        assert_eq!(expected, prefetch.vanished);
        assert_eq!(FetchResponseKind::Ok, result.kind);
    }

    #[test]
    fn fetch_unexpected_expunged() {
        let mut setup = set_up_fetch();

        setup.mb2.vanquish(&SeqRange::just(setup.uids[0])).unwrap();
        setup.mb2.purge_all();
        setup.mb2.poll().unwrap();

        let request = FetchRequest {
            ids: SeqRange::just(setup.uids[0]),
            // Need to try to fetch something from the file in order to
            // discover the hard way that someone else expunged the message
            // meanwhile.
            envelope: true,
            ..FetchRequest::default()
        };
        setup.mb1.prefetch(&request, &request.ids);
        let result = setup.mb1.fetch(&request, &setup.receiver()).unwrap();
        assert_eq!(FetchResponseKind::No, result.kind);

        // Happens implicitly after command
        setup.mb1.mini_poll();

        // Buggy client retries without even doing anything that would cause a
        // full poll
        setup.mb1.prefetch(&request, &request.ids);
        let result = setup.mb1.fetch(&request, &setup.receiver()).unwrap();
        assert_eq!(FetchResponseKind::Bye, result.kind);
    }

    #[test]
    fn fetch_unexpected_expunged_already_known_but_still_snapshotted() {
        let mut setup = set_up_fetch();

        setup.mb2.vanquish(&SeqRange::just(setup.uids[0])).unwrap();
        setup.mb2.poll().unwrap();

        // Cause mb1 to become aware of the expungement, though it does not get
        // applied to the snapshot yet
        setup.mb1.poll_for_new_changes().unwrap();

        let request = FetchRequest {
            ids: SeqRange::just(setup.uids[0]),
            // Need to try to fetch something from the file in order to
            // discover the hard way that someone else expunged the message
            // meanwhile.
            envelope: true,
            ..FetchRequest::default()
        };
        setup.mb1.prefetch(&request, &request.ids);
        let result = setup.mb1.fetch(&request, &setup.receiver()).unwrap();
        assert_eq!(FetchResponseKind::Ok, result.kind);
        assert_eq!(1, setup.received().len());
    }

    #[test]
    fn seqnum_fetch() {
        let mut setup = set_up_fetch();

        setup
            .mb1
            .vanquish(&SeqRange::range(setup.uids[0], setup.uids[3]))
            .unwrap();
        setup.mb1.poll().unwrap();

        let request = FetchRequest {
            ids: SeqRange::just(Seqnum::u(1)),
            uid: true,
            ..FetchRequest::default()
        };
        setup.mb1.prefetch(&request, &SeqRange::new());
        setup.mb1.seqnum_fetch(request, &setup.receiver()).unwrap();

        let fetched = setup.received();
        assert_eq!(1, fetched.len());
        assert_eq!(Seqnum::u(1), fetched[0].0);
        match &fetched[0].1[0] {
            &FetchedItem::Uid(uid) => assert_eq!(setup.uids[4], uid),
            f => panic!("Unexpected item: {:?}", f),
        }
    }
}
