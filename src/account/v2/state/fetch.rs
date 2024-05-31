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

use std::io::{self, BufRead};
use std::mem;
use std::sync::Arc;

use chrono::prelude::*;
use itertools::Itertools;
use log::error;

use super::super::storage;
use super::defs::*;
use crate::{
    account::{message_format, model::*},
    crypt::data_stream,
    mime::{
        fetch::multi::*,
        grovel::{grovel, MessageAccessor},
    },
    support::{chronox::*, error::Error},
};

pub type FetchReceiver = tokio::sync::mpsc::Sender<(Seqnum, Vec<FetchedItem>)>;

impl Account {
    /// Create an accessor for the given message.
    pub fn access_message<'a, 'm>(
        &'a mut self,
        mailbox: &'m Mailbox,
        uid: Uid,
    ) -> Result<MailboxMessageAccessor<'a, 'm>, Error> {
        let index = mailbox.uid_index(uid).ok_or(Error::NxMessage)?;
        Ok(MailboxMessageAccessor {
            account: self,
            mailbox,
            message_status: &mailbox.messages[index],
            index,
            access: None,
        })
    }

    /// Obtain pre-responses for the `FETCH` command.
    ///
    /// For this to produce an output compliant with the standards, no actions
    /// may be taken before this call and the subsequent `seqnum_fetch()` or
    /// `fetch()` call. The separation is merely to allow the pre-responses to
    /// be sent before streaming the real responses.
    pub fn seqnum_prefetch(
        &mut self,
        mailbox: &mut Mailbox,
        request: &FetchRequest<Seqnum>,
    ) -> Result<PrefetchResponse, Error> {
        let mut response = PrefetchResponse::default();

        assert!(!request.collect_vanished);

        if request.flags {
            response.flags = mailbox.flags_response_if_changed();
        }

        Ok(response)
    }

    /// Obtain pre-responses for the `UID FETCH` command.
    ///
    /// For this to produce an output compliant with the standards, no actions
    /// may be taken before this call and the subsequent `seqnum_fetch()` or
    /// `fetch()` call. The separation is merely to allow the pre-responses to
    /// be sent before streaming the real responses.
    pub fn prefetch(
        &mut self,
        mailbox: &mut Mailbox,
        request: &FetchRequest<Uid>,
    ) -> Result<PrefetchResponse, Error> {
        let mut response = PrefetchResponse::default();

        if request.collect_vanished {
            // Historical note: the V1 version of this code did some odd stuff
            // to *see through* the snapshot. This is not actually the purpose
            // of the VANISHED modifier, which is intended only to be used for
            // the client to synchronise with the snapshot itself.

            let changed_since = request.changed_since.unwrap_or(Modseq::MIN);
            let vanished = self.metadb.fetch_vanished_mailbox_messages(
                mailbox.id,
                changed_since,
                &mut |uid| {
                    request.ids.contains(uid)
                        && mailbox.uid_index(uid).is_none()
                },
            )?;

            for uid in vanished {
                response.vanished.append(uid);
            }
        }

        if request.flags {
            response.flags = mailbox.flags_response_if_changed();
        }

        Ok(response)
    }

    /// The `FETCH` command.
    ///
    /// `receiver` passed fetched data as it becomes available.
    ///
    /// This does not include the implicit `STORE` which `FETCH` sometimes
    /// implies.
    pub async fn seqnum_fetch(
        &mut self,
        mailbox: &mut Mailbox,
        request: FetchRequest<Seqnum>,
        receiver: FetchReceiver,
    ) -> Result<FetchResponse, Error> {
        let request = FetchRequest {
            ids: mailbox.seqnum_range_to_uid(&request.ids, false)?,
            uid: request.uid,
            flags: request.flags,
            rfc822size: request.rfc822size,
            internal_date: request.internal_date,
            save_date: request.save_date,
            envelope: request.envelope,
            bodystructure: request.bodystructure,
            sections: request.sections,
            modseq: request.modseq,
            changed_since: request.changed_since,
            collect_vanished: request.collect_vanished,
            email_id: request.email_id,
            thread_id: request.thread_id,
        };
        self.fetch(mailbox, request, receiver).await
    }

    /// The `UID FETCH` command.
    ///
    /// `receiver` is passed fetched data as it becomes available.
    ///
    /// This does not include the implicit `UID STORE` which `UID FETCH`
    /// sometimes implies.
    pub async fn fetch(
        &mut self,
        mailbox: &mut Mailbox,
        request: FetchRequest<Uid>,
        receiver: FetchReceiver,
    ) -> Result<FetchResponse, Error> {
        enum StrippedFetchResponse {
            Nil,
            UnexpectedExpunge(Uid),
        }

        let mut fetched = Vec::<Result<StrippedFetchResponse, Error>>::new();

        for uid in request.ids.items(mailbox.next_uid.0.get()) {
            let full_response = match self.fetch_single(mailbox, &request, uid)
            {
                Ok(r) => r,
                Err(e) => {
                    fetched.push(Err(e));
                    continue;
                },
            };

            let stripped_response = match full_response {
                SingleFetchResponse::Fetched(seqnum, fetched) => {
                    let _ = receiver.send((seqnum, fetched)).await;
                    Ok(StrippedFetchResponse::Nil)
                },

                SingleFetchResponse::NotModified
                | SingleFetchResponse::SilentExpunge => {
                    Ok(StrippedFetchResponse::Nil)
                },

                SingleFetchResponse::UnexpectedExpunge => {
                    Ok(StrippedFetchResponse::UnexpectedExpunge(uid))
                },
            };

            fetched.push(stripped_response);
        }

        let mut response = FetchResponse::default();

        for result in fetched {
            match result? {
                StrippedFetchResponse::Nil => (),
                StrippedFetchResponse::UnexpectedExpunge(uid) => {
                    let r = if mailbox.fetch_loopbreaker.insert(uid) {
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
        &mut self,
        mailbox: &Mailbox,
        request: &FetchRequest<Uid>,
        uid: Uid,
    ) -> Result<SingleFetchResponse, Error> {
        let result =
            self.access_message(mailbox, uid).and_then(|mut accessor| {
                let seqnum = Seqnum::from_index(accessor.index);

                if request.changed_since.is_some_and(|since| {
                    accessor.message_status.last_modified <= since
                }) {
                    return Ok(SingleFetchResponse::NotModified);
                }

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
                if request.save_date {
                    fetcher.add_save_date();
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
                        section.to_owned().fetcher(Arc::clone(
                            &accessor.account.common_paths,
                        )),
                    );
                }

                let mut fetched = grovel(&mut accessor, fetcher)?;

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
            });

        match result {
            // Silently drop requests for unaddressable UIDs
            Err(Error::NxMessage) => Ok(SingleFetchResponse::SilentExpunge),
            // If the underlying message file was removed, dive into the
            // quagmire that is FetchResponseKind.
            Err(Error::ExpungedMessage) => {
                Ok(SingleFetchResponse::UnexpectedExpunge)
            },
            // Any other error is unexpected and gets passed through.
            r => r,
        }
    }

    /// Open the message with the given UID for reading.
    #[cfg(test)]
    pub fn open_message_by_uid(
        &mut self,
        mb: &Mailbox,
        uid: Uid,
    ) -> Result<(MessageMetadata, Box<dyn BufRead>), Error> {
        let index = mb.uid_index(uid).ok_or(Error::NxMessage)?;
        self.open_message(mb.messages[index].id)
    }

    /// Open the given raw message ID for reading.
    ///
    /// If the message entry or its backing file is gone, returns
    /// `Error::ExpungedMessage`.
    pub(super) fn open_message(
        &mut self,
        message_id: storage::MessageId,
    ) -> Result<(MessageMetadata, Box<dyn BufRead>), Error> {
        let access = self.metadb.access_message(message_id)?;
        self.open_message_with_access(message_id, &access)
    }

    /// Open the given raw message ID for reading, with an already-loaded
    /// `MessageAccessData`.
    fn open_message_with_access(
        &mut self,
        message_id: storage::MessageId,
        access: &storage::MessageAccessData,
    ) -> Result<(MessageMetadata, Box<dyn BufRead>), Error> {
        let file = match self.message_store.open(access.path.as_ref()) {
            Ok(reader) => reader,
            Err(e) => {
                // If we can't open the message file, generate synthetic
                // contents to return instead. Set the dates to a point in the
                // distant future so that the message will show up at the top
                // of the mailbox and be more obvious.
                //
                // This is to make the situation where a partial backup was
                // restored more graceful. We still return an expunged error to
                // the client if it's been sitting on its snapshot long enough
                // that the database entry for the message is gone entirely;
                // i.e. getting here implies that the database is tracking a
                // file we can't read but is supposed to still be there.
                let data = format!(
                    "\
From: \"UNKNOWN SENDER\" <unknown>\r
Date: Wed, 1 Jan 3000 00:00:00 +0000\r
Subject: [UNREADABLE MESSAGE]\r
Message-ID: <message-placeholder-{message_id}@localhost>\r
Content-Type: text/plain; charset=utf-8\r
Content-Transfer-Encoding: 8bit\r
\r
The server was unable to access this message.\r
The file which is supposed to contain it is missing or corrupt.\r
\r
Error message:\r
  {e:?}\r
Expected file path:
  {file_path}\r
\r
You might consider asking your administrator to look into this or to search\r
for a copy of the file in a backup.\r
\r
If you cannot restore the message, it is safe to just delete this placeholder.\r
",
                    message_id = message_id.0,
                    file_path = access.path,
                );

                let metadata = MessageMetadata {
                    email_id: Default::default(),
                    size: data.len() as u32,
                    internal_date: FixedOffset::zero()
                        .ymd_hmsx(3000, 1, 1, 0, 0, 0),
                };
                let reader: Box<dyn BufRead> = Box::new(io::Cursor::new(data));
                return Ok((metadata, reader));
            },
        };

        let csk = access.session_key.as_ref().map(|sk| {
            data_stream::CachedSessionKey {
                master_key: &self.master_key,
                message_id: message_id.0,
                session_key: &sk.0,
            }
        });
        let mut new_session_key = None::<storage::SessionKey>;
        let (metadata, reader) = message_format::read_message(
            file,
            csk,
            &mut self.key_store,
            |r| {
                if access.session_key.is_none() {
                    new_session_key = Some(storage::SessionKey(
                        r.session_key(&self.master_key, message_id.0),
                    ));
                }
            },
        )?;

        if let Some(session_key) = new_session_key {
            if let Err(e) = self.metadb.cache_message_data(
                message_id,
                session_key,
                metadata.size.into(),
            ) {
                error!(
                    "{} Failed to cache access data for message {}: {:?}",
                    self.log_prefix, message_id.0, e,
                );
            }
        }

        Ok((metadata, reader))
    }
}

pub struct MailboxMessageAccessor<'a, 'm> {
    account: &'a mut Account,
    mailbox: &'m Mailbox,
    message_status: &'m MessageStatus,
    index: usize,
    access: Option<storage::MessageAccessData>,
}

impl MessageAccessor for MailboxMessageAccessor<'_, '_> {
    type Reader = Box<dyn BufRead>;

    fn uid(&mut self) -> Uid {
        self.message_status.uid
    }

    fn email_id(&mut self) -> Option<String> {
        Some(self.message_status.id.format_rfc8474())
    }

    fn last_modified(&mut self) -> Modseq {
        self.message_status.last_modified
    }

    fn savedate(&mut self) -> Option<DateTime<Utc>> {
        Some(self.message_status.savedate)
    }

    fn is_recent(&mut self) -> bool {
        self.message_status.recent
    }

    fn flags(&mut self) -> Vec<Flag> {
        self.message_status
            .flags
            .iter()
            .merge_join_by(self.mailbox.flags.iter(), |&ix, &&(id, _)| {
                ix.cmp(&id.0)
            })
            .filter_map(itertools::EitherOrBoth::both)
            .map(|(_, &(_, ref flag))| flag.clone())
            .collect()
    }

    fn rfc822_size(&mut self) -> Option<u32> {
        self.access = self
            .account
            .metadb
            .access_message(self.message_status.id)
            .ok();

        self.access.as_ref().and_then(|a| a.rfc822_size)
    }

    fn open(&mut self) -> Result<(MessageMetadata, Self::Reader), Error> {
        match self.access {
            None => self.account.open_message(self.message_status.id),
            Some(ref a) => self
                .account
                .open_message_with_access(self.message_status.id, a),
        }
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
    use super::*;
    use crate::mime::fetch::section;
    use crate::test_data::*;

    struct FetchFixture {
        fixture: TestFixture,
        uids: Vec<Uid>,

        receiver_tx: tokio::sync::mpsc::Sender<(Seqnum, Vec<FetchedItem>)>,
        receiver_rx: tokio::sync::mpsc::Receiver<(Seqnum, Vec<FetchedItem>)>,
    }

    impl FetchFixture {
        fn new() -> Self {
            let mut fixture = TestFixture::new();
            let uids = ENRON_SMALL_MULTIPARTS
                .iter()
                .map(|data| fixture.simple_append_data("INBOX", data))
                .collect::<Vec<_>>();

            let (receiver_tx, receiver_rx) = tokio::sync::mpsc::channel(999);

            Self {
                fixture,
                uids,
                receiver_tx,
                receiver_rx,
            }
        }

        fn receiver(&mut self) -> FetchReceiver {
            self.receiver_tx.clone()
        }

        fn received(&mut self) -> Vec<(Seqnum, Vec<FetchedItem>)> {
            let mut received = Vec::new();
            while let Ok(item) = self.receiver_rx.try_recv() {
                received.push(item);
            }
            received
        }
    }

    impl std::ops::Deref for FetchFixture {
        type Target = TestFixture;

        fn deref(&self) -> &TestFixture {
            &self.fixture
        }
    }

    impl std::ops::DerefMut for FetchFixture {
        fn deref_mut(&mut self) -> &mut TestFixture {
            &mut self.fixture
        }
    }

    #[test]
    fn fetch_all_the_things() {
        let mut fixture = FetchFixture::new();
        let mut mb = fixture.select("INBOX", false, None).unwrap().0;

        let request = FetchRequest {
            ids: SeqRange::range(
                *fixture.uids.first().unwrap(),
                *fixture.uids.last().unwrap(),
            ),
            uid: true,
            flags: true,
            rfc822size: true,
            internal_date: true,
            save_date: true,
            envelope: true,
            bodystructure: true,
            sections: vec![section::BodySection::default()],
            modseq: true,
            changed_since: None,
            collect_vanished: false,
            email_id: true,
            thread_id: true,
        };
        let prefetch = fixture.prefetch(&mut mb, &request).unwrap();
        let receiver = fixture.receiver();
        let response = futures::executor::block_on(fixture.fetch(
            &mut mb,
            request,
            receiver.clone(),
        ))
        .unwrap();

        let fetched = fixture.received();

        assert_eq!(FetchResponseKind::Ok, response.kind);
        assert!(prefetch.flags.is_empty());
        assert!(prefetch.vanished.is_empty());
        assert_eq!(fixture.uids.len(), fetched.len());

        for (_, fetched) in fetched {
            let mut has_uid = false;
            let mut has_flags = false;
            let mut has_rfc822size = false;
            let mut has_internal_date = false;
            let mut has_save_date = false;
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
                    FetchedItem::SaveDate(d) => has_save_date = d.is_some(),
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
            assert!(has_save_date);
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
        let mut fixture = FetchFixture::new();
        let mut mb = fixture.select("INBOX", true, None).unwrap().0;
        let receiver = fixture.receiver();

        // Make a hole between UIDs 1 and 3
        fixture
            .fixture
            .vanquish(&mb, &SeqRange::just(fixture.uids[1]))
            .unwrap();
        fixture.poll(&mut mb).unwrap();

        let mut seq = SeqRange::new();
        seq.insert(fixture.uids[0], fixture.uids[0]);
        seq.insert(fixture.uids[2], fixture.uids[2]);

        let request = FetchRequest {
            ids: seq,
            envelope: true,
            ..FetchRequest::default()
        };
        fixture.prefetch(&mut mb, &request).unwrap();
        futures::executor::block_on(fixture.fetch(
            &mut mb,
            request,
            receiver.clone(),
        ))
        .unwrap();

        let mut fetched = fixture.received();
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
        let mut fixture = FetchFixture::new();

        let mut mb1 = fixture.select("INBOX", false, None).unwrap().0;
        let mut mb2 = fixture.select("INBOX", false, None).unwrap().0;
        let mut mb3 = fixture.select("INBOX", true, None).unwrap().0;

        fixture
            .fixture
            .store(
                &mut mb3,
                &StoreRequest {
                    ids: &SeqRange::just(fixture.uids[2]),
                    flags: &[Flag::Keyword("NewKeyword".to_owned())],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                },
            )
            .unwrap();
        fixture.mini_poll(&mut mb1).unwrap();
        fixture.poll(&mut mb2).unwrap();

        let seqnum_request = FetchRequest {
            ids: SeqRange::just(Seqnum::u(3)),
            flags: true,
            ..FetchRequest::default()
        };
        let uid_request = FetchRequest {
            ids: SeqRange::just(fixture.uids[2]),
            flags: true,
            ..FetchRequest::default()
        };

        let mut prefetch =
            fixture.seqnum_prefetch(&mut mb1, &seqnum_request).unwrap();
        assert!(prefetch
            .flags
            .contains(&Flag::Keyword("NewKeyword".to_owned())));
        prefetch = fixture.seqnum_prefetch(&mut mb1, &seqnum_request).unwrap();
        assert!(prefetch.flags.is_empty());

        prefetch = fixture.prefetch(&mut mb2, &uid_request).unwrap();
        assert!(prefetch
            .flags
            .contains(&Flag::Keyword("NewKeyword".to_owned())));
        prefetch = fixture.prefetch(&mut mb2, &uid_request).unwrap();
        assert!(prefetch.flags.is_empty());
    }

    #[test]
    fn filter_not_modified() {
        let mut fixture = FetchFixture::new();
        let mut mb = fixture.select("INBOX", true, None).unwrap().0;
        let receiver = fixture.receiver();

        fixture
            .fixture
            .store(
                &mut mb,
                &StoreRequest {
                    ids: &SeqRange::just(fixture.uids[2]),
                    flags: &[Flag::Flagged],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                },
            )
            .unwrap();
        let modseq = fixture.poll(&mut mb).unwrap().max_modseq;

        fixture
            .fixture
            .store(
                &mut mb,
                &StoreRequest {
                    ids: &SeqRange::just(fixture.uids[3]),
                    flags: &[Flag::Flagged],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                },
            )
            .unwrap();
        fixture.poll(&mut mb).unwrap();

        let request = FetchRequest {
            ids: SeqRange::range(Uid::MIN, Uid::MAX),
            uid: true,
            changed_since: modseq,
            ..FetchRequest::default()
        };
        fixture.prefetch(&mut mb, &request).unwrap();
        futures::executor::block_on(fixture.fetch(
            &mut mb,
            request,
            receiver.clone(),
        ))
        .unwrap();

        let fetched = fixture.received();
        assert_eq!(1, fetched.len());
        assert_eq!(Seqnum::u(4), fetched[0].0);
        match &fetched[0].1[0] {
            &FetchedItem::Uid(uid) => assert_eq!(fixture.uids[3], uid),
            f => panic!("Unexpected item: {:?}", f),
        }
    }

    #[test]
    fn vanished_not_collected_if_not_requested() {
        let mut fixture = FetchFixture::new();
        let mut mb = fixture.select("INBOX", true, None).unwrap().0;

        fixture
            .fixture
            .vanquish(
                &mb,
                &SeqRange::range(
                    fixture.uids[4],
                    *fixture.uids.last().unwrap(),
                ),
            )
            .unwrap();
        fixture
            .fixture
            .vanquish(&mb, &SeqRange::range(fixture.uids[2], fixture.uids[3]))
            .unwrap();
        fixture.poll(&mut mb).unwrap();

        let request = FetchRequest {
            ids: SeqRange::range(Uid::MIN, Uid::MAX),
            uid: true,
            collect_vanished: false,
            ..FetchRequest::default()
        };
        let prefetch = fixture.prefetch(&mut mb, &request).unwrap();
        assert!(prefetch.vanished.is_empty());
    }

    #[test]
    fn fetch_vanished() {
        let mut fixture = FetchFixture::new();
        let mut mb = fixture.select("INBOX", true, None).unwrap().0;

        // Expunge two sets of messages, out-of-order to ensure that the
        // results get sorted properly.
        let modseq1 = mb.select_response().unwrap().max_modseq;
        fixture
            .fixture
            .vanquish(
                &mb,
                &SeqRange::range(
                    fixture.uids[4],
                    *fixture.uids.last().unwrap(),
                ),
            )
            .unwrap();
        let modseq2 = fixture.poll(&mut mb).unwrap().max_modseq.unwrap();
        fixture
            .fixture
            .vanquish(&mb, &SeqRange::range(fixture.uids[2], fixture.uids[3]))
            .unwrap();
        let modseq3 = fixture.poll(&mut mb).unwrap().max_modseq.unwrap();

        // Expunge another message, but don't get the expungement into the
        // snapshot. The fetches below should not report it as VANISHED.
        fixture
            .fixture
            .vanquish(&mb, &SeqRange::just(fixture.uids[0]))
            .unwrap();

        let mut request = FetchRequest {
            ids: SeqRange::range(Uid::MIN, Uid::MAX),
            uid: true,
            collect_vanished: true,
            changed_since: Some(modseq1),
            ..FetchRequest::default()
        };
        let mut prefetch = fixture.prefetch(&mut mb, &request).unwrap();
        assert_eq!(
            SeqRange::range(fixture.uids[2], *fixture.uids.last().unwrap(),),
            prefetch.vanished,
        );

        request.changed_since = Some(modseq2);
        prefetch = fixture.prefetch(&mut mb, &request).unwrap();
        assert_eq!(
            SeqRange::range(fixture.uids[2], fixture.uids[3],),
            prefetch.vanished,
        );

        request.changed_since = Some(modseq3);
        prefetch = fixture.prefetch(&mut mb, &request).unwrap();
        assert_eq!(SeqRange::new(), prefetch.vanished);

        request.changed_since = Some(modseq1);
        request.ids = SeqRange::range(fixture.uids[3], fixture.uids[5]);
        prefetch = fixture.prefetch(&mut mb, &request).unwrap();
        assert_eq!(
            SeqRange::range(fixture.uids[3], fixture.uids[5],),
            prefetch.vanished,
        );
    }

    #[test]
    fn fetch_unexpected_expunged() {
        let mut fixture = FetchFixture::new();
        let mut mb = fixture.select("INBOX", true, None).unwrap().0;
        let receiver = fixture.receiver();

        // Remove a message, but don't bring the expungement into the snapshot.
        fixture
            .fixture
            .vanquish(&mb, &SeqRange::just(fixture.uids[0]))
            .unwrap();
        // Force the underlying message to go away entirely.
        fixture.purge_all().unwrap();

        let request = FetchRequest {
            ids: SeqRange::just(Seqnum::u(1)),
            // Need to try to fetch something from the file in order to
            // discover the hard way that someone else expunged the message
            // meanwhile.
            envelope: true,
            ..FetchRequest::default()
        };
        fixture.seqnum_prefetch(&mut mb, &request).unwrap();
        let result = futures::executor::block_on(fixture.seqnum_fetch(
            &mut mb,
            request.clone(),
            receiver.clone(),
        ))
        .unwrap();
        assert_eq!(FetchResponseKind::No, result.kind);

        // Happens implicitly after command
        fixture.mini_poll(&mut mb).unwrap();

        // Buggy client retries without even doing anything that would cause a
        // full poll.
        fixture.seqnum_prefetch(&mut mb, &request).unwrap();
        let result = futures::executor::block_on(fixture.seqnum_fetch(
            &mut mb,
            request,
            receiver.clone(),
        ))
        .unwrap();
        assert_eq!(FetchResponseKind::Bye, result.kind);
    }

    #[test]
    fn seqnum_fetch() {
        let mut fixture = FetchFixture::new();
        let receiver = fixture.receiver();
        let mut mb = fixture.select("INBOX", true, None).unwrap().0;

        fixture
            .fixture
            .vanquish(&mb, &SeqRange::range(fixture.uids[0], fixture.uids[3]))
            .unwrap();
        fixture.poll(&mut mb).unwrap();

        let request = FetchRequest {
            ids: SeqRange::just(Seqnum::u(1)),
            uid: true,
            ..FetchRequest::default()
        };
        fixture.seqnum_prefetch(&mut mb, &request).unwrap();
        futures::executor::block_on(fixture.seqnum_fetch(
            &mut mb,
            request,
            receiver.clone(),
        ))
        .unwrap();

        let fetched = fixture.received();
        assert_eq!(1, fetched.len());
        assert_eq!(Seqnum::u(1), fetched[0].0);
        match &fetched[0].1[0] {
            &FetchedItem::Uid(uid) => assert_eq!(fixture.uids[4], uid),
            f => panic!("Unexpected item: {:?}", f),
        }
    }
}
