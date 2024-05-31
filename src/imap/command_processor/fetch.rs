//-
// Copyright (c) 2020, 2023, Jason Lingle
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

use std::borrow::Cow;
use std::convert::TryInto;
use std::fmt;
use std::future::Future;
use std::mem;

use log::{error, warn};

use super::defs::*;
use crate::account::{
    model::*,
    v2::{Account, FetchReceiver, Mailbox},
};
use crate::imap::literal_source::LiteralSource;
use crate::mime::fetch::{self, section::*};
use crate::support::error::Error;

impl CommandProcessor {
    pub(super) async fn cmd_fetch(
        &mut self,
        cmd: s::FetchCommand<'_>,
        sender: &mut SendResponse,
    ) -> CmdResult {
        let ids = self.parse_seqnum_range(&cmd.messages)?;
        self.fetch(
            cmd,
            sender,
            ids,
            false,
            false,
            Account::seqnum_store,
            |a, mb, r| a.seqnum_prefetch(mb, r),
            Account::seqnum_fetch,
        )
        .await
    }

    pub(super) async fn cmd_uid_fetch(
        &mut self,
        cmd: s::FetchCommand<'_>,
        sender: &mut SendResponse,
    ) -> CmdResult {
        let ids = self.parse_uid_range(&cmd.messages)?;
        self.fetch(
            cmd,
            sender,
            ids,
            true,
            true,
            Account::store,
            |a, mb, r| a.prefetch(mb, r),
            |a, mb, r, f| a.fetch(mb, r, f),
        )
        .await
    }

    pub(super) async fn fetch_for_background_update(
        &mut self,
        sender: &mut SendResponse,
        uids: Vec<Uid>,
    ) {
        let mut ids = SeqRange::new();
        for uid in uids {
            ids.append(uid);
        }

        let mut what = Vec::with_capacity(3);
        what.push(s::FetchAtt::Uid(()));
        what.push(s::FetchAtt::Flags(()));
        if self.condstore_enabled {
            what.push(s::FetchAtt::Modseq(()));
        }

        let _ = self
            .fetch(
                s::FetchCommand {
                    messages: Cow::Borrowed(""),
                    target: s::FetchCommandTarget::Multi(what),
                    modifiers: None,
                },
                sender,
                ids,
                false,
                false,
                |_, _, _| panic!("Shouldn't STORE in background update"),
                |a, mb, r| a.prefetch(mb, r),
                |a, mb, r, f| a.fetch(mb, r, f),
            )
            .await;
    }

    async fn fetch<
        'a,
        ID: Default,
        F: Future<Output = Result<FetchResponse, Error>> + 'a,
    >(
        &'a mut self,
        cmd: s::FetchCommand<'_>,
        sender: &mut SendResponse,
        ids: SeqRange<ID>,
        force_fetch_uid: bool,
        allow_vanished: bool,
        f_store: impl FnOnce(
            &mut Account,
            &mut Mailbox,
            &StoreRequest<ID>,
        ) -> Result<StoreResponse<ID>, Error>,
        f_prefetch: impl FnOnce(
            &mut Account,
            &mut Mailbox,
            &FetchRequest<ID>,
        ) -> Result<PrefetchResponse, Error>,
        f_fetch: impl FnOnce(
            &'a mut Account,
            &'a mut Mailbox,
            FetchRequest<ID>,
            FetchReceiver,
        ) -> F,
    ) -> CmdResult
    where
        SeqRange<ID>: fmt::Debug,
    {
        let mut request = FetchRequest {
            ids,
            uid: force_fetch_uid,
            ..FetchRequest::default()
        };

        let mut enable_condstore = false;
        let mut has_changedsince = false;
        for modifier in cmd.modifiers.unwrap_or_default() {
            match modifier {
                s::FetchModifier::ChangedSince(modseq) => {
                    if has_changedsince {
                        return Err(s::Response::Cond(s::CondResponse {
                            cond: s::RespCondType::Bad,
                            code: Some(s::RespTextCode::ClientBug(())),
                            quip: Some(Cow::Borrowed(
                                "CHANGEDSINCE passed more than once",
                            )),
                        }));
                    }

                    enable_condstore = true;
                    has_changedsince = true;
                    request.changed_since = Some(Modseq::of(modseq));
                },
                s::FetchModifier::Vanished(_) => {
                    if !self.qresync_enabled {
                        return Err(s::Response::Cond(s::CondResponse {
                            cond: s::RespCondType::Bad,
                            code: Some(s::RespTextCode::ClientBug(())),
                            quip: Some(Cow::Borrowed(
                                "VANISHED requires ENABLE QRESYNC",
                            )),
                        }));
                    }

                    if !allow_vanished {
                        return Err(s::Response::Cond(s::CondResponse {
                            cond: s::RespCondType::Bad,
                            code: Some(s::RespTextCode::ClientBug(())),
                            quip: Some(Cow::Borrowed(
                                "VANISHED not allowed here",
                            )),
                        }));
                    }

                    if request.collect_vanished {
                        return Err(s::Response::Cond(s::CondResponse {
                            cond: s::RespCondType::Bad,
                            code: Some(s::RespTextCode::ClientBug(())),
                            quip: Some(Cow::Borrowed(
                                "VANISHED passed more than once",
                            )),
                        }));
                    }

                    request.collect_vanished = true;
                },
            }
        }

        if request.collect_vanished && !has_changedsince {
            return Err(s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::Bad,
                code: Some(s::RespTextCode::ClientBug(())),
                quip: Some(Cow::Borrowed("VANISHED without CHANGEDSINCE")),
            }));
        }

        let fetch_properties = fetch_properties(&cmd.target);
        fetch_target_from_ast(&mut request, cmd.target);

        request.modseq |= has_changedsince;

        // Don't implicitly enable CONDSTORE if not selected since we will
        // return BAD in that case.
        if (enable_condstore || request.modseq) && self.selected.is_some() {
            self.enable_condstore(sender, true).await;
        }

        // If there are non-.PEEK body sections in the request, implicitly set
        // \Seen on all the messages.
        //
        // RFC 3501 does not define the ordering with respect to the data
        // retrieval itself. Some discussion on the mailing lists vaguely
        // suggests that the expectation is that the store happens first, which
        // seems less useful, but it's ultimately moot in the view of IMAP as a
        // cache-fill protocol.
        //
        // This is only best-effort, and we only log if anything goes wrong.
        if fetch_properties.set_seen && !selected!(self)?.read_only() {
            let account = account!(self)?;
            let selected = selected!(self)?;

            let store_res = f_store(
                account,
                selected,
                &StoreRequest {
                    ids: &request.ids,
                    flags: &[Flag::Seen],
                    remove_listed: false,
                    remove_unlisted: false,
                    loud: false,
                    unchanged_since: None,
                },
            );
            if let Err(e) = store_res {
                warn!(
                    "{} Implicit STORE \\Seen failed: {}",
                    self.log_prefix, e
                );
            }

            // We need to do a mini-poll to bring the STORE into effect.
            if let Ok(poll) = account.mini_poll(selected) {
                // We're not in a position to process these just yet, so feed
                // it back into the next poll.
                selected.add_changed_uids(poll.fetch.into_iter());
            }
        }

        let mut prefetch =
            f_prefetch(account!(self)?, selected!(self)?, &request)
                .map_err(map_error!(self))?;
        if !self.flag_responses_enabled {
            prefetch.flags.clear();
        }
        fetch_preresponse(sender, prefetch).await?;

        let (receiver_tx, mut receiver_rx) =
            tokio::sync::mpsc::channel(fetch_properties.channel_buffer_size);

        let do_fetch =
            f_fetch(account!(self)?, selected!(self)?, request, receiver_tx);
        let send_responses = async move {
            while let Some((seqnum, items)) = receiver_rx.recv().await {
                fetch_response(sender, fetch_properties, seqnum, items).await;
            }
        };

        let (response, _) = tokio::join!(do_fetch, send_responses);
        let response = response.map_err(map_error! {
            // XXX We can't use the `self` form because `f_fetch` borrows
            // `self.account` and `self.mailbox` permanently. This is due to a
            // limitation in the type system. Ideally, we'd declare `f_fetch`
            // as
            //
            //   impl for<'a> FnOnce (
            //     &'a mut Account,
            //     &'a mut Mailbox,
            //     ...
            //   ) -> impl Future<...> + 'a
            //
            // but there's no way to express that right now --- we need to
            // commit to some lifetime which exists for the entirety of this
            // function.
            //
            // This isn't that big of a problem though, as once we've gotten
            // past prefetch, there isn't really any way for the storage layer
            // to discover that the mailbox was deleted out from under us.
            log_prefix = &self.log_prefix,
            MasterKeyUnavailable => (No, Some(s::RespTextCode::ServerBug(()))),
            BadEncryptedKey => (No, Some(s::RespTextCode::Corruption(()))),
            ExpungedMessage => (No, Some(s::RespTextCode::ExpungeIssued(()))),
            NxMessage => (No, Some(s::RespTextCode::Nonexistent(()))),
            UnaddressableMessage => (No, Some(s::RespTextCode::ClientBug(()))),
            UnknownCte => (No, Some(s::RespTextCode::UnknownCte(()))),
        })?;
        fetch_response_final(response)
    }
}

#[derive(Clone, Copy, Debug)]
struct FetchProperties {
    set_seen: bool,
    extended_body_structure: bool,
    channel_buffer_size: usize,
}

impl Default for FetchProperties {
    fn default() -> Self {
        Self {
            set_seen: false,
            extended_body_structure: false,
            channel_buffer_size: 64,
        }
    }
}

fn fetch_properties(target: &s::FetchCommandTarget<'_>) -> FetchProperties {
    let mut props = FetchProperties::default();

    match *target {
        s::FetchCommandTarget::Single(ref att) => {
            scan_fetch_properties(&mut props, att);
        },
        s::FetchCommandTarget::Multi(ref atts) => {
            for att in atts {
                scan_fetch_properties(&mut props, att);
            }
        },
        _ => (),
    }

    props
}

fn scan_fetch_properties(props: &mut FetchProperties, att: &s::FetchAtt<'_>) {
    if matches!(
        *att,
        s::FetchAtt::Envelope(_)
            | s::FetchAtt::InternalDate(_)
            | s::FetchAtt::Rfc822(_)
            | s::FetchAtt::Body(_)
            | s::FetchAtt::ExtendedBodyStructure(_)
            | s::FetchAtt::ShortBodyStructure(_),
    ) {
        // Use a smaller channel size if we're fetching things that involve
        // actually reading the message.
        props.channel_buffer_size = 1;
    }

    match *att {
        s::FetchAtt::ExtendedBodyStructure(_) => {
            props.extended_body_structure = true;
        },
        s::FetchAtt::Body(ref body) if !body.peek && !body.size_only => {
            props.set_seen = true;
        },
        s::FetchAtt::Rfc822(Some(s::FetchAttRfc822::Size)) => (),
        s::FetchAtt::Rfc822(Some(s::FetchAttRfc822::Header)) => (),
        s::FetchAtt::Rfc822(_) => {
            props.set_seen = true;
        },
        _ => (),
    }
}

fn fetch_target_from_ast<T>(
    request: &mut FetchRequest<T>,
    target: s::FetchCommandTarget<'_>,
) where
    SeqRange<T>: fmt::Debug,
{
    match target {
        s::FetchCommandTarget::All(()) => {
            request.flags = true;
            request.internal_date = true;
            request.rfc822size = true;
            request.envelope = true;
        },
        s::FetchCommandTarget::Fast(()) => {
            request.flags = true;
            request.internal_date = true;
            request.rfc822size = true;
        },
        s::FetchCommandTarget::Full(()) => {
            request.flags = true;
            request.internal_date = true;
            request.rfc822size = true;
            request.envelope = true;
            request.bodystructure = true;
        },
        s::FetchCommandTarget::Single(att) => {
            fetch_att_from_ast(request, att);
        },
        s::FetchCommandTarget::Multi(atts) => {
            for att in atts {
                fetch_att_from_ast(request, att);
            }
        },
    }
}

fn fetch_att_from_ast<T>(request: &mut FetchRequest<T>, att: s::FetchAtt<'_>)
where
    SeqRange<T>: fmt::Debug,
{
    match att {
        s::FetchAtt::Envelope(()) => request.envelope = true,
        s::FetchAtt::Flags(()) => request.flags = true,
        s::FetchAtt::InternalDate(()) => request.internal_date = true,
        s::FetchAtt::SaveDate(()) => request.save_date = true,
        s::FetchAtt::Rfc822(Some(s::FetchAttRfc822::Size)) => {
            request.rfc822size = true;
        },
        s::FetchAtt::ExtendedBodyStructure(())
        | s::FetchAtt::ShortBodyStructure(()) => {
            request.bodystructure = true;
        },
        s::FetchAtt::Uid(()) => request.uid = true,
        s::FetchAtt::Modseq(()) => request.modseq = true,
        s::FetchAtt::EmailId(()) => request.email_id = true,
        s::FetchAtt::ThreadId(()) => request.thread_id = true,
        s::FetchAtt::Rfc822(Some(s::FetchAttRfc822::Header)) => {
            request.sections.push(BodySection {
                leaf_type: LeafType::Headers,
                report_as_legacy: Some(Imap2Section::Rfc822Header),
                ..BodySection::default()
            });
        },
        s::FetchAtt::Rfc822(Some(s::FetchAttRfc822::Text)) => {
            request.sections.push(BodySection {
                leaf_type: LeafType::Content,
                report_as_legacy: Some(Imap2Section::Rfc822Text),
                ..BodySection::default()
            });
        },
        s::FetchAtt::Rfc822(None) => {
            request.sections.push(BodySection {
                leaf_type: LeafType::Full,
                report_as_legacy: Some(Imap2Section::Rfc822),
                ..BodySection::default()
            });
        },
        s::FetchAtt::Body(body) => {
            fn apply_section_text(
                section: &mut BodySection,
                text: Option<s::SectionText<'_>>,
            ) {
                match text {
                    Some(s::SectionText::HeaderFields(fields)) => {
                        section.leaf_type = LeafType::Headers;
                        section.discard_matching_headers = fields.negative;
                        section.header_filter = fields
                            .headers
                            .into_iter()
                            .map(Cow::into_owned)
                            .collect();
                    },
                    Some(s::SectionText::Header(())) => {
                        section.leaf_type = LeafType::Headers;
                    },
                    Some(s::SectionText::Text(())) => {
                        section.leaf_type = LeafType::Text;
                    },
                    Some(s::SectionText::Mime(())) => {
                        section.leaf_type = LeafType::Mime;
                    },
                    None => section.leaf_type = LeafType::Content,
                }
            }

            let mut section = BodySection {
                report_as_binary: s::FetchAttBodyKind::Binary == body.kind,
                size_only: body.size_only,
                ..BodySection::default()
            };

            match body.section {
                None => (),
                Some(s::SectionSpec::TopLevel(spec)) => {
                    // We don't set decode_cte here --- BINARY[] is exactly
                    // equivalent to BODY[]
                    apply_section_text(&mut section, Some(spec));
                },
                Some(s::SectionSpec::Sub(spec)) => {
                    section.subscripts = spec.subscripts;
                    // With subscripts, we decode the CTE if this is a BINARY
                    // command
                    section.decode_cte = section.report_as_binary;
                    apply_section_text(&mut section, spec.text);
                },
            }
            if let Some(slice) = body.slice {
                let start: u64 = slice.start.into();
                let length: u64 = slice.length.into();
                let end = start + length;
                section.partial = Some((start, end));
            }

            request.sections.push(section);
        },
    }
}

async fn fetch_preresponse(
    sender: &mut SendResponse,
    response: PrefetchResponse,
) -> PartialResult<()> {
    if !response.vanished.is_empty() {
        send_response(
            sender,
            s::Response::Vanished(s::VanishedResponse {
                earlier: true,
                uids: Cow::Owned(response.vanished.to_string()),
            }),
        )
        .await;
    }
    if !response.flags.is_empty() {
        send_response(sender, s::Response::Flags(response.flags)).await;
    }
    Ok(())
}

async fn fetch_response(
    sender: &mut SendResponse,
    fetch_properties: FetchProperties,
    seqnum: Seqnum,
    items: Vec<fetch::multi::FetchedItem>,
) {
    send_response(
        sender,
        s::Response::Fetch(s::FetchResponse {
            seqnum: seqnum.0.get(),
            atts: s::MsgAtts {
                atts: items
                    .into_iter()
                    .filter_map(|att| fetch_att_to_ast(att, fetch_properties))
                    .collect(),
            },
        }),
    )
    .await;
}

fn fetch_response_final(response: FetchResponse) -> CmdResult {
    match response.kind {
        FetchResponseKind::Ok => success(),
        FetchResponseKind::No => Ok(s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::No,
            code: Some(s::RespTextCode::ExpungeIssued(())),
            quip: Some(Cow::Borrowed(
                "Message state out of sync; suggest NOOP",
            )),
        })),
        FetchResponseKind::Bye => Err(s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Bye,
            code: Some(s::RespTextCode::ClientBug(())),
            quip: Some(Cow::Borrowed("Possible FETCH loop bug detected")),
        })),
    }
}

fn fetch_att_to_ast(
    item: fetch::multi::FetchedItem,
    fetch_properties: FetchProperties,
) -> Option<s::MsgAtt<'static>> {
    use crate::mime::fetch::multi::FetchedItem as FI;

    match item {
        FI::Nil => panic!("Nil FetchedItem"),
        FI::Uid(uid) => Some(s::MsgAtt::Uid(uid.0.get())),
        FI::Modseq(modseq) => Some(s::MsgAtt::Modseq(modseq.raw())),
        FI::Flags(flags) => Some(s::MsgAtt::Flags(if flags.recent {
            s::FlagsFetch::Recent(flags.flags)
        } else {
            s::FlagsFetch::NotRecent(flags.flags)
        })),
        FI::Rfc822Size(size) => Some(s::MsgAtt::Rfc822Size(size)),
        FI::InternalDate(dt) => Some(s::MsgAtt::InternalDate(dt)),
        FI::SaveDate(dt) => Some(s::MsgAtt::SaveDate(dt)),
        FI::EmailId(ei) => Some(s::MsgAtt::EmailId(Cow::Owned(ei))),
        FI::ThreadIdNil => Some(s::MsgAtt::ThreadIdNil(())),
        FI::Envelope(env) => Some(s::MsgAtt::Envelope(envelope_to_ast(*env))),
        FI::BodyStructure(bs) => {
            let converted = body_structure_to_ast(
                *bs,
                fetch_properties.extended_body_structure,
            );
            Some(if fetch_properties.extended_body_structure {
                s::MsgAtt::ExtendedBodyStructure(converted)
            } else {
                s::MsgAtt::ShortBodyStructure(converted)
            })
        },
        FI::BodySection((mut section, fetched_result)) => {
            let data = match fetched_result {
                Ok(fetched) => {
                    let len = fetched.buffer.len();
                    LiteralSource::of_reader(
                        fetched.buffer,
                        len,
                        section.report_as_binary && fetched.contains_nul,
                    )
                },
                Err(e) => {
                    // Should never happen since the `fetch` implementation
                    // lifts all fetch errors up to top-level.
                    error!("Dropping unfetchable body section: {}", e);
                    return None;
                },
            };

            match section.report_as_legacy {
                None => (),
                Some(Imap2Section::Rfc822) => {
                    return Some(s::MsgAtt::Rfc822Full(data));
                },
                Some(Imap2Section::Rfc822Header) => {
                    return Some(s::MsgAtt::Rfc822Header(data));
                },
                Some(Imap2Section::Rfc822Text) => {
                    return Some(s::MsgAtt::Rfc822Text(data));
                },
            }

            fn section_text_to_ast(
                section: BodySection,
            ) -> Option<s::SectionText<'static>> {
                match section.leaf_type {
                    LeafType::Full => panic!("Full leaf type in subsection?"),
                    LeafType::Content => None,
                    LeafType::Text => Some(s::SectionText::Text(())),
                    LeafType::Mime => Some(s::SectionText::Mime(())),
                    LeafType::Headers if section.header_filter.is_empty() => {
                        Some(s::SectionText::Header(()))
                    },
                    LeafType::Headers => Some(s::SectionText::HeaderFields(
                        s::SectionTextHeaderField {
                            negative: section.discard_matching_headers,
                            headers: section
                                .header_filter
                                .into_iter()
                                .map(Cow::Owned)
                                .collect(),
                        },
                    )),
                }
            }

            let partial = section.partial;
            let report_as_binary = section.report_as_binary;
            let size_only = section.size_only;

            let section_spec =
                match (section.subscripts.is_empty(), section.leaf_type) {
                    (true, LeafType::Full) => None,
                    (true, _) => Some(s::SectionSpec::TopLevel(
                        section_text_to_ast(section)
                            .expect("Content leaf at top-level?"),
                    )),
                    (false, _) => {
                        Some(s::SectionSpec::Sub(s::SubSectionSpec {
                            subscripts: mem::take(&mut section.subscripts),
                            text: section_text_to_ast(section),
                        }))
                    },
                };

            if size_only {
                Some(s::MsgAtt::BinarySize(s::MsgAttBinarySize {
                    section: section_spec,
                    size: data.len.try_into().unwrap_or(u32::MAX),
                }))
            } else {
                Some(s::MsgAtt::Body(s::MsgAttBody {
                    kind: if report_as_binary {
                        s::FetchAttBodyKind::Binary
                    } else {
                        s::FetchAttBodyKind::Body
                    },
                    section: section_spec,
                    slice_origin: partial.map(|(start, _)| {
                        let start: u32 = start.try_into().unwrap_or(u32::MAX);
                        start
                    }),
                    data,
                }))
            }
        },
    }
}

fn envelope_to_ast(env: fetch::envelope::Envelope) -> s::Envelope<'static> {
    fn addresses_to_ast(
        src: Vec<fetch::envelope::EnvelopeAddress>,
    ) -> Vec<s::Address<'static>> {
        src.into_iter()
            .map(|a| {
                if a.domain.is_some() {
                    s::Address::Real(s::RealAddress {
                        display_name: a.name.map(Cow::Owned),
                        routing: a.routing.map(Cow::Owned),
                        local_part: Cow::Owned(
                            a.local.expect("No local part on real address"),
                        ),
                        domain: Cow::Owned(a.domain.unwrap()),
                    })
                } else {
                    s::Address::GroupDelim(a.local.map(Cow::Owned))
                }
            })
            .collect()
    }

    let from = addresses_to_ast(env.from);
    s::Envelope {
        date: env.date.map(Cow::Owned),
        subject: env.subject.map(Cow::Owned),
        sender: if env.sender.is_empty() {
            from.clone()
        } else {
            addresses_to_ast(env.sender)
        },
        reply_to: if env.reply_to.is_empty() {
            from.clone()
        } else {
            addresses_to_ast(env.reply_to)
        },
        from,
        to: addresses_to_ast(env.to),
        cc: addresses_to_ast(env.cc),
        bcc: addresses_to_ast(env.bcc),
        in_reply_to: env.in_reply_to.map(Cow::Owned),
        message_id: env.message_id.map(Cow::Owned),
    }
}

fn body_structure_to_ast(
    mut bs: fetch::bodystructure::BodyStructure,
    extended: bool,
) -> s::Body<'static> {
    if bs.content_type.0.eq_ignore_ascii_case("multipart") {
        s::Body::Multipart(s::BodyTypeMPart {
            bodies: bs
                .children
                .into_iter()
                .map(|c| body_structure_to_ast(c, extended))
                .collect(),
            media_subtype: Cow::Owned(bs.content_type.1),
            ext: if extended {
                Some(s::BodyExtMPart {
                    content_type_parms: content_parms_to_ast(
                        bs.content_type_parms,
                    ),
                    content_disposition: content_disposition_to_ast(
                        bs.content_disposition,
                        bs.content_disposition_parms,
                    ),
                    content_language: bs.content_language.map(Cow::Owned),
                    content_location: bs.content_location.map(Cow::Owned),
                })
            } else {
                None
            },
        })
    } else {
        let body_fields = s::BodyFields {
            content_type_parms: content_parms_to_ast(bs.content_type_parms),
            content_id: bs.content_id.map(Cow::Owned),
            content_description: bs.content_description.map(Cow::Owned),
            content_transfer_encoding: bs
                .content_transfer_encoding
                .map_or(Cow::Borrowed("7bit"), Cow::Owned),
            size_octets: bs.size_octets.try_into().unwrap_or(u32::MAX),
        };

        let core = if bs.content_type.0.eq_ignore_ascii_case("message")
            && bs.content_type.1.eq_ignore_ascii_case("rfc822")
        {
            s::ClassifiedBodyType1Part::Message(s::BodyTypeMsg {
                body_fields,
                // The envelope needs to reflect the content of the header
                // block **inside** this part.
                envelope: envelope_to_ast(if bs.children.is_empty() {
                    // Nothing to work with
                    bs.envelope
                } else {
                    mem::replace(&mut bs.children[0].envelope, bs.envelope)
                }),
                body: Box::new(body_structure_to_ast(
                    bs.children.into_iter().next().unwrap_or_default(),
                    extended,
                )),
                size_lines: bs.size_lines.try_into().unwrap_or(u32::MAX),
            })
        } else if bs.content_type.0.eq_ignore_ascii_case("text") {
            s::ClassifiedBodyType1Part::Text(s::BodyTypeText {
                media_subtype: Cow::Owned(bs.content_type.1),
                body_fields,
                size_lines: bs.size_lines.try_into().unwrap_or(u32::MAX),
            })
        } else {
            s::ClassifiedBodyType1Part::Basic(s::BodyTypeBasic {
                media_type: Cow::Owned(bs.content_type.0),
                media_subtype: Cow::Owned(bs.content_type.1),
                body_fields,
            })
        };

        s::Body::SinglePart(s::BodyType1Part {
            core,
            ext: if extended {
                Some(s::BodyExt1Part {
                    md5: Some(Cow::Owned(bs.md5)),
                    content_disposition: content_disposition_to_ast(
                        bs.content_disposition,
                        bs.content_disposition_parms,
                    ),
                    content_language: bs.content_language.map(Cow::Owned),
                    content_location: bs.content_location.map(Cow::Owned),
                })
            } else {
                None
            },
        })
    }
}

fn content_parms_to_ast(
    parms: Vec<(String, String)>,
) -> Vec<Cow<'static, str>> {
    let mut ret: Vec<Cow<'static, str>> = Vec::with_capacity(2 * parms.len());
    for (k, v) in parms {
        ret.push(Cow::Owned(k));
        ret.push(Cow::Owned(v));
    }
    ret
}

fn content_disposition_to_ast(
    disposition: Option<String>,
    parms: Vec<(String, String)>,
) -> Option<s::ContentDisposition<'static>> {
    disposition.map(|disposition| s::ContentDisposition {
        disposition: Cow::Owned(disposition),
        parms: content_parms_to_ast(parms),
    })
}
