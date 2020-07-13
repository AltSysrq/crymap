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

use std::borrow::Cow;
use std::convert::TryInto;
use std::fmt;
use std::mem;

use log::{error, warn};

use super::defs::*;
use crate::account::{mailbox::StatefulMailbox, model::*};
use crate::imap::literal_source::LiteralSource;
use crate::mime::fetch::{self, section::*};
use crate::support::error::Error;

impl CommandProcessor {
    pub(super) fn cmd_fetch(
        &mut self,
        cmd: s::FetchCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        let ids = self.parse_seqnum_range(&cmd.messages)?;
        self.fetch(
            cmd,
            sender,
            ids,
            false,
            StatefulMailbox::seqnum_store,
            StatefulMailbox::seqnum_fetch,
        )
    }

    pub(super) fn cmd_uid_fetch(
        &mut self,
        cmd: s::FetchCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        let ids = self.parse_uid_range(&cmd.messages)?;
        self.fetch(cmd, sender, ids, true, StatefulMailbox::store, |mb, r| {
            mb.fetch(&r)
        })
    }

    pub(super) fn fetch_for_background_update(
        &mut self,
        sender: SendResponse<'_>,
        uids: Vec<Uid>,
    ) {
        let mut ids = SeqRange::new();
        for uid in uids {
            ids.append(uid);
        }

        let _ = self.fetch(
            s::FetchCommand {
                messages: Cow::Borrowed(""),
                target: s::FetchCommandTarget::Multi(vec![
                    s::FetchAtt::Uid(()),
                    s::FetchAtt::Flags(()),
                ]),
            },
            sender,
            ids,
            false,
            |_, _| panic!("Shouldn't STORE in background update"),
            |mb, r| mb.fetch(&r),
        );
    }

    fn fetch<ID: Default>(
        &mut self,
        cmd: s::FetchCommand<'_>,
        sender: SendResponse<'_>,
        ids: SeqRange<ID>,
        force_fetch_uid: bool,
        f_store: impl FnOnce(
            &mut StatefulMailbox,
            &StoreRequest<ID>,
        ) -> Result<StoreResponse<ID>, Error>,
        f_fetch: impl FnOnce(
            &mut StatefulMailbox,
            FetchRequest<ID>,
        ) -> Result<FetchResponse, Error>,
    ) -> CmdResult
    where
        SeqRange<ID>: fmt::Debug,
    {
        let mut request = FetchRequest {
            ids,
            uid: force_fetch_uid,
            ..FetchRequest::default()
        };

        let fetch_properties = fetch_properties(&cmd.target);
        fetch_target_from_ast(&mut request, cmd.target);

        let selected = selected!(self)?;

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
        if fetch_properties.set_seen && !selected.stateless().read_only() {
            let store_res = f_store(
                selected,
                &StoreRequest {
                    ids: &request.ids,
                    flags: &[Flag::Seen],
                    remove_listed: false,
                    remove_unlisted: false,
                    // We must ensure that the client sees the updates this causes.
                    loud: true,
                    unchanged_since: None,
                },
            );
            if let Err(e) = store_res {
                warn!(
                    "{} Implicit STORE \\Seen failed: {}",
                    self.log_prefix, e
                );
            }
        }

        // TODO It would be better to stream these responses out rather than
        // buffer them
        let response = f_fetch(selected, request).map_err(map_error! {
            self,
            MasterKeyUnavailable | BadEncryptedKey | ExpungedMessage |
            NxMessage | UnaddressableMessage => (No, None),
        })?;
        fetch_response(sender, response, fetch_properties)
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct FetchProperties {
    set_seen: bool,
    extended_body_structure: bool,
}

fn fetch_properties(target: &s::FetchCommandTarget<'_>) -> FetchProperties {
    let mut props = FetchProperties::default();

    match *target {
        s::FetchCommandTarget::Single(ref att) => {
            scan_fetch_properties(&mut props, att);
        }
        s::FetchCommandTarget::Multi(ref atts) => {
            for att in atts {
                scan_fetch_properties(&mut props, att);
            }
        }
        _ => (),
    }

    props
}

fn scan_fetch_properties(props: &mut FetchProperties, att: &s::FetchAtt<'_>) {
    match *att {
        s::FetchAtt::ExtendedBodyStructure(_) => {
            props.extended_body_structure = true;
        }
        s::FetchAtt::Body(ref body) if !body.peek => {
            props.set_seen = true;
        }
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
        }
        s::FetchCommandTarget::Fast(()) => {
            request.flags = true;
            request.internal_date = true;
            request.rfc822size = true;
        }
        s::FetchCommandTarget::Full(()) => {
            request.flags = true;
            request.internal_date = true;
            request.rfc822size = true;
            request.envelope = true;
            request.bodystructure = true;
        }
        s::FetchCommandTarget::Single(att) => {
            fetch_att_from_ast(request, att);
        }
        s::FetchCommandTarget::Multi(atts) => {
            for att in atts {
                fetch_att_from_ast(request, att);
            }
        }
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
        s::FetchAtt::Rfc822(Some(s::FetchAttRfc822::Size)) => {
            request.rfc822size = true;
        }
        s::FetchAtt::ExtendedBodyStructure(())
        | s::FetchAtt::ShortBodyStructure(()) => {
            request.bodystructure = true;
        }
        s::FetchAtt::Uid(()) => request.uid = true,
        s::FetchAtt::Rfc822(Some(s::FetchAttRfc822::Header)) => {
            request.sections.push(BodySection {
                leaf_type: LeafType::Headers,
                report_as_legacy: Some(Imap2Section::Rfc822Header),
                ..BodySection::default()
            });
        }
        s::FetchAtt::Rfc822(Some(s::FetchAttRfc822::Text)) => {
            request.sections.push(BodySection {
                leaf_type: LeafType::Content,
                report_as_legacy: Some(Imap2Section::Rfc822Text),
                ..BodySection::default()
            });
        }
        s::FetchAtt::Rfc822(None) => {
            request.sections.push(BodySection {
                leaf_type: LeafType::Full,
                report_as_legacy: Some(Imap2Section::Rfc822),
                ..BodySection::default()
            });
        }
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
                    }
                    Some(s::SectionText::Header(())) => {
                        section.leaf_type = LeafType::Headers;
                    }
                    Some(s::SectionText::Text(())) => {
                        section.leaf_type = LeafType::Text;
                    }
                    Some(s::SectionText::Mime(())) => {
                        section.leaf_type = LeafType::Mime;
                    }
                    None => section.leaf_type = LeafType::Content,
                }
            }

            let mut section = BodySection::default();
            match body.section {
                None => (),
                Some(s::SectionSpec::TopLevel(spec)) => {
                    apply_section_text(&mut section, Some(spec));
                }
                Some(s::SectionSpec::Sub(spec)) => {
                    section.subscripts = spec.subscripts;
                    apply_section_text(&mut section, spec.text);
                }
            }
            if let Some(slice) = body.slice {
                let start: u64 = slice.start.into();
                let length: u64 = slice.length.into();
                let end = start + length;
                section.partial = Some((start, end));
            }

            request.sections.push(section);
        }
    }
}

fn fetch_response(
    sender: SendResponse,
    response: FetchResponse,
    fetch_properties: FetchProperties,
) -> CmdResult {
    if !response.flags.is_empty() {
        sender(s::Response::Flags(response.flags));
    }

    for (seqnum, items) in response.fetched {
        sender(s::Response::Fetch(s::FetchResponse {
            seqnum: seqnum.0.get(),
            atts: s::MsgAtts {
                atts: items
                    .into_iter()
                    .filter_map(|att| fetch_att_to_ast(att, fetch_properties))
                    .collect(),
            },
        }));
    }

    match response.kind {
        FetchResponseKind::Ok => success(),
        FetchResponseKind::No => Ok(s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::No,
            code: None,
            quip: Some(Cow::Borrowed(
                "Message state out of sync; suggest NOOP",
            )),
        })),
        FetchResponseKind::Bye => Err(s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Bye,
            code: None,
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
        FI::Modseq(_modseq) => unimplemented!("Modseq not yet implemented"),
        FI::Flags(flags) => Some(s::MsgAtt::Flags(if flags.recent {
            s::FlagsFetch::Recent(flags.flags)
        } else {
            s::FlagsFetch::NotRecent(flags.flags)
        })),
        FI::Rfc822Size(size) => Some(s::MsgAtt::Rfc822Size(size)),
        FI::InternalDate(dt) => Some(s::MsgAtt::InternalDate(dt)),
        FI::Envelope(env) => Some(s::MsgAtt::Envelope(envelope_to_ast(env))),
        FI::BodyStructure(bs) => {
            let converted = body_structure_to_ast(
                bs,
                fetch_properties.extended_body_structure,
            );
            Some(if fetch_properties.extended_body_structure {
                s::MsgAtt::ExtendedBodyStructure(converted)
            } else {
                s::MsgAtt::ShortBodyStructure(converted)
            })
        }
        FI::BodySection(Err(e)) => {
            // TODO We should make BodySection be (BodySection, Result<Data>)
            // or something, so then we could do the proper catch-all case and
            // return `SECTION {0}` here.
            error!("Dropping unfetchable body section: {}", e);
            None
        }
        FI::BodySection(Ok(mut fetched)) => {
            let len = fetched.buffer.len();
            let data = LiteralSource::of_reader(fetched.buffer, len, false);

            match fetched.section.report_as_legacy {
                None => (),
                Some(Imap2Section::Rfc822) => {
                    return Some(s::MsgAtt::Rfc822Full(data));
                }
                Some(Imap2Section::Rfc822Header) => {
                    return Some(s::MsgAtt::Rfc822Header(data));
                }
                Some(Imap2Section::Rfc822Text) => {
                    return Some(s::MsgAtt::Rfc822Text(data));
                }
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
                    }
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

            let partial = fetched.section.partial;
            let section_spec = match (
                fetched.section.subscripts.is_empty(),
                fetched.section.leaf_type,
            ) {
                (true, LeafType::Full) => None,
                (true, _) => Some(s::SectionSpec::TopLevel(
                    section_text_to_ast(fetched.section)
                        .expect("Content leaf at top-level?"),
                )),
                (false, _) => Some(s::SectionSpec::Sub(s::SubSectionSpec {
                    subscripts: mem::replace(
                        &mut fetched.section.subscripts,
                        vec![],
                    ),
                    text: section_text_to_ast(fetched.section),
                })),
            };

            Some(s::MsgAtt::Body(s::MsgAttBody {
                section: section_spec,
                slice_origin: partial.map(|(start, _)| {
                    let start: u32 = start.try_into().unwrap_or(u32::MAX);
                    start
                }),
                data,
            }))
        }
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
                        routing: None,
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
    bs: fetch::bodystructure::BodyStructure,
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
            content_transfer_encoding: Cow::Borrowed(
                bs.content_transfer_encoding.name(),
            ),
            size_octets: bs.size_octets.try_into().unwrap_or(u32::MAX),
        };

        let core = if bs.content_type.0.eq_ignore_ascii_case("message")
            && bs.content_type.1.eq_ignore_ascii_case("rfc822")
        {
            s::ClassifiedBodyType1Part::Message(s::BodyTypeMsg {
                body_fields,
                envelope: envelope_to_ast(bs.envelope),
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