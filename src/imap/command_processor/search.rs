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
use std::convert::TryFrom;
use std::marker::PhantomData;

use super::defs::*;
use crate::account::mailbox::StatefulMailbox;
use crate::account::model::*;
use crate::support::error::Error;

impl CommandProcessor {
    pub(super) fn cmd_search(
        &mut self,
        cmd: s::SearchCommand<'_>,
        tag: &str,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        self.search(cmd, tag, sender, false, StatefulMailbox::seqnum_search)
    }

    pub(super) fn cmd_uid_search(
        &mut self,
        cmd: s::SearchCommand<'_>,
        tag: &str,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        self.search(cmd, tag, sender, true, StatefulMailbox::search)
    }

    fn search<
        T: Into<u32> + TryFrom<u32> + Into<u32> + PartialOrd + Send + Sync + Copy,
    >(
        &mut self,
        mut cmd: s::SearchCommand<'_>,
        tag: &str,
        sender: SendResponse<'_>,
        is_uid: bool,
        f: impl FnOnce(
            &mut StatefulMailbox,
            &SearchRequest,
        ) -> Result<SearchResponse<T>, Error>,
    ) -> CmdResult {
        // RFC 4731 indicates:
        //
        // > If one or more result options described above are specified, the
        // > extended SEARCH command MUST return a single ESEARCH response
        //
        // This means that `SEARCH RETURN () ...` is semantically equivalent to
        // `SEARCH ...` and should return a vanilla SEARCH response instead of
        // ESEARCH, which is a bit weird since it's using extended search
        // syntax, but it makes our lives a bit easier.
        let return_opts = cmd.return_opts.take().unwrap_or_default();
        let return_extended = !return_opts.is_empty();

        let mut has_modseq = false;
        let request = self.search_command_from_ast(&mut has_modseq, cmd)?;

        if has_modseq && self.selected.is_some() {
            self.enable_condstore(sender, true);
        }

        let response =
            f(selected!(self)?, &request).map_err(map_error!(self))?;
        let mut return_response = false;

        let response = if return_extended {
            let mut r = s::EsearchResponse {
                tag: Cow::Borrowed(tag),
                uid: is_uid,
                min: None,
                max: None,
                all: None,
                count: None,
                modseq: None,
            };
            let mut modseq: Option<Modseq> = None;

            if return_opts.contains(&s::SearchReturnOpt::Save) {
                self.searchres.clear();

                // Per RFC 5182, SAVE interacts with MIN and MAX
                // pathologically: if either was specified, and no additional
                // return option that would cause all matching messages to be
                // enumerated was specified, only the MIN and MAX which were
                // requested are saved.
                if return_opts.contains(&s::SearchReturnOpt::All)
                    || return_opts.contains(&s::SearchReturnOpt::Count)
                    || (!return_opts.contains(&s::SearchReturnOpt::Min)
                        && !return_opts.contains(&s::SearchReturnOpt::Max))
                {
                    // Sane case
                    for uid in response.hit_uids {
                        self.searchres.append(uid);
                    }
                } else {
                    // Pathological case
                    if return_opts.contains(&s::SearchReturnOpt::Min) {
                        if let Some(&uid) = response.hit_uids.first() {
                            self.searchres.append(uid);
                        }
                    }

                    if return_opts.contains(&s::SearchReturnOpt::Max) {
                        if let Some(&uid) = response.hit_uids.last() {
                            // MIN could have inserted the same UID already
                            if !self.searchres.contains(uid) {
                                self.searchres.append(uid);
                            }
                        }
                    }
                }
            }

            if return_opts.contains(&s::SearchReturnOpt::Min) {
                r.min = response.hits.first().map(|&hit| hit.into());
                modseq = response.first_modseq;
                return_response = true;
            }

            if return_opts.contains(&s::SearchReturnOpt::Max) {
                r.max = response.hits.last().map(|&hit| hit.into());
                // If given MIN + MAX, the modseq is the maximum of the two
                if let Some(last_modseq) = response.last_modseq {
                    modseq = modseq
                        .map(|m| m.max(last_modseq))
                        .or(response.last_modseq);
                }
                return_response = true;
            }

            if return_opts.contains(&s::SearchReturnOpt::All)
                && !response.hits.is_empty()
            {
                let mut sr = SeqRange::new();
                for &hit in &response.hits {
                    sr.append(hit);
                }
                r.all = Some(Cow::Owned(sr.to_string()));
                modseq = response.max_modseq;
                return_response = true;
            }

            if return_opts.contains(&s::SearchReturnOpt::Count) {
                r.count = Some(response.hits.len() as u32);
                modseq = response.max_modseq;
                return_response = true;
            }

            if has_modseq {
                r.modseq = modseq.map(|m| m.raw().get());
            }

            s::Response::Esearch(r)
        } else {
            return_response = true;
            s::Response::Search(s::SearchResponse {
                hits: response.hits.into_iter().map(|u| u.into()).collect(),
                // Only return the MODSEQ item if the client specified a MODSEQ
                // criterion.
                max_modseq: if has_modseq {
                    response.max_modseq.map(|m| m.raw().get())
                } else {
                    None
                },
                _marker: PhantomData,
            })
        };

        if return_response {
            sender(response);
        }
        success()
    }

    fn search_command_from_ast(
        &mut self,
        has_modseq: &mut bool,
        cmd: s::SearchCommand<'_>,
    ) -> PartialResult<SearchRequest> {
        if let Some(charset) = cmd.charset {
            // RFC 6855 says we SHOULD reject SEARCH commands with a charset
            // specification. We don't, since that's a landmine for clients,
            // and the only thing we accept is UTF-8 either way, so there's no
            // possibility for conflicting charsets.
            if !charset.eq_ignore_ascii_case("us-ascii")
                && !charset.eq_ignore_ascii_case("utf-8")
            {
                return Err(s::Response::Cond(s::CondResponse {
                    cond: s::RespCondType::No,
                    code: Some(s::RespTextCode::BadCharset(vec![
                        Cow::Borrowed("us-ascii"),
                        Cow::Borrowed("utf-8"),
                    ])),
                    quip: None,
                }));
            }
        }

        Ok(SearchRequest {
            queries: cmd
                .keys
                .into_iter()
                .map(|k| self.search_query_from_ast(has_modseq, k))
                .collect::<PartialResult<Vec<_>>>()?,
        })
    }

    fn search_query_from_ast(
        &mut self,
        has_modseq: &mut bool,
        k: s::SearchKey<'_>,
    ) -> PartialResult<SearchQuery> {
        match k {
            s::SearchKey::Simple(simple) => Ok(match simple {
                s::SimpleSearchKey::All => SearchQuery::All,
                s::SimpleSearchKey::Answered => SearchQuery::Answered,
                s::SimpleSearchKey::Deleted => SearchQuery::Deleted,
                s::SimpleSearchKey::Flagged => SearchQuery::Flagged,
                s::SimpleSearchKey::New => SearchQuery::New,
                s::SimpleSearchKey::Old => SearchQuery::Old,
                s::SimpleSearchKey::Recent => SearchQuery::Recent,
                s::SimpleSearchKey::Seen => SearchQuery::Seen,
                s::SimpleSearchKey::Unanswered => SearchQuery::Unanswered,
                s::SimpleSearchKey::Undeleted => SearchQuery::Undeleted,
                s::SimpleSearchKey::Unflagged => SearchQuery::Unflagged,
                s::SimpleSearchKey::Unseen => SearchQuery::Unseen,
                s::SimpleSearchKey::Draft => SearchQuery::Draft,
                s::SimpleSearchKey::Undraft => SearchQuery::Undraft,
            }),
            s::SearchKey::Text(text_key) => {
                let val = text_key.value.into_owned();
                Ok(match text_key.typ {
                    s::TextSearchKeyType::Bcc => SearchQuery::Bcc(val),
                    s::TextSearchKeyType::Body => SearchQuery::Body(val),
                    s::TextSearchKeyType::Cc => SearchQuery::Cc(val),
                    s::TextSearchKeyType::From => SearchQuery::From(val),
                    s::TextSearchKeyType::Subject => SearchQuery::Subject(val),
                    s::TextSearchKeyType::Text => SearchQuery::Text(val),
                    s::TextSearchKeyType::To => SearchQuery::To(val),
                })
            }
            s::SearchKey::Date(date_key) => {
                let date = date_key.date;
                Ok(match date_key.typ {
                    s::DateSearchKeyType::Before => SearchQuery::Before(date),
                    s::DateSearchKeyType::On => SearchQuery::On(date),
                    s::DateSearchKeyType::Since => SearchQuery::Since(date),
                    s::DateSearchKeyType::SentBefore => {
                        SearchQuery::SentBefore(date)
                    }
                    s::DateSearchKeyType::SentOn => SearchQuery::SentOn(date),
                    s::DateSearchKeyType::SentSince => {
                        SearchQuery::SentSince(date)
                    }
                })
            }
            s::SearchKey::Keyword(flag) => {
                Ok(SearchQuery::Keyword(flag.to_string()))
            }
            s::SearchKey::Unkeyword(flag) => {
                Ok(SearchQuery::Unkeyword(flag.to_string()))
            }
            s::SearchKey::Header(header) => Ok(SearchQuery::Header(
                header.header.into_owned(),
                header.value.into_owned(),
            )),
            s::SearchKey::Larger(thresh) => Ok(SearchQuery::Larger(thresh)),
            s::SearchKey::Not(sub) => Ok(SearchQuery::Not(Box::new(
                self.search_query_from_ast(has_modseq, *sub)?,
            ))),
            s::SearchKey::Or(or) => Ok(SearchQuery::Or(
                Box::new(self.search_query_from_ast(has_modseq, *or.a)?),
                Box::new(self.search_query_from_ast(has_modseq, *or.b)?),
            )),
            s::SearchKey::Smaller(thresh) => Ok(SearchQuery::Smaller(thresh)),
            s::SearchKey::Uid(ss) => {
                Ok(SearchQuery::UidSet(self.parse_uid_range(&ss)?))
            }
            s::SearchKey::Seqnum(ss) => {
                Ok(SearchQuery::SequenceSet(self.parse_seqnum_range(&ss)?))
            }
            s::SearchKey::And(parts) => Ok(SearchQuery::And(
                parts
                    .into_iter()
                    .map(|part| self.search_query_from_ast(has_modseq, part))
                    .collect::<PartialResult<Vec<_>>>()?,
            )),
            s::SearchKey::Modseq(m) => {
                *has_modseq = true;
                Ok(SearchQuery::Modseq(m.modseq))
            }
        }
    }
}
