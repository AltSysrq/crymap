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

use super::defs::*;
use crate::account::model::*;

impl CommandProcessor {
    pub(super) fn cmd_search(
        &mut self,
        cmd: s::SearchCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        let request = self.search_command_from_ast(cmd)?;
        let response = selected!(self)?
            .seqnum_search(&request)
            .map_err(map_error!(self))?;

        sender(s::Response::Search(
            response.hits.into_iter().map(|u| u.0.get()).collect(),
        ));
        success()
    }

    pub(super) fn cmd_uid_search(
        &mut self,
        cmd: s::SearchCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        let request = self.search_command_from_ast(cmd)?;
        let response = selected!(self)?
            .search(&request)
            .map_err(map_error!(self))?;

        sender(s::Response::Search(
            response.hits.into_iter().map(|u| u.0.get()).collect(),
        ));
        success()
    }

    fn search_command_from_ast(
        &mut self,
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
                .map(|k| self.search_query_from_ast(k))
                .collect::<PartialResult<Vec<_>>>()?,
        })
    }

    fn search_query_from_ast(
        &mut self,
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
                self.search_query_from_ast(*sub)?,
            ))),
            s::SearchKey::Or(or) => Ok(SearchQuery::Or(
                Box::new(self.search_query_from_ast(*or.a)?),
                Box::new(self.search_query_from_ast(*or.b)?),
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
                    .map(|part| self.search_query_from_ast(part))
                    .collect::<PartialResult<Vec<_>>>()?,
            )),
        }
    }
}
