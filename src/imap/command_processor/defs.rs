//-
// Copyright (c) 2020, 2022, Jason Lingle
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
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use log::error;

use crate::account::{
    account::Account,
    mailbox::{StatefulMailbox, StatelessMailbox},
    model::*,
};
use crate::support::{error::Error, system_config::SystemConfig};

pub(super) use crate::imap::syntax as s;

pub(super) static CAPABILITIES: &[&str] = &[
    "IMAP4rev1",
    "IMAP4rev2",
    concat_appendlimit!("APPENDLIMIT="),
    "AUTH=PLAIN",
    "BINARY",
    "CHILDREN",
    "COMPRESS=DEFLATE",
    "CONDSTORE",
    "CREATE-SPECIAL-USE",
    "ENABLE",
    "ESEARCH",
    "ID",
    "IDLE",
    "LIST-EXTENDED",
    "LIST-STATUS",
    "LITERAL+",
    "MOVE",
    "MULTIAPPEND",
    "NAMESPACE",
    "OBJECTID",
    "QRESYNC",
    "SASL-IR",
    "SEARCHRES",
    "SPECIAL-USE",
    "STATUS=SIZE",
    "UIDPLUS",
    "UNSELECT",
    "UTF8=ACCEPT",
    "XCRY",
    "XLIST",
    "XVANQUISH",
    "XYZZY",
];

pub(super) static TAGLINE: &str = concat!(
    "It's my IMAP and I'll CRY if I want to! (",
    env!("CARGO_PKG_NAME"),
    " ",
    env!("CARGO_PKG_VERSION_MAJOR"),
    ".",
    env!("CARGO_PKG_VERSION_MINOR"),
    ".",
    env!("CARGO_PKG_VERSION_PATCH"),
    " ready)"
);

/// Receives commands in the raw AST defined in the `syntax` module, and emits
/// responses in that same raw AST model.
///
/// While primarily a translation layer, it also manages high-level IMAP state
/// (e.g., authentication status) and also handles certain cases where one IMAP
/// command does multiple distinct actions (e.g. `FETCH BODY[]` does an
/// implicit `STORE`, `CLOSE` does an implicit `EXPUNGE`).
pub struct CommandProcessor {
    pub(super) log_prefix: String,
    pub(super) system_config: Arc<SystemConfig>,
    pub(super) data_root: PathBuf,

    pub(super) account: Option<Account>,
    pub(super) selected: Option<StatefulMailbox>,
    pub(super) searchres: SeqRange<Uid>,
    pub(super) unicode_aware: bool,
    pub(super) utf8_enabled: bool,
    pub(super) condstore_enabled: bool,
    pub(super) qresync_enabled: bool,
    pub(super) imap4rev2_enabled: bool,

    pub(super) multiappend: Option<Multiappend>,

    pub(super) logged_out: bool,

    pub(super) id_exchanged: bool,
}

pub(super) struct Multiappend {
    pub(super) dst: StatelessMailbox,
    pub(super) request: AppendRequest,
}

/// Used just for the convenient `?` operator. We mostly don't distinguish `Ok`
/// from `Err` --- the contained value is sent down the wire --- though on
/// `Err` no polling happens.
pub(super) type CmdResult = Result<s::Response<'static>, s::Response<'static>>;

/// Return value from an operation that can either succeed with a value, or
/// fail with an IMAP response.
pub(super) type PartialResult<T> = Result<T, s::Response<'static>>;

/// Function pointer used to send additional non-tagged responses.
pub(super) type SendResponse<'a> = &'a (dyn Send + Sync + Fn(s::Response<'_>));

impl CommandProcessor {
    pub fn new(
        log_prefix: String,
        system_config: Arc<SystemConfig>,
        data_root: PathBuf,
    ) -> Self {
        CommandProcessor {
            log_prefix,
            system_config,
            data_root,

            account: None,
            selected: None,
            searchres: SeqRange::new(),
            unicode_aware: false,
            utf8_enabled: false,
            condstore_enabled: false,
            qresync_enabled: false,
            imap4rev2_enabled: false,

            multiappend: None,

            logged_out: false,

            id_exchanged: false,
        }
    }

    pub fn unicode_aware(&self) -> bool {
        self.unicode_aware
    }

    pub fn logged_out(&self) -> bool {
        self.logged_out
    }

    pub fn log_prefix(&self) -> &str {
        &self.log_prefix
    }

    pub(super) fn parse_seqnum_range(
        &mut self,
        raw: &str,
    ) -> PartialResult<SeqRange<Seqnum>> {
        if "$" == raw {
            return Ok(selected!(self)?.uid_range_to_seqnum(&self.searchres));
        }

        let max_seqnum = selected!(self)?.max_seqnum().unwrap_or(Seqnum::MIN);
        let seqrange = SeqRange::parse(raw, max_seqnum).ok_or_else(|| {
            s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::Bad,
                code: Some(s::RespTextCode::Parse(())),
                quip: Some(Cow::Borrowed("Unparsable sequence set")),
            })
        })?;

        if seqrange.max().unwrap_or(0) > max_seqnum.0.get() {
            // This behaviour is not explicitly described in RFC 3501, but
            // Crispin mentions it a couple times in the mailing list --- if
            // the client requests a seqnum outside the current snapshot, it's
            // a protocol violation and we return BAD.
            return Err(s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::Bad,
                code: Some(s::RespTextCode::ClientBug(())),
                quip: Some(Cow::Borrowed(
                    "Message sequence number out of range",
                )),
            }));
        }

        Ok(seqrange)
    }

    pub(super) fn parse_uid_range(
        &mut self,
        raw: &str,
    ) -> PartialResult<SeqRange<Uid>> {
        if "$" == raw {
            let _ = selected!(self)?;
            return Ok(self.searchres.clone());
        }

        let max_uid = selected!(self)?.max_uid().unwrap_or(Uid::MIN);
        let seqrange = SeqRange::parse(raw, max_uid).ok_or_else(|| {
            s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::Bad,
                code: Some(s::RespTextCode::Parse(())),
                quip: Some(Cow::Borrowed("Unparsable sequence set")),
            })
        })?;

        // The client is explicitly allowed to request UIDs out of range, so
        // there's nothing else to validate here.

        Ok(seqrange)
    }
}

pub(super) fn success() -> CmdResult {
    Ok(s::Response::Cond(s::CondResponse {
        cond: s::RespCondType::Ok,
        code: None,
        quip: None,
    }))
}

pub(super) fn parse_global_seqrange<
    T: TryFrom<u32> + Into<u32> + PartialOrd + Send + Sync + Default,
>(
    s: &str,
) -> PartialResult<SeqRange<T>>
where
    SeqRange<T>: fmt::Debug,
{
    if s.contains('*') {
        return Err(s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Bad,
            code: Some(s::RespTextCode::Parse(())),
            quip: Some(Cow::Borrowed("'*' not allowed in sequence set here")),
        }));
    }

    SeqRange::parse(s, T::default()).ok_or_else(|| {
        s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Bad,
            code: Some(s::RespTextCode::Parse(())),
            quip: Some(Cow::Borrowed("Invalid sequence set")),
        })
    })
}

#[cfg(not(test))]
pub(super) fn catch_all_error_handling(
    selected_ok: bool,
    log_prefix: &str,
    e: Error,
) -> s::Response<'static> {
    // Don't log if the selected mailbox is gone; it's probably a result of
    // that.
    if selected_ok {
        error!("{} Unhandled internal error: {}", log_prefix, e);
    }

    s::Response::Cond(s::CondResponse {
        cond: s::RespCondType::No,
        code: Some(s::RespTextCode::ServerBug(())),
        quip: Some(Cow::Borrowed(
            "Unexpected error; check server logs for details",
        )),
    })
}

#[cfg(test)]
pub(super) fn catch_all_error_handling(
    selected_ok: bool,
    log_prefix: &str,
    e: Error,
) -> s::Response<'static> {
    if !selected_ok {
        s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::No,
            code: Some(s::RespTextCode::ServerBug(())),
            quip: Some(Cow::Borrowed(
                "Unexpected error; check server logs for details",
            )),
        })
    } else {
        error!("{} Unhandled internal error: {}", log_prefix, e);
        panic!("{} Unhandled internal error: {}", log_prefix, e);
    }
}
