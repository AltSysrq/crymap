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

// TODO Delete once all the stubs are filled in
#![cfg_attr(not(test), allow(unused_variables))]

use std::borrow::Cow;
use std::convert::TryInto;
use std::sync::Arc;
use std::time::Instant;

use log::{error, warn};

use crate::account::{
    account::Account,
    mailbox::{StatefulMailbox, StatelessMailbox},
    model::*,
};
use crate::imap::syntax as s;
use crate::support::{error::Error, system_config::SystemConfig};

macro_rules! map_error {
    ($this:expr) => {
        |e| $this.catch_all_error_handling(e)
    };

    ($this:expr, $($($kind:ident)|+ => ($cond:ident, $code:expr),)+) => {
        |e| match e {
            $($(Error::$kind)|* => s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::$cond,
                code: $code,
                quip: Some(Cow::Owned(e.to_string())),
            }),)*
            e => $this.catch_all_error_handling(e),
        }
    };
}

static CAPABILITIES: &[&str] = &["IMAP4rev1", "AUTH=PLAIN", "XYZZY"];

static TAGLINE: &str = concat!(
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
    log_prefix: String,
    system_config: Arc<SystemConfig>,
    account: Option<Account>,
    selected: Option<StatefulMailbox>,

    caches_cleared: Option<Instant>,

    multiappend: Option<Multiappend>,
}

struct Multiappend {
    dst: StatelessMailbox,
    request: AppendRequest,
}

/// Used just for the convenient `?` operator. We mostly don't distinguish `Ok`
/// from `Err` --- the contained value is sent down the wire --- though on
/// `Err` no polling happens.
type CmdResult = Result<s::Response<'static>, s::Response<'static>>;

/// Return value from an operation that can either succeed with a value, or
/// fail with an IMAP response.
type PartialResult<T> = Result<T, s::Response<'static>>;

/// Function pointer used to send additional non-tagged responses.
type SendResponse<'a> = &'a (dyn Send + Sync + Fn(s::Response<'_>));

impl CommandProcessor {
    pub fn new(log_prefix: String, system_config: Arc<SystemConfig>) -> Self {
        CommandProcessor {
            log_prefix,
            system_config,
            account: None,
            selected: None,

            caches_cleared: None,

            multiappend: None,
        }
    }

    pub fn greet(&self) -> s::ResponseLine<'static> {
        s::ResponseLine {
            tag: None,
            response: s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::Ok,
                code: Some(s::RespTextCode::Capability(capability_data())),
                quip: Some(Cow::Borrowed(TAGLINE)),
            }),
        }
    }

    /// Handles a regular command, i.e., one that the protocol level does not
    /// give special treatment to.
    ///
    /// `sender` can be called with secondary responses as needed.
    ///
    /// Returns the final, tagged response. If the response condition is `BYE`,
    /// the connection will be closed after sending it.
    pub fn handle_command<'a>(
        &mut self,
        command_line: s::CommandLine<'a>,
        sender: SendResponse<'_>,
    ) -> s::ResponseLine<'a> {
        let res = match command_line.cmd {
            s::Command::Simple(s::SimpleCommand::Capability) => {
                self.cmd_capability(sender)
            }
            s::Command::Simple(s::SimpleCommand::Check) => {
                self.cmd_noop("Nothing exciting", sender)
            }
            s::Command::Simple(s::SimpleCommand::Close) => {
                self.cmd_close(sender)
            }
            s::Command::Simple(s::SimpleCommand::Expunge) => {
                self.cmd_expunge(sender)
            }
            s::Command::Simple(s::SimpleCommand::LogOut) => {
                self.cmd_log_out(sender)
            }
            s::Command::Simple(s::SimpleCommand::Noop) => {
                self.cmd_noop("NOOP OK", sender)
            }
            s::Command::Simple(s::SimpleCommand::StartTls) => {
                self.cmd_start_tls(sender)
            }
            s::Command::Simple(s::SimpleCommand::Xyzzy) => {
                self.cmd_noop("Nothing happens", sender)
            }

            s::Command::Create(cmd) => self.cmd_create(cmd, sender),
            s::Command::Delete(cmd) => self.cmd_delete(cmd, sender),
            s::Command::Examine(cmd) => self.cmd_examine(cmd, sender),
            s::Command::List(cmd) => self.cmd_list(cmd, sender),
            s::Command::Lsub(cmd) => self.cmd_lsub(cmd, sender),
            s::Command::Rename(cmd) => self.cmd_rename(cmd, sender),
            s::Command::Select(cmd) => self.cmd_select(cmd, sender),
            s::Command::Status(cmd) => self.cmd_status(cmd, sender),
            s::Command::Subscribe(cmd) => self.cmd_subscribe(cmd, sender),
            s::Command::Unsubscribe(cmd) => self.cmd_unsubscribe(cmd, sender),
            s::Command::LogIn(cmd) => self.cmd_log_in(cmd, sender),
            s::Command::Copy(cmd) => self.cmd_copy(cmd, sender),
            s::Command::Fetch(cmd) => self.cmd_fetch(cmd, sender),
            s::Command::Store(cmd) => self.cmd_store(cmd, sender),
            s::Command::Search(cmd) => self.cmd_search(cmd, sender),
            s::Command::Uid(s::UidCommand::Copy(cmd)) => {
                self.cmd_uid_copy(cmd, sender)
            }
            s::Command::Uid(s::UidCommand::Fetch(cmd)) => {
                self.cmd_uid_fetch(cmd, sender)
            }
            s::Command::Uid(s::UidCommand::Search(cmd)) => {
                self.cmd_uid_search(cmd, sender)
            }
            s::Command::Uid(s::UidCommand::Store(cmd)) => {
                self.cmd_uid_store(cmd, sender)
            }
        };

        let res = match res {
            Ok(res) => res,
            Err(res) => res,
        };

        if matches!(
            &res,
            &s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::Bye,
                ..
            })
        ) {
            // BYE is never tagged
            s::ResponseLine {
                tag: None,
                response: res,
            }
        } else {
            s::ResponseLine {
                tag: Some(command_line.tag),
                response: res,
            }
        }
    }

    fn cmd_capability(&mut self, sender: SendResponse<'_>) -> CmdResult {
        sender(s::Response::Capability(capability_data()));
        success()
    }

    fn cmd_noop(
        &mut self,
        quip: &'static str,
        _sender: SendResponse<'_>,
    ) -> CmdResult {
        // Nothing to do here; shared command processing takes care of the
        // actual poll operation.
        Ok(s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Ok,
            code: None,
            quip: Some(Cow::Borrowed(quip)),
        }))
    }

    fn cmd_close(&mut self, _sender: SendResponse<'_>) -> CmdResult {
        if let Some(mut selected) = self.selected.take() {
            if !selected.stateless().read_only() {
                if let Err(e) = selected.expunge_all_deleted() {
                    warn!(
                        "{} Implicit EXPUNGE failed: {}",
                        selected.stateless().log_prefix(),
                        e
                    );
                }
            }
        }

        success()
    }
    fn cmd_expunge(&mut self, _sender: SendResponse<'_>) -> CmdResult {
        // As with NOOP, the unsolicited responses that go with this are part
        // of the natural poll cycle.
        self.selected()?
            .expunge_all_deleted()
            .map_err(|e| self.catch_all_error_handling(e))?;
        success()
    }

    fn cmd_log_out(&mut self, _sender: SendResponse<'_>) -> CmdResult {
        Err(s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Bye,
            code: None,
            quip: Some(Cow::Borrowed("BYE")),
        }))
    }

    fn cmd_start_tls(&mut self, _sender: SendResponse<'_>) -> CmdResult {
        Err(s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Bad,
            code: None,
            quip: Some(Cow::Borrowed("Already using TLS")),
        }))
    }

    fn cmd_create(
        &mut self,
        cmd: s::CreateCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        let account = self.account()?;
        let request = CreateRequest {
            name: cmd.mailbox.into_owned(),
            special_use: vec![],
        };
        account.create(request).map_err(map_error! {
            self,
            MailboxExists | UnsafeName | BadOperationOnInbox => (No, None),
            // TODO This has its own code
            UnsupportedSpecialUse => (No, None),
        })?;
        success()
    }

    fn cmd_delete(
        &mut self,
        cmd: s::DeleteCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        let account = self.account()?;
        account.delete(&cmd.mailbox).map_err(map_error! {
            self,
            NxMailbox | UnsafeName | BadOperationOnInbox |
            MailboxHasInferiors => (No, None),
        })?;
        success()
    }

    fn cmd_examine(
        &mut self,
        cmd: s::ExamineCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        self.select(&cmd.mailbox, sender, true)
    }

    fn cmd_list(
        &mut self,
        cmd: s::ListCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        let request = ListRequest {
            reference: cmd.reference.into_owned(),
            patterns: vec![cmd.pattern.into_owned()],
            select_subscribed: false,
            select_special_use: false,
            recursive_match: false,
            return_subscribed: false,
            return_children: false,
            return_special_use: false,
            lsub_style: false,
        };

        let responses =
            self.account()?.list(&request).map_err(map_error!(self))?;
        for response in responses {
            sender(s::Response::List(s::MailboxList {
                flags: response
                    .attributes
                    .into_iter()
                    .map(|a| Cow::Borrowed(a.name()))
                    .collect(),
                name: Cow::Owned(response.name),
            }));
        }

        success()
    }

    fn cmd_lsub(
        &mut self,
        cmd: s::LsubCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        let request = ListRequest {
            reference: cmd.reference.into_owned(),
            patterns: vec![cmd.pattern.into_owned()],
            select_subscribed: true,
            select_special_use: false,
            recursive_match: true,
            return_subscribed: false,
            return_children: false,
            return_special_use: false,
            lsub_style: true,
        };

        let responses =
            self.account()?.list(&request).map_err(map_error!(self))?;
        for response in responses {
            sender(s::Response::Lsub(s::MailboxList {
                flags: response
                    .attributes
                    .into_iter()
                    .map(|a| Cow::Borrowed(a.name()))
                    .collect(),
                name: Cow::Owned(response.name),
            }));
        }

        success()
    }

    fn cmd_rename(
        &mut self,
        cmd: s::RenameCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        let account = self.account()?;
        let request = RenameRequest {
            existing_name: cmd.src.into_owned(),
            new_name: cmd.dst.into_owned(),
        };

        account.rename(request).map_err(map_error! {
            self,
            NxMailbox | BadOperationOnInbox | MailboxExists |
            RenameToSelf | RenameIntoSelf => (No, None),
        })?;

        success()
    }

    fn cmd_select(
        &mut self,
        cmd: s::SelectCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        self.select(&cmd.mailbox, sender, false)
    }

    fn cmd_status(
        &mut self,
        cmd: s::StatusCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        unimplemented!()
    }

    fn cmd_subscribe(
        &mut self,
        cmd: s::SubscribeCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        unimplemented!()
    }

    fn cmd_unsubscribe(
        &mut self,
        cmd: s::UnsubscribeCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        unimplemented!()
    }

    fn cmd_log_in(
        &mut self,
        cmd: s::LogInCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        unimplemented!()
    }

    fn cmd_copy(
        &mut self,
        cmd: s::CopyCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        unimplemented!()
    }

    fn cmd_fetch(
        &mut self,
        cmd: s::FetchCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        unimplemented!()
    }

    fn cmd_store(
        &mut self,
        cmd: s::StoreCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        unimplemented!()
    }

    fn cmd_search(
        &mut self,
        cmd: s::SearchCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        unimplemented!()
    }

    fn cmd_uid_copy(
        &mut self,
        cmd: s::CopyCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        unimplemented!()
    }

    fn cmd_uid_fetch(
        &mut self,
        cmd: s::FetchCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        unimplemented!()
    }

    fn cmd_uid_search(
        &mut self,
        cmd: s::SearchCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        unimplemented!()
    }

    fn cmd_uid_store(
        &mut self,
        cmd: s::StoreCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        unimplemented!()
    }

    fn account(&mut self) -> PartialResult<&mut Account> {
        self.account.as_mut().ok_or_else(|| {
            s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::Bad,
                code: None,
                quip: Some(Cow::Borrowed("Not logged in")),
            })
        })
    }

    fn selected(&mut self) -> PartialResult<&mut StatefulMailbox> {
        self.selected.as_mut().ok_or_else(|| {
            s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::Bad,
                code: None,
                quip: Some(Cow::Borrowed("No mailbox selected")),
            })
        })
    }

    fn catch_all_error_handling(&self, e: Error) -> s::Response<'static> {
        error!("{} Unhandled internal error: {}", self.log_prefix, e);
        s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::No,
            code: None,
            quip: Some(Cow::Borrowed(
                "Unexpected error; check server logs for details",
            )),
        })
    }

    fn select(
        &mut self,
        mailbox: &str,
        sender: SendResponse,
        read_only: bool,
    ) -> CmdResult {
        // SELECT and EXAMINE unselect any selected mailbox regardless of
        // whether they succeed.
        self.unselect();

        let stateless = self.account()?.mailbox(mailbox, read_only).map_err(
            map_error! {
                self,
                NxMailbox | UnsafeName | MailboxUnselectable => (No, None),
            },
        )?;
        let (stateful, select) =
            stateless.select().map_err(map_error!(self))?;
        sender(s::Response::Flags(select.flags.clone()));
        sender(s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Ok,
            code: Some(s::RespTextCode::PermanentFlags(select.flags)),
            quip: None,
        }));
        sender(s::Response::Exists(
            select.exists.try_into().unwrap_or(u32::MAX),
        ));
        sender(s::Response::Recent(
            select.recent.try_into().unwrap_or(u32::MAX),
        ));
        if let Some(unseen) = select.unseen {
            sender(s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::Ok,
                code: Some(s::RespTextCode::Unseen(unseen.0.get())),
                quip: None,
            }));
        }
        sender(s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Ok,
            code: Some(s::RespTextCode::UidNext(select.uidnext.0.get())),
            quip: None,
        }));
        sender(s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Ok,
            code: Some(s::RespTextCode::UidValidity(select.uidvalidity)),
            quip: None,
        }));

        let read_only = stateful.stateless().read_only();
        self.selected = Some(stateful);

        Ok(s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Ok,
            code: Some(if read_only {
                s::RespTextCode::ReadOnly(())
            } else {
                s::RespTextCode::ReadWrite(())
            }),
            quip: Some(Cow::Borrowed("Mailbox selected")),
        }))
    }

    fn unselect(&mut self) {
        self.selected = None;
    }
}

fn capability_data() -> s::CapabilityData<'static> {
    s::CapabilityData {
        capabilities: CAPABILITIES.iter().copied().map(Cow::Borrowed).collect(),
    }
}

fn success() -> CmdResult {
    Ok(s::Response::Cond(s::CondResponse {
        cond: s::RespCondType::Ok,
        code: None,
        quip: None,
    }))
}
