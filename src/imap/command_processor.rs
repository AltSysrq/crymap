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
use std::fmt;
use std::fs;
use std::io::Read;
use std::marker::PhantomData;
use std::mem;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use log::{error, info, warn};

use super::literal_source::LiteralSource;
use crate::account::{
    account::{account_config_file, Account},
    mailbox::{StatefulMailbox, StatelessMailbox},
    model::*,
};
use crate::crypt::master_key::MasterKey;
use crate::imap::syntax as s;
use crate::mime::fetch::{self, section::*};
use crate::support::{
    error::Error, safe_name::is_safe_name, system_config::SystemConfig,
    user_config::UserConfig,
};

macro_rules! map_error {
    ($this:expr) => {{
        let log_prefix = &$this.log_prefix;
        move |e| catch_all_error_handling(log_prefix, e)
    }};

    ($this:expr, $($($kind:ident)|+ => ($cond:ident, $code:expr),)+) => {{
        let log_prefix = &$this.log_prefix;
        move |e| match e {
            $($(Error::$kind)|* => s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::$cond,
                code: $code,
                quip: Some(Cow::Owned(e.to_string())),
            }),)*
            e => catch_all_error_handling(log_prefix, e),
        }
    }};
}

// account! and selected! are macros instead of methods on CommandProcessor
// since there is no way to express that they borrow only one field --- as a
// method, the returned value is considered to borrow the whole
// `CommandProcessor`.
macro_rules! account {
    ($this:expr) => {
        $this.account.as_mut().ok_or_else(|| {
            s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::Bad,
                code: None,
                quip: Some(Cow::Borrowed("Not logged in")),
            })
        })
    };
}

macro_rules! selected {
    ($this:expr) => {
        $this.selected.as_mut().ok_or_else(|| {
            s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::Bad,
                code: None,
                quip: Some(Cow::Borrowed("No mailbox selected")),
            })
        })
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
    data_root: PathBuf,

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
        selected!(self)?.expunge_all_deleted().map_err(map_error! {
            self,
            MailboxReadOnly => (No, None),
        })?;
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
        let account = account!(self)?;
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
        let account = account!(self)?;
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
            account!(self)?.list(&request).map_err(map_error!(self))?;
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
            account!(self)?.list(&request).map_err(map_error!(self))?;
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
        let account = account!(self)?;
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
        let account = account!(self)?;
        let request = StatusRequest {
            name: cmd.mailbox.into_owned(),
            messages: cmd.atts.contains(&s::StatusAtt::Messages),
            recent: cmd.atts.contains(&s::StatusAtt::Recent),
            uidnext: cmd.atts.contains(&s::StatusAtt::UidNext),
            uidvalidity: cmd.atts.contains(&s::StatusAtt::UidValidity),
            unseen: cmd.atts.contains(&s::StatusAtt::Unseen),
        };

        let responses = account.status(&request).map_err(map_error! {
            self,
            UnsafeName | NxMailbox | MailboxUnselectable => (No, None),
        })?;

        for response in responses {
            let mut atts: Vec<s::StatusResponseAtt<'static>> =
                Vec::with_capacity(10);
            if let Some(messages) = response.messages {
                atts.push(s::StatusResponseAtt {
                    att: s::StatusAtt::Messages,
                    value: messages.try_into().unwrap_or(u32::MAX),
                    _marker: PhantomData,
                });
            }
            if let Some(recent) = response.recent {
                atts.push(s::StatusResponseAtt {
                    att: s::StatusAtt::Recent,
                    value: recent.try_into().unwrap_or(u32::MAX),
                    _marker: PhantomData,
                });
            }
            if let Some(uid) = response.uidnext {
                atts.push(s::StatusResponseAtt {
                    att: s::StatusAtt::UidNext,
                    value: uid.0.get(),
                    _marker: PhantomData,
                });
            }
            if let Some(uidvalidity) = response.uidvalidity {
                atts.push(s::StatusResponseAtt {
                    att: s::StatusAtt::UidValidity,
                    value: uidvalidity,
                    _marker: PhantomData,
                });
            }
            if let Some(unseen) = response.unseen {
                atts.push(s::StatusResponseAtt {
                    att: s::StatusAtt::Unseen,
                    value: unseen.try_into().unwrap_or(u32::MAX),
                    _marker: PhantomData,
                });
            }

            sender(s::Response::Status(s::StatusResponse {
                mailbox: Cow::Owned(response.name),
                atts,
            }));
        }

        success()
    }

    fn cmd_subscribe(
        &mut self,
        cmd: s::SubscribeCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        account!(self)?
            .subscribe(&cmd.mailbox)
            .map_err(map_error! {
                self,
                NxMailbox | UnsafeName => (No, None),
            })?;
        success()
    }

    fn cmd_unsubscribe(
        &mut self,
        cmd: s::UnsubscribeCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        account!(self)?
            .unsubscribe(&cmd.mailbox)
            .map_err(map_error! {
                self,
                NxMailbox | UnsafeName => (No, None),
            })?;
        success()
    }

    fn cmd_log_in(
        &mut self,
        cmd: s::LogInCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        if self.account.is_some() {
            return Err(s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::Bad,
                code: None,
                quip: Some(Cow::Borrowed("Already logged in")),
            }));
        }

        if !is_safe_name(&cmd.userid) {
            return Err(s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::No,
                code: None,
                quip: Some(Cow::Borrowed("Illegal user id")),
            }));
        }

        let mut user_dir = self.data_root.join(&*cmd.userid);
        let user_data_file = account_config_file(&user_dir);
        let (user_config, master_key) = fs::File::open(&user_data_file)
            .ok()
            .and_then(|f| {
                let mut buf = Vec::<u8>::new();
                f.take(65536).read_to_end(&mut buf).ok()?;
                toml::from_slice::<UserConfig>(&buf).ok()
            })
            .and_then(|config| {
                let master_key = MasterKey::from_config(
                    &config.master_key,
                    cmd.password.as_bytes(),
                )?;
                Some((config, master_key))
            })
            .ok_or_else(|| {
                s::Response::Cond(s::CondResponse {
                    cond: s::RespCondType::No,
                    code: None,
                    quip: Some(Cow::Borrowed("Bad user id or password")),
                })
            })?;

        // Login successful (at least barring further operational issues)

        self.log_prefix.push_str(":~");
        self.log_prefix.push_str(&cmd.userid);
        info!("{} Login successful", self.log_prefix);

        self.drop_privelages(&mut user_dir)?;

        let account = Account::new(
            self.log_prefix.clone(),
            user_dir,
            Some(Arc::new(master_key)),
        );
        account
            .init(&user_config.key_store)
            .map_err(map_error!(self))?;

        self.account = Some(account);
        Ok(s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Ok,
            code: None,
            quip: Some(Cow::Borrowed("User login successful")),
        }))
    }

    fn cmd_copy(
        &mut self,
        cmd: s::CopyCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        let messages = self.parse_seqnum_range(&cmd.messages)?;
        let account = account!(self)?;
        let selected = selected!(self)?;
        let dst = account.mailbox(&cmd.dst, false).map_err(map_error! {
            self,
            NxMailbox => (No, Some(s::RespTextCode::TryCreate(()))),
            UnsafeName | MailboxUnselectable => (No, None),
        })?;
        let request = CopyRequest { ids: messages };
        selected.seqnum_copy(&request, &dst).map_err(map_error! {
           self,
            MailboxFull | NxMessage | ExpungedMessage | GaveUpInsertion =>
                (No, None),
        })?;
        success()
    }

    fn cmd_fetch(
        &mut self,
        cmd: s::FetchCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        let mut request = FetchRequest {
            ids: self.parse_seqnum_range(&cmd.messages)?,
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
            let store_res = selected.seqnum_store(&StoreRequest {
                ids: &request.ids,
                flags: &[Flag::Seen],
                remove_listed: false,
                remove_unlisted: false,
                // We must ensure that the client sees the updates this causes.
                loud: true,
                unchanged_since: None,
            });
            if let Err(e) = store_res {
                warn!(
                    "{} Implicit STORE \\Seen failed: {}",
                    self.log_prefix, e
                );
            }
        }

        // TODO It would be better to stream these responses out rather than
        // buffer them
        let response = selected.seqnum_fetch(request).map_err(map_error! {
            self,
            MasterKeyUnavailable | BadEncryptedKey | ExpungedMessage |
            NxMessage => (No, None),
        })?;
        fetch_response(sender, response, fetch_properties)
    }

    fn cmd_store(
        &mut self,
        cmd: s::StoreCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        let ids = self.parse_seqnum_range(&cmd.messages)?;
        let request = StoreRequest {
            ids: &ids,
            flags: &cmd.flags,
            remove_listed: s::StoreCommandType::Minus == cmd.typ,
            remove_unlisted: s::StoreCommandType::Eq == cmd.typ,
            loud: !cmd.silent,
            unchanged_since: None,
        };

        let resp = selected!(self)?.seqnum_store(&request).map_err(
            map_error! {
                self,
                MailboxFull | NxMessage | ExpungedMessage | MailboxReadOnly =>
                    (No, None),
            },
        )?;

        if resp.ok {
            success()
        } else {
            Ok(s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::No,
                code: None,
                quip: Some(Cow::Borrowed("Some messages have been expunged")),
            }))
        }
    }

    fn cmd_search(
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

    fn select(
        &mut self,
        mailbox: &str,
        sender: SendResponse,
        read_only: bool,
    ) -> CmdResult {
        // SELECT and EXAMINE unselect any selected mailbox regardless of
        // whether they succeed.
        self.unselect();

        let stateless = account!(self)?.mailbox(mailbox, read_only).map_err(
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

    fn drop_privelages(&mut self, user_dir: &mut PathBuf) -> PartialResult<()> {
        // Nothing to do if we aren't root
        if nix::unistd::ROOT != nix::unistd::getuid() {
            return Ok(());
        }

        // Before we can chroot, we need to figure out what our groups will be
        // once we drop down to the user, because we won't have access to
        // /etc/group after the chroot
        let md = match user_dir.metadata() {
            Ok(md) => md,
            Err(e) => {
                error!(
                    "{} Failed to stat '{}': {}",
                    self.log_prefix,
                    user_dir.display(),
                    e
                );
                return auth_misconfiguration();
            }
        };
        let target_uid =
            nix::unistd::Uid::from_raw(md.uid() as nix::libc::uid_t);
        let (has_user_groups, target_gid) = match nix::unistd::User::from_uid(
            target_uid,
        ) {
            Ok(Some(user)) => {
                match nix::unistd::initgroups(
                    &std::ffi::CString::new(user.name.to_owned())
                        .expect("Got UNIX user name with NUL?"),
                    user.gid,
                ) {
                    Ok(()) => (true, user.gid),
                    Err(e) => {
                        warn!(
                            "{} Failed to init groups for user: {}",
                            self.log_prefix, e
                        );
                        (false, user.gid)
                    }
                }
            }
            Ok(None) => {
                // Failure to access /etc/group is expected if we chroot'ed
                // into the system data directory already
                if !self.system_config.security.chroot_system {
                    warn!(
                        "{} No passwd entry for UID {}, assuming GID {}",
                        self.log_prefix,
                        target_uid,
                        md.gid()
                    );
                }
                (
                    false,
                    nix::unistd::Gid::from_raw(md.gid() as nix::libc::gid_t),
                )
            }
            Err(e) => {
                // Failure to access /etc/group is expected if we chroot'ed
                // into the system data directory already
                if !self.system_config.security.chroot_system {
                    warn!(
                        "{} Failed to look up passwd entry for UID {}, \
                         assuming GID {}: {}",
                        self.log_prefix,
                        target_uid,
                        md.gid(),
                        e
                    );
                }
                (
                    false,
                    nix::unistd::Gid::from_raw(md.gid() as nix::libc::gid_t),
                )
            }
        };

        if let Err(e) = nix::unistd::chdir(user_dir)
            .and_then(|()| nix::unistd::chroot(user_dir))
        {
            error!(
                "{} Chroot (forced because Crymap is running as root) \
                    into '{}' failed: {}",
                self.log_prefix,
                user_dir.display(),
                e
            );
            return auth_misconfiguration();
        }

        // Chroot successful, adjust the log prefix and path to reflect that
        self.log_prefix
            .push_str(&format!(":[chroot {}]", user_dir.display()));
        user_dir.push("/"); // Clears everything but '/'

        // Now we can finish dropping privileges
        if let Err(e) = if has_user_groups {
            Ok(())
        } else {
            nix::unistd::setgroups(&[target_gid])
        }
        .and_then(|()| nix::unistd::setgid(target_gid))
        .and_then(|()| nix::unistd::setuid(target_uid))
        {
            error!(
                "{} Failed to drop privileges to {}:{}: {}",
                self.log_prefix, target_uid, target_gid, e
            );
            return auth_misconfiguration();
        }

        if nix::unistd::ROOT == nix::unistd::getuid() {
            error!(
                "{} Crymap is still root! You must either \
                    (a) Run Crymap as a non-root user; \
                    (b) Set [security].system_user in crymap.toml; \
                    (c) Ensure that user directories are not owned by root.",
                self.log_prefix
            );
            return auth_misconfiguration();
        }

        Ok(())
    }

    fn parse_seqnum_range(
        &mut self,
        raw: &str,
    ) -> PartialResult<SeqRange<Seqnum>> {
        let max_seqnum = selected!(self)?.max_seqnum().unwrap_or(Seqnum::MIN);
        let seqrange = SeqRange::parse(raw, max_seqnum).ok_or_else(|| {
            s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::Bad,
                code: None,
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
                code: None,
                quip: Some(Cow::Borrowed(
                    "Message sequence number out of range",
                )),
            }));
        }

        Ok(seqrange)
    }

    fn parse_uid_range(&mut self, raw: &str) -> PartialResult<SeqRange<Uid>> {
        let max_uid = selected!(self)?.max_uid().unwrap_or(Uid::MIN);
        let seqrange = SeqRange::parse(raw, max_uid).ok_or_else(|| {
            s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::Bad,
                code: None,
                quip: Some(Cow::Borrowed("Unparsable sequence set")),
            })
        })?;

        // The client is explicitly allowed to request UIDs out of range, so
        // there's nothing else to validate here.

        Ok(seqrange)
    }

    fn search_command_from_ast(
        &mut self,
        cmd: s::SearchCommand<'_>,
    ) -> PartialResult<SearchRequest> {
        if let Some(charset) = cmd.charset {
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

fn auth_misconfiguration() -> PartialResult<()> {
    Err(s::Response::Cond(s::CondResponse {
        cond: s::RespCondType::Bye,
        code: Some(s::RespTextCode::Alert(())),
        quip: Some(Cow::Borrowed(
            "Fatal internal error or misconfiguration; refer to \
             server logs for details.",
        )),
    }))
}

fn catch_all_error_handling(
    log_prefix: &str,
    e: Error,
) -> s::Response<'static> {
    error!("{} Unhandled internal error: {}", log_prefix, e);
    s::Response::Cond(s::CondResponse {
        cond: s::RespCondType::No,
        code: None,
        quip: Some(Cow::Borrowed(
            "Unexpected error; check server logs for details",
        )),
    })
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
