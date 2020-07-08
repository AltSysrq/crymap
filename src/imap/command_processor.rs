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
use std::fs;
use std::io::Read;
use std::marker::PhantomData;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use log::{error, info, warn};

use crate::account::{
    account::{account_config_file, Account},
    mailbox::{StatefulMailbox, StatelessMailbox},
    model::*,
};
use crate::crypt::master_key::MasterKey;
use crate::imap::syntax as s;
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
        selected!(self)?
            .expunge_all_deleted()
            .map_err(|e| catch_all_error_handling(&self.log_prefix, e))?;
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
