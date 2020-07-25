//-
// Copyright (c) 2020 Jason Lingle
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

use log::{error, info};

use super::defs::*;
use crate::account::mailbox::IdleListener;
use crate::support::error::Error;

impl CommandProcessor {
    /// Return the greeting line to return to the client.
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
        let allow_full_poll = match command_line.cmd {
            // FETCH, STORE, and SEARCH (the non-UID versions) are the only
            // cursed commands that don't allow us to update the message state
            // in response.
            s::Command::Fetch(..)
            | s::Command::Store(..)
            | s::Command::Search(..) => false,
            _ => true,
        };

        // If this gets set to true and QRESYNC is enabled, a HIGHESTMODSEQ
        // response code must be stapled onto the tagged response if it doesn't
        // already have a response code.
        //
        // This is used to implement RFC 7162's requirement that the tagged
        // `OK` response to `UID EXPUNGE` include this response code, unlike
        // every other situation where the data is sent on an untagged
        // response. (Note we still send the untagged response as well, but
        // only if anything actually changed --- but the case for UID EXPUNGE
        // is unconditional for simplicity.)
        let mut staple_highest_modseq = false;

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
            s::Command::Simple(s::SimpleCommand::Compress) => {
                panic!("COMPRESS DEFLATE should be handled by server.rs")
            }
            s::Command::Simple(s::SimpleCommand::Expunge) => {
                self.cmd_expunge(sender)
            }
            s::Command::Simple(s::SimpleCommand::Idle) => {
                panic!("IDLE should be dispatched by server.rs")
            }
            s::Command::Simple(s::SimpleCommand::LogOut) => {
                self.cmd_log_out(sender)
            }
            s::Command::Simple(s::SimpleCommand::Namespace) => {
                self.cmd_namespace(sender)
            }
            s::Command::Simple(s::SimpleCommand::Noop) => {
                self.cmd_noop("NOOP OK", sender)
            }
            s::Command::Simple(s::SimpleCommand::StartTls) => {
                self.cmd_start_tls(sender)
            }
            s::Command::Simple(s::SimpleCommand::Unselect) => {
                self.cmd_unselect(sender)
            }
            s::Command::Simple(s::SimpleCommand::XCryPurge) => {
                self.cmd_xcry_purge()
            }
            s::Command::Simple(s::SimpleCommand::XCryZstdTrain) => {
                self.cmd_xcry_zstd_train()
            }
            s::Command::Simple(s::SimpleCommand::Xyzzy) => {
                self.cmd_noop("Nothing happens", sender)
            }
            s::Command::Simple(s::SimpleCommand::XAppendFinishedNoop) => {
                self.cmd_noop("APPEND OK", sender)
            }

            s::Command::Create(cmd) => self.cmd_create(cmd, sender),
            s::Command::Delete(cmd) => self.cmd_delete(cmd, sender),
            s::Command::Examine(cmd) => self.cmd_examine(cmd, sender),
            s::Command::List(cmd) => self.cmd_list(cmd, sender),
            s::Command::Lsub(cmd) => self.cmd_lsub(cmd, sender),
            s::Command::Xlist(cmd) => self.cmd_xlist(cmd, sender),
            s::Command::Rename(cmd) => self.cmd_rename(cmd, sender),
            s::Command::Select(cmd) => self.cmd_select(cmd, sender),
            s::Command::Status(cmd) => self.cmd_status(cmd, sender),
            s::Command::Subscribe(cmd) => self.cmd_subscribe(cmd, sender),
            s::Command::Unsubscribe(cmd) => self.cmd_unsubscribe(cmd, sender),
            s::Command::LogIn(cmd) => self.cmd_log_in(cmd),
            s::Command::Copy(cmd) => self.cmd_copy(cmd, sender),
            s::Command::Move(cmd) => self.cmd_move(cmd, sender),
            s::Command::Fetch(cmd) => self.cmd_fetch(cmd, sender),
            s::Command::Store(cmd) => self.cmd_store(cmd, sender),
            s::Command::Search(cmd) => self.cmd_search(cmd, sender),
            s::Command::XVanquish(uids) => self.cmd_vanquish(uids, sender),

            s::Command::Uid(s::UidCommand::Copy(cmd)) => {
                self.cmd_uid_copy(cmd, sender)
            }
            s::Command::Uid(s::UidCommand::Move(cmd)) => {
                self.cmd_uid_move(cmd, sender)
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
            s::Command::Uid(s::UidCommand::Expunge(uids)) => {
                staple_highest_modseq = self.qresync_enabled;
                self.cmd_uid_expunge(uids, sender)
            }

            s::Command::Id(parms) => self.cmd_id(parms, sender),

            s::Command::Enable(exts) => self.cmd_enable(exts, sender),
        };

        if res.is_ok() {
            let poll_res = if allow_full_poll {
                self.full_poll(sender)
            } else {
                self.mini_poll(sender)
            };

            if let Err(err) = poll_res {
                error!("{} Poll failed: {}", self.log_prefix, err);
            }
        } else if let Some(selected) = self.selected.as_ref() {
            // If an error occurred and we have a selected mailbox, check that
            // the mailbox still exists. If not, disconnect the client instead
            // of letting them continue to flail in confusion.
            if !selected.stateless().is_ok() {
                return s::ResponseLine {
                    tag: None,
                    response: s::Response::Cond(s::CondResponse {
                        cond: s::RespCondType::Bye,
                        code: None,
                        quip: Some(Cow::Borrowed("Mailbox renamed or deleted")),
                    }),
                };
            }
        }

        if let Some(ref mut account) = self.account {
            account.clear_cache();
        }

        let mut res = match res {
            Ok(res) => res,
            Err(res) => res,
        };

        if staple_highest_modseq {
            if let (&Some(ref selected), &mut s::Response::Cond(ref mut cr)) =
                (&self.selected, &mut res)
            {
                if s::RespCondType::Ok == cr.cond && cr.code.is_none() {
                    cr.code = Some(s::RespTextCode::HighestModseq(
                        selected
                            .report_max_modseq()
                            .map_or(1, |m| m.raw().get()),
                    ));
                }
            }
        }

        // For a cond response, if we have nothing better to say as far as a
        // "response code" goes and there's a pending unapplied expunge, tell
        // the client about it.
        if let s::Response::Cond(ref mut cr) = res {
            if cr.code.is_none()
                && self
                    .selected
                    .as_ref()
                    .map(|s| s.has_pending_expunge())
                    .unwrap_or(false)
            {
                cr.code = Some(s::RespTextCode::ExpungeIssued(()));
            }
        }

        if matches!(
            res,
            s::Response::Cond(s::CondResponse {
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

    fn cmd_enable(
        &mut self,
        exts: Vec<Cow<'_, str>>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        let mut enabled = Vec::new();
        // Per RFC 5161, we silently ignore any extension which isn't
        // ENABLE-able or known.
        for ext in exts {
            if "XYZZY".eq_ignore_ascii_case(&ext) {
                enabled.push(ext);
            } else if "UTF8=ACCEPT".eq_ignore_ascii_case(&ext) {
                self.unicode_aware = true;
                self.utf8_enabled = true;
                enabled.push(ext);
            } else if "CONDSTORE".eq_ignore_ascii_case(&ext) {
                self.enable_condstore(sender, false);
                enabled.push(ext);
            }
        }

        let quip = if enabled.is_empty() {
            "Nothing enabled"
        } else {
            "The future is now"
        };

        sender(s::Response::Enabled(enabled));
        Ok(s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Ok,
            code: None,
            quip: Some(Cow::Borrowed(quip)),
        }))
    }

    pub(super) fn enable_condstore(
        &mut self,
        sender: SendResponse<'_>,
        implicit: bool,
    ) {
        if self.condstore_enabled {
            return;
        }

        self.condstore_enabled = true;

        let highest_modseq = self
            .selected
            .as_ref()
            .map(|s| s.report_max_modseq().map_or(1, |m| m.raw().get()));

        // Only send an untagged OK if there's something interesting to say
        if implicit || highest_modseq.is_some() {
            sender(s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::Ok,
                code: highest_modseq.map(s::RespTextCode::HighestModseq),
                quip: Some(Cow::Borrowed(if implicit {
                    "CONDSTORE enabled implicitly"
                } else {
                    "CONDSTORE enabled while already selected"
                })),
            }));
        }
    }

    fn cmd_id(
        &mut self,
        ids: Vec<Option<Cow<'_, str>>>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        // Only take action on the first ID exchange so we don't keep
        // accumulating stuff in the log prefix.
        if !self.id_exchanged {
            let mut user_agent_name = String::new();
            let mut user_agent_version = String::new();
            let mut message = String::new();

            for pair in ids.chunks(2) {
                if 2 != pair.len() {
                    continue;
                }

                if let (&Some(ref name), &Some(ref value)) =
                    (&pair[0], &pair[1])
                {
                    if name.eq_ignore_ascii_case("name") {
                        user_agent_name = value.to_string();
                    }
                    if name.eq_ignore_ascii_case("version") {
                        user_agent_version = value.to_string();
                    }

                    message.push_str(" \"");
                    message.push_str(&name);
                    message.push_str("\" = \"");
                    message.push_str(&value);
                    message.push_str("\";");
                }
            }

            if !user_agent_name.is_empty() {
                self.log_prefix.push('(');
                self.log_prefix.push_str(&user_agent_name);
                if !user_agent_version.is_empty() {
                    self.log_prefix.push('/');
                    self.log_prefix.push_str(&user_agent_version);
                }
                self.log_prefix.push(')');
            }

            info!(
                "{} ID exchanged; client says it is{}",
                self.log_prefix, message
            );
            self.id_exchanged = true;
        }

        let mut id_info = vec![
            Some(Cow::Borrowed("name")),
            Some(Cow::Borrowed(env!("CARGO_PKG_NAME"))),
            Some(Cow::Borrowed("version")),
            Some(Cow::Borrowed(concat!(
                env!("CARGO_PKG_VERSION_MAJOR"),
                ".",
                env!("CARGO_PKG_VERSION_MINOR"),
                ".",
                env!("CARGO_PKG_VERSION_PATCH")
            ))),
        ];

        for (name, value) in &self.system_config.identification {
            // Silently replace _ with - since it's easy to accidentally use _
            // in the config but _ is never used in these parameters.
            id_info.push(Some(Cow::Owned(name.replace("_", "-"))));
            id_info.push(Some(Cow::Owned(value.clone())));
        }

        sender(s::Response::Id(id_info));
        success()
    }

    fn cmd_namespace(&mut self, sender: SendResponse<'_>) -> CmdResult {
        sender(s::Response::Namespace(()));
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

    fn cmd_log_out(&mut self, sender: SendResponse<'_>) -> CmdResult {
        self.selected = None;
        self.account = None;

        // LOGOUT is a bit weird because RFC 3501 requires sending an OK
        // response *AFTER* the BYE.
        self.logged_out = true;
        sender(s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Bye,
            code: None,
            quip: Some(Cow::Borrowed("BYE")),
        }));
        success()
    }

    fn cmd_start_tls(&mut self, _sender: SendResponse<'_>) -> CmdResult {
        Err(s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Bad,
            code: None,
            quip: Some(Cow::Borrowed("Already using TLS")),
        }))
    }

    #[cfg(not(feature = "dev-tools"))]
    fn cmd_xcry_zstd_train(&mut self) -> CmdResult {
        Err(s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::No,
            code: None,
            quip: Some(Cow::Borrowed("dev-tools not enabled")),
        }))
    }

    #[cfg(feature = "dev-tools")]
    fn cmd_xcry_zstd_train(&mut self) -> CmdResult {
        use chrono::prelude::*;

        let data = selected!(self)?.zstd_train().map_err(map_error!(self))?;
        let data = base64::encode(&data);
        let mut wrapped_data = String::new();
        for chunk in data.as_bytes().chunks(72) {
            wrapped_data.push_str(std::str::from_utf8(chunk).unwrap());
            wrapped_data.push_str("\n");
        }

        let message = format!(
            "\
From: Crymap <crymap@localhost>
Date: {}
Subject: Zstd training data
Content-Type: multipart/mixed; boundary=bound
Message-ID: <{}.zstdtrain@localhost>
MIME-Version: 1.0

--bound
Content-Type: text/plain

Attached is the result of zstd training.

--bound
Content-Type: application/octet-stream
Content-Disposition: attachment; filename=\"zstddict.dat\"
Content-Transfer-Encoding: base64

{}
--bound--
",
            Utc::now().to_rfc2822(),
            Utc::now().to_rfc3339(),
            wrapped_data
        );

        account!(self)?
            .mailbox("INBOX", false)
            .map_err(map_error!(self))?
            .append(
                FixedOffset::east(0)
                    .from_utc_datetime(&Utc::now().naive_local()),
                vec![],
                message.replace('\n', "\r\n").as_bytes(),
            )
            .map_err(map_error!(self))?;

        success()
    }

    fn full_poll(&mut self, sender: SendResponse<'_>) -> Result<(), Error> {
        let selected = match self.selected.as_mut() {
            Some(s) => s,
            None => return Ok(()),
        };

        let poll = selected.poll()?;
        for (seqnum, _) in poll.expunge.into_iter().rev() {
            sender(s::Response::Expunge(seqnum.0.get()));
        }
        if let Some(exists) = poll.exists {
            sender(s::Response::Exists(exists.try_into().unwrap_or(u32::MAX)));
        }
        if let Some(recent) = poll.recent {
            sender(s::Response::Recent(recent.try_into().unwrap_or(u32::MAX)));
        }

        self.fetch_for_background_update(sender, poll.fetch);

        if let Some(max_modseq) = poll.max_modseq {
            if self.condstore_enabled {
                sender(s::Response::Cond(s::CondResponse {
                    cond: s::RespCondType::Ok,
                    code: Some(s::RespTextCode::HighestModseq(
                        max_modseq.raw().get(),
                    )),
                    quip: None,
                }));
            }
        }

        Ok(())
    }

    fn mini_poll(&mut self, sender: SendResponse<'_>) -> Result<(), Error> {
        let selected = match self.selected.as_mut() {
            Some(s) => s,
            None => return Ok(()),
        };
        let uids = selected.mini_poll();

        self.fetch_for_background_update(sender, uids);

        // TODO(QRESYNC) We need to make sure that we also send HIGHESTMODSEQ
        // after the fetches if the reported HIGHESTMODSEQ is not the same as
        // the true HIGHESTMODSEQ and we sent at least one FETCH.

        Ok(())
    }

    /// The IDLE command.
    ///
    /// This needs to be dispatched directly by server.rs since it interacts
    /// with the protocol flow.
    ///
    /// `before_first_idle` is invoked after the first idle operation is
    /// prepared but before any waiting happens. This is used to send the
    /// continuation line back to the client.
    ///
    /// `keep_idling` is invoked each time immediately before idling is
    /// performed on the given listener. If it returns `false`, the idle
    /// command ends.
    ///
    /// `after_poll` is invoked each time immediately after sending poll
    /// responses. It is used to flush the output stream.
    pub fn cmd_idle<'a>(
        &mut self,
        before_first_idle: impl FnOnce() -> Result<(), Error>,
        mut keep_idling: impl FnMut(&IdleListener) -> bool,
        mut after_poll: impl FnMut() -> Result<(), Error>,
        tag: Cow<'a, str>,
        sender: SendResponse<'_>,
    ) -> s::ResponseLine<'a> {
        let mut before_first_idle = Some(before_first_idle);

        let result = loop {
            let selected = match selected!(self) {
                Ok(s) => s,
                Err(e) => break Err(e),
            };

            let listener = match selected
                .stateless()
                .prepare_idle()
                .map_err(map_error!(self))
            {
                Ok(l) => l,
                Err(e) => break Err(e),
            };

            if let Err(e) = self.full_poll(sender).map_err(map_error!(self)) {
                break Err(e);
            }

            if let Err(e) = after_poll().map_err(map_error!(self)) {
                break Err(e);
            }

            if let Some(before_first_idle) = before_first_idle.take() {
                if let Err(e) = before_first_idle().map_err(map_error!(self)) {
                    break Err(e);
                }
            }

            if !keep_idling(&listener) {
                break Ok(());
            }

            if let Err(e) = listener
                .idle()
                .map_err(Error::from)
                .map_err(map_error!(self))
            {
                break Err(e);
            }
        };

        if let Err(response) = result {
            if before_first_idle.is_some() {
                // We never sent the continuation line, so we're ok to return
                // the response
                s::ResponseLine {
                    tag: Some(tag),
                    response,
                }
            } else {
                // We sent a continuation line. We're not allowed to return any
                // tagged response, so die instead.
                let response = if self
                    .selected
                    .as_ref()
                    .map_or(true, |s| s.stateless().is_ok())
                {
                    s::Response::Cond(s::CondResponse {
                        cond: s::RespCondType::Bye,
                        code: Some(s::RespTextCode::ServerBug(())),
                        quip: Some(Cow::Borrowed("Unexpected internal error")),
                    })
                } else {
                    s::Response::Cond(s::CondResponse {
                        cond: s::RespCondType::Bye,
                        code: None,
                        quip: Some(Cow::Borrowed("Mailbox deleted or renamed")),
                    })
                };

                s::ResponseLine {
                    tag: None,
                    response,
                }
            }
        } else {
            s::ResponseLine {
                tag: Some(tag),
                response: s::Response::Cond(s::CondResponse {
                    cond: s::RespCondType::Ok,
                    code: None,
                    quip: Some(Cow::Borrowed("IDLE done")),
                }),
            }
        }
    }
}

pub(super) fn capability_data() -> s::CapabilityData<'static> {
    s::CapabilityData {
        capabilities: CAPABILITIES.iter().copied().map(Cow::Borrowed).collect(),
    }
}
