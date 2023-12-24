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

use log::{error, info};

use super::defs::*;
use crate::account::model::SeqRange;
use crate::account::v2::IdleListener;
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
    /// `sender` can passed secondary responses as needed.
    ///
    /// Returns the final, tagged response. If the response condition is `BYE`,
    /// the connection will be closed after sending it.
    pub async fn handle_command<'a>(
        &mut self,
        command_line: s::CommandLine<'a>,
        mut sender: SendResponse,
    ) -> s::ResponseLine<'a> {
        let sender = &mut sender;
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
        // `OK` response to `[UID] EXPUNGE` include this response code, unlike
        // every other situation where the data is sent on an untagged
        // response. (Note we still send the untagged response as well, but
        // only if anything actually changed --- but the case for [UID] EXPUNGE
        // is unconditional for simplicity.)
        let mut staple_highest_modseq = false;

        let res = match command_line.cmd {
            s::Command::Simple(s::SimpleCommand::Capability) => {
                self.cmd_capability(sender).await
            },
            s::Command::Simple(s::SimpleCommand::Check) => {
                self.cmd_noop("Nothing exciting")
            },
            s::Command::Simple(s::SimpleCommand::Close) => self.cmd_close(),
            s::Command::Simple(s::SimpleCommand::Compress) => {
                panic!("COMPRESS DEFLATE should be handled by server.rs")
            },
            s::Command::Simple(s::SimpleCommand::Expunge) => {
                staple_highest_modseq = self.qresync_enabled;
                self.cmd_expunge()
            },
            s::Command::Simple(s::SimpleCommand::Idle) => {
                panic!("IDLE should be dispatched by server.rs")
            },
            s::Command::Simple(s::SimpleCommand::LogOut) => {
                self.cmd_log_out(sender).await
            },
            s::Command::Simple(s::SimpleCommand::Namespace) => {
                self.cmd_namespace(sender).await
            },
            s::Command::Simple(s::SimpleCommand::Noop) => {
                self.cmd_noop("NOOP OK")
            },
            s::Command::Simple(s::SimpleCommand::StartTls) => {
                self.cmd_start_tls()
            },
            s::Command::Simple(s::SimpleCommand::Unselect) => {
                self.cmd_unselect()
            },
            s::Command::Simple(s::SimpleCommand::XCryFlagsOff) => {
                self.flag_responses_enabled = false;
                success()
            },
            s::Command::Simple(s::SimpleCommand::XCryFlagsOn) => {
                self.flag_responses_enabled = true;
                success()
            },
            s::Command::Simple(s::SimpleCommand::XCryPurge) => {
                self.cmd_xcry_purge()
            },
            s::Command::Simple(s::SimpleCommand::XCryGetUserConfig) => {
                self.cmd_xcry_get_user_config(sender).await
            },
            s::Command::Simple(s::SimpleCommand::XCryZstdTrain) => {
                self.cmd_xcry_zstd_train()
            },
            s::Command::Simple(s::SimpleCommand::Xyzzy) => {
                self.cmd_noop("Nothing happens")
            },
            s::Command::Simple(s::SimpleCommand::XAppendFinishedNoop) => {
                self.cmd_noop("APPEND OK")
            },

            s::Command::Create(cmd) => self.cmd_create(cmd),
            s::Command::Delete(cmd) => self.cmd_delete(cmd),
            s::Command::Examine(cmd) => self.cmd_examine(cmd, sender).await,
            s::Command::List(cmd) => self.cmd_list(cmd, sender).await,
            s::Command::Lsub(cmd) => self.cmd_lsub(cmd, sender).await,
            s::Command::Xlist(cmd) => self.cmd_xlist(cmd, sender).await,
            s::Command::Rename(cmd) => self.cmd_rename(cmd),
            s::Command::Select(cmd) => self.cmd_select(cmd, sender).await,
            s::Command::Status(cmd) => self.cmd_status(cmd, sender).await,
            s::Command::Subscribe(cmd) => self.cmd_subscribe(cmd),
            s::Command::Unsubscribe(cmd) => self.cmd_unsubscribe(cmd),
            s::Command::LogIn(cmd) => self.cmd_log_in(cmd),
            s::Command::Copy(cmd) => self.cmd_copy(cmd, sender).await,
            s::Command::Move(cmd) => self.cmd_move(cmd, sender).await,
            s::Command::Fetch(cmd) => self.cmd_fetch(cmd, sender).await,
            s::Command::Store(cmd) => self.cmd_store(cmd, sender).await,
            s::Command::Search(cmd) => {
                self.cmd_search(cmd, &command_line.tag, sender).await
            },
            s::Command::XVanquish(uids) => self.cmd_vanquish(uids),

            s::Command::Uid(s::UidCommand::Copy(cmd)) => {
                self.cmd_uid_copy(cmd, sender).await
            },
            s::Command::Uid(s::UidCommand::Move(cmd)) => {
                self.cmd_uid_move(cmd, sender).await
            },
            s::Command::Uid(s::UidCommand::Fetch(cmd)) => {
                self.cmd_uid_fetch(cmd, sender).await
            },
            s::Command::Uid(s::UidCommand::Search(cmd)) => {
                self.cmd_uid_search(cmd, &command_line.tag, sender).await
            },
            s::Command::Uid(s::UidCommand::Store(cmd)) => {
                self.cmd_uid_store(cmd, sender).await
            },
            s::Command::Uid(s::UidCommand::Expunge(uids)) => {
                staple_highest_modseq = self.qresync_enabled;
                self.cmd_uid_expunge(uids)
            },

            s::Command::Id(parms) => self.cmd_id(parms, sender).await,

            s::Command::Enable(exts) => self.cmd_enable(exts, sender).await,

            s::Command::XCrySetUserConfig(configs) => {
                self.cmd_xcry_set_user_config(configs, sender).await
            },
        };

        if res.is_ok() {
            let poll_res = if allow_full_poll {
                self.full_poll(sender).await
            } else {
                self.mini_poll(sender).await
            };

            if let Err(err) = poll_res {
                error!("{} Poll failed: {}", self.log_prefix, err);
            }
        } else if let Some(selected) = self.selected.as_ref() {
            // If an error occurred and we have a selected mailbox, check that
            // the mailbox still exists. If not, disconnect the client instead
            // of letting them continue to flail in confusion.
            if !self
                .account
                .as_mut()
                .is_some_and(|a| a.is_usable_mailbox(selected))
            {
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
                        selected.snapshot_modseq().raw(),
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

    async fn cmd_capability(&mut self, sender: &mut SendResponse) -> CmdResult {
        send_response(sender, s::Response::Capability(capability_data())).await;
        success()
    }

    async fn cmd_enable(
        &mut self,
        exts: Vec<Cow<'_, str>>,
        sender: &mut SendResponse,
    ) -> CmdResult {
        let mut enabled = Vec::new();
        // Per RFC 5161, we silently ignore any extension which isn't
        // ENABLE-able or known.
        for ext in exts {
            let ext = Cow::Owned(ext.clone().into_owned());
            if "XYZZY".eq_ignore_ascii_case(&ext) {
                enabled.push(ext);
            } else if "UTF8=ACCEPT".eq_ignore_ascii_case(&ext) {
                self.unicode_aware = true;
                self.utf8_enabled = true;
                enabled.push(ext);
            } else if "CONDSTORE".eq_ignore_ascii_case(&ext) {
                self.enable_condstore(sender, false).await;
                enabled.push(ext);
            } else if "QRESYNC".eq_ignore_ascii_case(&ext) {
                // RFC 7162 says:
                //
                // > A server compliant with this specification is REQUIRED to
                // > support "ENABLE QRESYNC" and "ENABLE QRESYNC CONDSTORE"
                // > (which are "CONDSTORE enabling commands", see Section 3.1,
                // > and have identical results).
                // > ...
                // > Clarified that ENABLE QRESYNC CONDSTORE and ENABLE
                // > CONDSTORE QRESYNC are equivalent.
                //
                // This would imply that `ENABLE QRESYNC` would need to include
                // an `ENABLED CONDSTORE` response, which is pretty strange.
                // Based on the trace in this (otherwise unrelated) post:
                // https://forum.vivaldi.net/topic/44076/can-t-add-email-account-to-mailspring-can-t-connect-to-smtp
                // it looks like Dovecot's approach is the more reasonable one:
                // `ENABLE QRESYNC` and `ENABLE QRESYNC CONDSTORE` are *not*
                // equivalent, but `ENABLE QRESYNC` enables a superset of
                // behaviours that `ENABLE CONDSTORE` does.
                //
                // That is, Dovecot answers
                //   . ENABLE QRESYNC
                // with
                //   * ENABLED QRESYNC
                // and not
                //   * ENABLED CONDSTORE QRESYNC
                //
                // This is what we do here as well.
                self.enable_condstore(sender, false).await;
                self.qresync_enabled = true;
                enabled.push(ext);
            } else if "IMAP4rev2".eq_ignore_ascii_case(&ext) {
                self.unicode_aware = true;
                self.imap4rev2_enabled = true;
                enabled.push(ext);
            }
        }

        let quip = if enabled.is_empty() {
            "Nothing enabled"
        } else {
            "The future is now"
        };

        send_response(sender, s::Response::Enabled(enabled)).await;
        Ok(s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Ok,
            code: None,
            quip: Some(Cow::Borrowed(quip)),
        }))
    }

    pub(super) async fn enable_condstore(
        &mut self,
        sender: &mut SendResponse,
        implicit: bool,
    ) {
        if self.condstore_enabled {
            return;
        }

        self.condstore_enabled = true;

        let highest_modseq =
            self.selected.as_ref().map(|s| s.snapshot_modseq().raw());

        // Only send an untagged OK if there's something interesting to say
        if implicit || highest_modseq.is_some() {
            send_response(
                sender,
                s::Response::Cond(s::CondResponse {
                    cond: s::RespCondType::Ok,
                    code: highest_modseq.map(s::RespTextCode::HighestModseq),
                    quip: Some(Cow::Borrowed(if implicit {
                        "CONDSTORE enabled implicitly"
                    } else {
                        "CONDSTORE enabled while already selected"
                    })),
                }),
            )
            .await;
        }
    }

    async fn cmd_id(
        &mut self,
        ids: Vec<Option<Cow<'_, str>>>,
        sender: &mut SendResponse,
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
                    message.push_str(name);
                    message.push_str("\" = \"");
                    message.push_str(value);
                    message.push_str("\";");
                }
            }

            if !user_agent_name.is_empty() {
                self.log_prefix.set_user_agent(
                    Some(user_agent_name),
                    Some(user_agent_version).filter(|v| !v.is_empty()),
                );
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
            id_info.push(Some(Cow::Owned(name.replace('_', "-"))));
            id_info.push(Some(Cow::Owned(value.clone())));
        }

        send_response(sender, s::Response::Id(id_info)).await;
        success()
    }

    async fn cmd_namespace(&mut self, sender: &mut SendResponse) -> CmdResult {
        send_response(sender, s::Response::Namespace(())).await;
        success()
    }

    fn cmd_noop(&mut self, quip: &'static str) -> CmdResult {
        // Nothing to do here; shared command processing takes care of the
        // actual poll operation.
        Ok(s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Ok,
            code: None,
            quip: Some(Cow::Borrowed(quip)),
        }))
    }

    async fn cmd_log_out(&mut self, sender: &mut SendResponse) -> CmdResult {
        self.selected = None;
        self.account = None;

        // LOGOUT is a bit weird because RFC 3501 requires sending an OK
        // response *AFTER* the BYE.
        self.logged_out = true;
        send_response(
            sender,
            s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::Bye,
                code: None,
                quip: Some(Cow::Borrowed("BYE")),
            }),
        )
        .await;
        success()
    }

    fn cmd_start_tls(&mut self) -> CmdResult {
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

        let data = account!(self)?
            .zstd_train(selected!(self)?)
            .map_err(map_error!(self))?;
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
            .append(
                "INBOX",
                Utc::now().into(),
                vec![],
                message.replace('\n', "\r\n").as_bytes(),
            )
            .map_err(map_error!(self))?;

        success()
    }

    async fn full_poll(
        &mut self,
        sender: &mut SendResponse,
    ) -> Result<(), Error> {
        let Some(ref mut account) = self.account else {
            return Ok(());
        };

        account.drain_deliveries();

        let Some(ref mut selected) = self.selected.as_mut() else {
            return Ok(());
        };

        let poll = account.poll(selected)?;
        if self.qresync_enabled {
            if !poll.expunge.is_empty() {
                let mut sr = SeqRange::new();
                for (_, uid) in poll.expunge {
                    sr.append(uid);
                }
                send_response(
                    sender,
                    s::Response::Vanished(s::VanishedResponse {
                        earlier: false,
                        uids: Cow::Owned(sr.to_string()),
                    }),
                )
                .await;
            }
        } else {
            for (seqnum, _) in poll.expunge.into_iter().rev() {
                send_response(sender, s::Response::Expunge(seqnum.0.get()))
                    .await;
            }
        }
        if let Some(exists) = poll.exists {
            send_response(
                sender,
                s::Response::Exists(exists.try_into().unwrap_or(u32::MAX)),
            )
            .await;
        }
        if let Some(recent) = poll.recent {
            send_response(
                sender,
                s::Response::Recent(recent.try_into().unwrap_or(u32::MAX)),
            )
            .await;
        }

        self.fetch_for_background_update(sender, poll.fetch).await;

        // This must come after fetch_for_background_update so that we can
        // override the client's own calculation of HIGHESTMODSEQ
        if let Some(max_modseq) = poll.max_modseq {
            if self.condstore_enabled {
                send_response(
                    sender,
                    s::Response::Cond(s::CondResponse {
                        cond: s::RespCondType::Ok,
                        code: Some(s::RespTextCode::HighestModseq(
                            max_modseq.raw(),
                        )),
                        quip: None,
                    }),
                )
                .await;
            }
        }

        Ok(())
    }

    async fn mini_poll(
        &mut self,
        sender: &mut SendResponse,
    ) -> Result<(), Error> {
        let Some(ref mut account) = self.account else {
            return Ok(());
        };

        let Some(ref mut selected) = self.selected else {
            return Ok(());
        };

        let poll = account.mini_poll(selected)?;
        let uids_empty = poll.fetch.is_empty();

        self.fetch_for_background_update(sender, poll.fetch).await;

        // If the true max modseq is not the same as the reported max modseq,
        // we need to also send a HIGHESTMODSEQ response (after the fetches
        // above) to override the client's own calculation of that value based
        // on looking at the FETCH responses, since the value from FETCH could
        // be greater than of an expungement the client hasn't seen.
        if !uids_empty && self.condstore_enabled {
            if let Some(divergent_modseq) = poll.divergent_modseq {
                send_response(
                    sender,
                    s::Response::Cond(s::CondResponse {
                        cond: s::RespCondType::Ok,
                        code: Some(s::RespTextCode::HighestModseq(
                            divergent_modseq.raw(),
                        )),
                        quip: Some(Cow::Borrowed(
                            "Snapshot diverged from reality",
                        )),
                    }),
                )
                .await;
            }
        }

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
    pub async fn cmd_idle<'a>(
        &mut self,
        before_first_idle: impl FnOnce() -> Result<(), Error>,
        mut keep_idling: impl FnMut(&IdleListener) -> bool,
        mut after_poll: impl FnMut() -> Result<(), Error>,
        tag: Cow<'a, str>,
        mut sender: SendResponse,
    ) -> s::ResponseLine<'a> {
        let mut before_first_idle = Some(before_first_idle);

        let result = loop {
            let account = match account!(self) {
                Ok(a) => a,
                Err(e) => break Err(e),
            };

            // Ensure a mailbox is actually selected before we even start.
            if let Err(e) = selected!(self) {
                break Err(e);
            };

            let listener =
                match account.prepare_idle().map_err(map_error!(self)) {
                    Ok(l) => l,
                    Err(e) => break Err(e),
                };

            if let Err(e) =
                self.full_poll(&mut sender).await.map_err(map_error!(self))
            {
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

            let account = match account!(self) {
                Ok(a) => a,
                Err(e) => break Err(e),
            };
            if let Err(e) = account.idle(listener).map_err(map_error!(self)) {
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
                let response = if self.account.as_mut().is_some_and(|a| {
                    self.selected
                        .as_ref()
                        .is_some_and(|s| a.is_usable_mailbox(s))
                }) {
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
