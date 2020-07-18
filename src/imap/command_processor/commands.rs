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

use log::error;

use super::defs::*;
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
            s::Command::Simple(s::SimpleCommand::XPurge) => self.cmd_purge(),
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
            s::Command::Rename(cmd) => self.cmd_rename(cmd, sender),
            s::Command::Select(cmd) => self.cmd_select(cmd, sender),
            s::Command::Status(cmd) => self.cmd_status(cmd, sender),
            s::Command::Subscribe(cmd) => self.cmd_subscribe(cmd, sender),
            s::Command::Unsubscribe(cmd) => self.cmd_unsubscribe(cmd, sender),
            s::Command::LogIn(cmd) => self.cmd_log_in(cmd),
            s::Command::Copy(cmd) => self.cmd_copy(cmd, sender),
            s::Command::Fetch(cmd) => self.cmd_fetch(cmd, sender),
            s::Command::Store(cmd) => self.cmd_store(cmd, sender),
            s::Command::Search(cmd) => self.cmd_search(cmd, sender),
            s::Command::XVanquish(uids) => self.cmd_vanquish(uids, sender),

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
            s::Command::Uid(s::UidCommand::Expunge(uids)) => {
                self.cmd_uid_expunge(uids, sender)
            }
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
        Ok(())
    }

    fn mini_poll(&mut self, sender: SendResponse<'_>) -> Result<(), Error> {
        let selected = match self.selected.as_mut() {
            Some(s) => s,
            None => return Ok(()),
        };
        let uids = selected.mini_poll();

        self.fetch_for_background_update(sender, uids);
        Ok(())
    }
}

pub(super) fn capability_data() -> s::CapabilityData<'static> {
    s::CapabilityData {
        capabilities: CAPABILITIES.iter().copied().map(Cow::Borrowed).collect(),
    }
}
