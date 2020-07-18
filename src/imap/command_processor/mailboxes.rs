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
use std::marker::PhantomData;

use log::warn;

use super::defs::*;
use crate::account::model::*;
use crate::support::error::Error;

impl CommandProcessor {
    pub(super) fn cmd_close(&mut self, _sender: SendResponse<'_>) -> CmdResult {
        {
            let selected = selected!(self)?;
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

        self.selected = None;
        success()
    }

    pub(crate) fn cmd_create(
        &mut self,
        cmd: s::CreateCommand<'_>,
        _sender: SendResponse<'_>,
    ) -> CmdResult {
        let account = account!(self)?;
        let request = CreateRequest {
            name: cmd.mailbox.into_owned(),
            special_use: vec![],
        };
        account.create(request).map_err(map_error! {
            self,
            MailboxExists =>
                (No, Some(s::RespTextCode::AlreadyExists(()))),
            UnsafeName | BadOperationOnInbox =>
                (No, Some(s::RespTextCode::Cannot(()))),
            // TODO This has its own code
            UnsupportedSpecialUse => (No, None),
        })?;
        success()
    }

    pub(crate) fn cmd_delete(
        &mut self,
        cmd: s::DeleteCommand<'_>,
        _sender: SendResponse<'_>,
    ) -> CmdResult {
        let account = account!(self)?;
        account.delete(&cmd.mailbox).map_err(map_error! {
            self,
            NxMailbox =>
                (No, Some(s::RespTextCode::Nonexistent(()))),
            MailboxHasInferiors =>
                (No, Some(s::RespTextCode::InUse(()))),
            UnsafeName | BadOperationOnInbox =>
                (No, Some(s::RespTextCode::Cannot(()))),
        })?;
        success()
    }

    pub(crate) fn cmd_examine(
        &mut self,
        cmd: s::ExamineCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        self.select(&cmd.mailbox, sender, true)
    }

    pub(crate) fn cmd_list(
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

    pub(crate) fn cmd_lsub(
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

    pub(crate) fn cmd_rename(
        &mut self,
        cmd: s::RenameCommand<'_>,
        _sender: SendResponse<'_>,
    ) -> CmdResult {
        let account = account!(self)?;
        let request = RenameRequest {
            existing_name: cmd.src.into_owned(),
            new_name: cmd.dst.into_owned(),
        };

        account.rename(request).map_err(map_error! {
            self,
            NxMailbox =>
                (No, Some(s::RespTextCode::Nonexistent(()))),
            MailboxExists | RenameToSelf =>
                (No, Some(s::RespTextCode::AlreadyExists(()))),
            BadOperationOnInbox | RenameIntoSelf | UnsafeName =>
                (No, Some(s::RespTextCode::Cannot(()))),
        })?;

        success()
    }

    pub(crate) fn cmd_select(
        &mut self,
        cmd: s::SelectCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        self.select(&cmd.mailbox, sender, false)
    }

    pub(crate) fn cmd_status(
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
            UnsafeName =>
                (No, Some(s::RespTextCode::Cannot(()))),
            NxMailbox | MailboxUnselectable =>
                (No, Some(s::RespTextCode::Nonexistent(()))),
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

    pub(crate) fn cmd_subscribe(
        &mut self,
        cmd: s::SubscribeCommand<'_>,
        _sender: SendResponse<'_>,
    ) -> CmdResult {
        account!(self)?
            .subscribe(&cmd.mailbox)
            .map_err(map_error! {
                self,
                NxMailbox => (No, Some(s::RespTextCode::Nonexistent(()))),
                UnsafeName => (No, Some(s::RespTextCode::Cannot(()))),
            })?;
        success()
    }

    pub(crate) fn cmd_unsubscribe(
        &mut self,
        cmd: s::UnsubscribeCommand<'_>,
        _sender: SendResponse<'_>,
    ) -> CmdResult {
        account!(self)?
            .unsubscribe(&cmd.mailbox)
            .map_err(map_error! {
                self,
                NxMailbox => (No, Some(s::RespTextCode::Nonexistent(()))),
                UnsafeName => (No, Some(s::RespTextCode::Cannot(()))),
            })?;
        success()
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
                NxMailbox | MailboxUnselectable =>
                    (No, Some(s::RespTextCode::Nonexistent(()))),
                UnsafeName =>
                    (No, Some(s::RespTextCode::Cannot(()))),
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
