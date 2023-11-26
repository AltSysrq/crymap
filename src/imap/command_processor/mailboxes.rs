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

use log::warn;

use super::defs::*;
use crate::account::model::*;
use crate::imap::mailbox_name::MailboxName;
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

    pub(super) fn cmd_unselect(
        &mut self,
        _sender: SendResponse<'_>,
    ) -> CmdResult {
        selected!(self)?;
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
            name: cmd.mailbox.get_utf8(self.unicode_aware).into_owned(),
            special_use: cmd
                .special_use
                .unwrap_or_default()
                .into_iter()
                .map(|u| u.into_owned())
                .collect(),
        };
        let mailbox_id = account.create(request).map_err(map_error! {
            self,
            MailboxExists =>
                (No, Some(s::RespTextCode::AlreadyExists(()))),
            UnsafeName | BadOperationOnInbox =>
                (No, Some(s::RespTextCode::Cannot(()))),
            UnsupportedSpecialUse =>
                (No, Some(s::RespTextCode::UseAttr(()))),
        })?;

        Ok(s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Ok,
            code: Some(s::RespTextCode::MailboxId(Cow::Owned(mailbox_id))),
            quip: None,
        }))
    }

    pub(crate) fn cmd_delete(
        &mut self,
        cmd: s::DeleteCommand<'_>,
        _sender: SendResponse<'_>,
    ) -> CmdResult {
        let account = account!(self)?;
        let mailbox = cmd.mailbox.get_utf8(self.unicode_aware);
        account.delete(&mailbox).map_err(map_error! {
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

    pub(crate) fn cmd_list(
        &mut self,
        cmd: s::ListCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        let is_extended = cmd.select_opts.is_some()
            || cmd.return_opts.is_some()
            || matches!(cmd.pattern, s::MboxOrPat::Multi(_));

        let reference = cmd.reference.get_utf8(self.unicode_aware);
        let patterns = match cmd.pattern {
            s::MboxOrPat::Single(pat) => {
                vec![pat.get_utf8(self.unicode_aware).into_owned()]
            },
            s::MboxOrPat::Multi(pats) => pats
                .into_iter()
                .map(|pat| pat.get_utf8(self.unicode_aware).into_owned())
                .collect::<Vec<_>>(),
        };

        let select_opts = cmd.select_opts.unwrap_or_default();
        let return_opts = cmd.return_opts.unwrap_or_default();
        let mut return_stati: Option<Vec<s::StatusAtt>> = None;
        for opt in &return_opts {
            if let s::ListReturnOpt::Status(ref stati) = opt {
                if return_stati.is_some() {
                    return Err(s::Response::Cond(s::CondResponse {
                        cond: s::RespCondType::Bad,
                        code: Some(s::RespTextCode::ClientBug(())),
                        quip: Some(Cow::Borrowed(
                            "STATUS passed more than once",
                        )),
                    }));
                }

                return_stati = Some(stati.clone());
            }
        }

        // If select_opts contains RECURSIVEMATCH, it must also contain some
        // item which implies filtering.
        if select_opts.contains(&s::ListSelectOpt::RecursiveMatch)
            && !select_opts.contains(&s::ListSelectOpt::Subscribed)
            && !select_opts.contains(&s::ListSelectOpt::SpecialUse)
        {
            return Err(s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::Bad,
                code: None,
                quip: Some(Cow::Borrowed(
                    "RECURSIVEMATCH may not be used without a filtering term",
                )),
            }));
        }

        // NB We can ignore REMOTE in return_opts because it is additive, and
        // we don't have such a concept.

        let request = ListRequest {
            reference: reference.into_owned(),
            patterns,
            select_subscribed: select_opts
                .contains(&s::ListSelectOpt::Subscribed),
            select_special_use: select_opts
                .contains(&s::ListSelectOpt::SpecialUse),
            recursive_match: select_opts
                .contains(&s::ListSelectOpt::RecursiveMatch),
            return_subscribed: select_opts
                .contains(&s::ListSelectOpt::Subscribed)
                || return_opts.contains(&s::ListReturnOpt::Subscribed(())),
            // For non-extended LIST, we return \HasChildren and
            // \HasNoChildren. For extended LIST, we'll let the client decide.
            return_children: !is_extended
                || return_opts.contains(&s::ListReturnOpt::Children(())),
            return_special_use: select_opts
                .contains(&s::ListSelectOpt::SpecialUse)
                || return_opts.contains(&s::ListReturnOpt::SpecialUse(())),
            lsub_style: false,
        };

        let responses =
            account!(self)?.list(&request).map_err(map_error!(self))?;
        for mut response in responses {
            let status = return_stati.as_ref().and_then(|stati| {
                // Unlike virtually every other place in IMAP, RFC 5819
                // stipulates a very strict response order: we return the LIST
                // response, then the STATUS, but the content of the LIST
                // depends on our result for computing the STATUS.

                // First off, there's no status if this mailbox is \Noselect or
                // \NonExistent.
                if response.attributes.contains(&MailboxAttribute::Noselect)
                    || response
                        .attributes
                        .contains(&MailboxAttribute::NonExistent)
                {
                    return None;
                }

                // It exists(ed), try to get its status
                if let Ok(status) = self.evaluate_status(
                    Cow::Borrowed(&response.name),
                    stati,
                    sender,
                ) {
                    Some(status)
                } else {
                    // RFC 5819 specifies to silently drop the STATUS response
                    // if anything goes wrong. However, we're still required to
                    // handle the case where the mailbox was deleted between
                    // getting the list response and STATUS.
                    if !self
                        .account
                        .as_ref()
                        .and_then(|a| a.mailbox_path(&response.name).ok())
                        .map_or(true, |mbp| mbp.is_selectable())
                    {
                        response.attributes.push(MailboxAttribute::Noselect);
                    }
                    None
                }
            });

            sender(s::Response::List(s::MailboxList {
                flags: response
                    .attributes
                    .into_iter()
                    .map(|a| Cow::Borrowed(a.name()))
                    .collect(),
                name: MailboxName::of_utf8(Cow::Owned(response.name)),
                child_info: if response.child_info.is_empty() {
                    None
                } else {
                    Some(
                        response
                            .child_info
                            .into_iter()
                            .map(Cow::Borrowed)
                            .collect(),
                    )
                },
            }));

            if let Some(status) = status {
                sender(status);
            }
        }

        success()
    }

    pub(crate) fn cmd_lsub(
        &mut self,
        cmd: s::LsubCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        let reference = cmd.reference.get_utf8(self.unicode_aware);
        let pattern = cmd.pattern.get_utf8(self.unicode_aware);
        let request = ListRequest {
            reference: reference.into_owned(),
            patterns: vec![pattern.into_owned()],
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
                name: MailboxName::of_utf8(Cow::Owned(response.name)),
                child_info: None,
            }));
        }

        success()
    }

    pub(crate) fn cmd_xlist(
        &mut self,
        cmd: s::XlistCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        let reference = cmd.reference.get_utf8(self.unicode_aware);
        let pattern = cmd.pattern.get_utf8(self.unicode_aware);
        let request = ListRequest {
            reference: reference.into_owned(),
            patterns: vec![pattern.into_owned()],
            select_subscribed: false,
            select_special_use: false,
            recursive_match: false,
            return_subscribed: false,
            return_children: true,
            return_special_use: true,
            lsub_style: false,
        };

        let responses =
            account!(self)?.list(&request).map_err(map_error!(self))?;
        for response in responses {
            sender(s::Response::Xlist(s::MailboxList {
                flags: response
                    .attributes
                    .into_iter()
                    .map(|a| Cow::Borrowed(a.name()))
                    .collect(),
                name: MailboxName::of_utf8(Cow::Owned(response.name)),
                child_info: None,
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
            existing_name: cmd.src.get_utf8(self.unicode_aware).into_owned(),
            new_name: cmd.dst.get_utf8(self.unicode_aware).into_owned(),
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

    pub(crate) fn cmd_examine(
        &mut self,
        cmd: s::ExamineCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        self.select(
            &cmd.mailbox,
            cmd.modifiers.unwrap_or_default(),
            sender,
            true,
        )
    }

    pub(crate) fn cmd_select(
        &mut self,
        cmd: s::SelectCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        self.select(
            &cmd.mailbox,
            cmd.modifiers.unwrap_or_default(),
            sender,
            false,
        )
    }

    pub(crate) fn cmd_status(
        &mut self,
        cmd: s::StatusCommand<'_>,
        sender: SendResponse<'_>,
    ) -> CmdResult {
        sender(self.evaluate_status(
            cmd.mailbox.get_utf8(self.unicode_aware),
            &cmd.atts,
            sender,
        )?);
        success()
    }

    fn evaluate_status(
        &mut self,
        mailbox_name: Cow<'_, str>,
        atts: &[s::StatusAtt],
        sender: SendResponse<'_>,
    ) -> PartialResult<s::Response<'static>> {
        let request = StatusRequest {
            name: mailbox_name.into_owned(),
            messages: atts.contains(&s::StatusAtt::Messages),
            recent: atts.contains(&s::StatusAtt::Recent),
            uidnext: atts.contains(&s::StatusAtt::UidNext),
            uidvalidity: atts.contains(&s::StatusAtt::UidValidity),
            unseen: atts.contains(&s::StatusAtt::Unseen),
            max_modseq: atts.contains(&s::StatusAtt::HighestModseq),
            mailbox_id: atts.contains(&s::StatusAtt::MailboxId),
            size: atts.contains(&s::StatusAtt::Size),
            deleted: atts.contains(&s::StatusAtt::Deleted),
        };

        if request.max_modseq && self.account.is_some() {
            self.enable_condstore(sender, true);
        }

        let response =
            account!(self)?.status(&request).map_err(map_error! {
                self,
                UnsafeName =>
                    (No, Some(s::RespTextCode::Cannot(()))),
                NxMailbox | MailboxUnselectable =>
                    (No, Some(s::RespTextCode::Nonexistent(()))),
            })?;

        let mut atts: Vec<s::StatusResponseAtt> = Vec::with_capacity(10);
        if let Some(messages) = response.messages {
            atts.push(s::StatusResponseAtt::Messages(
                messages.try_into().unwrap_or(u32::MAX),
            ));
        }
        if let Some(recent) = response.recent {
            atts.push(s::StatusResponseAtt::Recent(
                recent.try_into().unwrap_or(u32::MAX),
            ));
        }
        if let Some(uid) = response.uidnext {
            atts.push(s::StatusResponseAtt::UidNext(uid.0.get()));
        }
        if let Some(uidvalidity) = response.uidvalidity {
            atts.push(s::StatusResponseAtt::UidValidity(uidvalidity));
        }
        if let Some(unseen) = response.unseen {
            atts.push(s::StatusResponseAtt::Unseen(
                unseen.try_into().unwrap_or(u32::MAX),
            ));
        }
        if let Some(max_modseq) = response.max_modseq {
            atts.push(s::StatusResponseAtt::HighestModseq(max_modseq));
        }
        if let Some(mailbox_id) = response.mailbox_id {
            atts.push(s::StatusResponseAtt::MailboxId(Cow::Owned(mailbox_id)));
        }
        if let Some(size) = response.size {
            atts.push(s::StatusResponseAtt::Size(size));
        }
        if let Some(deleted) = response.deleted {
            atts.push(s::StatusResponseAtt::Deleted(
                deleted.try_into().unwrap_or(u32::MAX),
            ));
        }

        Ok(s::Response::Status(s::StatusResponse {
            mailbox: MailboxName::of_utf8(Cow::Owned(response.name)),
            atts,
        }))
    }

    pub(crate) fn cmd_subscribe(
        &mut self,
        cmd: s::SubscribeCommand<'_>,
        _sender: SendResponse<'_>,
    ) -> CmdResult {
        account!(self)?
            .subscribe(&cmd.mailbox.get_utf8(self.unicode_aware))
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
            .unsubscribe(&cmd.mailbox.get_utf8(self.unicode_aware))
            .map_err(map_error! {
                self,
                NxMailbox => (No, Some(s::RespTextCode::Nonexistent(()))),
                UnsafeName => (No, Some(s::RespTextCode::Cannot(()))),
            })?;
        success()
    }

    fn select(
        &mut self,
        mailbox: &MailboxName<'_>,
        modifiers: Vec<s::SelectModifier<'_>>,
        sender: SendResponse,
        read_only: bool,
    ) -> CmdResult {
        // We need to validate the modifiers before we do anything else
        let mut enable_condstore = false;
        let mut qresync: Option<QresyncRequest> = None;

        for modifier in modifiers {
            match modifier {
                s::SelectModifier::Condstore(()) => {
                    if enable_condstore {
                        return Err(s::Response::Cond(s::CondResponse {
                            cond: s::RespCondType::Bad,
                            code: Some(s::RespTextCode::ClientBug(())),
                            quip: Some(Cow::Borrowed(
                                "CONDSTORE passed more than once",
                            )),
                        }));
                    }

                    enable_condstore = true;
                },
                s::SelectModifier::Qresync(qr) => {
                    if !self.qresync_enabled {
                        return Err(s::Response::Cond(s::CondResponse {
                            cond: s::RespCondType::Bad,
                            code: Some(s::RespTextCode::ClientBug(())),
                            quip: Some(Cow::Borrowed(
                                "ENABLE QRESYNC required",
                            )),
                        }));
                    }

                    if qresync.is_some() {
                        return Err(s::Response::Cond(s::CondResponse {
                            cond: s::RespCondType::Bad,
                            code: Some(s::RespTextCode::ClientBug(())),
                            quip: Some(Cow::Borrowed(
                                "QRESYNC passed more than once",
                            )),
                        }));
                    }

                    let known_uids = if let Some(ku) = qr.known_uids {
                        Some(parse_global_seqrange(&ku)?)
                    } else {
                        None
                    };

                    let mapping_reference = if let Some(smd) = qr.seq_match_data
                    {
                        let seqnums: SeqRange<Seqnum> =
                            parse_global_seqrange(&smd.seqnums)?;
                        let uids: SeqRange<Uid> =
                            parse_global_seqrange(&smd.uids)?;

                        if seqnums.len() != uids.len() {
                            return Err(s::Response::Cond(s::CondResponse {
                                cond: s::RespCondType::Bad,
                                code: Some(s::RespTextCode::ClientBug(())),
                                quip: Some(Cow::Borrowed(
                                    "sequence sets in seq-match-data are \
                                     not the same length",
                                )),
                            }));
                        }

                        Some((seqnums, uids))
                    } else {
                        None
                    };

                    qresync = Some(QresyncRequest {
                        uid_validity: qr.uid_validity,
                        resync_from: Modseq::of(qr.modseq),
                        known_uids,
                        mapping_reference,
                    });
                },
            }
        }

        // SELECT and EXAMINE unselect any selected mailbox regardless of
        // whether they succeed.
        self.unselect(sender);

        // RFC 7162 does not describe whether an implicit enable of CONDSTORE
        // due to `SELECT mailbox (CONDSTORE)` while another mailbox was
        // already selected should emit a HIGHESTMODSEQ response for the
        // previous mailbox.
        //
        // Here, we do not do so (by doing this after the implicit unselect
        // above), on the basis of two theories:
        //
        // 1. It isn't useful to return HIGHESTMODSEQ for a mailbox about to be
        // unselected, so it is unlikely any client depends on this.
        //
        // 2. It is more likely a buggy client would be broken by a spurious
        // HIGHESTMODSEQ than a missing one.
        if enable_condstore {
            self.enable_condstore(sender, true);
        }

        let mailbox = mailbox.get_utf8(self.unicode_aware);
        let stateless = account!(self)?.mailbox(&mailbox, read_only).map_err(
            map_error! {
                self,
                NxMailbox | MailboxUnselectable =>
                    (No, Some(s::RespTextCode::Nonexistent(()))),
                UnsafeName =>
                    (No, Some(s::RespTextCode::Cannot(()))),
            },
        )?;
        let mailbox_id = stateless.path().mailbox_id().map_err(map_error! {
            self,
            NxMailbox | MailboxUnselectable =>
                (No, Some(s::RespTextCode::Nonexistent(()))),
            UnsafeName =>
                (No, Some(s::RespTextCode::Cannot(()))),
        })?;

        let (mut stateful, select) =
            stateless.select().map_err(map_error! {
                self,
                NxMailbox | MailboxUnselectable =>
                    (No, Some(s::RespTextCode::Nonexistent(()))),
                UnsafeName =>
                    (No, Some(s::RespTextCode::Cannot(()))),
            })?;
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
        sender(s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Ok,
            code: Some(s::RespTextCode::MailboxId(Cow::Owned(mailbox_id))),
            quip: None,
        }));
        if self.condstore_enabled {
            sender(s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::Ok,
                code: Some(s::RespTextCode::HighestModseq(
                    select.max_modseq.map_or(1, |m| m.raw().get()),
                )),
                quip: None,
            }));
        }

        if let Some(qresync) = qresync {
            let response =
                stateful.qresync(qresync).map_err(map_error!(self))?;
            if !response.expunged.is_empty() {
                sender(s::Response::Vanished(s::VanishedResponse {
                    earlier: true,
                    uids: Cow::Owned(response.expunged.to_string()),
                }));
            }
            // The FETCH responses, if any, are handled by the poll cycle at
            // the end of the SELECT.
        }

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

    fn unselect(&mut self, sender: SendResponse<'_>) {
        if self.selected.is_some() {
            sender(s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::Ok,
                code: Some(s::RespTextCode::Closed(())),
                quip: None,
            }));
        }
        self.selected = None;
        self.searchres.clear();
    }
}
