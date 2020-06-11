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

//! Support for working with mailboxes.
//!
//! A mailbox is an ensemble of a `MessageStore`, a `FlagStore`, its
//! children, and some ancillary data.
//!
//! The contents of a mailbox directory are:
//! - `%/msgs/`. The root of the `MessageStore`.
//! - `%/flags/`. The root of the `FlagStore`.
//! - `%/mailbox.toml`. Immutable metadata, specifically the UID validity and
//!   any special-use flags.
//! - `%/unsubscribe`. Marker file; if present, the mailbox is not subscribed.
//! - Directories containing child mailboxes, each of which is in a
//!   subdirectory corresponding to its name. Only exists if there are any such
//!   children.
//!
//! There are some wonky special cases to support IMAP's wonky data model.
//!
//! If the `s` directory is missing, this is a `\Noselect` mailbox. Mailboxes
//! are normally created as dual-use, but IMAP requires that a `DELETE`
//! operation on a dual-use mailbox with child mailboxes must transmogrify it
//! into a folder-like mailbox.
//!
//! The subscription model is different from what RFC 3501 prescribes. All
//! selectable mailboxes are subscribed by default, which corresponds to most
//! people's expectations (evidenced by the fact that real mail clients
//! scramble to subscribe a mailbox they create as soon as possible). It also
//! lets us fulfil the letter, though perhaps not the spirit, of the
//! requirement that deleting a mailbox does not unsubscribe it. Instead,
//! deleting a mailbox effectively subscribes it should it be recreated.
//! Ultimately, though, the subtleties of subscriptions likely don't matter too
//! much here since they are rarely used productively and the exotic use-cases
//! the standard urges to support (i.e. a shared mailbox that occasionally gets
//! deleted and later recreated) simply won't happen here.
//!
//! In general:
//!
//! - A mailbox exists (i.e., is visible to IMAP) if its directory exists.
//!
//! - A mailbox is selectable if the `%` subdirectory exists. It is assumed
//!   that the contents of that subdirectory will not be partially
//!   instantiated.
//!
//! - A mailbox is subscribed if it is selectable and does not have a
//!   `%/unsubscribe` file.

use std::path::Path;

use crate::support::error::Error;
use super::flag_store::FlagStore;
use super::message_store::MessageStore;
use super::mailbox_path::*;

/// A heavy-weight handle for a mailbox.
///
/// Like `MessageStore`, this has distinct "active" and "passive" modes. Active
/// mode is entered by the `select()` method.
pub struct Mailbox {
    path: MailboxPath,
    log_prefix: String,
    message_store: MessageStore,
    flag_store: FlagStore,
}

impl Mailbox {
    pub fn new(path: MailboxPath, log_prefix: String, read_only: bool,
               tmp: &Path,
               notify: impl Fn() + Send + Sync + 'static)
               -> Result<Self, Error> {
        if !path.exists() {
            Err(Error::NxMailbox)
        } else if !path.is_selectable() {
            Err(Error::MailboxUnselectable)
        } else {
            let log_prefix = format!("{}:{}", log_prefix, path.name);
            Ok(Mailbox {
                message_store: MessageStore::new(
                    log_prefix.clone(),
                    path.msgs_path.clone(),
                    tmp.to_owned(),
                    read_only,
                    notify),
                flag_store: FlagStore::new(
                    path.flags_path.clone(),
                    read_only),
                log_prefix,
                path,
            })
        }
    }
}
