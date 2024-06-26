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

//! Support for manipulating mailbox paths and operations that manipulate whole
//! mailboxes.
//!
//! Information on file layout is found in the `mailbox` module documentation.

use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use rand::{rngs::OsRng, Rng};
use serde::{Deserialize, Serialize};
use tempfile::TempDir;

use crate::account::model::*;
use crate::support::error::Error;
use crate::support::file_ops::{self, ErrorTransforms, IgnoreKinds};
use crate::support::safe_name::is_safe_name;

/// A lightweight reference to a mailbox by path.
///
/// This is used for most IMAP operations that take place outside the context
/// of selection (i.e. the "Authenticated State" in RFC 3501).
#[derive(Clone, Debug)]
pub struct MailboxPath {
    pub(super) name: String,
    pub(super) base_path: PathBuf,
    pub(super) data_path: PathBuf,
    pub(super) metadata_path: PathBuf,
    pub(super) socks_path: PathBuf,
    pub(super) shadow_path: PathBuf,
    pub(super) sub_path: PathBuf,
}

impl MailboxPath {
    fn from_name_and_path(
        name: String,
        base_path: PathBuf,
        shadow_path: PathBuf,
    ) -> Self {
        let data_path = base_path.join("%");
        MailboxPath {
            metadata_path: data_path.join("mailbox.toml"),
            sub_path: shadow_path.join("%subscribe"),
            socks_path: data_path.join("socks"),
            name,
            base_path,
            data_path,
            shadow_path,
        }
    }

    /// Instantiate a `MailboxPath` under the root.
    pub fn root(
        name: String,
        root: &Path,
        shadow_root: &Path,
    ) -> Result<Self, Error> {
        if !is_safe_name(&name) {
            return Err(Error::UnsafeName);
        }

        let path = root.join(&name);
        let shadow_path = shadow_root.join(&name);
        Ok(MailboxPath::from_name_and_path(name, path, shadow_path))
    }

    /// Instantiate a `MailboxPath` inferior to this one.
    pub fn child(&self, name: &str) -> Result<Self, Error> {
        if !is_safe_name(name) {
            return Err(Error::UnsafeName);
        }

        if !self.allows_children() {
            return Err(Error::BadOperationOnInbox);
        }

        Ok(MailboxPath::from_name_and_path(
            format!("{}/{}", self.name, name),
            self.base_path.join(name),
            self.shadow_path.join(name),
        ))
    }

    /// Return this mailbox's canonical name, e.g. "INBOX" or "Archive/2020".
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the *current* UID validity, i.e., that which would be used if
    /// the mailbox were opened right now.
    #[allow(clippy::needless_borrows_for_generic_args)] // false positive
    pub fn current_uid_validity(&self) -> Result<u32, Error> {
        if !self.exists() {
            return Err(Error::NxMailbox);
        }

        parse_uid_validity(
            &nix::fcntl::readlink(&self.data_path)
                .on_not_found(Error::MailboxUnselectable)?,
        )
    }

    /// Return the UID-specific root of the mailbox data.
    pub fn scoped_data_path(&self) -> Result<PathBuf, Error> {
        Ok(
            self.scoped_data_path_for_uid_validity(
                self.current_uid_validity()?,
            ),
        )
    }

    fn scoped_data_path_for_uid_validity(&self, uid_validity: u32) -> PathBuf {
        self.base_path.join(format!("%{:x}", uid_validity))
    }

    /// Whether this mailbox allows children.
    ///
    /// INBOX is not allowed to have children due to the crazy special case RFC
    /// 3501 adds to `RENAME INBOX`.
    pub fn allows_children(&self) -> bool {
        "INBOX" != &self.name
    }

    /// Whether this mailbox can be selected (i.e., whether it can contain
    /// messages).
    pub fn is_selectable(&self) -> bool {
        self.data_path.is_dir()
    }

    /// Whether this mailbox exists as a physical entity, i.e., whether it is a
    /// real mailbox in the view of IMAP.
    pub fn exists(&self) -> bool {
        self.base_path.is_dir()
    }

    /// Whether this mailbox is currently subscribed.
    pub fn is_subscribed(&self) -> bool {
        self.sub_path.is_file()
    }

    /// Return an iterator to the children of this mailbox, regardless of
    /// existence status.
    pub fn children(&self) -> impl Iterator<Item = MailboxPath> + '_ {
        self.children_impl(&self.base_path)
    }

    fn children_impl<'a>(
        &'a self,
        path: &Path,
    ) -> impl Iterator<Item = MailboxPath> + 'a {
        fs::read_dir(path)
            .ok()
            .map(move |it| {
                it.filter_map(|r| r.ok())
                    .filter_map(|entry| entry.file_name().into_string().ok())
                    .filter_map(move |name| self.child(&name).ok())
            })
            .map(|it| {
                Box::new(it) as Box<dyn Iterator<Item = MailboxPath> + 'a>
            })
            .unwrap_or_else(|| Box::new(std::iter::empty()))
    }

    /// Create this mailbox.
    ///
    /// A `\Noselect` mailbox cannot be "created" to restore its dual-use
    /// status.
    ///
    /// Does not create parent mailboxes implicitly.
    ///
    /// Returns the MAILBOXID of the new path.
    pub fn create(
        &self,
        tmp: &Path,
        special_use: Option<MailboxAttribute>,
    ) -> Result<String, Error> {
        // Generate the UID validity by using the lower 32 bits of the
        // UNIX time. It is fine that this will wrap in 2106. To even
        // have a chance of colliding, the mail server would need to be
        // in use for 136 years.
        let uid_validity = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        // ... but for some reason, RFC 3501 requires UIDVALIDITY to be
        // strictly ascending, despite the only sensible operation on the value
        // being equality. To maximise the time until we risk violating that
        // constraint, adjust the "zero epoch" to 2020-01-01. This gives until
        // 2156 before wrapping. We also need to avoid generating 0.
        let mut uid_validity = uid_validity.wrapping_sub(1577836800).max(1);

        // We need to avoid generating duplicate UID validity values when
        // mailboxes are created in quick succession, since otherwise the
        // identity requirements could be invalidated by renaming one mailbox,
        // then another to the former's old name.
        //
        // To do this, we simply try to create a token file in the temp
        // directory. If the UV is already taken, increment and try again
        // ("time creep"). We give up after 1000 tries, which ensures we don't
        // fail forever and also don't creep so far forward that markers needed
        // for correctness get cleaned up.
        for trie in 0.. {
            match fs::OpenOptions::new()
                .mode(0o600)
                .create_new(true)
                .write(true)
                .open(tmp.join(format!("uv-{:x}", uid_validity)))
            {
                Ok(_) => break,
                Err(e) if io::ErrorKind::AlreadyExists == e.kind() => {
                    if trie < 1000 {
                        uid_validity = uid_validity.wrapping_add(1).max(1);
                    } else {
                        return Err(Error::GaveUpInsertion);
                    }
                },
                Err(e) => return Err(e.into()),
            }
        }

        // Stage the new mailbox hierarchy inside tmp, then move the whole
        // thing in when done.
        let stage = TempDir::new_in(tmp)?;
        let stage_mbox = MailboxPath::from_name_and_path(
            String::new(),
            stage.path().to_owned(),
            // Shadow path doesn't matter
            stage.path().to_owned(),
        );
        let scoped_path =
            stage_mbox.scoped_data_path_for_uid_validity(uid_validity);
        fs::DirBuilder::new().mode(0o750).create(&scoped_path)?;
        std::os::unix::fs::symlink(
            scoped_path.file_name().unwrap(),
            &stage_mbox.data_path,
        )?;
        let mailbox_id = gen_mailbox_id();
        let full_mailbox_id = self.format_mailbox_id(&mailbox_id);
        let metadata = MailboxMetadata {
            imap: MailboxImapMetadata {
                special_use,
                mailbox_id,
            },
        };

        let metadata_toml = format!(
            "# Edit this file at your own peril!\n\
             # Crymap assumes it never changes.\n{}",
            toml::to_string_pretty(&metadata).unwrap()
        );
        file_ops::spit(
            tmp,
            &stage_mbox.metadata_path,
            false,
            0o440,
            metadata_toml.as_bytes(),
        )?;

        // Ready to go
        fs::rename(stage.into_path(), &self.base_path)
            .on_exists(Error::MailboxExists)
            .map_err(|e| match e {
                Error::Io(e)
                    if Some(nix::libc::ENOTEMPTY) == e.raw_os_error() =>
                {
                    Error::MailboxExists
                },
                e => e,
            })?;

        Ok(full_mailbox_id)
    }

    /// Create this mailbox if it does not already exist.
    pub fn create_if_nx(&self, tmp: &Path) -> Result<(), Error> {
        if !self.exists() {
            match self.create(tmp, None) {
                Err(Error::MailboxExists) => Ok(()),
                Err(e) => Err(e),
                Ok(_) => Ok(()),
            }
        } else {
            Ok(())
        }
    }

    /// Delete this mailbox, using IMAP semantics.
    ///
    /// If this mailbox is selectable, any messages it contains are destroyed
    /// and it becomes a `\Noselect` mailbox.
    ///
    /// If the mailbox has no inferiors, it is fully removed.
    ///
    /// A `MailboxHasInferiors` error is only returned if this mailbox was
    /// already `\Noselect` and it has inferiors visible to IMAP.
    pub fn delete(&self, garbage: &Path) -> Result<(), Error> {
        if &self.name == "INBOX" {
            return Err(Error::BadOperationOnInbox);
        }

        // If no children, completely remove self
        // This also handles the case where self does not exist
        if self.children().next().is_none() {
            file_ops::delete_atomically(&self.base_path, garbage)
                .on_not_found(Error::NxMailbox)
        } else {
            // Atomically turn into a \Noselect mailbox if we were selectable
            let selectable = match self.scoped_data_path().and_then(|p| {
                file_ops::delete_atomically(p, garbage).map_err(|e| e.into())
            }) {
                Ok(()) => true,
                Err(Error::MailboxUnselectable) => false,
                Err(Error::Io(e)) if io::ErrorKind::NotFound == e.kind() => {
                    false
                },
                Err(e) => return Err(e),
            };

            // Regardless of selectability, the %UV directory is gone, so
            // remove the symlink too
            let _ = fs::remove_file(&self.data_path);

            if selectable {
                // OK, silently keep existing as a \Noselect
                Ok(())
            } else {
                // We were already \Noselect, so complain
                Err(Error::MailboxHasInferiors)
            }
        }
    }

    /// Rename self to `dst`.
    ///
    /// Does not create parent mailboxes implicitly.
    ///
    /// `tmp` is used to stage files for the INBOX special case.
    pub fn rename(&self, dst: &MailboxPath, tmp: &Path) -> Result<(), Error> {
        fs::rename(&self.base_path, &dst.base_path)
            .on_not_found(Error::NxMailbox)
            .on_exists(Error::MailboxExists)
            .map_err(|e| match e {
                Error::Io(e)
                    if Some(nix::libc::ENOTEMPTY) == e.raw_os_error() =>
                {
                    Error::MailboxExists
                },
                e => e,
            })?;

        // RFC 3501 specifies a crazy special case for INBOX: A RENAME does not
        // rename it, but instead *creates* the destination and then moves all
        // *messages* into the new mailbox, while leaving all child mailboxes
        // alone.
        //
        // Due to the last clause, we forbid INBOX from having any children.
        //
        // In our implementation, we just rename INBOX and then recreate it.
        // This isn't ideal since it is non-atomic and results in a brief
        // window in which there *is no inbox*, but overall we have a choice
        // between doing that and having a period where the messages that were
        // in the inbox are not reachable by any mailbox, which is far worse.
        if &self.name == "INBOX" {
            match self.create(tmp, None) {
                Ok(_) => (),
                Err(Error::MailboxExists) => (),
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    /// Loads and returns the metadata for this mailbox.
    pub fn metadata(&self) -> Result<MailboxMetadata, Error> {
        if !self.exists() {
            return Err(Error::NxMailbox);
        }

        let mut reader = fs::File::open(&self.metadata_path)
            .on_not_found(Error::MailboxUnselectable)?;
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        Ok(toml::from_slice(&data)?)
    }

    /// Return the RFC 8474 MAILBOXID for this mailbox.
    pub fn mailbox_id(&self) -> Result<String, Error> {
        let base_id = self.metadata()?.imap.mailbox_id;
        Ok(self.format_mailbox_id(&base_id))
    }

    fn format_mailbox_id(&self, base_id: &str) -> String {
        if "INBOX" == self.name {
            format!("I{}", base_id)
        } else {
            format!("M{}", base_id)
        }
    }

    /// Mark this mailbox as subscribed.
    pub fn subscribe(&self) -> Result<(), Error> {
        fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(&self.shadow_path)
            .ignore_already_exists()?;
        fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&self.sub_path)
            .map(|_| ())?;
        Ok(())
    }

    /// Mark this mailbox as unsubscribed.
    pub fn unsubscribe(&self) -> Result<(), Error> {
        Ok(fs::remove_file(&self.sub_path).ignore_not_found()?)
    }

    /// Underlying implementation for `LIST`, `XLIST`, and `LSUB`.
    ///
    /// `matcher` is used to determine  whether the mailbox's name matches.
    ///
    /// Results are pushed into `dst` in post-order, so `dst` must be reversed
    /// once the full result set is in.
    ///
    /// On success, returns whether this mailbox exists, and whether there are
    /// selected but unmatched mailboxes within it (i.e. either itself or any
    /// direct or indirect children).
    pub fn list(
        &self,
        dst: &mut Vec<ListResponse>,
        request: &ListRequest,
        matcher: &impl Fn(&str) -> bool,
    ) -> ChildListResult {
        let mut self_result = ChildListResult::default();
        let selectable = self.is_selectable();
        self_result.exists = self.exists();

        let self_matches = matcher(&self.name);

        let subscribed = (request.select_subscribed
            || request.return_subscribed)
            && self.is_subscribed();
        let special_use =
            if request.select_special_use || request.return_special_use {
                self.metadata().ok().and_then(|md| md.imap.special_use)
            } else {
                None
            };

        let mut self_selected = (!request.select_subscribed || subscribed)
            && (!request.select_special_use || special_use.is_some());
        let mut has_children = false;

        let children = self.children_impl(if request.select_subscribed {
            &self.shadow_path
        } else {
            &self.base_path
        });
        for child in children {
            let child_result = child.list(dst, request, matcher);
            self_result.selected_subscribe |= child_result.selected_subscribe;
            self_result.selected_special_use |=
                child_result.selected_special_use;
            self_result.unmatched_but_selected |=
                child_result.unmatched_but_selected;

            // RFC 5258 does not specifically define the behaviour of
            // \HasChildren and \HasNoChildren when acting on subscriptions.
            // Here, we take the position that they still refer to the *real*
            // mailboxes and not the shadow hierarchy that subscriptions have.
            has_children |= child_result.exists;
        }

        // If we aren't doing subscriptions, we filter to only existing
        // mailboxes.
        self_selected &= request.select_subscribed || self_result.exists;

        // Add an entry for self if matching and selected, or if matching and
        // unselected but we have a selected but unmatching child and
        // recursive_match is enabled.
        if self_matches
            && (self_selected
                || (request.recursive_match
                    && self_result.unmatched_but_selected))
        {
            let mut info = ListResponse {
                name: self.name.clone(),
                ..ListResponse::default()
            };

            if !self_selected && request.lsub_style {
                // If not selected but being included anyway due to
                // recursive_match, tell the client about this. For LSUB,
                // \Noselect is abused. For extended list, it is implied by the
                // fact that the returned mailbox doesn't have the attribute
                // being selected.
                info.attributes.push(MailboxAttribute::Noselect);
            } else if !self_result.exists {
                // If this mailbox doesn't exist but is a subscription, tell
                // the client unless we're doing LSUB.
                if !request.lsub_style {
                    info.attributes.push(MailboxAttribute::NonExistent);
                }
            } else if !selectable {
                // In most cases, we return \Noselect for non-selectable
                // mailboxes that do exist. The exception is LSUB, where
                // \Noselect is repurposed to mean "not subscribed, but has
                // unreported inferiors which are subscribed".
                if !request.lsub_style {
                    info.attributes.push(MailboxAttribute::Noselect);
                }
            }

            if !self.allows_children() {
                info.attributes.push(MailboxAttribute::Noinferiors);
            }

            if subscribed && request.return_subscribed {
                info.attributes.push(MailboxAttribute::Subscribed);
            }

            if request.return_children {
                if has_children {
                    info.attributes.push(MailboxAttribute::HasChildren);
                } else if self.allows_children() {
                    // Only HasNoChildren if we allow children, since otherwise
                    // we have \Noinferiors which already implies
                    // \HasNoChildren. Sending both is still OK and isn't even
                    // a "SHOULD NOT", but it's best to conform to the
                    // examples.
                    info.attributes.push(MailboxAttribute::HasNoChildren);
                }
            }

            if request.return_special_use {
                if let Some(special_use) = special_use {
                    info.attributes.push(special_use);
                }
            }

            if request.recursive_match {
                if self_result.selected_special_use {
                    info.child_info.push("SPECIAL-USE");
                }

                if self_result.selected_subscribe {
                    info.child_info.push("SUBSCRIBED");
                }

                // We've covered the unmatched child, so this can stop
                // propagating.
                self_result.unmatched_but_selected = false;
            }

            dst.push(info);
        }

        // CHILDINFO data is passed the whole way up the tree unconditionally.
        self_result.selected_special_use |=
            request.select_special_use && special_use.is_some();
        self_result.selected_subscribe |=
            request.select_subscribed && subscribed;

        if !self_matches && self_selected {
            // Notify our parent that we were selected but not matched so that
            // it can insert a spurious result if it matches but isn't
            // selected.
            self_result.unmatched_but_selected = true;
        }

        self_result
    }
}

/// This is used internally by `MailboxPath::list`.
///
/// Its value is not meaningful outside that function, but must be `pub` here
/// since it is nonetheless returned.
#[derive(Clone, Copy, Default)]
pub struct ChildListResult {
    selected_subscribe: bool,
    selected_special_use: bool,
    unmatched_but_selected: bool,
    exists: bool,
}

/// Immutable metadata about a mailbox.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MailboxMetadata {
    pub imap: MailboxImapMetadata,
}

/// IMAP-specific immutable metadata about a mailbox.
///
/// The "general" vs "IMAP" distinction is mainly because TOML requires a top
/// level of nesting.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MailboxImapMetadata {
    /// If this is a special-use mailbox, the attribute representing that use.
    pub special_use: Option<MailboxAttribute>,
    /// The RFC 8474 MAILBOXID of this mailbox, sans prefix.
    ///
    /// On INBOX, this gets prefixed with "I". On any other mailbox, it gets
    /// prefixed with "M". This is needed to maintain the illusion that a
    /// RENAME of INBOX is not actually a rename.
    pub mailbox_id: String,
}

/// Parse the UID validity out of the given path.
///
/// Only the filename of the path is considered, so this will not work for
/// things inside the mailbox data directory.
pub fn parse_uid_validity(path: impl AsRef<Path>) -> Result<u32, Error> {
    let path = path.as_ref();
    let name = path
        .file_name()
        .ok_or(Error::CorruptFileLayout)?
        .to_str()
        .ok_or(Error::CorruptFileLayout)?;

    if !name.starts_with('%') {
        return Err(Error::CorruptFileLayout);
    }

    u32::from_str_radix(&name[1..], 16).map_err(|_| Error::CorruptFileLayout)
}

fn gen_mailbox_id() -> String {
    // 15 bytes = 120 bits of entropy, roughly the same as a V4 UUID, but
    // shorter since we can use base64 encoding. This outputs a 20 character
    // string, and then we have the extra 1-character prefix for a total of 21
    // character ids. Using 15 bytes means there is no padding, which is
    // important since the padding characters are not allowed in object ids.
    // (The set of allowed characters is exactly the set of "URL Safe" base64.)
    let data: [u8; 15] = OsRng.gen();
    base64::encode_config(data, base64::URL_SAFE)
}
