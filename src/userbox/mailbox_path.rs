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

use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tempfile::TempDir;

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
    pub(super) msgs_path: PathBuf,
    pub(super) flags_path: PathBuf,
    pub(super) metadata_path: PathBuf,
    pub(super) unsub_path: PathBuf,
}

/// Attributes that may be applied to mailboxes.
///
/// This includes the RFC 6154 special-use markers.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum MailboxAttribute {
    // RFC 3501
    // We never do anything with \Noinferiors, \Marked, or \Unmarked, so they
    // are not defined here.
    Noselect,
    // RFC 3348
    HasChildren,
    HasNoChildren,
    // RFC 6154
    // \All is not supported
    Archive,
    Drafts,
    Flagged,
    Junk,
    Sent,
    Trash,
}

impl fmt::Display for MailboxAttribute {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &MailboxAttribute::Noselect => write!(f, "\\Noselect"),
            &MailboxAttribute::HasChildren => write!(f, "\\HasChildren"),
            &MailboxAttribute::HasNoChildren => write!(f, "\\HasNoChildren"),
            &MailboxAttribute::Archive => write!(f, "\\Archive"),
            &MailboxAttribute::Drafts => write!(f, "\\Drafts"),
            &MailboxAttribute::Flagged => write!(f, "\\Flagged"),
            &MailboxAttribute::Junk => write!(f, "\\Junk"),
            &MailboxAttribute::Sent => write!(f, "\\Sent"),
            &MailboxAttribute::Trash => write!(f, "\\Trash"),
        }
    }
}

impl fmt::Debug for MailboxAttribute {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        <MailboxAttribute as fmt::Display>::fmt(self, f)
    }
}

impl MailboxPath {
    fn from_name_and_path(name: String, base_path: PathBuf) -> Self {
        let data_path = base_path.join("%");
        MailboxPath {
            msgs_path: data_path.join("msgs"),
            flags_path: data_path.join("flags"),
            metadata_path: data_path.join("mailbox.toml"),
            unsub_path: data_path.join("unsubscribe"),
            name,
            base_path,
            data_path,
        }
    }

    /// Instantiate a `MailboxPath` under the root.
    pub fn root(name: String, root: &Path) -> Result<Self, Error> {
        if !is_safe_name(&name) {
            return Err(Error::UnsafeName);
        }

        let path = root.join(&name);
        Ok(MailboxPath::from_name_and_path(name, path))
    }

    /// Instantiate a `MailboxPath` inferior to this one.
    pub fn child(&self, name: &str) -> Result<Self, Error> {
        if !is_safe_name(&name) {
            return Err(Error::UnsafeName);
        }

        Ok(MailboxPath::from_name_and_path(
            format!("{}/{}", self.name, name),
            self.base_path.join(name),
        ))
    }

    /// Return this mailbox's canonical name, e.g. "INBOX" or "Archive/2020".
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the root of the mailbox data.
    pub fn data_path(&self) -> &Path {
        &self.data_path
    }

    /// Return the *current* UID validity, i.e., that which would be used if
    /// the mailbox were opened right now.
    pub fn current_uid_validity(&self) -> Result<u32, Error> {
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

    /// Return the root of the `MessageStore`.
    pub fn msgs_path(&self) -> &Path {
        &self.msgs_path
    }

    /// Return the root of the `FlagStore`.
    pub fn flags_path(&self) -> &Path {
        &self.flags_path
    }

    /// Whether this mailbox can be selected (i.e., whether it can contain
    /// messages).
    pub fn is_selectable(&self) -> bool {
        self.data_path.is_dir()
    }

    /// Whether this mailbox exists
    pub fn exists(&self) -> bool {
        self.base_path.is_dir()
    }

    /// Whether this mailbox is currently subscribed.
    pub fn is_subscribed(&self) -> bool {
        self.is_selectable() && !self.unsub_path.is_file()
    }

    /// Return an iterator to the children of this mailbox, regardless of
    /// existence status.
    pub fn children<'a>(&'a self) -> impl Iterator<Item = MailboxPath> + 'a {
        fs::read_dir(&self.base_path)
            .ok()
            .map(move |it| {
                it.filter_map(|r| r.ok())
                    .filter_map(|entry| entry.file_name().into_string().ok())
                    .filter_map(move |name| self.child(&name).ok())
            })
            .map(|it| {
                Box::new(it) as Box<dyn Iterator<Item = MailboxPath> + 'a>
            })
            .unwrap_or(Box::new(std::iter::empty()))
    }

    /// Create this mailbox.
    ///
    /// A `\Noselect` mailbox cannot be "created" to restore its dual-use
    /// status.
    ///
    /// Does not create parent mailboxes implicitly.
    pub fn create(
        &self,
        tmp: &Path,
        special_use: Option<MailboxAttribute>,
    ) -> Result<(), Error> {
        // Generate the UID validity by using the lower 32 bits of the
        // UNIX time. It is fine that this will wrap in 2106. To even
        // have a chance of colliding, the mail server would need to be
        // in use for 136 years.
        let uid_validity = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        // Stage the new mailbox hierarchy inside tmp, then move the whole
        // thing in when done.
        let stage = TempDir::new_in(tmp)?;
        let stage_mbox = MailboxPath::from_name_and_path(
            String::new(),
            stage.path().to_owned(),
        );
        let scoped_path =
            stage_mbox.scoped_data_path_for_uid_validity(uid_validity);
        fs::DirBuilder::new().mode(0o750).create(&scoped_path)?;
        std::os::unix::fs::symlink(
            scoped_path.file_name().unwrap(),
            &stage_mbox.data_path,
        )?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&stage_mbox.flags_path)?;
        fs::DirBuilder::new()
            .mode(0o770)
            .create(&stage_mbox.msgs_path)?;
        let metadata = MailboxMetadata {
            imap: MailboxImapMetadata { special_use },
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
            .on_exists(Error::MailboxExists)?;

        Ok(())
    }

    /// Create this mailbox if it does not already exist.
    pub fn create_if_nx(&self, tmp: &Path) -> Result<(), Error> {
        if !self.exists() {
            match self.create(tmp, None) {
                Err(Error::MailboxExists) => Ok(()),
                r => r,
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
            file_ops::delete_async(&self.base_path, garbage)
                .on_not_found(Error::NxMailbox)
        } else {
            // Atomically turn into a \Noselect mailbox if we were selectable
            let selectable = match self.scoped_data_path().and_then(|p| {
                file_ops::delete_async(p, garbage).map_err(|e| e.into())
            }) {
                Ok(()) => true,
                Err(Error::Io(e)) if io::ErrorKind::NotFound == e.kind() => {
                    false
                }
                Err(e) => return Err(e),
            };

            // Regardless of selectability, the %UV directory is gone, so
            // remove the symlink to
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
    pub fn rename(&self, dst: &MailboxPath) -> Result<(), Error> {
        // RFC 3501 specifies a crazy special case for INBOX: A RENAME does not
        // rename it, but instead *creates* the destination and then moves all
        // *messages* into the new mailbox, while leaving all child mailboxes
        // alone. While this could be done, it would momentarily turn INBOX
        // into a \Noselect mailbox, and thereafter needs to reset the UID
        // validity. Overall it's a sufficiently icky special case to warrant
        // violating the standard until/if we come across a client insane
        // enough to depend on it.
        if &self.name == "INBOX" {
            return Err(Error::BadOperationOnInbox);
        }

        fs::rename(&self.base_path, &dst.base_path)
            .on_not_found(Error::NxMailbox)
            .on_exists(Error::MailboxExists)
    }

    /// Loads and returns the metadata for this mailbox.
    pub fn metadata(&self) -> Result<MailboxMetadata, Error> {
        let mut reader = fs::File::open(&self.metadata_path)
            .on_not_found(Error::MailboxUnselectable)?;
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        Ok(toml::from_slice(&data)?)
    }

    /// The RFC 3501+6154 LIST and XLIST commands.
    pub fn list(
        &self,
        dst: &mut Vec<ListInfo>,
        matcher: impl Copy + Fn(&str) -> bool,
    ) {
        if matcher(&self.name) {
            let mut self_info = ListInfo {
                name: self.name.clone(),
                attributes: vec![],
            };

            match self.metadata() {
                Ok(md) => {
                    if let Some(special_use) = md.imap.special_use {
                        self_info.attributes.push(special_use);
                    }
                }
                Err(_) => {
                    self_info.attributes.push(MailboxAttribute::Noselect);
                }
            }

            let mut childit = self.children().peekable();
            if childit.peek().is_some() {
                self_info.attributes.push(MailboxAttribute::HasChildren);
            } else {
                self_info.attributes.push(MailboxAttribute::HasNoChildren);
            }

            dst.push(self_info);

            for child in childit {
                child.list(dst, matcher);
            }
        } else {
            for child in self.children() {
                child.list(dst, matcher);
            }
        }
    }

    /// The RFC 3501 LSUB command.
    ///
    /// Returns true if this mailbox or any of its direct or indirect children
    /// are subscribed but were excluded by the matcher, and no mailboxes which
    /// did match were found between the two points to be able to communicate
    /// this (i.e., the `\Noselect` special case described for `LSUB` in RFC
    /// 3501).
    pub fn lsub(
        &self,
        dst: &mut Vec<ListInfo>,
        matcher: impl Copy + Fn(&str) -> bool,
    ) -> bool {
        let matches = matcher(&self.name);
        let subscribed = self.is_subscribed();

        if subscribed {
            if matches {
                dst.push(ListInfo {
                    name: self.name.clone(),
                    attributes: vec![],
                });
            }

            for child in self.children() {
                child.lsub(dst, matcher);
            }

            // If this mailbox is subscribed but didn't match, it is hidden.
            // Pass this on to the parent.
            !matches
        } else {
            let self_index = dst.len();
            let mut has_hidden_child = false;

            for child in self.children() {
                has_hidden_child = child.lsub(dst, matcher);
            }

            if has_hidden_child {
                // Not subscribed, but we have one or more children that are
                // subscribed and weren't included.
                if matches {
                    // We do match, so include insert self into the result,
                    // marked \Noselect.
                    dst.insert(
                        self_index,
                        ListInfo {
                            name: self.name.clone(),
                            attributes: vec![MailboxAttribute::Noselect],
                        },
                    );

                    // Nothing hidden now
                    false
                } else {
                    // We don't match either, so pass the hidden status up to
                    // the parent.
                    true
                }
            } else {
                // We're not hidden, nor are any children
                false
            }
        }
    }

    /// Mark this mailbox as subscribed.
    pub fn subscribe(&self) -> Result<(), Error> {
        if !self.exists() {
            Err(Error::NxMailbox)
        } else if !self.is_selectable() {
            Err(Error::MailboxUnselectable)
        } else {
            Ok(fs::remove_file(&self.unsub_path).ignore_not_found()?)
        }
    }

    /// Mark this mailbox as unsubscribed.
    pub fn unsubscribe(&self) -> Result<(), Error> {
        fs::OpenOptions::new()
            .create(true)
            .write(true)
            .mode(0o600)
            .open(&self.unsub_path)
            .map(|_| ())
            .on_not_found(Error::MailboxUnselectable)
    }
}

/// Given a raw mailbox path, emit the parts that comprise the actual path.
///
/// This accounts for the path delimiter, empty segments, and the required
/// case-insensitivity of the root `inbox` mailbox.
///
/// It does not check for name safety.
pub fn parse_mailbox_path<'a>(
    path: &'a str,
) -> impl Iterator<Item = &'a str> + 'a {
    path.split('/')
        .filter(|s| !s.is_empty())
        .enumerate()
        .map(|(ix, s)| {
            if 0 == ix && "inbox".eq_ignore_ascii_case(s) {
                "INBOX"
            } else {
                s
            }
        })
}

/// Creates a predicate which identifies which normalised mailbox names match
/// `pattern`, with pattern matching performed as per RFC 3501.
///
/// `pattern` is first normalised by `parse_mailbox_path`.
///
/// This design means that any `LIST` operation needs to fetch all mailboxes
/// and then narrow it down, instead of a more ideal recursive filtering.
/// However, the semantics of `*`, particularly the fact that it's permitted in
/// the _middle_ of the path, preclude doing that in any sane (i.e.,
/// non-exponential) way. Since we _only_ iterate actual mailboxes (and not,
/// say, all of USENET, or the user's whole home directory as UW-IMAP), this
/// shouldn't be a problem.
pub fn mailbox_path_matcher(pattern: &str) -> impl Fn(&str) -> bool {
    let mut rx = "^".to_owned();
    for part in parse_mailbox_path(pattern) {
        if rx.len() > 1 {
            rx.push('/');
        }

        let mut start = 0;
        for end in part
            .match_indices(|c| '%' == c || '*' == c)
            .map(|(ix, _)| ix)
            .chain(part.len()..=part.len())
        {
            let chunk = &part[start..end];
            start = (end + 1).min(part.len());

            rx.push_str(&regex::escape(chunk));
            match part.get(end..end + 1) {
                Some("*") => rx.push_str(".*"),
                Some("%") => rx.push_str("[^/]*"),
                _ => (),
            }
        }
    }
    rx.push_str("$");

    let rx = regex::Regex::new(&rx).expect("Built invalid regex?");
    move |s| rx.is_match(s)
}

/// Information needed to service LIST, XLIST, and LSUB requests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListInfo {
    /// The canonical name of the mailbox
    pub name: String,
    /// Any attributes to return.
    ///
    /// For `LSUB`, these are not actually the mailbox attributes, but the fake
    /// attributes that `LSUB` requires in certain situations.
    pub attributes: Vec<MailboxAttribute>,
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

    if !name.starts_with("%") {
        return Err(Error::CorruptFileLayout);
    }

    u32::from_str_radix(&name[1..], 16).map_err(|_| Error::CorruptFileLayout)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_mailbox_path() {
        fn p(p: &'static str) -> Vec<&'static str> {
            parse_mailbox_path(p).collect()
        }

        assert_eq!(vec!["INBOX"], p("inbox"));
        assert_eq!(vec!["INBOX", "foo"], p("Inbox/foo"));
        assert_eq!(vec!["bar"], p("/bar"));
        assert_eq!(vec!["bar"], p("bar/"));
        assert_eq!(vec!["foo", "bar"], p("foo//bar"));
        assert_eq!(vec!["foo", "InBoX"], p("foo/InBoX"));
    }

    #[test]
    fn test_mailbox_patterns() {
        fn matches(pat: &str, mb: &str) -> bool {
            mailbox_path_matcher(pat)(mb)
        }

        assert!(matches("*", "INBOX"));
        assert!(matches("%", "INBOX"));

        assert!(matches("INB*X", "INBOX"));
        assert!(matches("INB*X", "INB/BOX"));
        assert!(!matches("INB*X", "INBOX/plugh"));
        assert!(!matches("INB*X", "foo/INBOX"));
        assert!(matches("INB%X", "INBOX"));
        assert!(!matches("INB%X", "INB/BOX"));
        assert!(!matches("INB%X", "INBOX/plugh"));

        assert!(matches("INB*", "INBOX"));
        assert!(matches("INB*", "INBOX/plugh"));
        assert!(matches("INB%", "INBOX"));
        assert!(!matches("INB%", "INBOX/plugh"));
        assert!(!matches("INB%", "foo/INBOX"));

        assert!(matches("*X", "INBOX"));
        assert!(matches("*X", "foo/boX"));
        assert!(matches("%X", "INBOX"));
        assert!(!matches("%X", "foo/boX"));

        assert!(matches("foo/bar", "foo/bar"));
        assert!(!matches("foo/bar", "foo/bar/baz"));
        assert!(!matches("foo/*", "foo"));
        assert!(matches("foo/*", "foo/bar"));
        assert!(matches("foo/*", "foo/bar/baz"));
        assert!(matches("foo/%", "foo/bar"));
        assert!(!matches("foo/%", "foo/bar/baz"));

        assert!(matches("inbox", "INBOX"));
    }
}
