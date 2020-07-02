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
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::account::key_store::{KeyStore, KeyStoreConfig};
use crate::account::mailbox_path::*;
use crate::account::model::*;
use crate::crypt::master_key::MasterKey;
use crate::support::error::Error;
use crate::support::file_ops::IgnoreKinds;

#[derive(Clone)]
pub struct Account {
    log_prefix: String,
    root: PathBuf,
    key_store: Arc<Mutex<KeyStore>>,
    mailbox_root: PathBuf,
    common_paths: Arc<CommonPaths>,
}

impl Account {
    pub fn new(
        log_prefix: String,
        root: PathBuf,
        master_key: Option<Arc<MasterKey>>,
    ) -> Self {
        let common_paths = Arc::new(CommonPaths {
            tmp: root.join("tmp"),
            garbage: root.join("garbage"),
        });

        let key_store = KeyStore::new(
            log_prefix.clone(),
            root.join("keys"),
            common_paths.tmp.clone(),
            master_key,
        );

        Account {
            log_prefix,
            common_paths,
            key_store: Arc::new(Mutex::new(key_store)),
            mailbox_root: root.join("mail"),
            root,
        }
    }

    /// Perform minimal initialisation of the account.
    ///
    /// This ensures that critical paths exist and initialises the key store.
    /// It should be called whenever the user logs in.
    pub fn init(&self, key_store_config: &KeyStoreConfig) -> Result<(), Error> {
        fs::DirBuilder::new()
            .mode(0o770)
            .create(&self.common_paths.tmp)
            .ignore_already_exists()?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&self.common_paths.garbage)
            .ignore_already_exists()?;
        fs::DirBuilder::new()
            .mode(0o750)
            .create(&self.mailbox_root)
            .ignore_already_exists()?;
        self.key_store.lock().unwrap().init(key_store_config)?;
        // Ensure that, no matter what, we have an INBOX.
        MailboxPath::root("INBOX".to_owned(), &self.mailbox_root)
            .unwrap()
            .create_if_nx(&self.common_paths.tmp)?;

        Ok(())
    }

    /// Perform full provisioning of the account.
    ///
    /// In addition to everything `init()` does, this also creates the common
    /// special-use mailboxes:
    ///
    /// - Archive \Archive
    /// - Drafts \Drafts
    /// - Spam \Junk
    /// - Sent \Sent
    /// - Trash \Trash
    ///
    /// (INBOX is also created by way of `init()`.)
    pub fn provision(
        &self,
        key_store_config: &KeyStoreConfig,
    ) -> Result<(), Error> {
        self.init(key_store_config)?;
        self.create(CreateRequest {
            name: "Archive".to_owned(),
            special_use: vec!["\\Archive".to_owned()],
        })?;
        self.create(CreateRequest {
            name: "Drafts".to_owned(),
            special_use: vec!["\\Drafts".to_owned()],
        })?;
        self.create(CreateRequest {
            name: "Spam".to_owned(),
            special_use: vec!["\\Junk".to_owned()],
        })?;
        self.create(CreateRequest {
            name: "Sent".to_owned(),
            special_use: vec!["\\Sent".to_owned()],
        })?;
        self.create(CreateRequest {
            name: "Trash".to_owned(),
            special_use: vec!["\\Trash".to_owned()],
        })?;
        Ok(())
    }

    /// The RFC 3501 `CREATE` command.
    pub fn create(&self, request: CreateRequest) -> Result<(), Error> {
        if request.special_use.len() > 1 {
            return Err(Error::UnsupportedSpecialUse);
        }

        let special_use = if let Some(mut special_use) =
            request.special_use.into_iter().next()
        {
            special_use.make_ascii_lowercase();
            Some(match &special_use as &str {
                "\\archive" => MailboxAttribute::Archive,
                "\\drafts" => MailboxAttribute::Drafts,
                "\\flagged" => MailboxAttribute::Flagged,
                "\\junk" => MailboxAttribute::Junk,
                "\\sent" => MailboxAttribute::Sent,
                "\\trash" => MailboxAttribute::Trash,
                "\\important" => MailboxAttribute::Important,
                _ => return Err(Error::UnsupportedSpecialUse),
            })
        } else {
            None
        };

        let mut new_mailbox: Option<MailboxPath> = None;
        for part in parse_mailbox_path(&request.name) {
            if let Some(parent) = new_mailbox.take() {
                parent.create_if_nx(&self.common_paths.tmp)?;
                new_mailbox = Some(parent.child(part)?);
            } else {
                new_mailbox = Some(MailboxPath::root(
                    part.to_owned(),
                    &self.mailbox_root,
                )?);
            }
        }

        // Treat the empty mailbox name as "unsafe" for simplicity
        let new_mailbox = new_mailbox.ok_or(Error::UnsafeName)?;
        new_mailbox.create(&self.common_paths.tmp, special_use)?;
        Ok(())
    }

    /// The RFC 3501 `LIST` and `LSUB` commands and the non-standard `XLIST`
    /// command.
    ///
    /// `LSUB` is achieved by setting `select_subscribed`, `return_subscribed`,
    /// `recursive_match`, and `lsub_style`.
    ///
    /// `XLIST` is achieved by setting `return_children` and `return_special_use`.
    ///
    /// This handles the special case of `LIST "" ""`.
    pub fn list(
        &self,
        request: &ListRequest,
    ) -> Result<Vec<ListResponse>, Error> {
        // RFC 5258 does not describe any behaviour if extended list is used with
        // multiple patterns and one of them is "". Here, we just handle the ""
        // special case if there's exactly one pattern, and in other cases the
        // pattern is interpreted literally, i.e., matching an empty mailbox name.
        if 1 == request.patterns.len() && "" == &request.patterns[0] {
            return Ok(vec![ListResponse::default()]);
        }

        let mut pattern_prefix = request.reference.clone();
        // Wildcards in the reference have no significance, and we don't allow
        // creating mailboxes containing them, so if they are requested, we know
        // nothing at all can match.
        if pattern_prefix.contains('%') || pattern_prefix.contains('*') {
            return Ok(vec![]);
        }

        if !pattern_prefix.is_empty() && !pattern_prefix.ends_with("/") {
            pattern_prefix.push('/');
        }

        let patterns = request
            .patterns
            .iter()
            .map(Cow::Borrowed)
            .map(|p| {
                if pattern_prefix.is_empty() {
                    p
                } else {
                    Cow::Owned(pattern_prefix.clone() + &p)
                }
            })
            .collect::<Vec<_>>();

        let matcher = mailbox_path_matcher(patterns.iter().map(|s| s as &str));

        let mut accum = Vec::new();
        for entry in fs::read_dir(&self.mailbox_root)? {
            let entry = entry?;

            if let Ok(name) = entry.file_name().into_string() {
                if let Ok(mp) = MailboxPath::root(name, &self.mailbox_root) {
                    mp.list(&mut accum, request, &matcher);
                }
            }
        }

        accum.reverse();
        Ok(accum)
    }
}
