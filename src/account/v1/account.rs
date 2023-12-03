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
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chrono::prelude::*;
use log::{error, info, warn};

use super::{mailbox::StatelessMailbox, mailbox_path::*};
use crate::account::{
    key_store::{KeyStore, KeyStoreConfig},
    model::*,
};
use crate::crypt::master_key::MasterKey;
use crate::support::{
    chronox::*, error::Error, file_ops::IgnoreKinds, mailbox_paths::*,
    safe_name::is_safe_name, threading, user_config::UserConfig,
};

// Like format!, but returns None if the formatter fails instead of panicking.
macro_rules! try_format {
    ($($stuff:tt)*) => {{
        use std::io::Write;
        let mut buf = Vec::new();
        write!(&mut buf, $($stuff)*).ok()
            .and_then(|_| String::from_utf8(buf).ok())
    }}
}

#[derive(Clone)]
pub struct Account {
    log_prefix: String,
    root: PathBuf,
    master_key: Option<Arc<MasterKey>>,
    key_store: Arc<Mutex<KeyStore>>,
    config_file: PathBuf,
    mailbox_root: PathBuf,
    shadow_root: PathBuf,
    common_paths: Arc<CommonPaths>,
}

/// Given the root of a user directory, return the path to the user's
/// configuration file.
pub fn account_config_file(root: &Path) -> PathBuf {
    root.join("user.toml")
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
            master_key.clone(),
        );

        Account {
            log_prefix,
            common_paths,
            master_key,
            key_store: Arc::new(Mutex::new(key_store)),
            mailbox_root: root.join("mail"),
            shadow_root: root.join("shadow"),
            config_file: account_config_file(&root),
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
        self.root_mailbox_path("INBOX".to_owned())
            .unwrap()
            .create_if_nx(&self.common_paths.tmp)?;

        self.start_maintenance();

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
    ///
    /// The user configuration is also initialised to the defaults and the
    /// given password.
    ///
    /// Note that the *directory* which is the root of the account must already
    /// exist.
    pub fn provision(&self, password: &[u8]) -> Result<(), Error> {
        let user_config = UserConfig {
            master_key: self
                .master_key
                .as_ref()
                .expect("Account::provision() called without master key")
                .make_config(password)
                .expect("Password hashing failed"),
            key_store: KeyStoreConfig::default(),
        };

        let user_config_toml = toml::to_vec(&user_config)
            .expect("Failed to serialise user config to TOML");
        fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&self.config_file)?
            .write_all(&user_config_toml)?;

        self.init(&user_config.key_store)?;
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

        // Subscribe to all the default mailboxes since some clients only show
        // subscribed things.
        self.subscribe("INBOX")?;
        self.subscribe("Archive")?;
        self.subscribe("Drafts")?;
        self.subscribe("Spam")?;
        self.subscribe("Sent")?;
        self.subscribe("Trash")?;

        Ok(())
    }

    /// Load and return the user's current configuration.
    ///
    /// This may not be the exact configuration currently applied.
    pub fn load_config(&self) -> Result<UserConfig, Error> {
        let mut data = Vec::new();
        fs::File::open(&self.config_file)?.read_to_end(&mut data)?;

        let config: UserConfig = toml::from_slice(&data)?;
        Ok(config)
    }

    /// Update the user's configuration.
    ///
    /// The changes do not apply to the current connection.
    ///
    /// Returns the location of the backup file this creates.
    pub fn update_config(
        &self,
        request: SetUserConfigRequest,
    ) -> Result<String, Error> {
        let mut config = self.load_config()?;
        let master_key = self
            .master_key
            .as_ref()
            .ok_or(Error::MasterKeyUnavailable)?;
        let now = Utc::now();

        if let Some(internal_key_pattern) = request.internal_key_pattern {
            // We need to format the keys with some date to check the patterns
            // for validity. This is both because they contain % in raw form,
            // which makes for an unsafe name, and because format!() will
            // result in a panic if the date format is not understood by
            // chrono.
            if !is_safe_name(
                &try_format!("{}", now.format(&internal_key_pattern))
                    .unwrap_or_default(),
            ) {
                return Err(Error::UnsafeName);
            }

            config.key_store.internal_key_pattern = internal_key_pattern;
        }

        if let Some(external_key_pattern) = request.external_key_pattern {
            if !is_safe_name(
                &try_format!("{}", now.format(&external_key_pattern))
                    .unwrap_or_default(),
            ) {
                return Err(Error::UnsafeName);
            }

            config.key_store.external_key_pattern = external_key_pattern;
        }

        if let Some(password) = request.password {
            config.master_key = master_key
                .make_config(password.as_bytes())
                .expect("argon2 hash failed");
            config.master_key.last_changed =
                Some(FixedOffset::zero().from_utc_datetime(&now.naive_local()));
        }

        let config_toml =
            toml::to_vec(&config).expect("TOML serialisation failed");

        let mut tmpfile =
            tempfile::NamedTempFile::new_in(&self.common_paths.tmp)?;
        tmpfile.write_all(&config_toml)?;

        let backup_name = format!("config-backup-{}.toml", now.to_rfc3339());
        let backup_file = self.common_paths.tmp.join(&backup_name);
        nix::unistd::linkat(
            None,
            &self.config_file,
            None,
            &backup_file,
            nix::unistd::LinkatFlags::NoSymlinkFollow,
        )?;
        tmpfile.persist(&self.config_file).map_err(|e| e.error)?;

        Ok(backup_name)
    }

    fn start_maintenance(&self) {
        // Avoid running maintenance more than once per day
        // This isn't atomic, so it's possible for more than one process to
        // start maintenance at the same time, but that's ok.
        let timestamp_path = self.root.join("maintenance-run");
        if timestamp_path
            .metadata()
            .ok()
            .and_then(|md| md.modified().ok())
            .and_then(|mtime| mtime.elapsed().ok())
            .map_or(false, |dur| dur.as_secs() < 24 * 3600)
        {
            return;
        }

        if let Err(e) = fs::File::create(&timestamp_path) {
            warn!("{} Cannot start maintenance: {}", self.log_prefix, e);
            return;
        }

        let this = self.clone();
        threading::run_in_background(move || this.run_maintenance());
    }

    fn run_maintenance(&self) {
        if let Err(e) = clean_garbage(&self.common_paths.garbage) {
            error!("{} Failed to clean up garbage: {}", self.log_prefix, e);
        }

        if let Err(e) = clean_tmp(&self.log_prefix, &self.common_paths.tmp) {
            error!("{} Failed to clean up tmp: {}", self.log_prefix, e);
        }

        if let Ok(readdir) = fs::read_dir(&self.mailbox_root) {
            for entry in readdir {
                if let Some(mp) = entry
                    .ok()
                    .and_then(|entry| entry.file_name().into_string().ok())
                    .and_then(|name| self.root_mailbox_path(name).ok())
                {
                    self.run_maintenance_on_mailbox(mp);
                }
            }
        }
    }

    fn run_maintenance_on_mailbox(&self, path: MailboxPath) {
        match self.open(path.clone(), true).and_then(|mb| mb.select()) {
            Ok((mut mb, _)) => {
                let npurged = mb.purge(Utc::now());
                if npurged > 0 {
                    info!(
                        "{} Purged {} messages, running other maintenance",
                        mb.stateless().log_prefix(),
                        npurged
                    );

                    // If anything was purged, we know there's at least one
                    // CID, so dump_rollup() is safe.
                    if let Err(e) = mb.dump_rollup() {
                        warn!(
                            "{} Error dumping rollup: {}",
                            mb.stateless().log_prefix(),
                            e
                        );
                    } else if let Err(e) = mb.schedule_gc(true) {
                        warn!(
                            "{} Error scheduling GC: {}",
                            mb.stateless().log_prefix(),
                            e
                        );
                    }
                }
            },
            Err(e) => warn!(
                "{} Error opening {} for maintenance: {}",
                self.log_prefix,
                path.name(),
                e
            ),
        }

        for child in path.children() {
            self.run_maintenance_on_mailbox(child);
        }
    }

    /// Clear cache(s) only used for the duration of individual commands.
    pub fn clear_cache(&mut self) {
        self.key_store.lock().unwrap().clear_cache();
    }

    /// The RFC 3501 `CREATE` command.
    pub fn create(&self, request: CreateRequest) -> Result<String, Error> {
        if request.special_use.len() > 1 {
            return Err(Error::UnsupportedSpecialUse);
        }

        let special_use =
            if let Some(special_use) = request.special_use.into_iter().next() {
                Some(MailboxAttribute::special_use_from_str(&special_use)?)
            } else {
                None
            };

        self.mailbox_path_create_parents(&request.name)?
            .create(&self.common_paths.tmp, special_use)
    }

    /// The RFC 3501 `DELETE` command.
    pub fn delete(&self, name: &str) -> Result<(), Error> {
        self.mailbox_path(name)?.delete(&self.common_paths.garbage)
    }

    /// The RFC 3501 `RENAME` command.
    pub fn rename(&self, request: RenameRequest) -> Result<(), Error> {
        let src_parts =
            parse_mailbox_path(&request.existing_name).collect::<Vec<_>>();
        let dst_parts =
            parse_mailbox_path(&request.new_name).collect::<Vec<_>>();

        if src_parts == dst_parts {
            return Err(Error::RenameToSelf);
        }

        if dst_parts.len() > src_parts.len()
            && !src_parts.is_empty()
            && dst_parts[..src_parts.len()] == src_parts[..]
        {
            return Err(Error::RenameIntoSelf);
        }

        let src = self.mailbox_path(&request.existing_name)?;
        if !src.exists() {
            return Err(Error::NxMailbox);
        }

        let dst = self.mailbox_path_create_parents(&request.new_name)?;
        src.rename(&dst, &self.common_paths.tmp)
    }

    /// The RFC 3501 `SUBSCRIBE` command.
    pub fn subscribe(&self, name: &str) -> Result<(), Error> {
        self.mailbox_path(name)?.subscribe()
    }

    /// The RFC 3501 `UNSUBSCRIBE` command.
    pub fn unsubscribe(&self, name: &str) -> Result<(), Error> {
        self.mailbox_path(name)?.unsubscribe()
    }

    /// The RFC 3501 `LIST` and `LSUB` commands and the non-standard `XLIST`
    /// command.
    ///
    /// `LSUB` is achieved by setting `select_subscribed`, `recursive_match`,
    /// and `lsub_style` (and NOT `return_subscribed`).
    ///
    /// `XLIST` is achieved by setting `return_children` and `return_special_use`.
    ///
    /// This handles the special case of `LIST "" ""`.
    pub fn list(
        &self,
        request: &ListRequest,
    ) -> Result<Vec<ListResponse>, Error> {
        if request.patterns.is_empty() {
            return Ok(vec![]);
        }

        // RFC 5258 does not describe any behaviour if extended list is used with
        // multiple patterns and one of them is "". Here, we just handle the ""
        // special case if there's exactly one pattern, and in other cases the
        // pattern is interpreted literally, i.e., matching an empty mailbox name.
        if 1 == request.patterns.len() && request.patterns[0].is_empty() {
            return Ok(vec![ListResponse {
                name: String::new(),
                attributes: vec![MailboxAttribute::Noselect],
                child_info: vec![],
            }]);
        }

        let mut pattern_prefix = request.reference.clone();
        // Wildcards in the reference have no significance, and we don't allow
        // creating mailboxes containing them, so if they are requested, we know
        // nothing at all can match.
        if pattern_prefix.contains('%') || pattern_prefix.contains('*') {
            return Ok(vec![]);
        }

        if !pattern_prefix.is_empty() && !pattern_prefix.ends_with('/') {
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
        for entry in fs::read_dir(if request.select_subscribed {
            &self.shadow_root
        } else {
            &self.mailbox_root
        })? {
            let entry = entry?;

            if let Ok(name) = entry.file_name().into_string() {
                if let Ok(mp) = self.root_mailbox_path(name) {
                    mp.list(&mut accum, request, &matcher);
                }
            }
        }

        // We could just reverse accum to get the results in pre-order, but
        // fully sorting it makes the tests easier to write, protocol traces
        // easier to read, and doesn't add a meaningful amount of overhead.
        accum.sort_unstable();
        Ok(accum)
    }

    /// The RFC 3501 `STATUS` command.
    pub fn status(
        &self,
        request: &StatusRequest,
    ) -> Result<StatusResponse, Error> {
        let mailbox_path = self.mailbox_path(&request.name)?;
        self.status_for(mailbox_path, request)
    }

    fn status_for(
        &self,
        mailbox_path: MailboxPath,
        request: &StatusRequest,
    ) -> Result<StatusResponse, Error> {
        let mut response = StatusResponse {
            name: mailbox_path.name().to_owned(),
            ..StatusResponse::default()
        };

        let mailbox = self.open(mailbox_path, true)?;
        let (mailbox, select) = mailbox.select()?;

        if request.messages {
            response.messages = Some(select.exists);
        }

        if request.recent {
            response.recent = Some(select.recent);
        }

        if request.uidnext {
            response.uidnext = Some(select.uidnext);
        }

        if request.uidvalidity {
            response.uidvalidity = Some(select.uidvalidity);
        }

        if request.unseen {
            if select.unseen.is_some() {
                response.unseen = Some(mailbox.count_unseen());
            } else {
                response.unseen = Some(0);
            }
        }

        if request.max_modseq {
            response.max_modseq = Some(select.max_modseq);
        }

        if request.mailbox_id {
            response.mailbox_id =
                Some(mailbox.stateless().path().mailbox_id()?);
        }

        // To get the "size", we simply multiply the number of messages by
        // 2**32, which fulfils the letter of the standard:
        //
        // > The total size of the mailbox in octets.  This is not strictly
        // > required to be an exact value, but it MUST be equal to or greater
        // > than the sum of the values of the RFC822.SIZE FETCH message data
        // > item [IMAP4rev1] of all messages in the mailbox.
        //
        // It's unfortunate that the standard precludes us from calculating the
        // *actual* size of the mailbox, which would be useful. But since the
        // actual size is usually smaller than the sum of the `RFC822.SIZE`, we
        // can't do that, and have to do this useless exercise instead.
        //
        // Arguably, this approach is sufficiently useless that we could in
        // fact just return i64::MAX and call it a day.
        if request.size {
            let mut size = select.exists as u64;
            size *= u32::MAX as u64;
            // RFC 8438 requires accommodating environments that don't have
            // support for real 64-bit integers.
            //
            // Strictly, there's nothing stopping someone from having 2**32 4GB
            // messages, but that's sufficiently unlikely to ever happen that
            // naïve clamping is reasonable.
            size = size.min(i64::MAX as u64);

            response.size = Some(size);
        }

        if request.deleted {
            response.deleted = Some(mailbox.count_deleted());
        }

        Ok(response)
    }

    /// Open a `StatelessMailbox` on the given logical mailbox path.
    pub fn mailbox(
        &self,
        path: &str,
        read_only: bool,
    ) -> Result<StatelessMailbox, Error> {
        let path = self.mailbox_path(path)?;
        self.open(path, read_only)
    }

    fn open(
        &self,
        path: MailboxPath,
        read_only: bool,
    ) -> Result<StatelessMailbox, Error> {
        StatelessMailbox::new(
            self.log_prefix.clone(),
            path,
            read_only,
            Arc::clone(&self.key_store),
            Arc::clone(&self.common_paths),
        )
    }

    /// Return the `MailboxPath` corresponding to the given logical mailbox
    /// path.
    pub fn mailbox_path(&self, path: &str) -> Result<MailboxPath, Error> {
        let mut mp: Option<MailboxPath> = None;
        for part in parse_mailbox_path(path) {
            if let Some(parent) = mp.take() {
                mp = Some(parent.child(part)?);
            } else {
                mp = Some(self.root_mailbox_path(part.to_owned())?);
            }
        }

        mp.ok_or(Error::NxMailbox)
    }

    fn root_mailbox_path(&self, name: String) -> Result<MailboxPath, Error> {
        MailboxPath::root(name, &self.mailbox_root, &self.shadow_root)
    }

    fn mailbox_path_create_parents(
        &self,
        name: &str,
    ) -> Result<MailboxPath, Error> {
        let mut mp: Option<MailboxPath> = None;
        for part in parse_mailbox_path(name) {
            if let Some(parent) = mp.take() {
                parent.create_if_nx(&self.common_paths.tmp)?;
                mp = Some(parent.child(part)?);
            } else {
                mp = Some(self.root_mailbox_path(part.to_owned())?);
            }
        }

        // Treat the empty mailbox name as "unsafe" for simplicity
        mp.ok_or(Error::UnsafeName)
    }
}

fn clean_tmp(log_prefix: &str, tmp: &Path) -> Result<(), io::Error> {
    for entry in fs::read_dir(tmp)? {
        let entry = entry?;
        if entry
            .metadata()
            .ok()
            // Take the latest of mtime and ctime for considering whether to
            // remove. Files in active use (mtime) should be retained, but we
            // also want to avoid collecting config backups too early (ctime
            // gets reset when the file is link()ed into the backup location).
            .and_then(|md| match (md.modified(), md.created()) {
                (Err(_), Err(_)) => None,
                (Ok(mtime), Err(_)) => Some(mtime),
                (Err(_), Ok(ctime)) => Some(ctime),
                (Ok(mtime), Ok(ctime)) => Some(mtime.max(ctime)),
            })
            .and_then(|mtime| mtime.elapsed().ok())
            .map_or(false, |elapsed| elapsed.as_secs() > 24 * 3600)
        {
            let path = entry.path();
            warn!(
                "{} Removing orphaned temp file: {}",
                log_prefix,
                path.display()
            );
            if path.is_dir() {
                fs::remove_dir_all(entry.path()).ignore_not_found()?;
            } else {
                fs::remove_file(entry.path()).ignore_not_found()?;
            }
        }
    }

    Ok(())
}

fn clean_garbage(garbage: &Path) -> Result<(), io::Error> {
    for entry in fs::read_dir(garbage)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            fs::remove_dir_all(entry.path()).ignore_not_found()?;
        } else {
            fs::remove_file(entry.path()).ignore_not_found()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use chrono::prelude::*;
    use tempfile::TempDir;

    use super::*;

    struct Setup {
        _root: TempDir,
        account: Account,
    }

    impl Setup {
        fn create(&self, name: &str) {
            self.account
                .create(CreateRequest {
                    name: name.to_owned(),
                    special_use: vec![],
                })
                .unwrap();
        }
    }

    fn set_up() -> Setup {
        let root = TempDir::new().unwrap();
        let account = Account::new(
            "account".to_owned(),
            root.path().to_owned(),
            Some(Arc::new(MasterKey::new())),
        );

        account.key_store.lock().unwrap().set_rsa_bits(1024);
        account.provision(b"hunter2").unwrap();

        Setup {
            _root: root,
            account,
        }
    }

    fn list_formatted(account: &Account, request: ListRequest) -> String {
        let responses = account.list(&request).unwrap();
        let mut accum = String::new();
        for mut response in responses {
            // Sort the list fields so the tests aren't sensitive to order
            response.attributes.sort_unstable();
            response.child_info.sort_unstable();
            accum.push_str(&format!(
                "'{}' {:?} {:?}\n",
                response.name, response.attributes, response.child_info
            ));
        }

        accum
    }

    fn remove_all_but_inbox(account: &Account) {
        for result in account
            .list(&ListRequest {
                patterns: vec!["*".to_owned()],
                ..ListRequest::default()
            })
            .unwrap()
            .into_iter()
            .rev()
        {
            // We iterate in reverse so that children are deleted before their
            // parents (and so the parents can be fully removed).
            if "INBOX" != result.name {
                account.delete(&result.name).unwrap();
            }
        }

        for result in account
            .list(&ListRequest {
                patterns: vec!["*".to_owned()],
                select_subscribed: true,
                ..ListRequest::default()
            })
            .unwrap()
        {
            if "INBOX" != result.name {
                account.unsubscribe(&result.name).unwrap();
            }
        }
    }

    #[test]
    fn basic_list() {
        let setup = set_up();

        assert_eq!(
            "'Archive' [] []\n\
             'Drafts' [] []\n\
             'INBOX' [\\Noinferiors] []\n\
             'Sent' [] []\n\
             'Spam' [] []\n\
             'Trash' [] []\n",
            list_formatted(
                &setup.account,
                ListRequest {
                    patterns: vec!["*".to_owned()],
                    ..ListRequest::default()
                }
            )
        );
    }

    #[test]
    fn list_all_attributes() {
        let setup = set_up();

        setup
            .account
            .create(CreateRequest {
                name: "Archive/2020".to_owned(),
                special_use: vec!["\\important".to_owned()],
            })
            .unwrap();

        assert_eq!(
            "'Archive' [\\HasChildren, \\Subscribed, \\Archive] []\n\
             'Archive/2020' [\\HasNoChildren, \\Important] []\n\
             'Drafts' [\\HasNoChildren, \\Subscribed, \\Drafts] []\n\
             'INBOX' [\\Noinferiors, \\Subscribed] []\n\
             'Sent' [\\HasNoChildren, \\Subscribed, \\Sent] []\n\
             'Spam' [\\HasNoChildren, \\Subscribed, \\Junk] []\n\
             'Trash' [\\HasNoChildren, \\Subscribed, \\Trash] []\n",
            list_formatted(
                &setup.account,
                ListRequest {
                    patterns: vec!["*".to_owned()],
                    return_subscribed: true,
                    return_children: true,
                    return_special_use: true,
                    ..ListRequest::default()
                }
            )
        );
    }

    #[test]
    fn list_with_reference() {
        let setup = set_up();

        setup.create("foo");
        setup.create("food");
        setup.create("foo/bar");

        assert_eq!(
            "'foo/bar' [] []\n",
            list_formatted(
                &setup.account,
                ListRequest {
                    reference: "foo".to_owned(),
                    patterns: vec!["*".to_owned()],
                    ..ListRequest::default()
                }
            )
        );
        assert_eq!(
            "'foo/bar' [] []\n",
            list_formatted(
                &setup.account,
                ListRequest {
                    reference: "foo/".to_owned(),
                    patterns: vec!["*".to_owned()],
                    ..ListRequest::default()
                }
            )
        );
        assert_eq!(
            "'foo/bar' [] []\n",
            list_formatted(
                &setup.account,
                ListRequest {
                    reference: "/foo".to_owned(),
                    patterns: vec!["*".to_owned()],
                    ..ListRequest::default()
                }
            )
        );
        assert_eq!(
            "",
            list_formatted(
                &setup.account,
                ListRequest {
                    reference: "fo*".to_owned(),
                    patterns: vec!["*".to_owned()],
                    ..ListRequest::default()
                }
            )
        );
    }

    #[test]
    fn list_as_lsub() {
        let setup = set_up();

        // Examples from RFC 3501 section 6.3.9
        setup
            .account
            .create(CreateRequest {
                name: "news/comp/mail/misc".to_owned(),
                special_use: vec![],
            })
            .unwrap();
        setup
            .account
            .create(CreateRequest {
                name: "news/comp/mail/mime".to_owned(),
                special_use: vec![],
            })
            .unwrap();
        setup
            .account
            .create(CreateRequest {
                name: "news/comp/mail/sanity".to_owned(),
                special_use: vec![],
            })
            .unwrap();
        setup.account.subscribe("news/comp/mail/misc").unwrap();
        setup.account.subscribe("news/comp/mail/mime").unwrap();

        assert_eq!(
            "'news/comp/mail/mime' [] []\n\
             'news/comp/mail/misc' [] []\n",
            list_formatted(
                &setup.account,
                ListRequest {
                    reference: "news/".to_owned(),
                    patterns: vec!["comp/mail/*".to_owned()],
                    select_subscribed: true,
                    recursive_match: true,
                    lsub_style: true,
                    ..ListRequest::default()
                }
            )
        );

        assert_eq!(
            "'news/comp/mail' [\\Noselect] [\"SUBSCRIBED\"]\n",
            list_formatted(
                &setup.account,
                ListRequest {
                    reference: "news/".to_owned(),
                    patterns: vec!["comp/%".to_owned()],
                    select_subscribed: true,
                    recursive_match: true,
                    lsub_style: true,
                    ..ListRequest::default()
                }
            )
        );

        // Edge case not described by RFC 3501: Since \Noselect means "mailbox
        // has subscribed inferiors but is not itself subscribed", we can't use
        // it to indicate mailboxes that are actually \Noselect.
        setup.account.subscribe("news/comp").unwrap();
        setup.account.delete("news/comp").unwrap();
        assert_eq!(
            "'news/comp' [] [\"SUBSCRIBED\"]\n\
             'news/comp/mail/mime' [] []\n\
             'news/comp/mail/misc' [] []\n",
            list_formatted(
                &setup.account,
                ListRequest {
                    reference: "".to_owned(),
                    patterns: vec!["news/*".to_owned()],
                    select_subscribed: true,
                    recursive_match: true,
                    lsub_style: true,
                    ..ListRequest::default()
                }
            )
        );
    }

    #[test]
    fn list_extended() {
        let setup = set_up();

        remove_all_but_inbox(&setup.account);

        // Examples from RFC 5258
        setup.create("Fruit");
        setup.create("Fruit/Apple");
        setup.create("Fruit/Banana");
        setup.create("Tofu");
        setup.create("Vegetable");
        setup.create("Vegetable/Broccoli");
        setup.create("Vegetable/Corn");

        setup.account.subscribe("Fruit/Banana").unwrap();
        setup.account.subscribe("Fruit/Peach").unwrap();
        setup.account.subscribe("Vegetable").unwrap();
        setup.account.subscribe("Vegetable/Broccoli").unwrap();

        // Example 5.1
        assert_eq!(
            "'Fruit' [] []\n\
             'Fruit/Apple' [] []\n\
             'Fruit/Banana' [] []\n\
             'INBOX' [\\Noinferiors] []\n\
             'Tofu' [] []\n\
             'Vegetable' [] []\n\
             'Vegetable/Broccoli' [] []\n\
             'Vegetable/Corn' [] []\n",
            list_formatted(
                &setup.account,
                ListRequest {
                    patterns: vec!["*".to_owned()],
                    ..ListRequest::default()
                }
            )
        );

        // Example 5.2
        assert_eq!(
            "'Fruit/Banana' [\\Subscribed] []\n\
             'Fruit/Peach' [\\NonExistent, \\Subscribed] []\n\
             'INBOX' [\\Noinferiors, \\Subscribed] []\n\
             'Vegetable' [\\Subscribed] []\n\
             'Vegetable/Broccoli' [\\Subscribed] []\n",
            list_formatted(
                &setup.account,
                ListRequest {
                    patterns: vec!["*".to_owned()],
                    select_subscribed: true,
                    return_subscribed: true,
                    ..ListRequest::default()
                }
            )
        );

        // Example 5.3
        assert_eq!(
            "'Fruit' [\\HasChildren] []\n\
             'INBOX' [\\Noinferiors] []\n\
             'Tofu' [\\HasNoChildren] []\n\
             'Vegetable' [\\HasChildren] []\n",
            list_formatted(
                &setup.account,
                ListRequest {
                    patterns: vec!["%".to_owned()],
                    return_children: true,
                    ..ListRequest::default()
                }
            )
        );

        // Examples 5.4 and 5.5 are inapplicable since they involve remote
        // mailboxes and remote subscriptions.

        // Example 5.6 is also mainly concerned with remote stuff, but it also
        // demonstrates fetching subscription data without traversing
        // subscriptions instead of mailboxes.
        assert_eq!(
            "'Fruit' [] []\n\
             'Fruit/Apple' [] []\n\
             'Fruit/Banana' [\\Subscribed] []\n\
             'INBOX' [\\Noinferiors, \\Subscribed] []\n\
             'Tofu' [] []\n\
             'Vegetable' [\\Subscribed] []\n\
             'Vegetable/Broccoli' [\\Subscribed] []\n\
             'Vegetable/Corn' [] []\n",
            list_formatted(
                &setup.account,
                ListRequest {
                    patterns: vec!["*".to_owned()],
                    return_subscribed: true,
                    ..ListRequest::default()
                }
            )
        );

        // Example 5.7 uses a different hierarchy for some reason. Here, we
        // adapt it to the one above.
        assert_eq!(
            "'Fruit/Apple' [] []\n\
             'Fruit/Banana' [] []\n\
             'INBOX' [\\Noinferiors] []\n\
             'Vegetable' [] []\n",
            list_formatted(
                &setup.account,
                ListRequest {
                    patterns: vec![
                        "INBOX".to_owned(),
                        "Vegetable".to_owned(),
                        "Fruit/%".to_owned()
                    ],
                    ..ListRequest::default()
                }
            )
        );

        // Examples under 5.8 use a different hierarchy
        remove_all_but_inbox(&setup.account);
        setup.account.unsubscribe("INBOX").unwrap();
        setup.create("Foo");
        setup.create("Foo/Bar");
        setup.create("Foo/Baz");
        setup.create("Moo");

        // Example 5.8.?
        assert_eq!(
            "'Foo' [] []\n\
             'Foo/Bar' [] []\n\
             'Foo/Baz' [] []\n\
             'INBOX' [\\Noinferiors] []\n\
             'Moo' [] []\n",
            list_formatted(
                &setup.account,
                ListRequest {
                    patterns: vec!["*".to_owned()],
                    ..ListRequest::default()
                }
            )
        );

        // Example 5.8.@
        assert_eq!(
            "'Foo' [\\HasChildren] []\n\
             'INBOX' [\\Noinferiors] []\n\
             'Moo' [\\HasNoChildren] []\n",
            list_formatted(
                &setup.account,
                ListRequest {
                    patterns: vec!["%".to_owned()],
                    return_children: true,
                    ..ListRequest::default()
                }
            )
        );

        // Example 5.8.A
        setup.account.subscribe("Foo/Baz").unwrap();
        assert_eq!(
            "'Foo/Baz' [\\Subscribed] []\n",
            list_formatted(
                &setup.account,
                ListRequest {
                    patterns: vec!["*".to_owned()],
                    select_subscribed: true,
                    return_subscribed: true,
                    ..ListRequest::default()
                }
            )
        );
        assert_eq!(
            "",
            list_formatted(
                &setup.account,
                ListRequest {
                    patterns: vec!["%".to_owned()],
                    select_subscribed: true,
                    return_subscribed: true,
                    ..ListRequest::default()
                }
            )
        );
        assert_eq!(
            "'Foo' [] [\"SUBSCRIBED\"]\n",
            list_formatted(
                &setup.account,
                ListRequest {
                    patterns: vec!["%".to_owned()],
                    select_subscribed: true,
                    return_subscribed: true,
                    recursive_match: true,
                    ..ListRequest::default()
                }
            )
        );

        // Example 5.8.A1
        setup.account.subscribe("Foo").unwrap();
        assert_eq!(
            "'Foo' [\\Subscribed] [\"SUBSCRIBED\"]\n",
            list_formatted(
                &setup.account,
                ListRequest {
                    patterns: vec!["%".to_owned()],
                    select_subscribed: true,
                    return_subscribed: true,
                    recursive_match: true,
                    ..ListRequest::default()
                }
            )
        );

        // Example 5.8.A2
        // Using a name other than Foo so that we don't need to substantially
        // change the hierarchy
        setup.account.unsubscribe("Foo").unwrap();
        setup.account.unsubscribe("Foo/Baz").unwrap();
        setup.account.subscribe("Xyzzy/Plugh").unwrap();
        assert_eq!(
            "'Xyzzy' [\\NonExistent] [\"SUBSCRIBED\"]\n",
            list_formatted(
                &setup.account,
                ListRequest {
                    patterns: vec!["%".to_owned()],
                    select_subscribed: true,
                    return_subscribed: true,
                    recursive_match: true,
                    ..ListRequest::default()
                }
            )
        );

        // Example 5.8.B
        setup.account.unsubscribe("Xyzzy/Plugh").unwrap();
        assert_eq!(
            "",
            list_formatted(
                &setup.account,
                ListRequest {
                    patterns: vec!["%".to_owned()],
                    select_subscribed: true,
                    return_subscribed: true,
                    recursive_match: true,
                    ..ListRequest::default()
                }
            )
        );

        // Example 5.8.C
        setup.account.subscribe("Foo").unwrap();
        setup.account.subscribe("Moo").unwrap();
        assert_eq!(
            "'Foo' [\\HasChildren, \\Subscribed] []\n\
             'Moo' [\\HasNoChildren, \\Subscribed] []\n",
            list_formatted(
                &setup.account,
                ListRequest {
                    patterns: vec!["%".to_owned()],
                    select_subscribed: true,
                    return_subscribed: true,
                    return_children: true,
                    recursive_match: true,
                    ..ListRequest::default()
                }
            )
        );

        // Example 5.9
        remove_all_but_inbox(&setup.account);
        setup.create("foo2");
        setup.create("foo2/bar1");
        setup.create("foo2/bar2");
        setup.create("baz2");
        setup.create("baz2/bar2");
        setup.create("baz2/bar22");
        setup.create("baz2/bar222");
        setup.create("eps2");
        setup.create("eps2/mamba");
        setup.create("qux2/bar2");
        setup.account.subscribe("foo2/bar1").unwrap();
        setup.account.subscribe("foo2/bar2").unwrap();
        setup.account.subscribe("baz2/bar2").unwrap();
        setup.account.subscribe("baz2/bar22").unwrap();
        setup.account.subscribe("baz2/bar222").unwrap();
        setup.account.subscribe("eps2").unwrap();
        setup.account.subscribe("eps2/mamba").unwrap();
        setup.account.subscribe("qux2/bar2").unwrap();
        assert_eq!(
            "'baz2/bar2' [\\Subscribed] []\n\
             'baz2/bar22' [\\Subscribed] []\n\
             'baz2/bar222' [\\Subscribed] []\n\
             'eps2' [\\Subscribed] [\"SUBSCRIBED\"]\n\
             'foo2' [] [\"SUBSCRIBED\"]\n\
             'foo2/bar2' [\\Subscribed] []\n\
             'qux2/bar2' [\\Subscribed] []\n",
            list_formatted(
                &setup.account,
                ListRequest {
                    patterns: vec!["*2".to_owned()],
                    select_subscribed: true,
                    return_subscribed: true,
                    recursive_match: true,
                    ..ListRequest::default()
                }
            )
        );
        // Our result for qux2 is slightly different since we don't allow a
        // real mailbox to exist under a non-existent name.
        //
        // Also, the RFC includes `baz2`, `foo2`, and `qux2` in this example,
        // even though that violates a SHOULD NOT (and this very fact is
        // explained literally two paragraphs above and the previous example).
        assert_eq!(
            "'baz2/bar2' [\\Subscribed] []\n\
             'baz2/bar22' [\\Subscribed] []\n\
             'baz2/bar222' [\\Subscribed] []\n\
             'eps2' [\\Subscribed] [\"SUBSCRIBED\"]\n\
             'eps2/mamba' [\\Subscribed] []\n\
             'foo2/bar1' [\\Subscribed] []\n\
             'foo2/bar2' [\\Subscribed] []\n\
             'qux2/bar2' [\\Subscribed] []\n",
            list_formatted(
                &setup.account,
                ListRequest {
                    patterns: vec!["*".to_owned()],
                    select_subscribed: true,
                    return_subscribed: true,
                    recursive_match: true,
                    ..ListRequest::default()
                }
            )
        );

        // Example 5.10 is not generally useful; two sub-examples are redundant
        // with earlier examples, and one just shows that the server is allowed
        // to have the puzzling behaviour of returning \HasNoChildren at the
        // same time as a `CHILDINFO` result.

        // Example 5.11 is also inapplicable as it deals with mailboxes that
        // have real children but don't actually exist.
    }

    #[test]
    fn list_select_special_use() {
        let setup = set_up();

        setup
            .account
            .create(CreateRequest {
                name: "stuff/important".to_owned(),
                special_use: vec!["\\Important".to_owned()],
            })
            .unwrap();

        assert_eq!(
            "'Archive' [\\Archive] []\n\
             'Drafts' [\\Drafts] []\n\
             'Sent' [\\Sent] []\n\
             'Spam' [\\Junk] []\n\
             'Trash' [\\Trash] []\n\
             'stuff' [] [\"SPECIAL-USE\"]\n",
            list_formatted(
                &setup.account,
                ListRequest {
                    patterns: vec!["%".to_owned()],
                    select_special_use: true,
                    return_special_use: true,
                    recursive_match: true,
                    ..ListRequest::default()
                }
            )
        );
    }

    #[test]
    fn create_failure_cases() {
        let setup = set_up();

        assert_matches!(
            Err(Error::MailboxExists),
            setup.account.create(CreateRequest {
                name: "Archive".to_owned(),
                special_use: vec![],
            })
        );
        assert_matches!(
            Err(Error::BadOperationOnInbox),
            setup.account.create(CreateRequest {
                name: "INBOX/Foo".to_owned(),
                special_use: vec![],
            })
        );
        assert_matches!(
            Err(Error::UnsafeName),
            setup.account.create(CreateRequest {
                name: "../Foo".to_owned(),
                special_use: vec![],
            })
        );
        assert_matches!(
            Err(Error::UnsafeName),
            setup.account.create(CreateRequest {
                name: "".to_owned(),
                special_use: vec![],
            })
        );
        assert_matches!(
            Err(Error::UnsupportedSpecialUse),
            setup.account.create(CreateRequest {
                name: "Foo".to_owned(),
                special_use: vec!["\\Stuff".to_owned()],
            })
        );
        assert_matches!(
            Err(Error::UnsupportedSpecialUse),
            setup.account.create(CreateRequest {
                name: "Foo".to_owned(),
                special_use: vec!["\\Sent".to_owned(), "\\Junk".to_owned()],
            })
        );
    }

    #[test]
    fn test_delete() {
        let setup = set_up();
        setup.create("foo/bar");

        setup.account.delete("foo").unwrap();
        assert_eq!(
            "'foo' [\\Noselect] []\n\
             'foo/bar' [] []\n",
            list_formatted(
                &setup.account,
                ListRequest {
                    patterns: vec!["f*".to_owned()],
                    ..ListRequest::default()
                }
            )
        );

        assert_matches!(
            Err(Error::MailboxHasInferiors),
            setup.account.delete("foo")
        );

        setup.account.delete("foo/bar").unwrap();
        assert_eq!(
            "'foo' [\\Noselect] []\n",
            list_formatted(
                &setup.account,
                ListRequest {
                    patterns: vec!["f*".to_owned()],
                    ..ListRequest::default()
                }
            )
        );

        setup.account.delete("foo").unwrap();
        assert_eq!(
            "",
            list_formatted(
                &setup.account,
                ListRequest {
                    patterns: vec!["f*".to_owned()],
                    ..ListRequest::default()
                }
            )
        );

        assert_matches!(
            Err(Error::BadOperationOnInbox),
            setup.account.delete("INBOX")
        );

        assert_matches!(Err(Error::NxMailbox), setup.account.delete("foo"));

        assert_matches!(Err(Error::UnsafeName), setup.account.delete("../foo"));

        assert_matches!(Err(Error::NxMailbox), setup.account.delete(""));
    }

    #[test]
    fn test_rename() {
        let setup = set_up();

        setup
            .account
            .rename(RenameRequest {
                existing_name: "Archive".to_owned(),
                new_name: "Stuff/2020".to_owned(),
            })
            .unwrap();

        assert_eq!(
            "'Stuff' [] []\n\
             'Stuff/2020' [\\Archive] []\n",
            list_formatted(
                &setup.account,
                ListRequest {
                    patterns: vec!["Stuff*".to_owned()],
                    return_special_use: true,
                    ..ListRequest::default()
                }
            )
        );

        setup
            .account
            .mailbox("INBOX", false)
            .unwrap()
            .append(
                FixedOffset::zero().timestamp0(),
                vec![],
                &b"this is a test message"[..],
            )
            .unwrap();
        setup
            .account
            .rename(RenameRequest {
                existing_name: "INBOX".to_owned(),
                new_name: "INBOX Special Case".to_owned(),
            })
            .unwrap();

        assert_eq!(
            "'INBOX' [\\Noinferiors] []\n\
             'INBOX Special Case' [] []\n",
            list_formatted(
                &setup.account,
                ListRequest {
                    patterns: vec!["IN*".to_owned()],
                    ..ListRequest::default()
                }
            )
        );

        {
            let (_, select) = setup
                .account
                .mailbox("INBOX", true)
                .unwrap()
                .select()
                .unwrap();
            assert_eq!(0, select.exists);

            let (_, select) = setup
                .account
                .mailbox("INBOX Special Case", true)
                .unwrap()
                .select()
                .unwrap();
            assert_eq!(1, select.exists);
        }

        assert_matches!(
            Err(Error::RenameToSelf),
            setup.account.rename(RenameRequest {
                existing_name: "Sent".to_owned(),
                new_name: "Sent".to_owned(),
            })
        );
        assert_matches!(
            Err(Error::RenameIntoSelf),
            setup.account.rename(RenameRequest {
                existing_name: "Sent".to_owned(),
                new_name: "Sent/Child".to_owned(),
            })
        );
        assert_matches!(
            Err(Error::BadOperationOnInbox),
            setup.account.rename(RenameRequest {
                existing_name: "Sent".to_owned(),
                new_name: "INBOX/Sent".to_owned(),
            })
        );
        assert_matches!(
            Err(Error::MailboxExists),
            setup.account.rename(RenameRequest {
                existing_name: "Sent".to_owned(),
                new_name: "Spam".to_owned(),
            })
        );
        assert_matches!(
            Err(Error::NxMailbox),
            setup.account.rename(RenameRequest {
                existing_name: "Xyzzy".to_owned(),
                new_name: "Plugh".to_owned(),
            })
        );
        assert_matches!(
            Err(Error::NxMailbox),
            setup.account.rename(RenameRequest {
                existing_name: "".to_owned(),
                new_name: "Plugh".to_owned(),
            })
        );
        assert_matches!(
            Err(Error::NxMailbox),
            setup.account.rename(RenameRequest {
                existing_name: "/".to_owned(),
                new_name: "Plugh".to_owned(),
            })
        );
        assert_matches!(
            Err(Error::UnsafeName),
            setup.account.rename(RenameRequest {
                existing_name: "../Foo".to_owned(),
                new_name: "Plugh".to_owned(),
            })
        );
        assert_matches!(
            Err(Error::UnsafeName),
            setup.account.rename(RenameRequest {
                existing_name: "Sent".to_owned(),
                new_name: "../Plugh".to_owned(),
            })
        );
        assert_matches!(
            Err(Error::UnsafeName),
            setup.account.rename(RenameRequest {
                existing_name: "Sent".to_owned(),
                new_name: "".to_owned(),
            })
        );
    }

    #[test]
    fn test_status() {
        let setup = set_up();

        let (uidvalidity, uidnext) = {
            let (mut mb, select) = setup
                .account
                .mailbox("INBOX", false)
                .unwrap()
                .select()
                .unwrap();

            // Adjust inbox to have 1 recent, 2 unseen, 3 messages.
            mb.stateless()
                .append(
                    FixedOffset::zero().timestamp0(),
                    vec![],
                    &b"this is a test message"[..],
                )
                .unwrap();
            let uid2 = mb
                .stateless()
                .append(
                    FixedOffset::zero().timestamp0(),
                    vec![],
                    &b"this is a test message"[..],
                )
                .unwrap();
            mb.poll().unwrap(); // Remove \Recent from those two

            mb.store(&StoreRequest {
                ids: &SeqRange::just(uid2),
                flags: &[Flag::Seen],
                remove_listed: false,
                remove_unlisted: false,
                loud: false,
                unchanged_since: None,
            })
            .unwrap();
            mb.poll().unwrap();

            let uid3 = mb
                .stateless()
                .append(
                    FixedOffset::zero().timestamp0(),
                    vec![],
                    &b"this is a test message"[..],
                )
                .unwrap();

            (select.uidvalidity, uid3.next().unwrap())
        };

        assert_eq!(
            StatusResponse {
                name: "INBOX".to_owned(),
                messages: Some(3),
                ..StatusResponse::default()
            },
            setup
                .account
                .status(&StatusRequest {
                    name: "inbox".to_owned(),
                    messages: true,
                    ..StatusRequest::default()
                })
                .unwrap()
        );

        assert_eq!(
            StatusResponse {
                name: "INBOX".to_owned(),
                recent: Some(1),
                ..StatusResponse::default()
            },
            setup
                .account
                .status(&StatusRequest {
                    name: "inbox".to_owned(),
                    recent: true,
                    ..StatusRequest::default()
                })
                .unwrap()
        );

        assert_eq!(
            StatusResponse {
                name: "INBOX".to_owned(),
                uidnext: Some(uidnext),
                ..StatusResponse::default()
            },
            setup
                .account
                .status(&StatusRequest {
                    name: "inbox".to_owned(),
                    uidnext: true,
                    ..StatusRequest::default()
                })
                .unwrap()
        );

        assert_eq!(
            StatusResponse {
                name: "INBOX".to_owned(),
                uidvalidity: Some(uidvalidity),
                ..StatusResponse::default()
            },
            setup
                .account
                .status(&StatusRequest {
                    name: "inbox".to_owned(),
                    uidvalidity: true,
                    ..StatusRequest::default()
                })
                .unwrap()
        );

        assert_eq!(
            StatusResponse {
                name: "INBOX".to_owned(),
                unseen: Some(2),
                ..StatusResponse::default()
            },
            setup
                .account
                .status(&StatusRequest {
                    name: "inbox".to_owned(),
                    unseen: true,
                    ..StatusRequest::default()
                })
                .unwrap()
        );

        {
            let mb = setup.account.mailbox("Archive", false).unwrap();

            // Adjust Archive to have 1 recent, 1 unseen, 1 message.
            mb.append(
                FixedOffset::zero().timestamp0(),
                vec![],
                &b"this is a test message"[..],
            )
            .unwrap();
        };

        assert_eq!(
            StatusResponse {
                name: "Archive".to_owned(),
                unseen: Some(1),
                ..StatusResponse::default()
            },
            setup
                .account
                .status(&StatusRequest {
                    name: "Archive".to_owned(),
                    unseen: true,
                    ..StatusRequest::default()
                })
                .unwrap()
        );
    }
}
