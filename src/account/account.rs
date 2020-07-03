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
use crate::account::mailbox::StatelessMailbox;
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
    shadow_root: PathBuf,
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
            shadow_root: root.join("shadow"),
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

        // TODO We should do maintenance here like cleaning `tmp` and
        // `garbage`.

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

        self.mailbox_path_create_parents(&request.name)?
            .create(&self.common_paths.tmp, special_use)?;
        Ok(())
    }

    /// The RFC 3501 `DELETE` command.
    pub fn delete(&self, name: &str) -> Result<(), Error> {
        self.mailbox_path(name)?.delete(&self.common_paths.garbage)
    }

    /// The RFC 3501 `RENAME` command.
    pub fn rename(&self, request: RenameRequest) -> Result<(), Error> {
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

    pub fn status(
        &self,
        request: &StatusRequest,
    ) -> Result<Vec<StatusResponse>, Error> {
        let mailbox_path = self.mailbox_path(&request.name)?;
        Ok(vec![self.status_for(mailbox_path, request)?])
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

#[cfg(test)]
mod test {
    use tempfile::TempDir;

    use super::*;

    struct Setup {
        root: TempDir,
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
        account.provision(&KeyStoreConfig::default()).unwrap();

        Setup { root, account }
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
}
