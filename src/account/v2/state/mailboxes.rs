//-
// Copyright (c) 2023, Jason Lingle
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
use std::collections::HashMap;
use std::rc::Rc;

use super::super::storage;
use super::defs::*;
use crate::{
    account::model::*,
    support::{error::Error, mailbox_paths::*, safe_name::is_safe_name},
};

impl Account {
    /// The RFC 3501 `CREATE` command.
    ///
    /// Returns the RFC 8474 `MAILBOXID` of the new mailbox.
    pub fn create(&mut self, request: CreateRequest) -> Result<String, Error> {
        if request.special_use.len() > 1 {
            return Err(Error::UnsupportedSpecialUse);
        }

        // We allow actually creating the INBOX itself through this method for
        // simplicity. Otherwise, reject things that would create a mailbox
        // inside the INBOX or suggest a different casing for it.
        if request.name != "INBOX" && path_is_inbox(&request.name) {
            return Err(Error::BadOperationOnInbox);
        }

        let special_use =
            if let Some(special_use) = request.special_use.into_iter().next() {
                Some(MailboxAttribute::special_use_from_str(&special_use)?)
            } else {
                None
            };

        // create_mailbox_hierarchy validates that all parts of request.name
        // are safe names.
        self.metadb
            .create_mailbox_hierarchy(&request.name, special_use)
            .map(storage::MailboxId::format_rfc8474)
    }

    /// Like `create()`, but returns no error if the mailbox already exists.
    pub fn create_if_nx(
        &mut self,
        request: CreateRequest,
    ) -> Result<(), Error> {
        match self.create(request) {
            Ok(_) | Err(Error::MailboxExists) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// The RFC 3501 `DELETE` command.
    pub fn delete(&mut self, name: &str) -> Result<(), Error> {
        if path_is_inbox(name) {
            return Err(Error::BadOperationOnInbox);
        }

        let id = self.metadb.find_mailbox(name)?;
        self.metadb.delete_mailbox(id)
    }

    /// The RFC 3501 `RENAME` command, with handling of the `RENAME INBOX`
    /// quirk.
    pub fn rename(&mut self, request: RenameRequest) -> Result<(), Error> {
        // Validate we're not creating something under INBOX. We don't validate
        // name safety here because
        // `move_all_mailbox_messages_into_create_hierarchy` and
        // `move_mailbox_into_hierarchy` both validate that implicitly.
        if path_is_inbox(&request.new_name) {
            return Err(Error::BadOperationOnInbox);
        }

        let src = self.metadb.find_mailbox(&request.existing_name)?;
        if path_is_inbox(&request.existing_name) {
            self.metadb
                .move_all_mailbox_messages_into_create_hierarchy(
                    src,
                    &request.new_name,
                )?;
        } else {
            self.metadb
                .move_mailbox_into_hierarchy(src, &request.new_name)?;
        }

        Ok(())
    }

    /// The RFC 3501 `SUBSCRIBE` command.
    pub fn subscribe(&mut self, name: &str) -> Result<(), Error> {
        // Subscriptions would also count as an inferior to INBOX in some cases
        // of LIST, so ensure no subscriptions to children of INBOX are ever
        // created.
        if path_is_inbox(name) && name != "INBOX" {
            return Err(Error::BadOperationOnInbox);
        }

        let name = normalise_path(name)?;
        if name.is_empty() {
            return Err(Error::UnsafeName);
        }

        self.metadb.add_subscription(&name)
    }

    /// The RFC 3501 `UNSUBSCRIBE` command.
    pub fn unsubscribe(&mut self, name: &str) -> Result<(), Error> {
        self.metadb.rm_subscription(&normalise_path(name)?)
    }

    /// The RFC 3501 `LIST` and `LSUB` commands and the non-standard `XLIST`
    /// command.
    ///
    /// `LSUB` is achieved by setting `select_subscribed`, `recursive_match`,
    /// and `lsub_style` (and NOT `return_subscribed`).
    ///
    /// `XLIST` is achieved by setting `return_children` and
    /// `return_special_use`.
    ///
    /// The special case of `LIST "" ""` (a query for the path separator) is
    /// handled here.
    pub fn list(
        &mut self,
        request: &ListRequest,
    ) -> Result<Vec<ListResponse>, Error> {
        if request.patterns.is_empty() {
            // Extended list with zero patterns necessarily matches nothing.
            return Ok(vec![]);
        }

        // RFC 5258 does not describe any behaviour if extended list is used with
        // multiple patterns and one of them is "". Here, we just handle the ""
        // special case if there's exactly one pattern, and in other cases the
        // pattern is interpreted literally, i.e., matching an empty mailbox name.
        //
        // In other words, any `LIST`-like request with exactly one empty
        // pattern is interpreted as a query for the path separator.
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

        let mailboxes = self.metadb.fetch_all_mailboxes()?;
        let subscriptions = self.metadb.fetch_all_subscriptions()?;
        let hierarchy = reify_mailbox_hierarchy(&mailboxes, &subscriptions);

        let mut accum = Vec::new();
        let root = &hierarchy[""];
        let top_level = if request.select_subscribed {
            &root.subscribed_children
        } else {
            &root.real_children
        };

        for path in top_level {
            walk_hierarchy(&mut accum, request, &matcher, &hierarchy, path);
        }

        // `accum` is in post-order with siblings sorted reverse. Reverse the
        // whole `Vec` to get pre-order output with sorted siblings.
        accum.reverse();

        Ok(accum)
    }
}

fn path_is_inbox(path: &str) -> bool {
    Some("INBOX") == parse_mailbox_path(path).next()
}

fn normalise_path(path: &str) -> Result<String, Error> {
    let mut normalised = String::with_capacity(path.len());
    for part in parse_mailbox_path(path) {
        if !is_safe_name(part) {
            return Err(Error::UnsafeName);
        }

        if !normalised.is_empty() {
            normalised.push('/');
        }
        normalised.push_str(part);
    }

    Ok(normalised)
}

/// An intermediate representation of a mailbox and/or subscription used by the
/// `list` implementation.
#[derive(Debug, Default)]
struct HierarchyElement<'a> {
    /// If this is a real mailbox, the information about that mailbox.
    real: Option<&'a storage::Mailbox>,
    /// Whether this node is an existing subscription.
    subscribed: bool,
    /// The paths of mailboxes immediately nested beneath this mailbox if a
    /// real mailbox; otherwise, empty. Sorted descending.
    real_children: Vec<Rc<str>>,
    /// The paths of subscription nodes immediately nested beneath this node if
    /// a subscription node; otherwise, empty. Sorted descending.
    subscribed_children: Vec<Rc<str>>,
}

/// Converts the set of mailboxes and subscriptions into a hierarchical
/// structure that is easier to process for the `LIST` command family.
///
/// The tree is rooted at `""`.
///
/// A post-order traversal of the tree processes the mailboxes in reverse
/// lexicographical order.
fn reify_mailbox_hierarchy<'a>(
    real_mailboxes: &'a [storage::Mailbox],
    subscriptions: &[String],
) -> HashMap<Rc<str>, HierarchyElement<'a>> {
    let mut hierarchy = HashMap::<Rc<str>, HierarchyElement<'a>>::new();

    let root_path = Rc::from("");
    hierarchy.insert(
        Rc::clone(&root_path),
        HierarchyElement {
            real: None,
            subscribed: false,
            real_children: Vec::new(),
            subscribed_children: Vec::new(),
        },
    );

    let mailbox_id_to_info = real_mailboxes
        .iter()
        .map(|mb| (mb.id, mb))
        .collect::<HashMap<_, _>>();

    let mut path_buffer = String::new();
    let mut mailbox_stack = Vec::<storage::MailboxId>::new();
    for mailbox in real_mailboxes {
        if storage::MailboxId::ROOT == mailbox.id {
            continue;
        }

        path_buffer.clear();
        let mut ancestor = mailbox.parent_id;
        while storage::MailboxId::ROOT != ancestor {
            mailbox_stack.push(ancestor);
            ancestor = mailbox_id_to_info[&ancestor].parent_id;
        }
        while let Some(ancestor) = mailbox_stack.pop() {
            path_buffer.push_str(&mailbox_id_to_info[&ancestor].name);
            path_buffer.push('/');
        }
        let parent_path_len = path_buffer.len().saturating_sub(1);

        path_buffer.push_str(&mailbox.name);

        let path = Rc::from(path_buffer.as_str());
        let parent_path = &path_buffer[..parent_path_len];

        hierarchy.entry(Rc::clone(&path)).or_default().real = Some(mailbox);

        let parent_path = hierarchy
            .get_key_value(parent_path)
            .map(|(k, _)| Rc::clone(k))
            .unwrap_or_else(|| Rc::from(parent_path));
        hierarchy
            .entry(parent_path)
            .or_default()
            .real_children
            .push(path);
    }

    for subscription in subscriptions {
        path_buffer.clear();

        // Ensure entries for each level of the subscription tree are present.
        let mut prev_path = Rc::clone(&root_path);
        for part in parse_mailbox_path(subscription) {
            if !path_buffer.is_empty() {
                path_buffer.push('/');
            }
            path_buffer.push_str(part);

            let next_path = Rc::from(path_buffer.as_str());
            hierarchy
                .entry(Rc::clone(&prev_path))
                .or_default()
                .subscribed_children
                .push(Rc::clone(&next_path));

            prev_path = next_path;
        }

        hierarchy.entry(prev_path).or_default().subscribed = true;
    }

    for entry in hierarchy.values_mut() {
        entry.real_children.sort_unstable_by(|a, b| b.cmp(a));
        entry.subscribed_children.sort_unstable_by(|a, b| b.cmp(a));
        entry.subscribed_children.dedup();
    }

    hierarchy
}

/// Used to return information about lower-levels of the hierarchy to the
/// ancestors when processing a `LIST`-like command.
#[derive(Clone, Copy, Default)]
pub struct ChildListResult {
    /// True if subscriptions are being selected any node in the hierarchy
    /// below this one is subscribed.
    selected_subscribe: bool,
    /// True if special use information is being selected any node in the
    /// hierarchy below this one has a special use.
    selected_special_use: bool,
    /// Set to `true` if a node in the hierarchy or any of its descendants
    /// matched the selection criteria, but not the match criteria, and none of
    /// the ancestors up to and including the node which returned this
    /// `ChildListResult` satisfied the match criteria.
    unmatched_but_selected: bool,
    /// Whether the node of the hierarchy represents a real (but potentially
    /// `\Noselect`) mailbox.
    exists: bool,
}

/// The bulk of the `LIST` logic, which works by doing a post-order traversal
/// of the hierarchy.
fn walk_hierarchy(
    accum: &mut Vec<ListResponse>,
    request: &ListRequest,
    matcher: &impl Fn(&str) -> bool,
    hierarchy: &HashMap<Rc<str>, HierarchyElement>,
    path: &str,
) -> ChildListResult {
    let mailbox = &hierarchy[path];
    let mut self_result = ChildListResult::default();
    let selectable = mailbox.real.is_some_and(|mb| mb.selectable);
    self_result.exists = mailbox.real.is_some();
    let self_matches = matcher(path);

    let subscribed = mailbox.subscribed
        && (request.select_subscribed || request.return_subscribed);
    let special_use =
        if request.select_special_use || request.return_special_use {
            mailbox.real.and_then(|mb| mb.special_use)
        } else {
            None
        };

    let mut self_selected = (!request.select_subscribed || subscribed)
        && (!request.select_special_use || special_use.is_some());
    let has_children = !mailbox.real_children.is_empty();

    let children = if request.select_subscribed {
        &mailbox.subscribed_children
    } else {
        &mailbox.real_children
    };
    for child in children {
        let child_result =
            walk_hierarchy(accum, request, matcher, hierarchy, child);

        self_result.selected_subscribe |= child_result.selected_subscribe;
        self_result.selected_special_use |= child_result.selected_special_use;
        self_result.unmatched_but_selected |=
            child_result.unmatched_but_selected;
    }

    // If we aren't doing subscriptions, we filter to only existing
    // mailboxes.
    self_selected &= request.select_subscribed || self_result.exists;

    // Add an entry for self if matching and selected, or if matching and
    // unselected but we have a selected but unmatching child and
    // recursive_match is enabled.
    if self_matches
        && (self_selected
            || (request.recursive_match && self_result.unmatched_but_selected))
    {
        let mut info = ListResponse {
            name: path.to_owned(),
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

        if path_is_inbox(path) {
            info.attributes.push(MailboxAttribute::Noinferiors);
        }

        if subscribed && request.return_subscribed {
            info.attributes.push(MailboxAttribute::Subscribed);
        }

        if request.return_children {
            if has_children {
                info.attributes.push(MailboxAttribute::HasChildren);
            } else if !path_is_inbox(path) {
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

        accum.push(info);
    }

    // CHILDINFO data is passed the whole way up the tree unconditionally.
    self_result.selected_special_use |=
        request.select_special_use && special_use.is_some();
    self_result.selected_subscribe |= request.select_subscribed && subscribed;

    if !self_matches && self_selected {
        // Notify our parent that we were selected but not matched so that
        // it can insert a spurious result if it matches but isn't
        // selected.
        self_result.unmatched_but_selected = true;
    }

    self_result
}

#[cfg(test)]
mod test {
    use super::*;

    fn list_formatted(account: &mut Account, request: ListRequest) -> String {
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

    fn remove_all_but_inbox(account: &mut Account) {
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
        let mut fixture = TestFixture::new();

        assert_eq!(
            "'Archive' [] []\n\
             'Drafts' [] []\n\
             'INBOX' [\\Noinferiors] []\n\
             'Sent' [] []\n\
             'Spam' [] []\n\
             'Trash' [] []\n",
            list_formatted(
                &mut fixture.account,
                ListRequest {
                    patterns: vec!["*".to_owned()],
                    ..ListRequest::default()
                }
            )
        );
    }

    #[test]
    fn list_all_attributes() {
        let mut fixture = TestFixture::new();

        fixture
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
                &mut fixture.account,
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
        let mut fixture = TestFixture::new();

        fixture.create("foo");
        fixture.create("food");
        fixture.create("foo/bar");

        assert_eq!(
            "'foo/bar' [] []\n",
            list_formatted(
                &mut fixture.account,
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
                &mut fixture.account,
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
                &mut fixture.account,
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
                &mut fixture.account,
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
        let mut fixture = TestFixture::new();

        // Examples from RFC 3501 section 6.3.9
        fixture
            .account
            .create(CreateRequest {
                name: "news/comp/mail/misc".to_owned(),
                special_use: vec![],
            })
            .unwrap();
        fixture
            .account
            .create(CreateRequest {
                name: "news/comp/mail/mime".to_owned(),
                special_use: vec![],
            })
            .unwrap();
        fixture
            .account
            .create(CreateRequest {
                name: "news/comp/mail/sanity".to_owned(),
                special_use: vec![],
            })
            .unwrap();
        fixture.account.subscribe("news/comp/mail/misc").unwrap();
        fixture.account.subscribe("news/comp/mail/mime").unwrap();

        assert_eq!(
            "'news/comp/mail/mime' [] []\n\
             'news/comp/mail/misc' [] []\n",
            list_formatted(
                &mut fixture.account,
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
                &mut fixture.account,
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
        fixture.account.subscribe("news/comp").unwrap();
        fixture.account.delete("news/comp").unwrap();
        assert_eq!(
            "'news/comp' [] [\"SUBSCRIBED\"]\n\
             'news/comp/mail/mime' [] []\n\
             'news/comp/mail/misc' [] []\n",
            list_formatted(
                &mut fixture.account,
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
        let mut fixture = TestFixture::new();

        remove_all_but_inbox(&mut fixture.account);

        // Examples from RFC 5258
        fixture.create("Fruit");
        fixture.create("Fruit/Apple");
        fixture.create("Fruit/Banana");
        fixture.create("Tofu");
        fixture.create("Vegetable");
        fixture.create("Vegetable/Broccoli");
        fixture.create("Vegetable/Corn");

        fixture.account.subscribe("Fruit/Banana").unwrap();
        fixture.account.subscribe("Fruit/Peach").unwrap();
        fixture.account.subscribe("Vegetable").unwrap();
        fixture.account.subscribe("Vegetable/Broccoli").unwrap();

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
                &mut fixture.account,
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
                &mut fixture.account,
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
                &mut fixture.account,
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
                &mut fixture.account,
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
                &mut fixture.account,
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
        remove_all_but_inbox(&mut fixture.account);
        fixture.account.unsubscribe("INBOX").unwrap();
        fixture.create("Foo");
        fixture.create("Foo/Bar");
        fixture.create("Foo/Baz");
        fixture.create("Moo");

        // Example 5.8.?
        assert_eq!(
            "'Foo' [] []\n\
             'Foo/Bar' [] []\n\
             'Foo/Baz' [] []\n\
             'INBOX' [\\Noinferiors] []\n\
             'Moo' [] []\n",
            list_formatted(
                &mut fixture.account,
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
                &mut fixture.account,
                ListRequest {
                    patterns: vec!["%".to_owned()],
                    return_children: true,
                    ..ListRequest::default()
                }
            )
        );

        // Example 5.8.A
        fixture.account.subscribe("Foo/Baz").unwrap();
        assert_eq!(
            "'Foo/Baz' [\\Subscribed] []\n",
            list_formatted(
                &mut fixture.account,
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
                &mut fixture.account,
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
                &mut fixture.account,
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
        fixture.account.subscribe("Foo").unwrap();
        assert_eq!(
            "'Foo' [\\Subscribed] [\"SUBSCRIBED\"]\n",
            list_formatted(
                &mut fixture.account,
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
        fixture.account.unsubscribe("Foo").unwrap();
        fixture.account.unsubscribe("Foo/Baz").unwrap();
        fixture.account.subscribe("Xyzzy/Plugh").unwrap();
        assert_eq!(
            "'Xyzzy' [\\NonExistent] [\"SUBSCRIBED\"]\n",
            list_formatted(
                &mut fixture.account,
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
        fixture.account.unsubscribe("Xyzzy/Plugh").unwrap();
        assert_eq!(
            "",
            list_formatted(
                &mut fixture.account,
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
        fixture.account.subscribe("Foo").unwrap();
        fixture.account.subscribe("Moo").unwrap();
        assert_eq!(
            "'Foo' [\\HasChildren, \\Subscribed] []\n\
             'Moo' [\\HasNoChildren, \\Subscribed] []\n",
            list_formatted(
                &mut fixture.account,
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
        remove_all_but_inbox(&mut fixture.account);
        fixture.create("foo2");
        fixture.create("foo2/bar1");
        fixture.create("foo2/bar2");
        fixture.create("baz2");
        fixture.create("baz2/bar2");
        fixture.create("baz2/bar22");
        fixture.create("baz2/bar222");
        fixture.create("eps2");
        fixture.create("eps2/mamba");
        fixture.create("qux2/bar2");
        fixture.account.subscribe("foo2/bar1").unwrap();
        fixture.account.subscribe("foo2/bar2").unwrap();
        fixture.account.subscribe("baz2/bar2").unwrap();
        fixture.account.subscribe("baz2/bar22").unwrap();
        fixture.account.subscribe("baz2/bar222").unwrap();
        fixture.account.subscribe("eps2").unwrap();
        fixture.account.subscribe("eps2/mamba").unwrap();
        fixture.account.subscribe("qux2/bar2").unwrap();
        assert_eq!(
            "'baz2/bar2' [\\Subscribed] []\n\
             'baz2/bar22' [\\Subscribed] []\n\
             'baz2/bar222' [\\Subscribed] []\n\
             'eps2' [\\Subscribed] [\"SUBSCRIBED\"]\n\
             'foo2' [] [\"SUBSCRIBED\"]\n\
             'foo2/bar2' [\\Subscribed] []\n\
             'qux2/bar2' [\\Subscribed] []\n",
            list_formatted(
                &mut fixture.account,
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
                &mut fixture.account,
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
        let mut fixture = TestFixture::new();

        fixture
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
                &mut fixture.account,
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
    fn test_reify_mailbox_hierarchy() {
        fn mailbox(
            parent: Option<i64>,
            id: i64,
            name: &str,
        ) -> storage::Mailbox {
            storage::Mailbox {
                id: storage::MailboxId(id),
                name: name.to_owned(),
                parent_id: parent
                    .map(storage::MailboxId)
                    .unwrap_or(storage::MailboxId::ROOT),
                selectable: true,
                special_use: None,
                next_uid: Uid::MIN,
                recent_uid: Uid::MIN,
                max_modseq: Modseq::MIN,
            }
        }

        // Hierarchy:
        //   foo/               subscribed
        //     bar/             not subscribed
        //       baz            subscribed
        //       qux            not subscribed
        //   oof/               not subscribed; discovered after children
        //     rab/             not subscribed; discovered after children
        //       zab            not subscribed
        //       xuq            not subscribed
        //   sub1               subscription-only
        //     sub2             subscription-only
        //     nx               not represented anywhere
        //       sub3           subscription-only
        //   bus1               subscription-only; discovered after children
        //     bus2             subscription-only
        let mailboxes = [
            mailbox(None, storage::MailboxId::ROOT.0, "/"),
            mailbox(None, 1, "foo"),
            mailbox(Some(1), 2, "bar"),
            mailbox(Some(2), 3, "baz"),
            mailbox(Some(2), 4, "qux"),
            mailbox(Some(10), 13, "zab"),
            mailbox(Some(10), 14, "xuq"),
            mailbox(Some(11), 10, "rab"),
            mailbox(None, 11, "oof"),
        ];
        let hierarchy = reify_mailbox_hierarchy(
            &mailboxes,
            &[
                "foo".to_owned(),
                "foo/bar/baz".to_owned(),
                "sub1".to_owned(),
                "sub1/sub2".to_owned(),
                "sub1/nx/sub3".to_owned(),
                "bus1/bus2".to_owned(),
                "bus1".to_owned(),
            ],
        );

        fn collect_children(v: &[Rc<str>]) -> Vec<&str> {
            v.iter().map(|s| &**s).collect()
        }

        macro_rules! assert_children {
            ([$($e:expr),*], $c:expr) => {
                assert_eq!(vec![$($e),*] as Vec<&str>, collect_children(&$c));
            }
        }

        let root = &hierarchy[""];
        assert_children!(["oof", "foo"], root.real_children);
        assert_children!(["sub1", "foo", "bus1"], root.subscribed_children);

        let foo = &hierarchy["foo"];
        assert!(foo.real.is_some());
        assert!(foo.subscribed);
        assert_children!(["foo/bar"], foo.real_children);
        assert_children!(["foo/bar"], foo.subscribed_children);

        let bar = &hierarchy["foo/bar"];
        assert!(bar.real.is_some());
        assert!(!bar.subscribed);
        assert_children!(["foo/bar/qux", "foo/bar/baz"], bar.real_children);
        assert_children!(["foo/bar/baz"], bar.subscribed_children);

        let baz = &hierarchy["foo/bar/baz"];
        assert!(baz.real.is_some());
        assert!(baz.subscribed);
        assert_children!([], baz.real_children);
        assert_children!([], baz.subscribed_children);

        let qux = &hierarchy["foo/bar/qux"];
        assert!(qux.real.is_some());
        assert!(!qux.subscribed);
        assert_children!([], qux.real_children);
        assert_children!([], qux.subscribed_children);

        let oof = &hierarchy["oof"];
        assert!(oof.real.is_some());
        assert!(!oof.subscribed);
        assert_children!(["oof/rab"], oof.real_children);
        assert_children!([], oof.subscribed_children);

        let rab = &hierarchy["oof/rab"];
        assert!(rab.real.is_some());
        assert!(!rab.subscribed);
        assert_children!(["oof/rab/zab", "oof/rab/xuq"], rab.real_children);
        assert_children!([], rab.subscribed_children);

        let sub1 = &hierarchy["sub1"];
        assert!(sub1.real.is_none());
        assert!(sub1.subscribed);
        assert_children!([], sub1.real_children);
        assert_children!(["sub1/sub2", "sub1/nx"], sub1.subscribed_children);

        let sub2 = &hierarchy["sub1/sub2"];
        assert!(sub2.real.is_none());
        assert!(sub2.subscribed);
        assert_children!([], sub2.real_children);
        assert_children!([], sub2.subscribed_children);

        let nx = &hierarchy["sub1/nx"];
        assert!(nx.real.is_none());
        assert!(!nx.subscribed);
        assert_children!([], nx.real_children);
        assert_children!(["sub1/nx/sub3"], nx.subscribed_children);

        let sub3 = &hierarchy["sub1/nx/sub3"];
        assert!(sub3.real.is_none());
        assert!(sub3.subscribed);
        assert_children!([], sub3.real_children);
        assert_children!([], sub3.subscribed_children);

        let bus1 = &hierarchy["bus1"];
        assert!(bus1.real.is_none());
        assert!(bus1.subscribed);
        assert_children!([], bus1.real_children);
        assert_children!(["bus1/bus2"], bus1.subscribed_children);
    }

    #[test]
    fn create_failure_cases() {
        let mut fixture = TestFixture::new();

        assert_matches!(
            Err(Error::MailboxExists),
            fixture.account.create(CreateRequest {
                name: "Archive".to_owned(),
                special_use: vec![],
            })
        );
        assert_matches!(
            Err(Error::BadOperationOnInbox),
            fixture.account.create(CreateRequest {
                name: "INBOX/Foo".to_owned(),
                special_use: vec![],
            })
        );
        assert_matches!(
            Err(Error::UnsafeName),
            fixture.account.create(CreateRequest {
                name: "../Foo".to_owned(),
                special_use: vec![],
            })
        );
        assert_matches!(
            Err(Error::UnsafeName),
            fixture.account.create(CreateRequest {
                name: "".to_owned(),
                special_use: vec![],
            })
        );
        assert_matches!(
            Err(Error::UnsupportedSpecialUse),
            fixture.account.create(CreateRequest {
                name: "Foo".to_owned(),
                special_use: vec!["\\Stuff".to_owned()],
            })
        );
        assert_matches!(
            Err(Error::UnsupportedSpecialUse),
            fixture.account.create(CreateRequest {
                name: "Foo".to_owned(),
                special_use: vec!["\\Sent".to_owned(), "\\Junk".to_owned()],
            })
        );
    }

    #[test]
    fn test_delete() {
        let mut fixture = TestFixture::new();
        fixture.create("foo/bar");

        fixture.account.delete("foo").unwrap();
        assert_eq!(
            "'foo' [\\Noselect] []\n\
             'foo/bar' [] []\n",
            list_formatted(
                &mut fixture.account,
                ListRequest {
                    patterns: vec!["f*".to_owned()],
                    ..ListRequest::default()
                }
            )
        );

        assert_matches!(
            Err(Error::MailboxHasInferiors),
            fixture.account.delete("foo")
        );

        fixture.account.delete("foo/bar").unwrap();
        assert_eq!(
            "'foo' [\\Noselect] []\n",
            list_formatted(
                &mut fixture.account,
                ListRequest {
                    patterns: vec!["f*".to_owned()],
                    ..ListRequest::default()
                }
            )
        );

        fixture.account.delete("foo").unwrap();
        assert_eq!(
            "",
            list_formatted(
                &mut fixture.account,
                ListRequest {
                    patterns: vec!["f*".to_owned()],
                    ..ListRequest::default()
                }
            )
        );

        assert_matches!(
            Err(Error::BadOperationOnInbox),
            fixture.account.delete("INBOX")
        );

        assert_matches!(Err(Error::NxMailbox), fixture.account.delete("foo"));
        assert_matches!(
            Err(Error::NxMailbox),
            fixture.account.delete("../foo")
        );
        assert_matches!(Err(Error::NxMailbox), fixture.account.delete(""));
    }

    // TODO This test depends on appending messages, which is not yet
    // implemented.
    // #[test]
    // fn test_rename() {
    //     let mut fixture = TestFixture::new();

    //     fixture
    //         .account
    //         .rename(RenameRequest {
    //             existing_name: "Archive".to_owned(),
    //             new_name: "Stuff/2020".to_owned(),
    //         })
    //         .unwrap();

    //     assert_eq!(
    //         "'Stuff' [] []\n\
    //          'Stuff/2020' [\\Archive] []\n",
    //         list_formatted(
    //             &mut fixture.account,
    //             ListRequest {
    //                 patterns: vec!["Stuff*".to_owned()],
    //                 return_special_use: true,
    //                 ..ListRequest::default()
    //             }
    //         )
    //     );

    //     fixture
    //         .account
    //         .mailbox("INBOX", false)
    //         .unwrap()
    //         .append(
    //             FixedOffset::zero().timestamp0(),
    //             vec![],
    //             &b"this is a test message"[..],
    //         )
    //         .unwrap();
    //     fixture
    //         .account
    //         .rename(RenameRequest {
    //             existing_name: "INBOX".to_owned(),
    //             new_name: "INBOX Special Case".to_owned(),
    //         })
    //         .unwrap();

    //     assert_eq!(
    //         "'INBOX' [\\Noinferiors] []\n\
    //          'INBOX Special Case' [] []\n",
    //         list_formatted(
    //             &mut fixture.account,
    //             ListRequest {
    //                 patterns: vec!["IN*".to_owned()],
    //                 ..ListRequest::default()
    //             }
    //         )
    //     );

    //     {
    //         let (_, select) = fixture
    //             .account
    //             .mailbox("INBOX", true)
    //             .unwrap()
    //             .select()
    //             .unwrap();
    //         assert_eq!(0, select.exists);

    //         let (_, select) = fixture
    //             .account
    //             .mailbox("INBOX Special Case", true)
    //             .unwrap()
    //             .select()
    //             .unwrap();
    //         assert_eq!(1, select.exists);
    //     }

    //     assert_matches!(
    //         Err(Error::RenameToSelf),
    //         fixture.account.rename(RenameRequest {
    //             existing_name: "Sent".to_owned(),
    //             new_name: "Sent".to_owned(),
    //         })
    //     );
    //     assert_matches!(
    //         Err(Error::RenameIntoSelf),
    //         fixture.account.rename(RenameRequest {
    //             existing_name: "Sent".to_owned(),
    //             new_name: "Sent/Child".to_owned(),
    //         })
    //     );
    //     assert_matches!(
    //         Err(Error::BadOperationOnInbox),
    //         fixture.account.rename(RenameRequest {
    //             existing_name: "Sent".to_owned(),
    //             new_name: "INBOX/Sent".to_owned(),
    //         })
    //     );
    //     assert_matches!(
    //         Err(Error::MailboxExists),
    //         fixture.account.rename(RenameRequest {
    //             existing_name: "Sent".to_owned(),
    //             new_name: "Spam".to_owned(),
    //         })
    //     );
    //     assert_matches!(
    //         Err(Error::NxMailbox),
    //         fixture.account.rename(RenameRequest {
    //             existing_name: "Xyzzy".to_owned(),
    //             new_name: "Plugh".to_owned(),
    //         })
    //     );
    //     assert_matches!(
    //         Err(Error::NxMailbox),
    //         fixture.account.rename(RenameRequest {
    //             existing_name: "".to_owned(),
    //             new_name: "Plugh".to_owned(),
    //         })
    //     );
    //     assert_matches!(
    //         Err(Error::NxMailbox),
    //         fixture.account.rename(RenameRequest {
    //             existing_name: "/".to_owned(),
    //             new_name: "Plugh".to_owned(),
    //         })
    //     );
    //     assert_matches!(
    //         Err(Error::UnsafeName),
    //         fixture.account.rename(RenameRequest {
    //             existing_name: "../Foo".to_owned(),
    //             new_name: "Plugh".to_owned(),
    //         })
    //     );
    //     assert_matches!(
    //         Err(Error::UnsafeName),
    //         fixture.account.rename(RenameRequest {
    //             existing_name: "Sent".to_owned(),
    //             new_name: "../Plugh".to_owned(),
    //         })
    //     );
    //     assert_matches!(
    //         Err(Error::UnsafeName),
    //         fixture.account.rename(RenameRequest {
    //             existing_name: "Sent".to_owned(),
    //             new_name: "".to_owned(),
    //         })
    //     );
    // }
}
