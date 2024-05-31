//-
// Copyright (c) 2024, Jason Lingle
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

//! The "public suffix list".
//!
//! The data here is derived from the list Mozilla maintains:
//! https://github.com/publicsuffix/list
//!
//! The PSL data is compiled into the application. This means it is harder to
//! update, but DMARC is a relatively low-stakes context, so this is acceptable
//! in exchange for simpler operation and administration (as opposed to a
//! dynamically updating list).
//!
//! ## Data format
//!
//! The file format is text to be git-friendly. The start of the file may have
//! lines beginning with `#`, which are skipped.
//!
//! The file is essentially a tree walking down the ASCII domain labels from
//! right to left. Each line can be one of the following:
//!
//! - Blank. No more records for this branch of the tree.
//! - A single token, a leaf node.
//! - A triplet, separated by spaces:
//!   - The label for this level.
//!   - Flags: '.' = domains one level below this branch are organisational
//!     domains. Leaf nodes below this branch are treated as '.' branches with
//!     zero length. '*' = domains two levels below this branch are
//!     organisational domains. Leaf nodes below this branch are exceptions,
//!     and are themselves organisational domains.
//!   - Length. A base-10 integer. If the current label does not match the
//!     branch's label, skip this many bytes.
//!
//! ## Other notes
//!
//! This implementation is geared to DMARC, where we just need to sensibly
//! strip away subdomains to find an authority. We don't handle the case of an
//! input which *is* itself a public suffix. For example, `hokkaido.jp` is
//! considered strictly a suffix, but it will be identified as the authority of
//! `foo.hokkaido.jp` due to the `*.jp` rule.

use crate::support::dns;

#[cfg(any(test, feature = "dev-tools"))]
mod compile {
    use super::*;

    struct Node {
        label: String,
        kind: NodeKind,
        children: Vec<Node>,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum NodeKind {
        Branch,
        OrgParent,
        OrgGrandparent,
    }

    pub(super) fn compile(psl: &str) -> String {
        let tree = build_tree(psl);
        let mut data = String::new();
        for node in tree {
            to_text(&mut data, &node);
        }
        data
    }

    fn build_tree(psl: &str) -> Vec<Node> {
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum LineKind {
            Normal,
            Wildcard,
            Exception,
        }

        let mut nodes = Vec::<Node>::new();

        for line in psl.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("//") {
                continue;
            }

            let (unicode_name, line_kind) = if line.starts_with('!') {
                (&line[1..], LineKind::Exception)
            } else if line.starts_with("*.") {
                (&line[2..], LineKind::Wildcard)
            } else {
                (line, LineKind::Normal)
            };

            let domain = dns::Name::from_utf8(unicode_name)
                .unwrap()
                .to_ascii()
                .to_lowercase();
            let num_labels = domain.split('.').count();

            let mut search = &mut nodes;
            for (i, label) in domain.rsplit('.').enumerate() {
                let new_node_kind = if i + 1 < num_labels {
                    // The PSL input always gives us parents before their
                    // children, so we can just assume any node we create here
                    // is a non-org branch.
                    NodeKind::Branch
                } else {
                    match line_kind {
                        LineKind::Normal => NodeKind::OrgParent,
                        LineKind::Wildcard => NodeKind::OrgGrandparent,
                        LineKind::Exception => NodeKind::Branch,
                    }
                };

                let existing_ix =
                    match search.iter_mut().position(|n| n.label == label) {
                        Some(ix) => ix,
                        None => {
                            let ix = search.len();
                            search.push(Node {
                                label: label.to_owned(),
                                kind: new_node_kind,
                                children: Vec::new(),
                            });
                            ix
                        },
                    };

                search = &mut search[existing_ix].children;
            }
        }

        sort_nodes(&mut nodes);
        nodes
    }

    fn sort_nodes(nodes: &mut [Node]) {
        nodes.sort_unstable_by(|a, b| a.label.cmp(&b.label));
        for node in nodes {
            sort_nodes(&mut node.children);
        }
    }

    fn to_text(s: &mut String, node: &Node) {
        use std::fmt::Write as _;

        s.push_str(&node.label);
        if !node.children.is_empty() || NodeKind::OrgGrandparent == node.kind {
            let mut children = String::new();
            for child in &node.children {
                to_text(&mut children, child);
            }
            children.push('\n');

            s.push(' ');
            match node.kind {
                NodeKind::Branch => {},
                NodeKind::OrgParent => s.push('.'),
                NodeKind::OrgGrandparent => s.push('*'),
            }
            s.push(' ');

            let _ = write!(s, "{}\n", children.len());
            s.push_str(&children);
        } else {
            s.push('\n');
        }
    }
}

#[cfg(feature = "dev-tools")]
pub mod cli {
    use std::fs;
    use std::path::Path;

    use super::*;

    pub fn compile_psl(infile: &Path, outfile: &Path) {
        use chrono::prelude::*;

        let src_data = fs::read(infile).unwrap();
        let compiled = compile::compile(&String::from_utf8(src_data).unwrap());
        let compiled = format!(
            "\
# This is a compiled representation of the Mozilla Public Suffix
# List, which can be found here:
#   https://publicsuffix.org/list/public_suffix_list.dat
#
# This Data is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Compiled on {date}.
{compiled}",
            date = Utc::now(),
        );
        fs::write(outfile, compiled.as_bytes()).unwrap();
    }
}

static PSL_DATA: &str = include_str!("psl.txt");

/// Returns the "organisational domain" of `domain`, or a best guess if no data
/// is available.
pub fn organisational_domain(domain: &dns::Name) -> dns::Name {
    eval(PSL_DATA, domain)
}

fn eval(mut psl_data: &str, domain: &dns::Name) -> dns::Name {
    let domain_str = domain.to_ascii().to_lowercase();

    // We have a special case for this domain in the test build for the sake of
    // the live tests.
    #[cfg(test)]
    {
        if "smtpin.sptest.lin.gl" == domain_str {
            return domain.clone();
        }
    }

    let mut best_match = None::<dns::Name>;

    while psl_data.starts_with('#') {
        psl_data = psl_data.split_once('\n').unwrap().1;
    }

    let mut under_wildcard = false;
    for (i, label) in domain_str.rsplit('.').enumerate() {
        let found_match = loop {
            let Some((line, rest)) = psl_data.split_once('\n') else {
                break None;
            };
            psl_data = rest;

            if line.is_empty() {
                break None;
            }

            let (branch_label, info) =
                line.split_once(' ').unwrap_or((line, ""));

            if branch_label > label {
                break None;
            }

            if branch_label < label {
                if let Some((_, len_str)) = info.split_once(' ') {
                    let len = len_str.parse::<usize>().unwrap();
                    psl_data = &psl_data[len..];
                }
                continue;
            }

            // This line is a match.
            break Some(info);
        };

        // If we couldn't find a matching line, there's nothing left to search.
        let Some(info) = found_match else {
            break;
        };

        let match_labels = if info.starts_with('.') || info.is_empty() {
            if under_wildcard {
                Some(i + 1)
            } else {
                Some(i + 2)
            }
        } else if info.starts_with('*') {
            under_wildcard = true;
            Some(i + 3)
        } else {
            None
        };

        if let Some(match_labels) = match_labels {
            if match_labels <= usize::from(domain.num_labels()) {
                best_match = Some(domain.trim_to(match_labels));
            }
        }

        // If this node has no children, we're done.
        if info.is_empty() {
            break;
        }
    }

    best_match.unwrap_or_else(|| {
        domain.trim_to(2usize.min(usize::from(domain.num_labels())))
    })
}

#[cfg(test)]
mod test {
    use super::*;

    fn dn(s: &str) -> dns::Name {
        dns::Name::from_ascii(s).unwrap()
    }

    #[test]
    fn psl_examples() {
        let psl = compile::compile(
            "com\n\
             *.foo.com\n\
             *.jp\n\
             *.hokkaido.jp\n\
             *.tokyo.jp\n\
             !pref.hokkaido.jp\n\
             !metro.tokyo.jp\n",
        );
        println!("{}", psl);

        assert_eq!(dn("bar.com"), eval(&psl, &dn("bar.com")));
        assert_eq!(dn("bar.com"), eval(&psl, &dn("mail.bar.com")));
        assert_eq!(dn("foo.com"), eval(&psl, &dn("foo.com")));
        assert_eq!(dn("foo.com"), eval(&psl, &dn("bar.foo.com")));
        assert_eq!(
            dn("example.bar.foo.com"),
            eval(&psl, &dn("example.bar.foo.com")),
        );
        assert_eq!(
            dn("foo.bar.hokkaido.jp"),
            eval(&psl, &dn("foo.bar.hokkaido.jp")),
        );
        assert_eq!(
            dn("foo.bar.hokkaido.jp"),
            eval(&psl, &dn("mail.foo.bar.hokkaido.jp")),
        );
        assert_eq!(dn("pref.hokkaido.jp"), eval(&psl, &dn("pref.hokkaido.jp")));
        assert_eq!(
            dn("pref.hokkaido.jp"),
            eval(&psl, &dn("mail.pref.hokkaido.jp")),
        );

        assert_eq!(dn("foo.xyz"), eval(&psl, &dn("foo.xyz")));
        assert_eq!(dn("foo.xyz"), eval(&psl, &dn("mail.foo.xyz")));
        assert_eq!(dn("xyz"), eval(&psl, &dn("xyz")));
    }

    #[test]
    fn test_organisational_domain() {
        assert_eq!(dn("foo.com"), organisational_domain(&dn("foo.com")));
        assert_eq!(dn("foo.com"), organisational_domain(&dn("BAR.FOO.com")));
        assert_eq!(dn("foo.co.uk"), organisational_domain(&dn("foo.co.uk")));
        assert_eq!(
            dn("foo.co.uk"),
            organisational_domain(&dn("mail.foo.co.uk"))
        );
        assert_eq!(dn("z.zzz"), organisational_domain(&dn("z.z.zzz")));
        assert_eq!(
            dn("foo.kyoto.jp"),
            organisational_domain(&dn("mail.foo.kyoto.jp")),
        );
        assert_eq!(
            dn("foo.xii.jp"),
            organisational_domain(&dn("mail.foo.xii.jp")),
        );
        assert_eq!(
            dns::Name::from_utf8("foo.京都.jp").unwrap(),
            organisational_domain(
                &dns::Name::from_utf8("mail.foo.京都.jp").unwrap()
            ),
        );
    }
}
