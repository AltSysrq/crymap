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

use crate::support::safe_name::is_safe_name;
use crate::support::system_config::LmtpConfig;

#[derive(Debug, Clone)]
struct Recipient {
    normalised: String,
    smtp: String,
}

impl Recipient {
    pub fn normalise(config: &LmtpConfig, smtp: String) -> Option<Self> {
        let mut split = smtp.split('@');
        let (mut local, domain) =
            match (split.next(), split.next(), split.next()) {
                (Some(l), None, _) => (l.to_owned(), None),
                (Some(l), Some(d), None) => {
                    (l.to_owned(), Some(d.to_lowercase()))
                }
                _ => return None,
            };

        if !config.verbatim_user_names {
            local = local.to_lowercase();
            let mut has_plus = false;
            local.retain(|c| {
                has_plus |= '+' == c;
                !has_plus && c != '.'
            });
        }

        let normalised = match (config.keep_recipient_domain, domain) {
            (false, _) | (_, None) => local,
            (true, Some(domain)) => format!("{}@{}", local, domain),
        };

        if !is_safe_name(&normalised) {
            return None;
        }

        Some(Recipient { smtp, normalised })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn user_normalisation() {
        fn normalise(smtp: &str, keep_domain: bool, verbatim: bool) -> String {
            Recipient::normalise(
                &LmtpConfig {
                    keep_recipient_domain: keep_domain,
                    verbatim_user_names: verbatim,
                    ..LmtpConfig::default()
                },
                smtp.to_owned(),
            )
            .map(|r| r.normalised)
            .unwrap_or_else(|| "<None>".to_owned())
        }

        assert_eq!("foobar", normalise("foobar", false, false));
        assert_eq!("foobar", normalise("foobar", false, true));
        assert_eq!("foobar", normalise("foobar", true, false));
        assert_eq!("foobar", normalise("foobar", true, true));

        assert_eq!("foobar", normalise("Foo.Bar", false, false));
        assert_eq!("Foo.Bar", normalise("Foo.Bar", false, true));
        assert_eq!("foobar", normalise("Foo.Bar", true, false));
        assert_eq!("Foo.Bar", normalise("Foo.Bar", true, true));

        assert_eq!("foo", normalise("foo+bar", false, false));
        assert_eq!("foo+bar", normalise("foo+bar", false, true));
        assert_eq!("foo", normalise("foo+bar", true, false));
        assert_eq!("foo+bar", normalise("foo+bar", true, true));

        assert_eq!("foo", normalise("foo@bar.com", false, false));
        assert_eq!("foo", normalise("foo@bar.com", false, true));
        assert_eq!("foo@bar.com", normalise("foo@bar.com", true, false));
        assert_eq!("foo@bar.com", normalise("foo@bar.com", true, true));

        assert_eq!("foo", normalise("foo@BAR.COM", false, false));
        assert_eq!("foo", normalise("foo@BAR.COM", false, true));
        assert_eq!("foo@bar.com", normalise("foo@BAR.COM", true, false));
        assert_eq!("foo@bar.com", normalise("foo@BAR.COM", true, true));

        assert_eq!("föö", normalise("FÖ.Ö+bar@Baz.Com", false, false));
        assert_eq!("FÖ.Ö+bar", normalise("FÖ.Ö+bar@Baz.Com", false, true));
        assert_eq!("föö@baz.com", normalise("FÖ.Ö+bar@Baz.Com", true, false));
        assert_eq!(
            "FÖ.Ö+bar@baz.com",
            normalise("FÖ.Ö+bar@Baz.Com", true, true)
        );

        assert_eq!("<None>", normalise("foo@bar@baz", false, false));
        assert_eq!("<None>", normalise("foo/bar@baz.com", false, false));
        assert_eq!("<None>", normalise("@foo.com", false, false));
    }
}
