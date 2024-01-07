//-
// Copyright (c) 2020, 2023, 2024, Jason Lingle
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

//! Common utilities for processing local deliveries.

use std::borrow::Cow;
use std::io;
use std::path::Path;

use log::error;

use super::super::codes::*;
use super::bridge::SmtpResponse;
use crate::{
    account::v2::DeliveryAccount,
    support::{
        append_limit::APPEND_SIZE_LIMIT,
        buffer::BufferReader,
        log_prefix::LogPrefix,
        safe_name::is_safe_name,
        system_config::{SmtpConfig, SystemConfig},
        unix_privileges,
    },
};

#[derive(Debug, Clone)]
pub struct Recipient {
    pub normalised: String,
    pub smtp: String,
}

impl Recipient {
    pub fn normalise(config: &SmtpConfig, smtp: String) -> Option<Self> {
        let mut split = smtp.split('@');
        let (mut local, domain) =
            match (split.next(), split.next(), split.next()) {
                (Some(l), None, _) => (l.to_owned(), None),
                (Some(l), Some(d), None) => {
                    (l.to_owned(), Some(d.to_lowercase()))
                },
                _ => return None,
            };

        // TODO Ensure domain is Punycode

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

    /// Normalise `smtp` to a recipient according to `config`, and validate
    /// that it appears to be a user inside `users_dir`.
    ///
    /// On failure, returns the appropriate SMTP response.
    pub fn normalise_and_validate(
        config: &SmtpConfig,
        users_dir: &Path,
        smtp: &str,
    ) -> Result<Self, SmtpResponse<'static>> {
        let recipient =
            Self::normalise(config, smtp.to_owned()).ok_or_else(|| {
                SmtpResponse(
                    pc::ActionNotTakenPermanent,
                    Some((cc::PermFail, sc::BadDestinationMailboxAddress)),
                    // The "no such user - " prefix has significance with some
                    // agents according to RFC 5321
                    Cow::Owned(format!(
                        "no such user - {smtp} (disallowed name)"
                    )),
                )
            })?;

        if !users_dir.join(&recipient.normalised).is_dir() {
            return Err(SmtpResponse(
                pc::ActionNotTakenPermanent,
                Some((cc::PermFail, sc::BadDestinationMailboxAddress)),
                Cow::Owned(format!("no such user - {smtp}")),
            ));
        }

        Ok(recipient)
    }
}

/// Delivers a message to a local recipient.
pub fn deliver_local(
    log_prefix: &LogPrefix,
    system_config: &SystemConfig,
    users_dir: &Path,
    recipient: &Recipient,
    data_buffer: &mut BufferReader,
    message_prefix: &str,
) -> Result<(), SmtpResponse<'static>> {
    struct RestoreUidGid;
    impl Drop for RestoreUidGid {
        fn drop(&mut self) {
            let _ = nix::unistd::seteuid(nix::unistd::getuid());
            let _ = nix::unistd::setegid(nix::unistd::getgid());
        }
    }

    if data_buffer.len() > APPEND_SIZE_LIMIT as u64 {
        return Err(SmtpResponse(
            pc::ExceededStorageAllocation,
            Some((cc::PermFail, sc::MessageLengthExceedsLimit)),
            Cow::Owned(format!(
                "Maximum message size is {} bytes",
                APPEND_SIZE_LIMIT,
            )),
        ));
    }

    let mut user_dir = users_dir.join(&recipient.normalised);
    let _restore_uid_gid = RestoreUidGid;
    unix_privileges::assume_user_privileges(
        &log_prefix.to_string(),
        system_config.security.chroot_system,
        &mut user_dir,
        true,
    )
    .map_err(|_| {
        SmtpResponse(
            pc::ActionNotTakenTemporary,
            Some((
                cc::TempFail,
                if user_dir.is_dir() {
                    sc::SystemIncorrectlyConfigured
                } else {
                    sc::OtherMailboxStatus
                },
            )),
            Cow::Borrowed("Problem with mailbox permissions"),
        )
    })?;

    let sub_log_prefix = log_prefix.deep_clone();
    sub_log_prefix.set_user(recipient.normalised.clone());

    data_buffer
        .rewind()
        .map_err(crate::support::error::Error::Io)
        .and_then(|_| DeliveryAccount::new(sub_log_prefix, user_dir))
        .and_then(|mut account| {
            account.deliver(
                "INBOX",
                &[],
                io::Read::chain(message_prefix.as_bytes(), data_buffer),
            )
        })
        .map_err(|e| {
            // NB In the one LMTP test that (normally) gets to this path, it's
            // because the user was deliberately deleted.
            error!(
                "{} Unexpected error delivering to {}: {}",
                log_prefix, recipient.normalised, e
            );
            SmtpResponse(
                pc::ActionNotTakenTemporary,
                Some((cc::TempFail, sc::OtherMailboxStatus)),
                Cow::Borrowed("Unexpected problem delivering mail"),
            )
        })?;

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn user_normalisation() {
        fn normalise(smtp: &str, keep_domain: bool, verbatim: bool) -> String {
            Recipient::normalise(
                &SmtpConfig {
                    keep_recipient_domain: keep_domain,
                    verbatim_user_names: verbatim,
                    ..SmtpConfig::default()
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
