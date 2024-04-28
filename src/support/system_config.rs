//-
// Copyright (c) 2020, 2022, 2024, Jason Lingle
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

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Deserialize;

/// The system-wide configuration for Crymap.
///
/// This is stored in a file named `crymap.toml` under the Crymap system root,
/// which is typically `/usr/local/etc/crymap` or `/etc/crymap`.
#[derive(Clone, Debug, Deserialize, Default)]
pub struct SystemConfig {
    /// Options relating to operational security of Crymap.
    #[serde(default)]
    pub security: SecurityConfig,

    /// Configuration for TLS.
    pub tls: TlsConfig,

    /// Extra values to report in the ID command.
    /// The main useful value here is `support-url`.
    #[serde(default)]
    pub identification: BTreeMap<String, String>,

    /// Configuration for the SMTP/LMTP servers.
    ///
    /// For LMTP, the defaults are reasonable for most installations. SMTP
    /// requires manual configuration of the SMTP domains.
    ///
    /// This field can be named `lmtp` for backwards-compatibility with Crymap
    /// 1.0.
    #[serde(default, alias = "lmtp")]
    pub smtp: SmtpConfig,

    /// Configuration for server diagnostics.
    #[serde(default)]
    pub diagnostic: DiagnosticConfig,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct SecurityConfig {
    /// If true, chroot into the system data directory before communicating
    /// with the client.
    ///
    /// If enabled and Crymap is started as root, it will load the
    /// configuration and TLS keys, then immediately chroot into the system
    /// data directory before doing any communication with the client.
    ///
    /// This option must be disabled if the user directories are symlinks to
    /// other locations, as is typical with a "UNIX-style" setup.
    ///
    /// In conjunction with `system_user`, this supports "black box" style
    /// setups where all the user directories are in one place and under the
    /// same UNIX user, as it allows Crymap to be isolated from the rest of the
    /// file system while still being able to load its shared libraries and
    /// keys.
    #[serde(default)]
    pub chroot_system: bool,
    /// If non-empty, set the process UID to this value after initialisation
    /// but before doing any communication with the client. The name must refer
    /// to a non-root user.
    ///
    /// This should be set for "black box" style setups where mail users are
    /// not mapped to UNIX users, but Crymap must be started as root for some
    /// other reason (such as for `chroot_system`).
    ///
    /// When used in conjunction with `chroot_system`, the UID change is done
    /// after the chroot operation.
    ///
    /// If this is not set, and Crymap is run as root, it will continue running
    /// as root until a successful login, at which point it will drop its
    /// privileges to those of the user that owns the user directory. If it is
    /// still running as root at that point, it will refuse further operation.
    #[serde(default)]
    pub system_user: String,
}

// The Default implementation of TlsConfig is not useful in the real world, but
// is helpful for tests.
#[derive(Clone, Debug, Deserialize, Default)]
pub struct TlsConfig {
    /// The path to the TLS private key, which must be in PEM format.
    pub private_key: PathBuf,
    /// The path to the TLS certificate chain, which must be in PEM format.
    pub certificate_chain: PathBuf,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct SmtpConfig {
    /// The host name to report as.
    ///
    /// If unset, the system host name is used.
    ///
    /// This MUST be configured explicitly for SMTP submission since it must be
    /// a resolvable, fully-qualified host for that case.
    pub host_name: String,

    /// If true, the domain part of destination email addresses is kept.
    ///
    /// When false, `user@foo.com` and `user@bar.com` are both delivered to a
    /// user named `user`. When true, they are delivered to separate users
    /// called `user@foo.com` and `user@bar.com`, respectively.
    pub keep_recipient_domain: bool,

    /// If true, no modification of the user name is performed. This puts the
    /// burden of user resolution and normalisation on the SMTP gateway.
    ///
    /// By default, all periods are removed, everything after and including a
    /// `+` is deleted, and the user name is converted to Unicode lower case.
    ///
    /// When false, `foo.bar`, `FooBar`, and `foobar+anything` all resolve to
    /// the user `foobar`. When true, all are distinct users.
    ///
    /// When `keep_recipient_domain` is true, this option does not interact
    /// with the domain part of the email, which is always converted to
    /// Punycode, lower-cased, and retains its periods.
    pub verbatim_user_names: bool,

    /// The domains governed by this server.
    ///
    /// Each entry describes a single domain. Domains may be named either in
    /// Unicode or in Punycode; the two configuration styles are equivalent.
    ///
    /// Inbound SMTP will reject mail addressed to any domain not in this
    /// table, regardless of the configuration of `keep_recipient_domain`. This
    /// is necessary to prevent the server appearing as an open relay.
    ///
    /// Outbound SMTP will reject mail sent from any domain not in this table.
    /// If the matching domain specifies DKIM private keys, they will be used
    /// to sign outgoing mail.
    ///
    /// The LMTP server does not use this configuration. If
    /// `keep_recipient_domain` is false, LMTP will accept mail for any domain.
    /// It is up to the upstream SMTP server to perform filtering.
    pub domains: BTreeMap<DomainName, SmtpDomain>,

    /// Whether inbound SMTP will reject messages that have a hard failure.
    ///
    /// Inbound SMTP always evaluates SPF, DKIM, and DMARC and attaches their
    /// results to the message. If this is true, and the DMARC configuration
    /// indicates that hard failures should be rejected, inbound SMTP will fail
    /// the mail transaction of hard failures. Otherwise, hard failures are
    /// delivered normally.
    pub reject_dmarc_failures: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct SmtpDomain {
    /// DKIM keys to use to sign outgoing mail for this domain.
    ///
    /// The key of this map is the selector. The value is one of the following:
    /// - The string "rsa:" followed by the RSA private key in DER format,
    ///   encoded in base64.
    /// - The string "ed25519:" followed by the ED25519 private key in raw
    ///   format, encoded in base64.
    pub dkim: BTreeMap<String, DkimKey>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct DiagnosticConfig {
    /// On startup, redirect standard error to this file.
    ///
    /// This is applied before any part of the security configuration is
    /// applied and before any communication with the remote host.
    ///
    /// This is useful if `inetd` (or equivalent) or your MTA runs Crymap such
    /// that standard error goes to a less useful place, such as to the remote
    /// host. If anything actually ends up in this file, it represents a bug in
    /// Crymap, as actual errors should go through the logging system.
    pub stderr: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DomainName(pub hickory_resolver::Name);

impl<'de> serde::Deserialize<'de> for DomainName {
    fn deserialize<D: serde::Deserializer<'de>>(
        de: D,
    ) -> Result<Self, D::Error> {
        let s = <String as serde::Deserialize<'de>>::deserialize(de)?;
        hickory_resolver::Name::from_str_relaxed(&s)
            .map(|name| Self(name.to_lowercase()))
            .map_err(|_| {
                serde::de::Error::custom(format!("invalid domain: {s}"))
            })
    }
}

#[derive(Debug, Clone)]
pub struct DkimKey(pub openssl::pkey::PKey<openssl::pkey::Private>);

impl<'de> serde::Deserialize<'de> for DkimKey {
    fn deserialize<D: serde::Deserializer<'de>>(
        de: D,
    ) -> Result<Self, D::Error> {
        let s = <String as serde::Deserialize<'de>>::deserialize(de)?;
        let Some((kind, data)) = s.split_once(':') else {
            return Err(serde::de::Error::custom("missing ':' in DKIM key"));
        };

        let Ok(data) = base64::decode(data.as_bytes()) else {
            return Err(serde::de::Error::custom("bad base64 in DKIM key"));
        };

        let inner = match kind {
            "rsa" => {
                let rsa_key =
                    match openssl::rsa::Rsa::private_key_from_der(&data) {
                        Ok(k) => k,
                        Err(e) => {
                            return Err(serde::de::Error::custom(format!(
                                "invalid DER-format RSA private key: {e}",
                            )));
                        },
                    };

                match openssl::pkey::PKey::from_rsa(rsa_key) {
                    Ok(k) => k,
                    Err(e) => {
                        return Err(serde::de::Error::custom(format!(
                            "unexpected error converting DKIM key: {e}",
                        )));
                    },
                }
            },

            "ed25519" => {
                match openssl::pkey::PKey::private_key_from_raw_bytes(
                    &data,
                    openssl::pkey::Id::ED25519,
                ) {
                    Ok(k) => k,
                    Err(e) => {
                        return Err(serde::de::Error::custom(format!(
                            "invalid raw ED25519 private key: {e}",
                        )));
                    },
                }
            },

            _ => {
                return Err(serde::de::Error::custom(format!(
                    "unknown DKIM key type: '{kind}'",
                )))
            },
        };

        Ok(Self(inner))
    }
}
