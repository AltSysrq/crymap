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
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;

use log::{info, warn};

use super::defs::*;
use crate::account::account::{account_config_file, Account};
use crate::crypt::master_key::MasterKey;
use crate::support::{
    safe_name::is_safe_name, unix_privileges, user_config::UserConfig,
};

impl CommandProcessor {
    /// Called when a line initiating an `AUTHENTICATE` is received.
    ///
    /// If this returns `Some`, that response is sent to the client and the
    /// server returns to the normal command loop. If it returns `None`, the
    /// sever will send a continuation line to the client and the next line is
    /// fed to `authenticate_finish`.
    ///
    /// Note that we currently only support `AUTHENTICATE` flows that take at
    /// most one input from the client and no server challenge.
    pub(crate) fn authenticate_start<'a>(
        &mut self,
        cmd: &'a s::AuthenticateCommandStart<'a>,
    ) -> Option<s::ResponseLine<'a>> {
        if "plain".eq_ignore_ascii_case(&cmd.auth_type) {
            cmd.initial_response.as_ref().map(|ir| {
                self.authenticate_finish(cmd.to_owned(), ir.as_bytes())
            })
        } else {
            Some(s::ResponseLine {
                tag: Some(Cow::Borrowed(&cmd.tag)),
                response: s::Response::Cond(s::CondResponse {
                    cond: s::RespCondType::Bad,
                    code: Some(s::RespTextCode::Cannot(())),
                    quip: Some(Cow::Borrowed("Unsupported AUTHENTICATE type")),
                }),
            })
        }
    }

    pub(crate) fn authenticate_finish<'a>(
        &mut self,
        cmd: s::AuthenticateCommandStart<'a>,
        data: &[u8],
    ) -> s::ResponseLine<'a> {
        if b"*" == data {
            return s::ResponseLine {
                tag: Some(cmd.tag),
                response: s::Response::Cond(s::CondResponse {
                    cond: s::RespCondType::Bad,
                    code: None,
                    quip: Some(Cow::Borrowed("AUTHENTICATE aborted")),
                }),
            };
        }

        let string = match base64::decode(data)
            .ok()
            .and_then(|decoded| String::from_utf8(decoded).ok())
        {
            Some(s) => s,
            None => {
                return s::ResponseLine {
                    tag: Some(cmd.tag),
                    response: s::Response::Cond(s::CondResponse {
                        cond: s::RespCondType::Bad,
                        code: Some(s::RespTextCode::Parse(())),
                        quip: Some(Cow::Borrowed("Bad base64 or UTF-8")),
                    }),
                }
            }
        };

        // All we currently support is RFC 2595 PLAIN
        // Format is <authorise-id>NUL<authenticate-id<NUL>password
        // <authorise-id> is optional if it is the same as <authenticate-id>.
        let mut parts = string.split('\x00');
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(authorise), Some(authenticate), Some(password), None) => {
                if !authorise.is_empty() && authorise != authenticate {
                    return s::ResponseLine {
                        tag: Some(cmd.tag),
                        response: s::Response::Cond(s::CondResponse {
                            cond: s::RespCondType::No,
                            code: Some(s::RespTextCode::Cannot(())),
                            quip: Some(Cow::Borrowed(
                                "AUTHENTICATE PLAIN with different \
                                 authorising and authenticating users \
                                 is not supported",
                            )),
                        }),
                    };
                }

                let r = self.cmd_log_in(s::LogInCommand {
                    userid: Cow::Borrowed(authenticate),
                    password: Cow::Borrowed(password),
                });
                let r = match r {
                    Ok(r) => r,
                    Err(r) => r,
                };

                s::ResponseLine {
                    tag: Some(cmd.tag),
                    response: r,
                }
            }
            _ => s::ResponseLine {
                tag: Some(cmd.tag),
                response: s::Response::Cond(s::CondResponse {
                    cond: s::RespCondType::Bad,
                    code: Some(s::RespTextCode::Parse(())),
                    quip: Some(Cow::Borrowed(
                        "Malformed AUTHENTICATE PLAIN string",
                    )),
                }),
            },
        }
    }

    pub(crate) fn cmd_log_in(&mut self, cmd: s::LogInCommand<'_>) -> CmdResult {
        if self.account.is_some() {
            return Err(s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::Bad,
                code: Some(s::RespTextCode::ClientBug(())),
                quip: Some(Cow::Borrowed("Already logged in")),
            }));
        }

        if !is_safe_name(&cmd.userid) {
            return Err(s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::No,
                code: Some(s::RespTextCode::AuthenticationFailed(())),
                quip: Some(Cow::Borrowed("Illegal user id")),
            }));
        }

        let mut user_dir = self.data_root.join(&*cmd.userid);
        let user_data_file = account_config_file(&user_dir);
        let (user_config, master_key) = fs::File::open(&user_data_file)
            .ok()
            .and_then(|f| {
                let mut buf = Vec::<u8>::new();
                f.take(65536).read_to_end(&mut buf).ok()?;
                toml::from_slice::<UserConfig>(&buf).ok()
            })
            .and_then(|config| {
                let master_key = MasterKey::from_config(
                    &config.master_key,
                    cmd.password.as_bytes(),
                )?;
                Some((config, master_key))
            })
            .ok_or_else(|| {
                // Only log a warning if a password was actually provided.
                // Login attempts with now password aren't generally
                // remarkable, but importantly, they can occur if the user
                // accidentally inputs their password in the username field.
                // For the same reason, we're silent if the userid and password
                // are equal.
                if !cmd.password.is_empty() && cmd.password != cmd.userid {
                    warn!(
                        "{} Rejected login for user '{}'",
                        self.log_prefix, cmd.userid
                    );
                }

                s::Response::Cond(s::CondResponse {
                    cond: s::RespCondType::No,
                    code: Some(s::RespTextCode::AuthenticationFailed(())),
                    quip: Some(Cow::Borrowed("Bad user id or password")),
                })
            })?;

        // Login successful (at least barring further operational issues)

        self.log_prefix.push_str(":~");
        self.log_prefix.push_str(&cmd.userid);
        info!("{} Login successful", self.log_prefix);

        self.drop_privileges(&mut user_dir)?;

        let account = Account::new(
            self.log_prefix.clone(),
            user_dir,
            Some(Arc::new(master_key)),
        );
        account
            .init(&user_config.key_store)
            .map_err(map_error!(self))?;

        self.account = Some(account);
        Ok(s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Ok,
            code: Some(s::RespTextCode::Capability(
                super::commands::capability_data(),
            )),
            quip: Some(Cow::Borrowed("User login successful")),
        }))
    }

    fn drop_privileges(&mut self, user_dir: &mut PathBuf) -> PartialResult<()> {
        if unix_privileges::drop_privileges(
            &self.log_prefix,
            self.system_config.security.chroot_system,
            user_dir,
        ) {
            Ok(())
        } else {
            auth_misconfiguration()
        }
    }
}

fn auth_misconfiguration() -> PartialResult<()> {
    Err(s::Response::Cond(s::CondResponse {
        cond: s::RespCondType::Bye,
        code: Some(s::RespTextCode::ContactAdmin(())),
        quip: Some(Cow::Borrowed(
            "Fatal internal error or misconfiguration; refer to \
             server logs for details.",
        )),
    }))
}
