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

use std::borrow::Cow;

use super::defs::*;
use crate::account::v2::{Account, LogInError};

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
    pub(crate) fn authenticate_start(
        &mut self,
        cmd: &s::AuthenticateCommandStart<'_>,
    ) -> Option<s::ResponseLine<'static>> {
        if "plain".eq_ignore_ascii_case(&cmd.auth_type) {
            cmd.initial_response.as_ref().map(|ir| {
                self.authenticate_finish(cmd.to_owned(), ir.as_bytes())
            })
        } else {
            Some(s::ResponseLine {
                tag: Some(Cow::Owned(cmd.tag.clone().into_owned())),
                response: s::Response::Cond(s::CondResponse {
                    cond: s::RespCondType::Bad,
                    code: Some(s::RespTextCode::Cannot(())),
                    quip: Some(Cow::Borrowed("Unsupported AUTHENTICATE type")),
                }),
            })
        }
    }

    pub(crate) fn authenticate_finish(
        &mut self,
        cmd: s::AuthenticateCommandStart<'_>,
        data: &[u8],
    ) -> s::ResponseLine<'static> {
        let tag = Cow::Owned(cmd.tag.into_owned());
        if b"*" == data {
            return s::ResponseLine {
                tag: Some(tag),
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
                    tag: Some(tag),
                    response: s::Response::Cond(s::CondResponse {
                        cond: s::RespCondType::Bad,
                        code: Some(s::RespTextCode::Parse(())),
                        quip: Some(Cow::Borrowed("Bad base64 or UTF-8")),
                    }),
                }
            },
        };

        // All we currently support is RFC 2595 PLAIN
        // Format is <authorise-id>NUL<authenticate-id<NUL>password
        // <authorise-id> is optional if it is the same as <authenticate-id>.
        let mut parts = string.split('\x00');
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(authorise), Some(authenticate), Some(password), None) => {
                if !authorise.is_empty() && authorise != authenticate {
                    return s::ResponseLine {
                        tag: Some(tag),
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
                    tag: Some(tag),
                    response: r,
                }
            },
            _ => s::ResponseLine {
                tag: Some(tag),
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

        match Account::log_in(
            self.log_prefix.clone(),
            &self.system_config,
            &self.data_root,
            &cmd.userid,
            &cmd.password,
        ) {
            Ok((account, _)) => {
                self.account = Some(account);
                Ok(s::Response::Cond(s::CondResponse {
                    cond: s::RespCondType::Ok,
                    code: Some(s::RespTextCode::Capability(
                        super::commands::capability_data(),
                    )),
                    quip: Some(Cow::Borrowed("User login successful")),
                }))
            },

            Err(LogInError::IllegalUserId) => {
                Err(s::Response::Cond(s::CondResponse {
                    cond: s::RespCondType::No,
                    code: Some(s::RespTextCode::AuthenticationFailed(())),
                    quip: Some(Cow::Borrowed("Illegal user id")),
                }))
            },

            Err(LogInError::InvalidCredentials) => {
                Err(s::Response::Cond(s::CondResponse {
                    cond: s::RespCondType::No,
                    code: Some(s::RespTextCode::AuthenticationFailed(())),
                    quip: Some(Cow::Borrowed("Bad user id or password")),
                }))
            },

            Err(e @ LogInError::ConfigError) => {
                Err(s::Response::Cond(s::CondResponse {
                    cond: s::RespCondType::Bye,
                    code: Some(s::RespTextCode::ContactAdmin(())),
                    quip: Some(Cow::Owned(e.to_string())),
                }))
            },

            Err(e @ LogInError::SetupError) => {
                Err(s::Response::Cond(s::CondResponse {
                    cond: s::RespCondType::No,
                    code: Some(s::RespTextCode::ContactAdmin(())),
                    quip: Some(Cow::Owned(e.to_string())),
                }))
            },
        }
    }
}
