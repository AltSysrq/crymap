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

use std::borrow::Cow;
use std::cell::RefCell;
use std::rc::Rc;

use super::defs::*;
use crate::{
    account::{model::*, v2::SpooledMessageId},
    support::{dns, error::Error},
};

impl CommandProcessor {
    pub(super) async fn cmd_xcry_foreign_smtp_tls(
        &mut self,
        cmd: s::XCryForeignSmtpTlsCommand<'_>,
        sender: &mut SendResponse,
    ) -> CmdResult {
        match cmd {
            s::XCryForeignSmtpTlsCommand::List(()) => {
                let stati = account!(self)?
                    .fetch_all_foreign_smtp_tls_stati()
                    .map_err(map_error!(self))?;
                for status in stati {
                    send_response(
                        sender,
                        s::Response::XCryForeignSmtpTls(
                            s::XCryForeignSmtpTlsData {
                                domain: Cow::Owned(status.domain),
                                starttls: status.starttls,
                                valid_certificate: status.valid_certificate,
                                tls_version: status
                                    .tls_version
                                    .map(|t| Cow::Borrowed(t.human_readable())),
                            },
                        ),
                    )
                    .await;
                }

                success()
            },

            s::XCryForeignSmtpTlsCommand::InitTest(()) => {
                let stati = [
                    ForeignSmtpTlsStatus {
                        domain: "secure.example.com".to_owned(),
                        starttls: true,
                        valid_certificate: true,
                        tls_version: Some(TlsVersion::Tls13),
                    },
                    ForeignSmtpTlsStatus {
                        domain: "insecure.example.com".to_owned(),
                        starttls: false,
                        valid_certificate: false,
                        tls_version: None,
                    },
                ];
                for status in stati {
                    account!(self)?
                        .put_foreign_smtp_tls_status(&status)
                        .map_err(map_error!(self))?;
                }

                success()
            },

            s::XCryForeignSmtpTlsCommand::Delete(domains) => {
                for domain in domains {
                    let Ok(domain) = dns::Name::from_str_relaxed(&domain)
                    else {
                        continue;
                    };
                    account!(self)?
                        .delete_foreign_smtp_tls_status(&domain.to_ascii())
                        .map_err(map_error!(self))?;
                }

                success()
            },
        }
    }

    pub(super) async fn cmd_xcry_smtp_spool_execute(
        &mut self,
        id: Cow<'_, str>,
    ) -> CmdResult {
        let Ok(id) = id.parse::<SpooledMessageId>() else {
            return Err(s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::No,
                code: Some(s::RespTextCode::Nonexistent(())),
                quip: Some(Cow::Borrowed("Bad spool ID")),
            }));
        };

        if self.system_config.smtp.host_name.is_empty() {
            return Err(s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::No,
                code: Some(s::RespTextCode::Cannot(())),
                quip: Some(Cow::Borrowed("SMTP host name not configured")),
            }));
        }

        let dns_cache = Rc::new(RefCell::new(dns::Cache::default()));

        let Some(account) = self.account.take() else {
            return Err(s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::Bad,
                code: None,
                quip: Some(Cow::Borrowed("Not logged in")),
            }));
        };

        let account = Rc::new(RefCell::new(account));
        let result = crate::smtp::outbound::send_message(
            dns_cache,
            self.dns_resolver.clone(),
            Rc::clone(&account),
            id,
            self.system_config.smtp.host_name.clone(),
            self.system_config.smtp.verbose_outbound_tls,
            None,
        )
        .await;
        self.account = Some(
            Rc::into_inner(account)
                .expect("send_message retained a reference to Account")
                .into_inner(),
        );

        result.map_err(map_error! {
            self,
            NxMessage => (No, Some(s::RespTextCode::Nonexistent(()))),
        })?;
        success()
    }
}
