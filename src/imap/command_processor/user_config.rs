//-
// Copyright (c) 2020, 2024, Jason Lingle
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
use crate::account::model::*;
use crate::support::error::Error;

impl CommandProcessor {
    pub(super) async fn cmd_xcry_get_user_config(
        &mut self,
        sender: &mut SendResponse,
    ) -> CmdResult {
        let user_config =
            account!(self)?.load_config().map_err(map_error!(self))?;

        send_response(
            sender,
            s::Response::XCryUserConfig(s::XCryUserConfigData {
                capabilities: vec![
                    Cow::Borrowed("INTERNAL-KEY-PATTERN"),
                    Cow::Borrowed("EXTERNAL-KEY-PATTERN"),
                    Cow::Borrowed("PASSWORD"),
                    Cow::Borrowed("SMTP-OUT"),
                ],
                internal_key_pattern: Cow::Owned(
                    user_config.key_store.internal_key_pattern,
                ),
                external_key_pattern: Cow::Owned(
                    user_config.key_store.external_key_pattern,
                ),
                password_changed: user_config.master_key.last_changed,
                extended: vec![
                    s::XCry2UserConfigData::SmtpOutSave(
                        user_config.smtp_out.save.clone().map(Cow::Owned),
                    ),
                    s::XCry2UserConfigData::SmtpOutSuccessReceipts(
                        user_config
                            .smtp_out
                            .success_receipts
                            .clone()
                            .map(Cow::Owned),
                    ),
                    s::XCry2UserConfigData::SmtpOutFailureReceipts(
                        user_config
                            .smtp_out
                            .failure_receipts
                            .clone()
                            .map(Cow::Owned),
                    ),
                ],
            }),
        )
        .await;
        success()
    }

    pub(super) async fn cmd_xcry_set_user_config(
        &mut self,
        configs: Vec<s::XCryUserConfigOption<'_>>,
        sender: &mut SendResponse,
    ) -> CmdResult {
        let mut request = SetUserConfigRequest::default();
        for config in configs {
            match config {
                s::XCryUserConfigOption::InternalKeyPattern(ikp) => {
                    request.internal_key_pattern = Some(ikp.into_owned());
                },
                s::XCryUserConfigOption::ExternalKeyPattern(ekp) => {
                    request.external_key_pattern = Some(ekp.into_owned());
                },
                s::XCryUserConfigOption::Password(pw) => {
                    request.password = Some(pw.into_owned());
                },
                s::XCryUserConfigOption::SmtpOutSave(s) => {
                    request.smtp_out_save = Some(s.map(Cow::into_owned));
                },
                s::XCryUserConfigOption::SmtpOutSuccessReceipts(s) => {
                    request.smtp_out_success_receipts =
                        Some(s.map(Cow::into_owned));
                },
                s::XCryUserConfigOption::SmtpOutFailureReceipts(s) => {
                    request.smtp_out_failure_receipts =
                        Some(s.map(Cow::into_owned));
                },
            }
        }

        let backup_file =
            account!(self)?.update_config(request).map_err(map_error! {
                self,
                UnsafeName => (No, Some(s::RespTextCode::Cannot(()))),
            })?;

        send_response(
            sender,
            s::Response::XCryBackupFile(Cow::Owned(backup_file)),
        )
        .await;
        success()
    }
}
