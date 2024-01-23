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
use crate::support::error::Error;

#[test]
fn capability_declared() {
    test_require_capability("xcrycapa", "XCRY");
}

#[test]
fn user_configuration() {
    // Need to use a unique root since we'll be changing the password
    let setup = set_up_new_root();
    let mut client = setup.connect("xcryucfg");
    quick_log_in(&mut client);

    command!(
        [response] = client,
        c("XCRY SET-USER-CONFIG INTERNAL-KEY-PATTERN \"../foo\"")
    );
    assert_error_response(
        response,
        Some(s::RespTextCode::Cannot(())),
        Error::UnsafeName,
    );

    command!(
        [response] = client,
        c("XCRY SET-USER-CONFIG EXTERNAL-KEY-PATTERN \"../foo\"")
    );
    assert_error_response(
        response,
        Some(s::RespTextCode::Cannot(())),
        Error::UnsafeName,
    );

    command!(
        [response] = client,
        c("XCRY SET-USER-CONFIG EXTERNAL-KEY-PATTERN \"foo%\"")
    );
    assert_error_response(
        response,
        Some(s::RespTextCode::Cannot(())),
        Error::UnsafeName,
    );

    command!(mut responses = client,
             c("XCRY SET-USER-CONFIG INTERNAL-KEY-PATTERN \"ikp%Y\" \
                EXTERNAL-KEY-PATTERN \"ekp%d\""));
    assert_tagged_ok(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::XCryBackupFile(..) in responses
    };

    command!(mut responses = client, c("XCRY GET-USER-CONFIG"));
    assert_tagged_ok(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::XCryUserConfig(ref cfg) in responses => {
            assert_eq!("ikp%Y", cfg.internal_key_pattern);
            assert_eq!("ekp%d", cfg.external_key_pattern);
            assert!(cfg.password_changed.is_none());
        }
    };

    command!(mut responses = client,
             c("XCRY SET-USER-CONFIG PASSWORD hunter3"));
    assert_tagged_ok(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::XCryBackupFile(..) in responses
    };

    let mut client = setup.connect("xcryucfg");
    ok_command!(client, c("LOGIN azure hunter3"));

    command!(mut responses = client, c("XCRY GET-USER-CONFIG"));
    assert_tagged_ok(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::XCryUserConfig(ref cfg) in responses => {
            assert_eq!("ikp%Y", cfg.internal_key_pattern);
            assert_eq!("ekp%d", cfg.external_key_pattern);
            assert!(cfg.password_changed.is_some());
        }
    };

    ok_command!(
        client,
        c("XCRY SET-USER-CONFIG SMTP-OUT-SAVE \"Sent\" \
           SMTP-OUT-SUCCESS-RECEIPTS \"Sent/Success\" \
           SMTP-OUT-FAILURE-RECEIPTS \"Sent/Failure\"")
    );

    command!(mut responses = client, c("XCRY GET-USER-CONFIG"));
    assert_tagged_ok(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::XCryUserConfig(ref cfg) in responses => {
            assert!(cfg.extended.contains(
                &s::XCry2UserConfigData::SmtpOutSave(
                    Some(Cow::Borrowed("Sent")))));
            assert!(cfg.extended.contains(
                &s::XCry2UserConfigData::SmtpOutSuccessReceipts(
                    Some(Cow::Borrowed("Sent/Success")))));
            assert!(cfg.extended.contains(
                &s::XCry2UserConfigData::SmtpOutFailureReceipts(
                    Some(Cow::Borrowed("Sent/Failure")))));
        }
    };

    ok_command!(
        client,
        c("XCRY SET-USER-CONFIG SMTP-OUT-SAVE NIL \
           SMTP-OUT-SUCCESS-RECEIPTS NIL \
           SMTP-OUT-FAILURE-RECEIPTS NIL")
    );

    command!(mut responses = client, c("XCRY GET-USER-CONFIG"));
    assert_tagged_ok(responses.pop().unwrap());
    has_untagged_response_matching! {
        s::Response::XCryUserConfig(ref cfg) in responses => {
            assert!(cfg.extended.contains(
                &s::XCry2UserConfigData::SmtpOutSave(None)));
            assert!(cfg.extended.contains(
                &s::XCry2UserConfigData::SmtpOutSuccessReceipts(None)));
            assert!(cfg.extended.contains(
                &s::XCry2UserConfigData::SmtpOutFailureReceipts(None)));
        }
    };
}
