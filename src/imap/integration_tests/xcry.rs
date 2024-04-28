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

#[test]
fn foreign_smtp_tls() {
    let setup = set_up();
    let mut client = setup.connect("xcryfstl");
    quick_log_in(&mut client);

    ok_command!(client, c("XCRY SMTP-OUT FOREIGN-TLS INIT-TEST"));
    command!(mut responses = client, c("XCRY SMTP-OUT FOREIGN-TLS LIST"));
    assert_eq!(3, responses.len());
    assert_tagged_ok(responses.pop().unwrap());

    let mut stati = responses
        .into_iter()
        .map(|line| match line.response {
            s::Response::XCryForeignSmtpTls(data) => data,
            r => panic!("unexpected response: {r:?}"),
        })
        .collect::<Vec<_>>();
    stati.sort_by_key(|s| s.domain.clone());

    assert_eq!(
        vec![
            s::XCryForeignSmtpTlsData {
                domain: Cow::Borrowed("insecure.example.com"),
                starttls: false,
                valid_certificate: false,
                tls_version: None,
            },
            s::XCryForeignSmtpTlsData {
                domain: Cow::Borrowed("secure.example.com"),
                starttls: true,
                valid_certificate: true,
                tls_version: Some(Cow::Borrowed("TLS 1.3")),
            },
        ],
        stati,
    );

    ok_command!(
        client,
        c("XCRY SMTP-OUT FOREIGN-TLS DELETE INSECURE.EXAMPLE.COM")
    );

    command!(mut responses = client, c("XCRY SMTP-OUT FOREIGN-TLS LIST"));
    assert_eq!(2, responses.len());
    assert_tagged_ok(responses.pop().unwrap());
}

#[test]
fn spool_execute() {
    let setup = set_up();
    let mut client = setup.connect("xcryspex");
    quick_log_in(&mut client);

    // We don't have a way to actually verify that a real message would be
    // executed properly, so just ensure the command is understood and that we
    // get the message for a non-existent but valid ID.
    command!([response] = client, c("XCRY SMTP-OUT SPOOL EXECUTE 42"));
    assert_error_response(
        response,
        Some(s::RespTextCode::Nonexistent(())),
        Error::NxMessage,
    );

    // Executing the command finagles with the `account` field; ensure we're
    // still logged in properly.
    quick_select(&mut client, "INBOX");
}
