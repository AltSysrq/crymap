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
use std::io::{self, BufRead, Write};
use std::net::{self, ToSocketAddrs};

use openssl::ssl::{HandshakeError, SslConnector, SslMethod, SslVerifyMode};
use thiserror::Error;

use super::main::*;
use crate::{
    imap::{client::Client, syntax as s},
    support::rcio::*,
};

type RemoteClient = Client<Box<dyn BufRead>, Box<dyn Write>>;

#[derive(Error, Debug)]
enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Ssl(#[from] openssl::error::ErrorStack),
    #[error(transparent)]
    Ssl2(#[from] openssl::ssl::Error),
    #[error(transparent)]
    Client(#[from] crate::imap::client::Error),
}

pub(super) fn main(cmd: RemoteSubcommand) {
    if let Err(e) = main_impl(cmd) {
        die!(EX_SOFTWARE, "Error: {}", e);
    }
}

fn main_impl(mut cmd: RemoteSubcommand) -> Result<(), Error> {
    let mut client = connect(cmd.common_options())?;

    match cmd {
        RemoteSubcommand::Test(_) => {
            println!("Server looks OK");
        },
        RemoteSubcommand::Chpw(_) => {
            change_password(&mut client)?;
        },
        RemoteSubcommand::Config(cmd) => {
            config(&mut client, cmd)?;
        },
        RemoteSubcommand::ForeignSmtpTls(ForeignSmtpTlsCommand::List(_)) => {
            list_foreign_smtp_tls(&mut client)?;
        },
        RemoteSubcommand::ForeignSmtpTls(ForeignSmtpTlsCommand::Delete(
            cmd,
        )) => {
            delete_foreign_smtp_tls(&mut client, cmd.domains)?;
        },
        RemoteSubcommand::RetryEmail(cmd) => {
            retry_email(&mut client, cmd.message_id)?;
        },
    }

    let mut buffer = Vec::new();
    let _ = client
        .command(s::Command::Simple(s::SimpleCommand::LogOut), &mut buffer);
    Ok(())
}

fn connect(options: RemoteCommonOptions) -> Result<RemoteClient, Error> {
    let user = match options.user {
        Some(user) => user,
        None => match nix::unistd::User::from_uid(nix::unistd::getuid()) {
            Ok(Some(u)) => u.name,
            Ok(None) => die!(EX_NOUSER, "No passwd entry for current user"),
            Err(e) => {
                die!(EX_OSFILE, "Failed to look up current UNIX user: {}", e)
            },
        },
    };

    let mut addresses =
        (&options.host as &str, options.port).to_socket_addrs()?;
    let address = addresses.next().ok_or_else(|| {
        Error::Io(io::Error::new(io::ErrorKind::Other, "Host not found"))
    })?;

    if options.trace {
        eprintln!("Opening connection to {}", address);
    }

    let tcp_stream = net::TcpStream::connect(address)?;

    if options.trace {
        eprintln!("Starting TLS handshake");
    }

    let mut connector = SslConnector::builder(SslMethod::tls())?;
    if options.allow_insecure_tls_connections {
        connector.set_verify(SslVerifyMode::NONE);
    }

    let ssl_stream = connector
        .build()
        .connect(&options.host, tcp_stream)
        .map_err(|e| match e {
            HandshakeError::SetupFailure(es) => Error::Ssl(es),
            HandshakeError::Failure(f) => Error::Ssl2(f.into_error()),
            HandshakeError::WouldBlock(_) => unreachable!(),
        })?;

    let write = RcIo::wrap(ssl_stream);
    let read = io::BufReader::new(write.clone());

    let mut client: RemoteClient = Client::new(
        Box::new(read),
        Box::new(write),
        if options.trace { Some("") } else { None },
    );

    if options.trace {
        eprintln!("Connection established; reading server greeting");
    }

    let mut buffer = Vec::new();
    let response = client.read_one_response(&mut buffer)?;
    die_if_not_success("Greeting", response);
    buffer.clear();

    check_capabilities(&mut client, &["AUTH=PLAIN"])?;

    client.write_raw(b"A1 AUTHENTICATE PLAIN\r\n")?;
    client.read_logical_line(&mut buffer)?;
    if !buffer.starts_with(b"+") {
        die!(
            EX_PROTOCOL,
            "Server refused AUTHENTICATE: {}",
            String::from_utf8_lossy(&buffer).trim()
        );
    }

    let password = match rpassword::prompt_password("Current password: ") {
        Ok(p) => p,
        Err(e) => die!(EX_NOINPUT, "Failed to read password: {}", e),
    };

    let mut auth_string =
        base64::encode(format!("{}\0{}\0{}", user, user, password));
    auth_string.push_str("\r\n");
    client.write_raw_censored(auth_string.as_bytes())?;

    let mut responses = client.read_responses_until_tagged(&mut buffer)?;
    die_if_not_success("AUTHENTICATE", responses.pop().unwrap());

    check_capabilities(&mut client, &["LITERAL+", "XCRY"])?;

    Ok(client)
}

fn check_capabilities(
    client: &mut RemoteClient,
    required: &[&str],
) -> Result<(), Error> {
    let mut buffer = Vec::new();
    let mut responses = client.command(
        s::Command::Simple(s::SimpleCommand::Capability),
        &mut buffer,
    )?;
    die_if_not_success("CAPABILITY", responses.pop().unwrap());

    for r in responses {
        let r = r.response;
        if let s::Response::Capability(s::CapabilityData { capabilities }) = r {
            for cap in required {
                if !capabilities.iter().any(|c| cap.eq_ignore_ascii_case(c)) {
                    die!(EX_PROTOCOL, "Required capability {} missing", cap);
                }
            }

            return Ok(());
        }
    }

    die!(EX_PROTOCOL, "Missing CAPABILITY response")
}

fn die_if_not_success(what: &str, response: s::ResponseLine<'_>) {
    match response.response {
        s::Response::Cond(s::CondResponse {
            cond: s::RespCondType::Ok,
            ..
        }) => (),
        s::Response::Cond(s::CondResponse { cond, quip, .. }) => {
            die!(
                EX_PROTOCOL,
                "{} failed; condition: {:?}; text: {}",
                what,
                cond,
                quip.unwrap_or_default(),
            );
        },
        r => {
            die!(
                EX_PROTOCOL,
                "Server returned unexpected response for {}: {:?}",
                what,
                r,
            );
        },
    }
}

fn change_password(client: &mut RemoteClient) -> Result<(), Error> {
    let new_password = loop {
        match rpassword::prompt_password("New password: ").and_then(|a| {
            rpassword::prompt_password("Confirm: ").map(|b| (a, b))
        }) {
            Err(e) => die!(EX_NOINPUT, "Failed to read password: {}", e),
            Ok((a, b)) if a != b => {
                eprintln!("Passwords don't match, try again");
            },
            Ok((a, _)) if a.is_empty() => die!(EX_NOINPUT, "No password given"),
            Ok((a, _)) => break a,
        }
    };

    client.write_raw(b"C1 XCRY SET-USER-CONFIG PASSWORD ")?;
    client.write_raw_censored(
        format!("{{{}+}}\r\n{}", new_password.len(), new_password).as_bytes(),
    )?;
    client.write_raw(b"\r\n")?;

    let mut buffer = Vec::new();
    let mut responses = client.read_responses_until_tagged(&mut buffer)?;
    die_if_not_success("SET-USER-CONFIG", responses.pop().unwrap());

    println!("Password changed successfully");

    for response in responses {
        if let s::Response::XCryBackupFile(file) = response.response {
            println!(
                "\
In case you need to undo this, a backup file has been created with the
following name inside the 'tmp' directory of your Crymap account:
  {}
If you need to undo the password change, you or an administrator can replace
'user.toml' in your Crymap account with that file. The backup file will be
deleted on the next successful login 24 hours from now.",
                file,
            );
            break;
        }
    }

    Ok(())
}

fn config(
    client: &mut RemoteClient,
    cmd: RemoteConfigSubcommand,
) -> Result<(), Error> {
    let mut buffer = Vec::new();
    let mut responses = client.command(
        s::Command::Simple(s::SimpleCommand::XCryGetUserConfig),
        &mut buffer,
    )?;
    die_if_not_success("GET-USER-CONFIG", responses.pop().unwrap());

    let current_config = responses
        .into_iter()
        .filter_map(|r| match r.response {
            s::Response::XCryUserConfig(c) => Some(c),
            _ => None,
        })
        .next()
        .unwrap_or_else(|| die!(EX_PROTOCOL, "No user config returned"));

    let mut configs = Vec::<s::XCryUserConfigOption<'_>>::new();

    if let Some(ikp) = cmd.internal_key_pattern {
        require_configurable(&current_config, "INTERNAL-KEY-PATTERN");
        configs
            .push(s::XCryUserConfigOption::InternalKeyPattern(Cow::Owned(ikp)));
    }

    if let Some(ekp) = cmd.external_key_pattern {
        require_configurable(&current_config, "EXTERNAL-KEY-PATTERN");
        configs
            .push(s::XCryUserConfigOption::ExternalKeyPattern(Cow::Owned(ekp)));
    }

    if let Some(s) = cmd.smtp_out_save {
        require_configurable(&current_config, "SMTP-OUT");
        configs.push(s::XCryUserConfigOption::SmtpOutSave(
            Some(Cow::<str>::Owned(s)).filter(|s| !s.is_empty()),
        ));
    }

    if let Some(s) = cmd.smtp_out_success_receipts {
        require_configurable(&current_config, "SMTP-OUT");
        configs.push(s::XCryUserConfigOption::SmtpOutSuccessReceipts(
            Some(Cow::<str>::Owned(s)).filter(|s| !s.is_empty()),
        ));
    }

    if let Some(s) = cmd.smtp_out_failure_receipts {
        require_configurable(&current_config, "SMTP-OUT");
        configs.push(s::XCryUserConfigOption::SmtpOutFailureReceipts(
            Some(Cow::<str>::Owned(s)).filter(|s| !s.is_empty()),
        ));
    }

    if configs.is_empty() {
        println!(
            "Current configuration:\n\
             \tinternal-key-pattern: {}\n\
             \texternal-key-pattern: {}\n\
             \tpassword last changed: {}",
            current_config.internal_key_pattern,
            current_config.external_key_pattern,
            current_config
                .password_changed
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_else(|| "never".to_owned()),
        );
        for extended in current_config.extended {
            match extended {
                s::XCry2UserConfigData::SmtpOutSave(None) => {
                    println!("\tsmtp-out-save: messages NOT saved");
                },
                s::XCry2UserConfigData::SmtpOutSave(Some(ref mb)) => {
                    println!("\tsmtp-out-save: messages saved to {mb}");
                },
                s::XCry2UserConfigData::SmtpOutSuccessReceipts(None) => {
                    println!("\tsmtp-out-success-receipts: not enabled");
                },
                s::XCry2UserConfigData::SmtpOutSuccessReceipts(Some(
                    ref mb,
                )) => {
                    println!("\tsmtp-out-success-receipts: delivered to {mb}");
                },
                s::XCry2UserConfigData::SmtpOutFailureReceipts(None) => {
                    println!(
                        "\tsmtp-out-failure-receipts: \
                              delivered to INBOX by default"
                    );
                },
                s::XCry2UserConfigData::SmtpOutFailureReceipts(Some(
                    ref mb,
                )) => {
                    println!("\tsmtp-out-failure-receipts: delivered to {mb}");
                },
                s::XCry2UserConfigData::Unknown(..) => {},
            }
        }
    } else {
        let mut buffer = Vec::new();
        let mut responses = client
            .command(s::Command::XCrySetUserConfig(configs), &mut buffer)?;
        die_if_not_success("SET-USER-CONFIG", responses.pop().unwrap());
    }

    Ok(())
}

fn require_configurable(
    current_config: &s::XCryUserConfigData<'_>,
    required: &str,
) {
    for cap in &current_config.capabilities {
        if required.eq_ignore_ascii_case(cap) {
            return;
        }
    }

    die!(
        EX_SOFTWARE,
        "{} is not configurable on this server",
        required,
    );
}

fn list_foreign_smtp_tls(client: &mut RemoteClient) -> Result<(), Error> {
    require_smtp_out_support(client)?;

    let mut buffer = Vec::new();
    let mut responses = client.command(
        s::Command::XCryForeignSmtpTls(s::XCryForeignSmtpTlsCommand::List(())),
        &mut buffer,
    )?;
    die_if_not_success("FOREIGN-TLS LIST", responses.pop().unwrap());

    if responses.is_empty() {
        println!("no foreign SMTP TLS stati in database");
    } else {
        for line in responses {
            if let s::Response::XCryForeignSmtpTls(data) = line.response {
                if !data.starttls {
                    println!(
                        "{domain}: TLS not required",
                        domain = data.domain
                    );
                } else {
                    println!(
                        "{domain}: TLS required, at least {version}; \
                         valid certificate {certreq}",
                        domain = data.domain,
                        version = data
                            .tls_version
                            .unwrap_or(Cow::Borrowed("any version")),
                        certreq = if data.valid_certificate {
                            "is required"
                        } else {
                            "is NOT required"
                        },
                    );
                }
            }
        }
    }

    Ok(())
}

fn delete_foreign_smtp_tls(
    client: &mut RemoteClient,
    domains: Vec<String>,
) -> Result<(), Error> {
    require_smtp_out_support(client)?;

    if domains.is_empty() {
        die!(EX_USAGE, "At least one domain must be specified");
    }

    let mut buffer = Vec::new();
    let mut responses = client.command(
        s::Command::XCryForeignSmtpTls(s::XCryForeignSmtpTlsCommand::Delete(
            domains.into_iter().map(Cow::Owned).collect(),
        )),
        &mut buffer,
    )?;
    die_if_not_success("FOREIGN-TLS DELETE", responses.pop().unwrap());
    Ok(())
}

fn retry_email(client: &mut RemoteClient, id: String) -> Result<(), Error> {
    require_smtp_out_support(client)?;

    let mut buffer = Vec::new();
    let mut responses = client.command(
        s::Command::XCrySmtpSpoolExecute(Cow::Owned(id)),
        &mut buffer,
    )?;
    die_if_not_success("SMTP-OUT SPOOL EXECUTE", responses.pop().unwrap());
    Ok(())
}

fn require_smtp_out_support(client: &mut RemoteClient) -> Result<(), Error> {
    let mut buffer = Vec::new();
    let mut responses = client.command(
        s::Command::Simple(s::SimpleCommand::XCryGetUserConfig),
        &mut buffer,
    )?;
    die_if_not_success("GET-USER-CONFIG", responses.pop().unwrap());

    let current_config = responses
        .into_iter()
        .filter_map(|r| match r.response {
            s::Response::XCryUserConfig(c) => Some(c),
            _ => None,
        })
        .next()
        .unwrap_or_else(|| die!(EX_PROTOCOL, "No user config returned"));

    for cap in &current_config.capabilities {
        if "SMTP-OUT".eq_ignore_ascii_case(cap) {
            return Ok(());
        }
    }

    die!(
        EX_SOFTWARE,
        "Crymap server does not support SMTP-OUT extensions",
    )
}
