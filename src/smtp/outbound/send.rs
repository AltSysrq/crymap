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

use std::cell::RefCell;
use std::io::{self, BufRead, Write};
use std::rc::Rc;
use std::sync::Arc;

use chrono::prelude::*;
use log::error;

use super::serverseq;
use crate::{
    account::{
        model::{CommonPaths, Flag},
        v2::{Account, SpooledMessageId},
    },
    mime::header::FULL_HEADER_LINE,
    support::{
        buffer::{BufferReader, BufferWriter},
        dns,
        error::Error,
    },
};

#[derive(Default)]
struct OverallResults {
    success: Vec<String>,
    tempfail: Vec<String>,
    permfail: Vec<String>,
    transcripts: Vec<Box<dyn io::Read>>,
}

/// Sends the spooled message identified by `message_id`.
///
/// If an error is returned, it indicates that the transaction could not even
/// be started, for example because the message does not exist.
pub async fn send_message(
    dns_cache: Rc<RefCell<dns::Cache>>,
    dns_resolver: Option<Rc<dns::Resolver>>,
    account: Rc<RefCell<Account>>,
    message_id: SpooledMessageId,
    local_host_name: String,
    mock_serverseq: Option<
        &dyn Fn(Rc<dns::Name>, Vec<String>) -> serverseq::Results,
    >,
) -> Result<(), Error> {
    let user_config = account.borrow().load_config()?;
    let message = account.borrow_mut().open_spooled_message(message_id)?;
    let subject = extract_raw_subject(message.data)
        .unwrap_or_else(|e| format!("[ERROR READING SUBJECT: {e}]"));
    let destinations = message.destinations;
    let common_paths = account.borrow().common_paths();

    let mut outputs = Vec::<(dns::Name, Vec<String>)>::new();
    let overall_results = Rc::new(RefCell::new(OverallResults::default()));

    // Group the destinations into distinct destination domains.
    for destination in destinations {
        let Some(domain) = destination
            .rsplit_once('@')
            .and_then(|(_, d)| dns::Name::from_str_relaxed(d).ok())
        else {
            let mut overall_results = overall_results.borrow_mut();
            account.borrow_mut().delete_spooled_message_destinations(
                message_id,
                &mut std::iter::once(&*destination),
            )?;
            overall_results.push_transcript_str(format!(
                "Dropping invalid email address {destination}"
            ));
            overall_results.permfail.push(destination);

            continue;
        };

        if let Some(&mut (_, ref mut domain_destinations)) = outputs
            .iter_mut()
            .find(|&&mut (ref name, _)| *name == domain)
        {
            domain_destinations.push(destination);
        } else {
            outputs.push((domain, vec![destination]));
        }
    }

    // Execute one transaction for each destination domain, and perform all the
    // transactions in parallel.
    let futures = outputs
        .into_iter()
        .map(|(domain, destinations)| {
            let domain = Rc::new(domain);
            let dns_cache = Rc::clone(&dns_cache);
            let dns_resolver = dns_resolver.clone();
            let account = Rc::clone(&account);
            let local_host_name = local_host_name.clone();
            let overall_results = Rc::clone(&overall_results);
            async move {
                let mut results = if let Some(mock_serverseq) = mock_serverseq {
                    mock_serverseq(Rc::clone(&domain), destinations)
                } else {
                    serverseq::execute(
                        dns_cache,
                        dns_resolver,
                        Rc::clone(&account),
                        message_id,
                        Rc::clone(&domain),
                        destinations,
                        local_host_name,
                        None,
                    )
                    .await
                };

                let mut overall_results = overall_results.borrow_mut();
                if let Err(e) =
                    account.borrow_mut().delete_spooled_message_destinations(
                        message_id,
                        &mut results
                            .success
                            .iter()
                            .chain(&results.permfail)
                            .map(|s| &**s),
                    )
                {
                    overall_results.push_transcript_str(format!(
                        "Failed to remove spool destinations: {e}",
                    ));
                }

                overall_results.success.append(&mut results.success);
                overall_results.tempfail.append(&mut results.tempfail);
                overall_results.permfail.append(&mut results.permfail);

                match results.transcript {
                    Ok(reader) => {
                        overall_results.transcripts.push(Box::new(reader))
                    },
                    Err(e) => overall_results.push_transcript_str(format!(
                        "I/O error reading transcript for {domain}: {e}"
                    )),
                }
            }
        })
        .collect::<Vec<_>>();

    futures::future::join_all(futures).await;

    // We now have all the results. See if the user wants a receipt.
    let mut account = account.borrow_mut();
    let mut overall_results = overall_results.borrow_mut();
    let want_receipt = if overall_results.success() {
        user_config.smtp_out.success_receipts.as_deref()
    } else {
        Some(
            user_config
                .smtp_out
                .failure_receipts
                .as_deref()
                .unwrap_or("INBOX"),
        )
    };

    let Some(mut want_receipt) = want_receipt else {
        return Ok(());
    };

    // If the requested mailbox doesn't exist, fall back to the inbox.
    if account.probe_mailbox(want_receipt).is_err() {
        want_receipt = "INBOX";
    }

    match generate_receipt(
        common_paths,
        &local_host_name,
        &subject,
        message_id,
        &mut overall_results,
    ) {
        Ok(buffered_receipt) => {
            // Success receipts are less interesting, so mark them as read
            // at delivery.
            let flags: &[Flag] = if overall_results.success() {
                &[Flag::Seen]
            } else {
                &[]
            };
            if let Err(e) = account.append(
                want_receipt,
                Utc::now().into(),
                flags.iter().cloned(),
                buffered_receipt,
            ) {
                error!("Failed to deliver message receipt: {e}");
            }
        },

        Err(e) => {
            error!("Failed to generate message receipt: {e}");
        },
    }

    Ok(())
}

impl OverallResults {
    fn push_transcript_str(&mut self, s: String) {
        self.transcripts
            .push(Box::new(io::Cursor::new(Vec::<u8>::from(s))))
    }

    fn success(&self) -> bool {
        self.tempfail.is_empty() && self.permfail.is_empty()
    }
}

fn extract_raw_subject(reader: impl io::BufRead) -> io::Result<String> {
    let mut reader = reader.take(65536);
    let mut header_block = Vec::<u8>::new();
    while !header_block.ends_with(b"\n\n") && !header_block.ends_with(b"\n\r\n")
    {
        let nread = reader.read_until(b'\n', &mut header_block)?;
        if 0 == nread {
            break;
        }
    }

    let subject = FULL_HEADER_LINE
        .captures_iter(&header_block)
        .find(|m| {
            std::str::from_utf8(m.get(2).unwrap().as_bytes())
                .ok()
                .is_some_and(|n| "Subject".eq_ignore_ascii_case(n))
        })
        .and_then(|m| std::str::from_utf8(m.get(3).unwrap().as_bytes()).ok())
        .map(str::to_owned)
        .unwrap_or_else(|| "[NO SUBJECT]".to_owned());
    Ok(subject)
}

fn generate_receipt(
    common_paths: Arc<CommonPaths>,
    local_host_name: &str,
    raw_subject: &str,
    message_id: SpooledMessageId,
    results: &mut OverallResults,
) -> io::Result<BufferReader> {
    let mut writer = BufferWriter::new(common_paths);
    let classification = if !results.tempfail.is_empty() {
        "[TEMPORARY ERROR - ACTION REQUIRED]"
    } else if !results.permfail.is_empty() {
        "[FAILURE]"
    } else {
        "[SUCCESS]"
    };
    writeln!(
        writer,
        "\
From: \"Mailer Daemon\" <postmaster>\r
Subject: {classification}\r\n {raw_subject}\r
Date: {now}\r
Content-Type: text/plain; charset=utf-8\r
Content-Transfer-Encoding: 8bit\r
MIME-Version: 1.0\r
\r",
        now = Utc::now().to_rfc2822(),
    )?;

    if !results.tempfail.is_empty() {
        writeln!(
            writer,
            "\
Sending the email to the following addresses FAILED TEMPORARILY.\r
It may be possible to retry sending the message to these addresses, but this\r
must be done MANUALLY.\r
\r",
        )?;
        for email in &results.tempfail {
            writeln!(writer, "\t{email}\r")?;
        }
        // TODO Implement this CLI command and verify it has this syntax.
        writeln!(
            writer,
            "\
\r
To trigger a retry, run the following command:\r
\tcrymap remote retry-email {local_host_name} {message_id}\r
\r",
        )?;
    }

    if !results.permfail.is_empty() {
        writeln!(
            writer,
            "\
Sending the email to the following addresses FAILED PERMANENTLY.\r
It is not possible to retry.\r
\r",
        )?;
        for email in &results.permfail {
            writeln!(writer, "\t{email}\r")?;
        }
        writeln!(writer, "\r")?;
    }

    if !results.success.is_empty() {
        writeln!(
            writer,
            "\
The email was ACCEPTED FOR DELIVERY by the remote mail system for the\r
following addresses.\r
\r",
        )?;
        for email in &results.success {
            writeln!(writer, "\t{email}\r")?;
        }
        writeln!(writer, "\r")?;
    }

    writeln!(
        writer,
        "\
The rest of this receipt contains technical details of the mail transaction.\r
\r",
    )?;

    for mut transcript in results.transcripts.drain(..) {
        io::copy(&mut transcript, &mut writer)?;
        writeln!(writer, "\r")?;
    }

    writer.flip()
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use tempfile::TempDir;

    use super::*;
    use crate::{
        account::model::{CreateRequest, SetUserConfigRequest, Uid},
        crypt::master_key::MasterKey,
        support::log_prefix::LogPrefix,
    };

    struct Setup {
        account_dir: TempDir,
        account: Rc<RefCell<Account>>,
    }

    fn set_up_new_root() -> Setup {
        crate::init_test_log();

        let account_dir = TempDir::new().unwrap();
        let master_key = Arc::new(MasterKey::new());

        let mut account = Account::new(
            LogPrefix::new("test".to_owned()),
            account_dir.path().to_owned(),
            Arc::clone(&master_key),
        )
        .unwrap();
        account.provision(b"hunter2").unwrap();

        Setup {
            account_dir,
            account: Rc::new(RefCell::new(account)),
        }
    }

    struct TestCase {
        message: &'static str,
        destinations: &'static [&'static str],
        domains: &'static [DomainResult],
        remaining_destinations: &'static [&'static str],
        receipt_in: Option<&'static str>,
        receipt_not_in: &'static [&'static str],
        receipt_strings: &'static [&'static str],
    }

    struct DomainResult {
        domain: &'static str,
        success: &'static [&'static str],
        tempfail: &'static [&'static str],
        permfail: &'static [&'static str],
        transcript: &'static str,
    }

    #[tokio::main(flavor = "current_thread")]
    async fn run_test(setup: &Setup, tc: TestCase) {
        let spooled_message_id = {
            let mut account = setup.account.borrow_mut();
            let buffered_message = account
                .buffer_message(Utc::now().into(), tc.message.as_bytes())
                .unwrap();
            account
                .spool_message(
                    buffered_message,
                    crate::account::v2::SmtpTransfer::EightBit,
                    "zim@earth.com".to_owned(),
                    tc.destinations
                        .iter()
                        .copied()
                        .map(str::to_owned)
                        .collect(),
                )
                .unwrap()
        };

        let mock_serverseq = |domain: Rc<dns::Name>, mut dests: Vec<String>| {
            let domain_result = tc
                .domains
                .iter()
                .find(|d| *domain == dns::Name::from_ascii(d.domain).unwrap())
                .unwrap_or_else(|| panic!("unexpected domain: {domain}"));
            dests.sort();
            let mut expected_dests = domain_result
                .success
                .iter()
                .chain(domain_result.tempfail)
                .chain(domain_result.permfail)
                .copied()
                .map(str::to_owned)
                .collect::<Vec<String>>();
            expected_dests.sort();
            assert_eq!(expected_dests, dests);
            serverseq::Results {
                success: domain_result
                    .success
                    .iter()
                    .copied()
                    .map(str::to_owned)
                    .collect(),
                tempfail: domain_result
                    .tempfail
                    .iter()
                    .copied()
                    .map(str::to_owned)
                    .collect(),
                permfail: domain_result
                    .permfail
                    .iter()
                    .copied()
                    .map(str::to_owned)
                    .collect(),
                transcript: Ok(BufferReader::new(
                    domain_result.transcript.as_bytes().to_vec(),
                )),
            }
        };

        send_message(
            Rc::new(RefCell::new(dns::Cache::default())),
            None,
            Rc::clone(&setup.account),
            spooled_message_id,
            "localhost".to_owned(),
            Some(&mock_serverseq),
        )
        .await
        .unwrap();

        let mut account = setup.account.borrow_mut();
        if tc.remaining_destinations.is_empty() {
            assert_matches!(
                Err(crate::support::error::Error::NxMessage),
                account.open_spooled_message(spooled_message_id).map(|_| ()),
            );
        } else {
            let mut spooled =
                account.open_spooled_message(spooled_message_id).unwrap();
            spooled.destinations.sort();
            let mut expected_dests = tc
                .remaining_destinations
                .iter()
                .copied()
                .map(str::to_owned)
                .collect::<Vec<String>>();
            expected_dests.sort();
            assert_eq!(expected_dests, spooled.destinations);
        }

        for &mailbox_path in tc.receipt_not_in {
            let (mailbox, _) = account
                .select(mailbox_path, false, None)
                .unwrap_or_else(|e| {
                    panic!("failed to open {mailbox_path}: {e}")
                });
            let select = mailbox.select_response().unwrap();
            assert_eq!(
                0, select.exists,
                "unexpected message in {mailbox_path}"
            );
        }

        if let Some(mailbox_path) = tc.receipt_in {
            let (mailbox, _) = account
                .select(mailbox_path, false, None)
                .unwrap_or_else(|e| {
                    panic!("failed to open {mailbox_path}: {e}")
                });
            let select = mailbox.select_response().unwrap();
            assert_eq!(1, select.exists, "no messages in {mailbox_path}");

            let (_, mut reader) =
                account.open_message_by_uid(&mailbox, Uid::u(1)).unwrap();

            let mut receipt = String::new();
            reader.read_to_string(&mut receipt).unwrap();

            println!("Delivered receipt:\n{receipt}");
            for fragment in tc.receipt_strings {
                assert!(
                    receipt.contains(fragment),
                    "{fragment:?} not found in receipt"
                );
            }
        }
    }

    #[test]
    fn mixed_results_defaults() {
        let setup = set_up_new_root();
        run_test(
            &setup,
            TestCase {
                message: "\
From: foo@bar.com
Subject: This is the subject

Hello world
",
                destinations: &[
                    "success@foo.com",
                    "tempfail@bar.com",
                    "permfail@foo.com",
                    "tempfail@foo.com",
                ],
                domains: &[
                    DomainResult {
                        domain: "foo.com",
                        success: &["success@foo.com"],
                        tempfail: &["tempfail@foo.com"],
                        permfail: &["permfail@foo.com"],
                        transcript: "transcript for foo.com",
                    },
                    DomainResult {
                        domain: "bar.com",
                        success: &[],
                        tempfail: &["tempfail@bar.com"],
                        permfail: &[],
                        transcript: "transcript for bar.com",
                    },
                ],
                remaining_destinations: &[
                    "tempfail@bar.com",
                    "tempfail@foo.com",
                ],
                receipt_in: Some("INBOX"),
                receipt_not_in: &[],
                receipt_strings: &[
                    "Subject: [TEMPORARY ERROR - ACTION REQUIRED]\r\n\
                 \x20This is the subject\r\n",
                    "transcript for foo.com",
                    "transcript for bar.com",
                ],
            },
        );
    }

    #[test]
    fn success_only_no_receipt() {
        let setup = set_up_new_root();
        run_test(
            &setup,
            TestCase {
                message: "From: foo@bar.com\r\n\r\nHello world\r\n",
                destinations: &["success@foo.com"],
                domains: &[DomainResult {
                    domain: "foo.com",
                    success: &["success@foo.com"],
                    tempfail: &[],
                    permfail: &[],
                    transcript: "transcript for foo.com",
                }],
                remaining_destinations: &[],
                receipt_in: None,
                receipt_not_in: &["INBOX"],
                receipt_strings: &[],
            },
        );
    }

    #[test]
    fn permfail_only_non_default_output() {
        let setup = set_up_new_root();
        setup
            .account
            .borrow()
            .update_config(SetUserConfigRequest {
                smtp_out_failure_receipts: Some(Some("Sent".to_owned())),
                ..Default::default()
            })
            .unwrap();
        run_test(
            &setup,
            TestCase {
                message: "From: foo@bar.com\r\n\r\nHello world\r\n",
                destinations: &["permfail@foo.com"],
                domains: &[DomainResult {
                    domain: "foo.com",
                    success: &[],
                    tempfail: &[],
                    permfail: &["permfail@foo.com"],
                    transcript: "transcript for foo.com",
                }],
                remaining_destinations: &[],
                receipt_in: Some("Sent"),
                receipt_not_in: &["INBOX"],
                receipt_strings: &[
                    "Subject: [FAILURE]",
                    "transcript for foo.com",
                ],
            },
        );
    }

    #[test]
    fn success_with_receipt_no_subject() {
        let setup = set_up_new_root();
        setup
            .account
            .borrow()
            .update_config(SetUserConfigRequest {
                smtp_out_success_receipts: Some(Some("success".to_owned())),
                ..Default::default()
            })
            .unwrap();
        setup
            .account
            .borrow_mut()
            .create(CreateRequest {
                name: "success".to_owned(),
                special_use: vec![],
            })
            .unwrap();

        run_test(
            &setup,
            TestCase {
                message: "\
From: foo@bar.com

Subject: This is not the subject
",
                destinations: &["success@foo.com"],
                domains: &[DomainResult {
                    domain: "foo.com",
                    success: &["success@foo.com"],
                    tempfail: &[],
                    permfail: &[],
                    transcript: "transcript for foo.com",
                }],
                remaining_destinations: &[],
                receipt_in: Some("success"),
                receipt_not_in: &["INBOX"],
                receipt_strings: &["Subject: [SUCCESS]\r\n [NO SUBJECT]\r\n"],
            },
        );
    }

    #[test]
    fn invalid_emails_discarded() {
        let setup = set_up_new_root();
        run_test(
            &setup,
            TestCase {
                message: "",
                destinations: &["no-domain", "invalid-domain@/"],
                domains: &[],
                remaining_destinations: &[],
                receipt_in: Some("INBOX"),
                receipt_not_in: &[],
                receipt_strings: &["no-domain", "invalid-domain"],
            },
        );
    }
}
