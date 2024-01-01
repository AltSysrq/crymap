//-
// Copyright (c) 2023, Jason Lingle
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

//! The syntactic structures defined in RFC 7489.

use bitflags::bitflags;
use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record<'a> {
    pub version: &'a str,
    pub dkim: AlignmentMode,
    pub spf: AlignmentMode,
    pub failure_reporting: FailureReportingOptions,
    pub requested_receiver_policy: ReceiverPolicy,
    pub subdomain_receiver_policy: ReceiverPolicy,
    pub percent: u32,
    pub report_format: &'a str,
    pub report_interval: u32,
    pub aggregate_report_addresses: Option<&'a str>,
    pub message_report_addresses: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum AlignmentMode {
    #[default]
    Relaxed,
    Strict,
}

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct FailureReportingOptions: u32 {
        /// > 0: Generate a DMARC failure report if all underlying
        /// >    authentication mechanisms fail to produce an aligned "pass"
        /// >    result.
        const FAIL_TO_PASS = 1 << 0;
        /// > 1: Generate a DMARC failure report if any underlying >
        /// >    authentication mechanism produced something other than an
        /// >    aligned "pass" result.
        const EVAL_NOT_PASS = 1 << 1;
        /// > d: Generate a DKIM failure report if the message had a signature
        /// >    that failed evaluation, regardless of its alignment. DKIM-
        /// >    specific reporting is described in [AFRF-DKIM].
        const FAILED_DKIM = 1 << 2;
        /// > s: Generate an SPF failure report if the message failed SPF
        /// >    evaluation, regardless of its alignment.  SPF-specific
        /// >    reporting is described in [AFRF-SPF].
        const FAILED_SPF = 1 << 3;
    }
}

impl Default for FailureReportingOptions {
    fn default() -> Self {
        Self::FAIL_TO_PASS
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiverPolicy {
    None,
    Quarantine,
    Reject,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum Error {
    #[error("unsupported DMARC record version")]
    UnsupportedVersion,
    #[error("no DMARC record version")]
    NoVersion,
    #[error("no policy (p=) field")]
    NoPolicy,
    #[error("invalid policy (p=) field")]
    InvalidPolicy,
    #[error("more than one {0}= field")]
    DuplicateField(&'static str),
}

impl<'a> Record<'a> {
    pub fn parse(s: &'a str) -> Result<Self, Error> {
        fn set_opt<T>(
            field: &'static str,
            opt: &mut Option<T>,
            value: T,
        ) -> Result<(), Error> {
            if opt.is_some() {
                Err(Error::DuplicateField(field))
            } else {
                *opt = Some(value);
                Ok(())
            }
        }

        let mut version = None::<&'a str>;
        let mut dkim = None::<AlignmentMode>;
        let mut spf = None::<AlignmentMode>;
        let mut failure_reporting = None::<FailureReportingOptions>;
        let mut requested_receiver_policy = None::<ReceiverPolicy>;
        let mut subdomain_receiver_policy = None::<ReceiverPolicy>;
        let mut percent = None::<u32>;
        let mut report_format = None::<&'a str>;
        let mut report_interval = None::<u32>;
        let mut aggregate_report_addresses = None::<&'a str>;
        let mut message_report_addresses = None::<&'a str>;

        for word in s.split([' ', '\t']) {
            if word.is_empty() {
                continue;
            }

            // Unlike SPF and DKIM, DMARC requires very permissive parsing.
            let Some((k, v)) = word.split_once('=') else {
                continue;
            };

            match k {
                "v" => {
                    set_opt("v", &mut version, v)?;
                    if v != "DMARC1" {
                        return Err(Error::UnsupportedVersion);
                    }
                },

                "adkim" => {
                    let mode = if "s" == v {
                        AlignmentMode::Strict
                    } else {
                        AlignmentMode::Relaxed
                    };
                    set_opt("adkim", &mut dkim, mode)?;
                },

                "aspf" => {
                    let mode = if "s" == v {
                        AlignmentMode::Strict
                    } else {
                        AlignmentMode::Relaxed
                    };
                    set_opt("aspf", &mut spf, mode)?;
                },

                "fo" => {
                    let mut opts = FailureReportingOptions::empty();
                    for opt in v.split(':') {
                        use FailureReportingOptions as Fro;

                        match opt {
                            "0" => opts |= Fro::FAIL_TO_PASS,
                            "1" => opts |= Fro::EVAL_NOT_PASS,
                            "d" => opts |= Fro::FAILED_DKIM,
                            "s" => opts |= Fro::FAILED_SPF,
                            _ => {},
                        }
                    }

                    if opts == FailureReportingOptions::empty() {
                        opts = FailureReportingOptions::default();
                    }

                    set_opt("fo", &mut failure_reporting, opts)?;
                },

                "p" => {
                    let p = ReceiverPolicy::parse(v)?;
                    set_opt("p", &mut requested_receiver_policy, p)?;
                },

                "pct" => {
                    let pct = v.parse::<u32>().unwrap_or(100).min(100);
                    set_opt("pct", &mut percent, pct)?;
                },

                "rf" => set_opt("rf", &mut report_format, v)?,
                "ri" => {
                    let ri = v.parse::<u32>().unwrap_or(86400);
                    set_opt("ri", &mut report_interval, ri)?;
                },
                "rua" => set_opt("rua", &mut aggregate_report_addresses, v)?,
                "ruf" => set_opt("ruf", &mut message_report_addresses, v)?,

                "s" => {
                    let p = ReceiverPolicy::parse(v)?;
                    set_opt("s", &mut subdomain_receiver_policy, p)?;
                },
                _ => {},
            }
        }

        let version = version.ok_or(Error::NoVersion)?;
        let requested_receiver_policy =
            requested_receiver_policy.ok_or(Error::NoPolicy)?;

        Ok(Self {
            version,
            dkim: dkim.unwrap_or_default(),
            spf: spf.unwrap_or_default(),
            failure_reporting: failure_reporting.unwrap_or_default(),
            requested_receiver_policy,
            subdomain_receiver_policy: subdomain_receiver_policy
                .unwrap_or(requested_receiver_policy),
            percent: percent.unwrap_or(100),
            report_format: report_format.unwrap_or("afrf"),
            report_interval: report_interval.unwrap_or(86400),
            aggregate_report_addresses,
            message_report_addresses,
        })
    }
}

impl ReceiverPolicy {
    fn parse(s: &str) -> Result<Self, Error> {
        match s {
            "none" => Ok(Self::None),
            "quarantine" => Ok(Self::Quarantine),
            "reject" => Ok(Self::Reject),
            _ => Err(Error::InvalidPolicy),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse() {
        assert_eq!(Err(Error::NoVersion), Record::parse(""));
        assert_eq!(Err(Error::UnsupportedVersion), Record::parse("v=DMARC2"));
        assert_eq!(Err(Error::NoPolicy), Record::parse("v=DMARC1"));
        assert_eq!(
            Err(Error::InvalidPolicy),
            Record::parse("v=DMARC1 p=whatever"),
        );
        assert_eq!(
            Err(Error::DuplicateField("p")),
            Record::parse("v=DMARC1 p=reject p=none"),
        );

        // Minimal record
        assert_eq!(
            Ok(Record {
                version: "DMARC1",
                dkim: AlignmentMode::Relaxed,
                spf: AlignmentMode::Relaxed,
                failure_reporting: FailureReportingOptions::FAIL_TO_PASS,
                requested_receiver_policy: ReceiverPolicy::Quarantine,
                subdomain_receiver_policy: ReceiverPolicy::Quarantine,
                percent: 100,
                report_format: "afrf",
                report_interval: 86400,
                aggregate_report_addresses: None,
                message_report_addresses: None,
            }),
            Record::parse("v=DMARC1 p=quarantine"),
        );

        // Maximal record
        assert_eq!(
            Ok(Record {
                version: "DMARC1",
                dkim: AlignmentMode::Strict,
                spf: AlignmentMode::Strict,
                failure_reporting: FailureReportingOptions::FAIL_TO_PASS
                    | FailureReportingOptions::EVAL_NOT_PASS
                    | FailureReportingOptions::FAILED_SPF
                    | FailureReportingOptions::FAILED_DKIM,
                requested_receiver_policy: ReceiverPolicy::None,
                subdomain_receiver_policy: ReceiverPolicy::Reject,
                percent: 42,
                report_format: "text/plain",
                report_interval: 3600,
                aggregate_report_addresses: Some("mailto:foo@example.com"),
                message_report_addresses: Some("mailto:bar@example.com"),
            }),
            Record::parse(
                "v=DMARC1 p=none s=reject adkim=s aspf=s fo=1:0:s:d \
                 pct=42 rf=text/plain ri=3600 \
                 rua=mailto:foo@example.com ruf=mailto:bar@example.com",
            ),
        );

        // Record with all optional fields we parse set to bogus values
        assert_eq!(
            Ok(Record {
                version: "DMARC1",
                dkim: AlignmentMode::Relaxed,
                spf: AlignmentMode::Relaxed,
                failure_reporting: FailureReportingOptions::FAIL_TO_PASS,
                requested_receiver_policy: ReceiverPolicy::None,
                subdomain_receiver_policy: ReceiverPolicy::None,
                percent: 100,
                report_format: "afrf",
                report_interval: 86400,
                aggregate_report_addresses: None,
                message_report_addresses: None,
            }),
            Record::parse(
                "v=DMARC1 p=none adkim=y aspf=y fo=y pct=all ri=never",
            ),
        );
    }
}
