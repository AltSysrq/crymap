//-
// Copyright (c) 2020, 2023, 2024, 2025, Jason Lingle
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

use std::str::FromStr;

use lazy_static::lazy_static;
use regex::Regex;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// (HELO|EHLO|LHLO) origin-host ignored...
    Helo(String, String),
    /// AUTH mechanism [base64]
    Auth(String, Option<String>),
    /// MAIL FROM:<return-path> [SIZE=sz] [BODY=encoding]
    /// The final element is a list of warnings.
    MailFrom(String, Option<u64>, Vec<String>),
    /// RCPT TO:<ignored...:email>
    /// The final element is a list of warnings.
    Recipient(String, Vec<String>),
    /// DATA
    Data,
    /// BDAT length [LAST]
    BinaryData(u64, bool),
    /// RSET
    Reset,
    /// VRFY ignored...
    Verify,
    /// EXPN ignored...
    Expand,
    /// HELP ignored...
    Help,
    /// NOOP
    Noop,
    /// QUIT
    Quit,
    /// STARTTLS
    StartTls,
    /// Anything that looks like a common HTTP command.
    Http,
}

const MAX_WARNINGS: usize = 4;

static SIMPLE_COMMANDS: &[(&str, Command, bool)] = &[
    ("DATA", Command::Data, false),
    ("RSET", Command::Reset, false),
    ("VRFY ", Command::Verify, true),
    ("EXPN ", Command::Expand, true),
    ("HELP", Command::Help, true),
    ("NOOP", Command::Noop, false),
    ("QUIT", Command::Quit, false),
    ("STARTTLS", Command::StartTls, false),
    ("GET", Command::Http, true),
    ("HEAD", Command::Http, true),
    ("PUT", Command::Http, true),
    ("POST", Command::Http, true),
    ("DELETE", Command::Http, true),
    ("OPTIONS", Command::Http, true),
];

lazy_static! {
    static ref RX_HELO: Regex =
        Regex::new("^(?i)(HELO|EHLO|LHLO) ([^ ]*)").unwrap();
    static ref RX_MAIL: Regex =
        Regex::new("^(?i)MAIL FROM:<([^>]*)>(.*)$").unwrap();
    static ref RX_MAIL_BODY_PARM: Regex =
        Regex::new("(?i)BODY=(7BIT|8BITMIME|BINARYMIME)").unwrap();
    static ref RX_MAIL_SIZE_PARM: Regex =
        Regex::new("(?i)SIZE=([0-9]+)").unwrap();
    static ref RX_RCPT: Regex =
        Regex::new("^(?i)RCPT TO:<(?:@[^:]+:)?([^>]+)>(.*)$").unwrap();
    static ref RX_BDAT: Regex =
        Regex::new("^(?i)BDAT ([0-9]+)( LAST)?$").unwrap();
    static ref RX_AUTH: Regex =
        Regex::new("^(?i)AUTH ([A-Z0-9-]+)(?: ([0-9A-Za-z+/=]+))?$").unwrap();
    static ref RX_KNOWN_COMMANDS: Regex = Regex::new(
        "^(?i)(DATA|RSET|VRFY|EXPN|HELP|NOOP|QUIT|\
         STARTTLS|LHLO|MAIL|RCPT|BDAT|HELO|EHLO|AUTH)( .*)?$"
    )
    .unwrap();
}

pub fn looks_like_known_command(s: &str) -> bool {
    RX_KNOWN_COMMANDS.is_match(s)
}

impl FromStr for Command {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, ()> {
        let mut warnings = Vec::<String>::new();
        let mut add_warning = |w: String| {
            if warnings.len() < MAX_WARNINGS {
                warnings.push(w);
            }
        };

        for &(prefix, ref cmd, allow_trailing_garbage) in SIMPLE_COMMANDS {
            if s.len() >= prefix.len()
                && (allow_trailing_garbage || s.len() == prefix.len())
                && s.get(0..prefix.len())
                    .is_some_and(|sp| prefix.eq_ignore_ascii_case(sp))
            {
                return Ok(cmd.clone());
            }
        }

        if let Some(cap) = RX_HELO.captures(s) {
            Ok(Command::Helo(
                cap.get(1).unwrap().as_str().to_owned(),
                cap.get(2).unwrap().as_str().to_owned(),
            ))
        } else if let Some(cap) = RX_MAIL.captures(s) {
            let mut size = None::<u64>;
            for parm in cap
                .get(2)
                .map(|c| c.as_str())
                .unwrap_or("")
                .split(' ')
                .filter(|s| !s.is_empty())
            {
                let truncated_parm = &parm[..parm
                    .char_indices()
                    .nth(64)
                    .map(|(ix, _)| ix)
                    .unwrap_or(parm.len())];
                if let Some(cap) = RX_MAIL_SIZE_PARM.captures(parm) {
                    if let Some(s) =
                        cap.get(1).and_then(|c| c.as_str().parse::<u64>().ok())
                    {
                        size = Some(s);
                    } else {
                        add_warning(format!(
                            "Ignoring invalid MAIL FROM parameter {:?}",
                            truncated_parm,
                        ));
                    }
                } else if !RX_MAIL_BODY_PARM.is_match(parm) {
                    add_warning(format!(
                        "Ignoring unknown MAIL FROM parameter {:?}",
                        truncated_parm,
                    ));
                }
            }

            Ok(Command::MailFrom(
                cap.get(1).unwrap().as_str().to_owned(),
                size,
                warnings,
            ))
        } else if let Some(cap) = RX_RCPT.captures(s) {
            if let Some(extra) = cap.get(2).filter(|c| !c.as_str().is_empty()) {
                let extra = extra.as_str().trim();
                let extra = &extra[..extra
                    .char_indices()
                    .nth(64)
                    .map(|(ix, _)| ix)
                    .unwrap_or(extra.len())];
                add_warning(format!(
                    "Ignoring extraneous RCPT TO parameters: {extra:?}"
                ));
            };

            Ok(Command::Recipient(
                cap.get(1).unwrap().as_str().to_owned(),
                warnings,
            ))
        } else if let Some(cap) = RX_BDAT.captures(s) {
            cap.get(1)
                .unwrap()
                .as_str()
                .parse::<u64>()
                .map_err(|_| ())
                .map(|len| Command::BinaryData(len, cap.get(2).is_some()))
        } else if let Some(cap) = RX_AUTH.captures(s) {
            let mechanism = cap.get(1).unwrap().as_str().to_owned();
            let data = cap.get(2).map(|data| data.as_str().to_owned());
            Ok(Command::Auth(mechanism, data))
        } else {
            Err(())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn command_parsing() {
        assert_eq!(
            Ok(Command::Helo(
                "LHLO".to_owned(),
                "foo.example.com".to_owned()
            )),
            "LHLO foo.example.com".parse()
        );
        assert_eq!(
            Ok(Command::Helo(
                "lhlo".to_owned(),
                "foo.example.com".to_owned()
            )),
            "lhlo foo.example.com some client implementation".parse()
        );

        assert_eq!(
            Ok(Command::Helo(
                "HELO".to_owned(),
                "foo.example.com".to_owned()
            )),
            "HELO foo.example.com".parse()
        );
        assert_eq!(
            Ok(Command::Helo(
                "helo".to_owned(),
                "foo.example.com".to_owned()
            )),
            "helo foo.example.com some client implementation".parse()
        );

        assert_eq!(
            Ok(Command::Helo(
                "EHLO".to_owned(),
                "foo.example.com".to_owned()
            )),
            "EHLO foo.example.com".parse()
        );
        assert_eq!(
            Ok(Command::Helo(
                "ehlo".to_owned(),
                "foo.example.com".to_owned()
            )),
            "ehlo foo.example.com some client implementation".parse()
        );

        assert_eq!(
            Ok(Command::MailFrom("foo@bar.com".to_owned(), None, vec![])),
            "MAIL FROM:<foo@bar.com>".parse()
        );
        assert_eq!(
            Ok(Command::MailFrom("foo@bar.com".to_owned(), None, vec![])),
            "MAIL FROM:<foo@bar.com> BODY=BiNaRyMiMe".parse()
        );
        assert_eq!(
            Ok(Command::MailFrom("foo@bar.com".to_owned(), None, vec![])),
            "MAIL FROM:<foo@bar.com> body=8bitmime".parse()
        );
        assert_eq!(
            Ok(Command::MailFrom("foo@bar.com".to_owned(), None, vec![])),
            "MAIL FROM:<foo@bar.com> body=7bit".parse()
        );
        assert_eq!(
            Ok(Command::MailFrom(
                "foo@bar.com".to_owned(),
                None,
                vec!["Ignoring unknown MAIL FROM parameter \"body=9BIT\""
                    .to_owned()],
            )),
            "MAIL FROM:<foo@bar.com> body=9BIT".parse()
        );
        assert_eq!(
            Ok(Command::MailFrom(
                "foo@bar.com".to_owned(),
                Some(42),
                vec![]
            )),
            "MAIL FROM:<foo@bar.com> SIZE=42".parse()
        );
        assert_eq!(
            Ok(Command::MailFrom(
                "foo@bar.com".to_owned(),
                Some(42),
                vec![]
            )),
            "MAIL FROM:<foo@bar.com> body=7bit size=42".parse()
        );
        assert_eq!(
            Ok(Command::MailFrom(
                "foo@bar.com".to_owned(),
                Some(42),
                vec![]
            )),
            "MAIL FROM:<foo@bar.com> size=42 body=7bit".parse()
        );
        assert_eq!(
            Ok(Command::MailFrom(String::new(), None, vec![])),
            "mail from:<>".parse()
        );
        assert_eq!(
            Ok(Command::MailFrom(
                "foo@bar.com".to_owned(),
                None,
                vec!["Ignoring invalid MAIL FROM parameter \"size=99999999999999999999\"".to_owned()],
            )),
            "MAIL FROM:<foo@bar.com> size=99999999999999999999".parse::<Command>()
        );
        assert_eq!(
            Ok(Command::MailFrom(
                "foo@bar.com".to_owned(),
                None,
                vec!["Ignoring unknown MAIL FROM parameter \"FOO=BAR\""
                    .to_owned()],
            )),
            "MAIL FROM:<foo@bar.com> FOO=BAR".parse::<Command>()
        );

        assert_eq!(
            Ok(Command::Recipient("userc@d.bar.org".to_owned(), vec![])),
            "RCPT TO:<userc@d.bar.org>".parse()
        );
        assert_eq!(
            Ok(Command::Recipient("userc@d.bar.org".to_owned(), vec![])),
            "rcpt to:<@hosta.int,@jkl.org:userc@d.bar.org>".parse()
        );
        assert_eq!(
            Ok(Command::Recipient(
                "userc@d.bar.org".to_owned(),
                vec!["Ignoring extraneous RCPT TO parameters: \"FOO=BAR\""
                    .to_owned()],
            )),
            "RCPT TO:<userc@d.bar.org> FOO=BAR".parse()
        );

        assert_eq!(Ok(Command::Data), "DATA".parse());
        assert_eq!(Ok(Command::Data), "data".parse());
        assert_eq!(Err(()), "DATA DATA".parse::<Command>());
        assert_eq!(Err(()), "DATABASE".parse::<Command>());

        assert_eq!(Ok(Command::BinaryData(42, false)), "BDAT 42".parse());
        assert_eq!(
            Ok(Command::BinaryData(1000, true)),
            "BDAT 1000 LAST".parse()
        );
        assert_eq!(Ok(Command::BinaryData(1, true)), "bdat 1 last".parse());

        assert_eq!(Ok(Command::Reset), "RSET".parse());
        assert_eq!(Err(()), "RSET FOO".parse::<Command>());

        assert_eq!(Ok(Command::Verify), "VRFY Smith".parse());
        assert_eq!(Ok(Command::Verify), "vrfy <foo@bar.com>".parse());
        assert_eq!(Err(()), "VRFY".parse::<Command>());

        assert_eq!(Ok(Command::Expand), "EXPN Smith".parse());
        assert_eq!(Ok(Command::Expand), "EXPN <foo@bar.com>".parse());
        assert_eq!(Err(()), "EXPN".parse::<Command>());

        assert_eq!(Ok(Command::Help), "HELP".parse());
        assert_eq!(Ok(Command::Help), "help me".parse());

        assert_eq!(Ok(Command::Noop), "NOOP".parse());
        assert_eq!(Err(()), "NOOP NOP".parse::<Command>());

        assert_eq!(Ok(Command::Quit), "QUIT".parse());
        assert_eq!(Err(()), "QUIT NOW".parse::<Command>());

        assert_eq!(Ok(Command::StartTls), "STARTTLS".parse());
        assert_eq!(Err(()), "STARTTLS 1.3".parse::<Command>());

        assert_eq!(
            Ok(Command::Auth(
                "PLAIN".to_owned(),
                Some("AGF6dXJlAGh1bnRlcjI+//=".to_owned()),
            )),
            "AUTH PLAIN AGF6dXJlAGh1bnRlcjI+//=".parse::<Command>(),
        );
        assert_eq!(
            Ok(Command::Auth("NTLM".to_owned(), None)),
            "auth NTLM".parse::<Command>(),
        );

        assert_eq!(Ok(Command::Http), "GET / HTTP/1.0".parse());
        assert_eq!(Ok(Command::Http), "HEAD /favicon HTTP/1.1".parse());
        assert_eq!(
            Ok(Command::Http),
            "PUT /../../../etc/passwd HTTP/1.0".parse()
        );
        assert_eq!(Ok(Command::Http), "POST /adminmyphp HTTP/1.2".parse());
        assert_eq!(Ok(Command::Http), "DELETE /bar HTTP/1.0".parse());
        assert_eq!(Ok(Command::Http), "OPTIONS * HTTP/1.1".parse());
    }
}
