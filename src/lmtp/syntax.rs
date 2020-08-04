//-
// Copyright (c) 2020 Jason Lingle
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
    /// LHLO origin-host ignored...
    Lhlo(String),
    /// MAIL FROM:<return-path>
    MailFrom(String),
    /// RCPT TO:<ignored...:email>
    Recipient(String),
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
}

static SIMPLE_COMMANDS: &[(&str, Command, bool)] = &[
    ("DATA", Command::Data, false),
    ("RSET", Command::Reset, false),
    ("VRFY ", Command::Verify, true),
    ("EXPN ", Command::Expand, true),
    ("HELP", Command::Help, true),
    ("NOOP", Command::Noop, false),
    ("QUIT", Command::Quit, false),
    ("STARTTLS", Command::StartTls, false),
];

lazy_static! {
    static ref RX_LHLO: Regex = Regex::new("^(?i)LHLO ([^ ]*)").unwrap();
    static ref RX_MAIL: Regex = Regex::new(
        "^(?i)MAIL FROM:<([^>]*)>\
                    (?: BODY=(?:7BIT|8BIT|BINARYMIME))*$"
    )
    .unwrap();
    static ref RX_RCPT: Regex =
        Regex::new("^(?i)RCPT TO:<(?:@[^:]+:)?([^>]+)>$").unwrap();
    static ref RX_BDAT: Regex =
        Regex::new("^(?i)BDAT ([0-9]+)( LAST)?$").unwrap();
    static ref RX_KNOWN_COMMANDS: Regex = Regex::new(
        "^(?i)(DATA|RSET|VRFY|EXPN|HELP|NOOP|QUIT|\
                    STARTTLS|LHLO|MAIL|RCPT|BDAT)( .*)?$"
    )
    .unwrap();
    static ref RX_HELO_EHLO: Regex =
        Regex::new("^(?i)(HELO|EHLO)( .*)?$").unwrap();
}

pub fn looks_like_known_command(s: &str) -> bool {
    RX_KNOWN_COMMANDS.is_match(s)
}

pub fn looks_like_smtp_helo(s: &str) -> bool {
    RX_HELO_EHLO.is_match(s)
}

impl FromStr for Command {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, ()> {
        for &(prefix, ref cmd, allow_trailing_garbage) in SIMPLE_COMMANDS {
            if s.len() >= prefix.len()
                && (allow_trailing_garbage || s.len() == prefix.len())
                && s.get(0..prefix.len())
                    .map_or(false, |sp| prefix.eq_ignore_ascii_case(sp))
            {
                return Ok(cmd.clone());
            }
        }

        if let Some(cap) = RX_LHLO.captures(s) {
            Ok(Command::Lhlo(cap.get(1).unwrap().as_str().to_owned()))
        } else if let Some(cap) = RX_MAIL.captures(s) {
            Ok(Command::MailFrom(cap.get(1).unwrap().as_str().to_owned()))
        } else if let Some(cap) = RX_RCPT.captures(s) {
            Ok(Command::Recipient(cap.get(1).unwrap().as_str().to_owned()))
        } else if let Some(cap) = RX_BDAT.captures(s) {
            cap.get(1)
                .unwrap()
                .as_str()
                .parse::<u64>()
                .map_err(|_| ())
                .map(|len| Command::BinaryData(len, cap.get(2).is_some()))
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
            Ok(Command::Lhlo("foo.example.com".to_owned())),
            "LHLO foo.example.com".parse()
        );
        assert_eq!(
            Ok(Command::Lhlo("foo.example.com".to_owned())),
            "lhlo foo.example.com some client implementation".parse()
        );

        assert_eq!(
            Ok(Command::MailFrom("foo@bar.com".to_owned())),
            "MAIL FROM:<foo@bar.com>".parse()
        );
        assert_eq!(
            Ok(Command::MailFrom("foo@bar.com".to_owned())),
            "MAIL FROM:<foo@bar.com> BODY=BiNaRyMiMe".parse()
        );
        assert_eq!(
            Ok(Command::MailFrom("foo@bar.com".to_owned())),
            "MAIL FROM:<foo@bar.com> body=8bit".parse()
        );
        assert_eq!(
            Ok(Command::MailFrom("foo@bar.com".to_owned())),
            "MAIL FROM:<foo@bar.com> body=7bit".parse()
        );
        assert_eq!(
            Ok(Command::MailFrom(String::new())),
            "mail from:<>".parse()
        );

        assert_eq!(
            Ok(Command::Recipient("userc@d.bar.org".to_owned())),
            "RCPT TO:<userc@d.bar.org>".parse()
        );
        assert_eq!(
            Ok(Command::Recipient("userc@d.bar.org".to_owned())),
            "rcpt to:<@hosta.int,@jkl.org:userc@d.bar.org>".parse()
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
        assert_eq!(Err(()), "VRFY".parse::<Command>());

        assert_eq!(Ok(Command::Help), "HELP".parse());
        assert_eq!(Ok(Command::Help), "help me".parse());

        assert_eq!(Ok(Command::Noop), "NOOP".parse());
        assert_eq!(Err(()), "NOOP NOP".parse::<Command>());

        assert_eq!(Ok(Command::Quit), "QUIT".parse());
        assert_eq!(Err(()), "QUIT NOW".parse::<Command>());

        assert_eq!(Ok(Command::StartTls), "STARTTLS".parse());
        assert_eq!(Err(()), "STARTTLS 1.3".parse::<Command>());
    }
}
