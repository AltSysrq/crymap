//-
// Copyright (c) 2020, Jason Lingle
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
use std::mem;
use std::str;

use bitflags::bitflags;

use super::strings::*;
use crate::mime::grovel::{self, Visitor as _};
use crate::mime::header;

/// The `ENVELOPE` structure defined by RFC 3501, in the order the fields are
/// to be sent.
#[derive(Debug, Clone, Default)]
pub struct Envelope {
    /// The `Date` header.
    ///
    /// RFC 3501 forbids this from being empty since it is a required field in
    /// RFC 2822, but offers no guidance of what the server should do if it
    /// nonetheless encounters such a message.
    pub date: Option<String>,
    /// The `Subject` header, decoded.
    pub subject: Option<String>,
    /// The `From` header, decoded.
    ///
    /// RFC 3501 states that
    ///
    /// > Note: [RFC-2822] requires that all messages have a valid
    /// > From header.  Therefore, the from, sender, and reply-to
    /// > members in the envelope can not be NIL.
    ///
    /// However, messages with no `From` header, or at least no intelligible
    /// `From` header, do exist in the wild. For these, we break the
    /// requirement and return NIL.
    pub from: Vec<EnvelopeAddress>,
    /// The `Sender` header, decoded.
    ///
    /// If empty, copy `from`.
    pub sender: Vec<EnvelopeAddress>,
    /// The `Reply-To` header, decoded.
    ///
    /// If empty, copy `from`.
    pub reply_to: Vec<EnvelopeAddress>,
    /// The `To` header, decoded.
    pub to: Vec<EnvelopeAddress>,
    /// The `CC` header, decoded.
    pub cc: Vec<EnvelopeAddress>,
    /// The `BCC` header, decoded.
    pub bcc: Vec<EnvelopeAddress>,
    /// The `In-Reply-To` header, trimmed.
    pub in_reply_to: Option<String>,
    /// The `Message-ID` header, trimmed.
    pub message_id: Option<String>,
}

bitflags! {
    struct EnvelopeParts: u32 {
        const DATE = 1 << 0;
        const SUBJECT = 1 << 1;
        const FROM = 1 << 2;
        const SENDER = 1 << 3;
        const REPLY_TO = 1 << 4;
        const TO = 1 << 5;
        const CC = 1 << 6;
        const BCC = 1 << 7;
        const IN_REPLY_TO = 1 << 8;
        const MESSAGE_ID = 1 << 9;
    }
}

/// Representation of an email address, or a group fragment, in an RFC 3501
/// `ENVELOPE`.
///
/// Weirdly, though it has the capability of directly representing hierarchical
/// data, RFC 3501 opts to use a weird delimination scheme to encode groups: A
/// group is started with an "address" with a name but no domain, and
/// terminated with an "address" with neither local part nor domain.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvelopeAddress {
    /// The display name if present, decoded.
    pub name: Option<String>,
    /// RFC 3501 includes the RFC 822 routing information, but per RFC 2822 and
    /// later, we discard that unconditionally, so the field must always be
    /// NIL. The () is here as a token reminder.
    pub routing: (),
    /// The local part of the email (RFC 3501 calls it "mailbox name", despite
    /// "mailbox" referring to things like "INBOX" in the same document),
    /// decoded.
    ///
    /// If `None` and `domain` is also `None`, this is a group-end delimiter.
    pub local: Option<String>,
    /// The domain of the email (RFC 3501 calls it "host"), decoded.
    ///
    /// If `None`, this is either a group-start or group-end delimiter,
    /// depending on the value of `local`.
    pub domain: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EnvelopeFetcher {
    envelope: Envelope,
    has_parts: EnvelopeParts,
}

impl EnvelopeFetcher {
    pub fn new() -> Self {
        EnvelopeFetcher {
            envelope: Envelope::default(),
            has_parts: EnvelopeParts::empty(),
        }
    }
}

impl grovel::Visitor for EnvelopeFetcher {
    type Output = Envelope;

    fn header(&mut self, name: &str, value: &[u8]) -> Result<(), Envelope> {
        use EnvelopeParts as E;

        if "Date".eq_ignore_ascii_case(name) {
            self.date(value)
        } else if "Subject".eq_ignore_ascii_case(name) {
            self.unstructured(E::SUBJECT, |e| &mut e.subject, value)
        } else if "From".eq_ignore_ascii_case(name) {
            self.addr_list(E::FROM, |e| &mut e.from, value)
        } else if "Sender".eq_ignore_ascii_case(name) {
            self.addr_list(E::SENDER, |e| &mut e.from, value)
        } else if "Reply-To".eq_ignore_ascii_case(name) {
            self.addr_list(E::REPLY_TO, |e| &mut e.reply_to, value)
        } else if "To".eq_ignore_ascii_case(name) {
            self.addr_list(E::TO, |e| &mut e.to, value)
        } else if "CC".eq_ignore_ascii_case(name) {
            self.addr_list(E::CC, |e| &mut e.cc, value)
        } else if "BCC".eq_ignore_ascii_case(name) {
            self.addr_list(E::BCC, |e| &mut e.bcc, value)
        } else if "In-Reply-To".eq_ignore_ascii_case(name) {
            self.message_id(E::IN_REPLY_TO, |e| &mut e.in_reply_to, value)
        } else if "Message-Id".eq_ignore_ascii_case(name) {
            self.message_id(E::MESSAGE_ID, |e| &mut e.message_id, value)
        } else {
            Ok(())
        }
    }

    fn start_content(&mut self) -> Result<(), Envelope> {
        Err(self.end())
    }

    fn end(&mut self) -> Envelope {
        mem::replace(&mut self.envelope, Envelope::default())
    }
}

impl EnvelopeFetcher {
    fn date(&mut self, value: &[u8]) -> Result<(), Envelope> {
        self.envelope.date = str::from_utf8(value)
            .ok()
            .and_then(header::parse_datetime)
            .map(|dt| dt.to_rfc2822())
            // If we can't parse the date, send whatever we have to the client
            // and let them try to figure it out.
            .or_else(|| Some(String::from_utf8_lossy(value).trim().to_owned()));
        self.complete(EnvelopeParts::DATE)
    }

    fn addr_list(
        &mut self,
        part: EnvelopeParts,
        accessor: impl FnOnce(&mut Envelope) -> &mut Vec<EnvelopeAddress>,
        value: &[u8],
    ) -> Result<(), Envelope> {
        let field = accessor(&mut self.envelope);
        let addrlist = header::parse_address_list(value).unwrap_or(Vec::new());
        for address in addrlist {
            match address {
                header::Address::Mailbox(mailbox) => {
                    field.push(to_envelope_address(mailbox))
                }
                header::Address::Group(group) => {
                    field.push(EnvelopeAddress {
                        name: None,
                        routing: (),
                        // Bizarrely, despite there being a field for the
                        // display name, RFC 3501 has us put the display name
                        // of groups into the local part...
                        local: Some(decode_phrase(group.name)),
                        domain: None,
                    });
                    for mbox in group.boxes {
                        field.push(to_envelope_address(mbox));
                    }
                    field.push(EnvelopeAddress {
                        name: None,
                        routing: (),
                        local: None,
                        domain: None,
                    });
                }
            }
        }

        self.complete(part)
    }

    fn unstructured(
        &mut self,
        part: EnvelopeParts,
        accessor: impl FnOnce(&mut Envelope) -> &mut Option<String>,
        value: &[u8],
    ) -> Result<(), Envelope> {
        *accessor(&mut self.envelope) =
            Some(decode_unstructured(Cow::Borrowed(value)));
        self.complete(part)
    }

    fn message_id(
        &mut self,
        part: EnvelopeParts,
        accessor: impl FnOnce(&mut Envelope) -> &mut Option<String>,
        value: &[u8],
    ) -> Result<(), Envelope> {
        *accessor(&mut self.envelope) =
            header::parse_message_id(value).map(|v| v.to_owned());
        self.complete(part)
    }

    fn complete(&mut self, part: EnvelopeParts) -> Result<(), Envelope> {
        self.has_parts |= part;
        if self.has_parts.is_all() {
            Err(self.end())
        } else {
            Ok(())
        }
    }
}

fn to_envelope_address(mbox: header::Mailbox) -> EnvelopeAddress {
    EnvelopeAddress {
        name: Some(decode_phrase(mbox.name)).filter(|s| !s.is_empty()),
        routing: (),
        local: Some(decode_dotted(mbox.addr.local)),
        domain: Some(decode_dotted(mbox.addr.domain)),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn parse(message: &str) -> Envelope {
        let message = message.replace('\n', "\r\n");
        grovel::grovel(
            &grovel::SimpleAccessor {
                data: message.into(),
                ..grovel::SimpleAccessor::default()
            },
            EnvelopeFetcher::new(),
        )
        .unwrap()
    }

    #[test]
    fn parse_simple() {
        let envelope = parse(
            "\
Message-ID: <4102090.1075845189404.JavaMail.evans@thyme>
Date: Mon, 14 May 2001 19:36:00 -0700 (PDT)
From: vmartinez@winstead.com
To: kenneth.lay@enron.com
Subject: Request for meeting -- Subject: short speech to US Olympic Commit
\ttee 7.16-19.01
Mime-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
X-From: Martinez, Vidal  <VMartinez@winstead.com>
X-To: Kenneth L. Lay (E-mail)  <kenneth.lay@enron.com>
X-cc:
X-bcc:
X-Folder: \\Lay, Kenneth\\Lay, Kenneth\\Inbox
X-Origin: LAY-K
X-FileName: Lay, Kenneth.pst

",
        );

        assert_eq!("Mon, 14 May 2001 19:36:00 -0700", envelope.date.unwrap());
        assert_eq!(
            "<4102090.1075845189404.JavaMail.evans@thyme>",
            envelope.message_id.unwrap()
        );
        assert_eq!(
            vec![EnvelopeAddress {
                name: None,
                routing: (),
                local: Some("vmartinez".to_owned()),
                domain: Some("winstead.com".to_owned()),
            }],
            envelope.from
        );
        assert_eq!(
            vec![EnvelopeAddress {
                name: None,
                routing: (),
                local: Some("kenneth.lay".to_owned()),
                domain: Some("enron.com".to_owned()),
            }],
            envelope.to
        );
        assert_eq!(
            // "Commit tee" [sic], RFC 5322 makes it abundantly clear that
            // folding does not work the way this client thinks it does;
            // section 2.2.3 in fact kicks off with an example with the Subject
            // header folded, and the one space used to indicate the folding is
            // retained as whitespace.
            "Request for meeting -- Subject: short speech to US \
             Olympic Commit tee 7.16-19.01",
            envelope.subject.unwrap()
        );
    }
}
