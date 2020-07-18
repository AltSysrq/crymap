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

use crate::mime::utf7;

/// Represents a mailbox name which may be in UTF-8 or wire format.
///
/// This structure deals with the fact that mailbox names can have two
/// interpretations depending on whether the client has enabled `UTF8=ACCEPT`
/// or `IMAP4rev2`.
///
/// A `MailboxName` value is necessarily bound conceptually to a single
/// connection, and cannot be held across command boundaries, since the meaning
/// of "wire format" can vary between connections or across an `ENABLE`
/// command.
///
/// ## On UTF-8 and MUTF7:
///
/// Our interpretation is that once the client enables sending UTF-8 mailbox
/// names over the wire, MUTF7 no longer happens.
///
/// RFC 6855 is actually horribly vague on this point:
///
/// > All IMAP servers that support "UTF8=ACCEPT" SHOULD accept UTF-8 in
/// > mailbox names, and those that also support the Mailbox International
/// > Naming Convention described in RFC 3501, Section 5.1.3, MUST accept
/// > UTF8-quoted mailbox names and convert them to the appropriate
/// > internal format.  Mailbox names MUST comply with the Net-Unicode
/// > Definition ([RFC5198], Section 2) with the specific exception that
/// > they MUST NOT contain control characters (U+0000-U+001F and U+0080-U+
/// > 009F), a delete character (U+007F), a line separator (U+2028), or a
/// > paragraph separator (U+2029).
///
/// We MUST support UTF-8 mailbox names, as expected, but it doesn't say
/// whether we are expected to stop MUTF7 or keep doing it.
///
/// The IMAP4rev2 draft doesn't provide guidance here either:
///
/// > Support for the Mailbox International Naming Convention described in
/// > this section is not required for IMAP4rev2-only clients and servers.
/// >
/// > By convention, international mailbox names in IMAP4rev1 are specified
/// > using a modified version of the UTF-7 encoding described in [UTF-7].
/// > Modified UTF-7 may also be usable in servers that implement an
/// > earlier version of this protocol.
///
/// All that follows is a description of how MUTF7 works.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MailboxName<'a> {
    /// Whether `raw` is in UTF-8 format or wire format.
    pub utf8: bool,
    /// The possibly M-UTF7 string representation of this name.
    pub raw: Cow<'a, str>,
}

impl<'a> MailboxName<'a> {
    /// Construct a new `MailboxName` in UTF-8 format.
    pub fn of_utf8(utf8_name: Cow<'a, str>) -> Self {
        MailboxName {
            utf8: true,
            raw: utf8_name,
        }
    }

    /// Construct a new `MailboxName` in wire format.
    pub fn of_wire(wire_name: Cow<'a, str>) -> Self {
        MailboxName {
            utf8: false,
            raw: wire_name,
        }
    }

    /// Return the UTF-8 representation of this `MailboxName`.
    ///
    /// If the underlying string is already UTF-8 or `unicode_aware` indicates
    /// that the wire format is also UTF-8, returns the raw value. Otherwise,
    /// runs UTF-7 decoding on the value and returns that.
    pub fn get_utf8<'b>(&'b self, unicode_aware: bool) -> Cow<'b, str> {
        if self.utf8 || unicode_aware {
            self.raw.clone()
        } else {
            utf7::IMAP.decode(&self.raw)
        }
    }
}
