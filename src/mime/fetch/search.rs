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

//! Support for retrieving data from a message needed for search.
//!
//! This does not implement searching itself.
//!
//! The system is built around gathering data into the `SearchData` structure
//! and invoking an evaluation function as data is obtained. The evaluation
//! function can return `Some(true)` or `Some(false)` to indicate that the
//! result of the search is known and no more data is needed, or `None` to
//! indicate that the result depends on data not yet available.

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::mem;
use std::rc::Rc;
use std::str;

use bitflags::bitflags;
use chrono::prelude::*;

use super::strings::*;
use crate::account::model::*;
use crate::mime::content_encoding::ContentDecoder;
use crate::mime::grovel::Visitor;
use crate::mime::header;

const READ_LIMIT: usize = 131072;

bitflags! {
    /// Message properties that are optional as part of the search process.
    ///
    /// I.e., these are things that may be encountered naturally before inputs
    /// that actually contribute to the search result and can be usefully
    /// skipped.
    pub struct OptionalSearchParts: u32 {
        const FLAGS = 1 << 0;
        const HEADER_MAP = 1 << 1;
        const FROM = 1 << 2;
        const CC = 1 << 3;
        const BCC = 1 << 4;
        const TO = 1 << 5;
        const DATE = 1 << 6;
        const SUBJECT = 1 << 7;
    }
}

/// Data which can be fetched as part of the search process.
///
/// A field is `None` if it its value is still unknown. If the value is known
/// to be absent, it is set to `Some("")`.
#[derive(Debug, Clone, Default)]
pub struct SearchData {
    pub uid: Option<Uid>,
    pub last_modified: Option<Modseq>,
    pub flags: Option<Vec<Flag>>,
    pub recent: Option<bool>,

    pub metadata: Option<MessageMetadata>,

    /// All headers on the message, with encoded words decoded.
    ///
    /// Header names are lowercase.
    ///
    /// Encoded word decoding is done irrespective of per-header syntax; in
    /// essence, every header is treated as an unstructured string. This also
    /// means that comments remain in this text.
    ///
    /// Whitespace is not collapsed; the search system should instead prepare
    /// the regex it uses to match the uncollapsed whitespace.
    ///
    /// If multiple values of the same header are found, they are concatenated,
    /// separated with a NUL character.
    pub headers: Option<HashMap<String, String>>,
    /// The From header, in "normalised" format.
    ///
    /// RFC 3501 does not define what it means to search for a substring in any
    /// of the addressing fields. In the IMAP mailing list, Crispin recommends
    /// putting it into some sort of normalised format, primarily so that a
    /// query like `<foo@bar.com>` can be used to match an email exactly. Here,
    /// we put the address list into a sort of naïve normalised format: display
    /// names are wrapped in double quotes (but not escaped, so products like
    /// `"Foo "Bar"` are possible), emails are surrounded by angle brackets,
    /// and groups are more or less in RFC 5322 syntax.
    pub from: Option<String>,
    /// The CC header, in "normalised" format (see `from`).
    pub cc: Option<String>,
    /// The BCC header, in "normalised" format (see `from`).
    pub bcc: Option<String>,
    /// The To header, in "normalised" format (see `from`).
    pub to: Option<String>,
    /// The Date header.
    pub date: Option<DateTime<FixedOffset>>,
    /// The Subject header, decoded.
    pub subject: Option<String>,

    /// A concatenation of `text` sections, fully decoded and converted to
    /// UTF-8. Each section is terminated with a NUL character.
    pub content: Option<String>,
}

/// Fetches search data from a message, stopping only when the evaluation
/// function `F` produces a result.
pub struct SearchFetcher<F> {
    eval: F,
    data: SearchData,
    want: OptionalSearchParts,

    headers: HashMap<String, String>,
    content_accumulator: ContentDecoder<ContentAccumulator>,
    bytes_scanned: usize,
}

#[derive(Debug)]
struct ContentAccumulator {
    dst: Rc<RefCell<String>>,
    collect_content: bool,
}

impl<F> fmt::Debug for SearchFetcher<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("SearchFetcher")
            .field("eval", &"<function>")
            .field("data", &self.data)
            .field("want", &self.want)
            .field("headers", &self.headers)
            .field("content_accumulator", &self.content_accumulator)
            .field("bytes_scanned", &self.bytes_scanned)
            .finish()
    }
}

impl<F: FnMut(&SearchData) -> Option<bool>> SearchFetcher<F> {
    /// Create a new `SearchFetcher` which only forces a fetch of the optional
    /// components given by `want`, and uses `eval` to evaluate the final
    /// result.
    pub fn new(want: OptionalSearchParts, eval: F) -> Self {
        SearchFetcher {
            eval,
            data: SearchData::default(),
            want,
            headers: HashMap::new(),
            content_accumulator: ContentDecoder::new(
                Box::new(ContentAccumulator {
                    dst: Rc::new(RefCell::new(String::new())),
                    collect_content: false,
                }),
                true,
            ),
            bytes_scanned: 0,
        }
    }
}

impl<F: FnMut(&SearchData) -> Option<bool>> Visitor for SearchFetcher<F> {
    type Output = bool;

    fn raw_line(&mut self, line: &[u8]) -> Result<(), bool> {
        self.bytes_scanned += line.len();
        if self.bytes_scanned >= READ_LIMIT {
            Err(self.end())
        } else {
            Ok(())
        }
    }

    fn uid(&mut self, uid: Uid) -> Result<(), bool> {
        self.data.uid = Some(uid);
        // Don't waste time eval()ing this step
        Ok(())
    }

    fn last_modified(&mut self, modseq: Modseq) -> Result<(), bool> {
        self.data.last_modified = Some(modseq);
        self.eval()
    }

    fn want_flags(&self) -> bool {
        self.want.contains(OptionalSearchParts::FLAGS)
    }

    fn flags(&mut self, flags: &[Flag]) -> Result<(), bool> {
        self.data.flags = Some(flags.to_owned());
        Ok(())
    }

    fn recent(&mut self) -> Result<(), bool> {
        self.data.recent = Some(true);
        Ok(())
    }

    fn end_flags(&mut self) -> Result<(), bool> {
        self.data.flags.get_or_insert_with(Vec::new);
        self.data.recent.get_or_insert(false);
        self.eval()
    }

    fn metadata(&mut self, md: &MessageMetadata) -> Result<(), bool> {
        self.data.metadata = Some(md.to_owned());
        self.eval()
    }

    fn header(
        &mut self,
        raw: &[u8],
        name: &str,
        value: &[u8],
    ) -> Result<(), bool> {
        let _ = self.content_accumulator.header(raw, name, value);

        if self.want.contains(OptionalSearchParts::HEADER_MAP) {
            let mut name = name.to_owned();
            let value = decode_unstructured(Cow::Borrowed(value));
            name.make_ascii_lowercase();
            self.headers
                .entry(name)
                .and_modify(|v| {
                    v.push('\0');
                    v.push_str(&value);
                })
                .or_insert(value);
        }

        if "From".eq_ignore_ascii_case(name) {
            self.address_header(
                OptionalSearchParts::FROM,
                |d| &mut d.from,
                value,
            )
        } else if "CC".eq_ignore_ascii_case(name) {
            self.address_header(OptionalSearchParts::CC, |d| &mut d.cc, value)
        } else if "BCC".eq_ignore_ascii_case(name) {
            self.address_header(OptionalSearchParts::BCC, |d| &mut d.bcc, value)
        } else if "To".eq_ignore_ascii_case(name) {
            self.address_header(OptionalSearchParts::TO, |d| &mut d.to, value)
        } else if "Date".eq_ignore_ascii_case(name) {
            if self.want.contains(OptionalSearchParts::DATE) {
                self.data.date =
                    str::from_utf8(value).ok().and_then(header::parse_datetime);
                self.eval()
            } else {
                Ok(())
            }
        } else if "Subject".eq_ignore_ascii_case(name) {
            if self.want.contains(OptionalSearchParts::SUBJECT) {
                self.data.subject =
                    Some(decode_unstructured(Cow::Borrowed(value)));
                self.eval()
            } else {
                Ok(())
            }
        } else {
            Ok(())
        }
    }

    fn start_content(&mut self) -> Result<(), bool> {
        let _ = self.content_accumulator.start_content();
        self.finish_headers();
        self.eval()
    }

    fn content_type(
        &mut self,
        ct: &header::ContentType<'_>,
    ) -> Result<(), bool> {
        self.content_accumulator
            .content_type(ct)
            // This case happens if the top-level content type of a message is
            // something non-text. In this case, we do want to end quickly, but
            // we do need to eval the actual result.
            .map_err(|_| self.end())
    }

    fn content(&mut self, data: &[u8]) -> Result<(), bool> {
        self.content_accumulator
            .content(data)
            // This case doesn't currently happen, but we might as well handle
            // it as if it did.
            .map_err(|_| self.end())
    }

    fn start_part(&mut self) -> Option<Box<dyn Visitor<Output = bool>>> {
        self.content_accumulator.start_part()
    }

    fn end(&mut self) -> bool {
        self.content_accumulator.end();

        // Make sure all fields are set so we can evaluate to *something*.
        self.data.uid.get_or_insert(Uid::MIN);
        self.data.last_modified.get_or_insert(Modseq::MIN);
        self.data.flags.get_or_insert_with(Vec::new);
        self.data.recent.get_or_insert(false);
        self.data.metadata.get_or_insert_with(|| MessageMetadata {
            size: 0,
            internal_date: FixedOffset::east(0).timestamp_millis(0),
            email_id: Default::default(),
        });
        self.finish_headers();
        self.data.content = Some(
            self.content_accumulator
                .inner_mut()
                .dst
                .replace(String::new()),
        );

        self.eval()
            .err()
            .expect("Failed to eval() to something after all fields set")
    }
}

impl<F: FnMut(&SearchData) -> Option<bool>> SearchFetcher<F> {
    fn finish_headers(&mut self) {
        if self.data.headers.is_none() {
            self.data.headers =
                Some(mem::replace(&mut self.headers, HashMap::new()));
        }
        self.data.from.get_or_insert_with(String::new);
        self.data.cc.get_or_insert_with(String::new);
        self.data.bcc.get_or_insert_with(String::new);
        self.data.to.get_or_insert_with(String::new);
        self.data
            .date
            .get_or_insert_with(|| FixedOffset::east(0).timestamp_millis(0));
        self.data.subject.get_or_insert_with(String::new);
    }

    fn eval(&mut self) -> Result<(), bool> {
        match (self.eval)(&self.data) {
            Some(r) => Err(r),
            None => Ok(()),
        }
    }

    fn address_header(
        &mut self,
        kind: OptionalSearchParts,
        accessor: impl FnOnce(&mut SearchData) -> &mut Option<String>,
        value: &[u8],
    ) -> Result<(), bool> {
        fn push_mailbox(dst: &mut String, mailbox: header::Mailbox<'_>) {
            dst.push('"');
            dst.push_str(&decode_phrase(mailbox.name));
            dst.push_str("\" <");
            dst.push_str(&decode_dotted(mailbox.addr.local));
            dst.push('@');
            dst.push_str(&decode_dotted(mailbox.addr.domain));
            dst.push_str(">, ");
        }

        if !self.want.contains(kind) {
            return Ok(());
        }

        let mut result = String::with_capacity(value.len() + 16);
        let parsed = header::parse_address_list(value).unwrap_or_else(Vec::new);
        for address in parsed {
            match address {
                header::Address::Mailbox(mailbox) => {
                    push_mailbox(&mut result, mailbox);
                },
                header::Address::Group(group) => {
                    result.push('"');
                    result.push_str(&decode_phrase(group.name));
                    result.push_str("\": ");
                    for mailbox in group.boxes {
                        push_mailbox(&mut result, mailbox);
                    }
                    result.push_str("; ");
                },
            }
        }

        *accessor(&mut self.data) = Some(result);
        self.eval()
    }
}

impl Visitor for ContentAccumulator {
    // We don't do anything useful with this; it's just so that we have a
    // compatible type signature with the top-level visitor. This visitor only
    // returns a value if it finds it is not useful to go on or when it ends.
    type Output = bool;

    fn content_type(
        &mut self,
        ct: &header::ContentType<'_>,
    ) -> Result<(), bool> {
        if ct.is_type("text") {
            // Useful data
            self.collect_content = true;
            Ok(())
        } else if ct.is_type("multipart") || ct.is_type("message") {
            // Not useful data here, but we *are* interested in the children
            Ok(())
        } else {
            // Not useful, and this is a leaf
            Err(false)
        }
    }

    fn content(&mut self, data: &[u8]) -> Result<(), bool> {
        if self.collect_content {
            // We can only get non-UTF-8 data here if the text encoding is not
            // recognised. In this case, we just lossily coerce it to UTF-8 and
            // hope for the best.
            self.dst
                .borrow_mut()
                .push_str(&String::from_utf8_lossy(data));
        }
        Ok(())
    }

    fn start_part(
        &mut self,
    ) -> Option<Box<dyn Visitor<Output = Self::Output>>> {
        Some(Box::new(ContentAccumulator {
            dst: Rc::clone(&self.dst),
            collect_content: false,
        }))
    }

    fn end(&mut self) -> bool {
        let _ = self.content(&[0]);
        false
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::mime::grovel;

    fn parse(message: &str) -> SearchData {
        let message = message.replace('\n', "\r\n");
        let accessor = grovel::SimpleAccessor {
            uid: Uid::u(42),
            last_modified: Modseq::new(Uid::u(56), Cid(100)),
            recent: true,
            flags: vec![Flag::Flagged],
            metadata: MessageMetadata {
                size: 12345,
                internal_date: FixedOffset::east(3600).timestamp_millis(1000),
                email_id: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            },
            data: message.into(),
        };

        let capture = Rc::new(RefCell::new(SearchData::default()));
        let capture2 = Rc::clone(&capture);

        grovel::grovel(
            &accessor,
            SearchFetcher::new(OptionalSearchParts::all(), move |sd| {
                if sd.content.is_some() {
                    *capture2.borrow_mut() = sd.clone();
                    Some(true)
                } else {
                    None
                }
            }),
        )
        .unwrap();

        Rc::try_unwrap(capture).unwrap().into_inner()
    }

    #[test]
    fn parse_all_the_things() {
        let result = parse(
            "\
date: Fri, 21 Nov 1997 09:55:06 -0600
from: foo@bar.com, \"John Doe\" <jdoe@bar.com>
to: Some Mailing List: a@b.com, c@d.com
cc: =?utf-8?q?Nobody_in_particular?= <nobody@example.com>
bcc: Undisclosed Recipients:;
subject: =?utf-8?q?Hello_world?=
XYzzY: =?utf-8?b?bm90aGluZyBoYXBwZW5z?=
xYzzY: plugh
content-type: text/plain

This is the content.
",
        );

        assert_eq!(Some(Uid::u(42)), result.uid);
        assert_eq!(
            Some(Modseq::new(Uid::u(56), Cid(100))),
            result.last_modified
        );
        assert_eq!(Some(true), result.recent);
        assert_eq!(Some(vec![Flag::Flagged]), result.flags);
        assert_eq!(12345, result.metadata.as_ref().unwrap().size);
        assert_eq!(
            "1970-01-01T01:00:01+01:00",
            result.metadata.as_ref().unwrap().internal_date.to_rfc3339()
        );

        assert_eq!("nothing happens\0plugh", result.headers.unwrap()["xyzzy"]);

        // The exact format of the from/cc/bcc/to fields isn't that sensitive
        assert_eq!(
            "\"\" <foo@bar.com>, \"John Doe\" <jdoe@bar.com>, ",
            result.from.unwrap()
        );
        assert_eq!(
            "\"Some Mailing List\": \"\" <a@b.com>, \"\" <c@d.com>, ; ",
            result.to.unwrap()
        );
        assert_eq!(
            "\"Nobody in particular\" <nobody@example.com>, ",
            result.cc.unwrap()
        );
        assert_eq!("\"Undisclosed Recipients\": ; ", result.bcc.unwrap());

        assert_eq!("Hello world", result.subject.unwrap());
        assert_eq!(
            "1997-11-21T09:55:06-06:00",
            result.date.unwrap().to_rfc3339()
        );

        assert_eq!("This is the content.\r\n\0", result.content.unwrap());
    }

    #[test]
    fn parse_multipart() {
        let result = parse(
            "\
Content-Type: multipart/mixed; boundary=bound

This is the prologue.

--bound
Content-Type: text/plain

Content A
--bound
Content-Type: application/octet-stream

Content B, ignored since it's not text
--bound
Content-Type: multipart/alternative; boundary=sub

More prologue
--sub
Content-Type: text/html

Content C
--sub--
Inner epilogue
--bound--
Outer epilogue
",
        );
        assert_eq!("Content A\0Content C\0", result.content.unwrap());
    }

    #[test]
    fn parse_encoded() {
        let result = parse(
            "Content-Type: text/plain; charset=\"SHIFT-JIS\"\n\
             Content-Transfer-Encoding: base64\n\
             \n\
             iOqPj4LJiOqU1IuWgrOC6oLIgqKCsYLGgvCCtYLmgqQ=\n",
        );
        assert_eq!(
            "一緒に一番許されないことをしよう\0",
            result.content.unwrap()
        );
    }
}
