//-
// Copyright (c) 2020, 2023, Jason Lingle
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
use std::fmt;
use std::mem;
use std::str;

use openssl::hash::{Hasher, MessageDigest};

use super::envelope::*;
use super::strings::*;
use crate::mime::grovel::Visitor;
use crate::mime::header;

/// The RFC 3501 `BODYSTRUCTURE` structure, sort of.
///
/// The actual `BODYSTRUCTURE` structure is wild and depends on the content
/// type of each part of the message, as well as whether the client requested
/// `BODY` or `BODYSTRUCTURE`.
///
/// This structure is simply the union of every possible field we could need.
/// Every field is computed for every part. A later pass takes this result and
/// transforms it into the more convoluted form suitable for sending to the
/// client.
///
/// This is structure also reflects the saner structure of embedded
/// `message/rfc822` parts as `grovel` --- such a part is treated as a
/// multipart that has exactly one child, the message.
///
/// The RFC 3501 is pretty hard to interpret due to being given in prose and
/// sequential self-amendment and with non-standard names. The actual format is
/// shown below, with § indicating the boundary between "basic" and "extended"
/// fields.
///
/// - `multipart/*`: (child)(child)(...) content-subtype §
///   (content-type-parms) (content-disposition content-disposition-parms)
///   content-language content-location
/// - `message/rfc822`: content-type content-subtype (content-type-parms)
///   content-id content-description content-transfer-encoding size-octets
///   (rfc3501-envelope) (rfc3501-bodystructure) size-lines §
///   md5 (content-disposition content-disposition-parms) content-language
///   content-location
/// - `text/*`: content-type content-subtype (content-type-parms) content-id
///   content-description content-transfer-encoding size-octets size-lines §
///   md5 (content-disposition content-disposition-parms) content-language
///   content-location
/// - `*/*`: content-type content-subtype (content-type-parms) content-id
///   content-description content-transfer-encoding size-octets §
///   md5 (content-disposition content-disposition-parms) content-language
///   content-location
///
/// (Note that RFC 3501 specifies that `content-location` is a string list, but
/// an Erratum published by Crispin changes it to a bare string.)
///
/// See also http://sgerwk.altervista.org/imapbodystructure.html, which unlike
/// the RFC, actually has useful examples, though none including a
/// `message/rfc822`.
#[derive(Debug, Clone, Default)]
pub struct BodyStructure {
    /// The content type and subtype of this part.
    pub content_type: (String, String),
    /// Any parameters on the content type.
    pub content_type_parms: Vec<(String, String)>,
    /// The `Content-Disposition` of this part, if set.
    pub content_disposition: Option<String>,
    /// Any parameters on the `Content-Disposition` header.
    pub content_disposition_parms: Vec<(String, String)>,
    /// The `Content-Language` header, if set.
    pub content_language: Option<String>,
    /// The `Content-Location` header, if set.
    pub content_location: Option<String>,
    /// The `Content-Id` header, if set.
    pub content_id: Option<String>,
    /// The `Content-Description` header, if set, decoded.
    pub content_description: Option<String>,
    /// The `Content-Transfer-Encoding` of this part.
    pub content_transfer_encoding: Option<String>,
    /// The exact length of the content of this part, measured in encoded form
    pub size_octets: u64,
    /// The number of lines of the content of this part, measured in encoded
    /// form.
    pub size_lines: u64,
    /// The lowercase hexadecimal representation of the MD5 of this part's
    /// content.
    pub md5: String,
    /// The envelope extracted from this part's headers.
    pub envelope: Envelope,
    /// If this is a multipart, the parts it contains.
    pub children: Vec<BodyStructure>,
}

pub struct BodyStructureFetcher {
    bs: BodyStructure,
    envelope_fetcher: Option<EnvelopeFetcher>,
    md5_hasher: Hasher,
}

impl fmt::Debug for BodyStructureFetcher {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("BodyStructureFetcher")
            .field("bs", &self.bs)
            .field("envelope_fetcher", &self.envelope_fetcher)
            .field("md5_hasher", &"(Hasher)")
            .finish()
    }
}

impl BodyStructureFetcher {
    pub fn new() -> Self {
        BodyStructureFetcher {
            bs: BodyStructure::default(),
            envelope_fetcher: Some(EnvelopeFetcher::new()),
            md5_hasher: Hasher::new(MessageDigest::md5()).unwrap(),
        }
    }
}

impl Visitor for BodyStructureFetcher {
    type Output = BodyStructure;

    fn header(
        &mut self,
        raw: &[u8],
        name: &str,
        value: &[u8],
    ) -> Result<(), Self::Output> {
        self.on_envelope(|e| e.header(raw, name, value));

        if "Content-Disposition".eq_ignore_ascii_case(name) {
            self.content_disposition(value);
        } else if "Content-Language".eq_ignore_ascii_case(name) {
            self.content_language(value);
        } else if "Content-Location".eq_ignore_ascii_case(name) {
            self.content_location(value);
        } else if "Content-Id".eq_ignore_ascii_case(name) {
            self.content_id(value);
        } else if "Content-Description".eq_ignore_ascii_case(name) {
            self.content_description(value);
        } else if "Content-Transfer-Encoding".eq_ignore_ascii_case(name) {
            self.content_transfer_encoding(value);
        }

        Ok(())
    }

    fn content_type(
        &mut self,
        ct: &header::ContentType<'_>,
    ) -> Result<(), Self::Output> {
        self.bs.content_type = (
            String::from_utf8_lossy(&ct.typ).into_owned(),
            String::from_utf8_lossy(&ct.subtype).into_owned(),
        );
        extend_parms(&mut self.bs.content_type_parms, &ct.parms);

        Ok(())
    }

    fn start_content(&mut self) -> Result<(), Self::Output> {
        self.on_envelope(|e| e.start_content());
        Ok(())
    }

    fn content(&mut self, data: &[u8]) -> Result<(), Self::Output> {
        self.md5_hasher.update(data).unwrap();
        self.bs.size_octets += data.len() as u64;
        // Naïvely counting line endings is sufficient to count lines.
        // Line-oriented formats are generally required to end with a
        // properly-terminated line, so we only compute an arguably incorrect
        // value for things that aren't line-oriented. Crispin's "answer key"
        // for the "torture test" also uses this interpretation.
        self.bs.size_lines += memchr::memchr_iter(b'\n', data).count() as u64;
        Ok(())
    }

    fn start_part(
        &mut self,
    ) -> Option<Box<dyn Visitor<Output = BodyStructure>>> {
        Some(Box::new(BodyStructureFetcher::new()))
    }

    fn child_result(
        &mut self,
        child: BodyStructure,
    ) -> Result<(), Self::Output> {
        self.bs.children.push(child);
        Ok(())
    }

    fn end(&mut self) -> Self::Output {
        self.on_envelope(|e| Err(e.end()));
        let mut md5 = String::with_capacity(32);
        for &byte in self.md5_hasher.finish().unwrap().as_ref() {
            md5.push_str(&format!("{:02x}", byte));
        }

        self.bs.md5 = md5;

        mem::take(&mut self.bs)
    }
}

impl BodyStructureFetcher {
    fn on_envelope(
        &mut self,
        f: impl FnOnce(&mut EnvelopeFetcher) -> Result<(), Envelope>,
    ) {
        let r = self.envelope_fetcher.as_mut().map(f).unwrap_or(Ok(()));
        if let Err(e) = r {
            self.envelope_fetcher = None;
            self.bs.envelope = e;
        }
    }

    fn content_disposition(&mut self, value: &[u8]) {
        if let Some(cd) = header::parse_content_disposition(value) {
            self.bs.content_disposition =
                Some(String::from_utf8_lossy(&cd.disposition).into_owned());
            extend_parms(&mut self.bs.content_disposition_parms, &cd.parms);
        }
    }

    fn content_language(&mut self, value: &[u8]) {
        self.bs.content_language = header::parse_content_language(value)
            .map(|s| String::from_utf8_lossy(s).into_owned())
    }

    fn content_location(&mut self, value: &[u8]) {
        self.bs.content_location =
            header::parse_content_location(value).map(str::to_owned);
    }

    fn content_id(&mut self, value: &[u8]) {
        self.bs.content_id = header::parse_message_id(value).map(str::to_owned);
    }

    fn content_description(&mut self, value: &[u8]) {
        self.bs.content_description =
            Some(decode_unstructured(Cow::Borrowed(value)));
    }

    fn content_transfer_encoding(&mut self, value: &[u8]) {
        self.bs.content_transfer_encoding =
            header::parse_content_transfer_encoding_raw(value)
                .map(|v| v.to_owned())
    }
}

fn extend_parms(
    dst: &mut Vec<(String, String)>,
    parms: &[(Cow<[u8]>, Cow<[u8]>)],
) {
    for &(ref name, ref value) in parms {
        if let (Ok(name), Ok(value)) =
            (str::from_utf8(name), str::from_utf8(value))
        {
            if !name.is_empty() && !value.is_empty() {
                dst.push((name.to_owned(), value.to_owned()));
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::fs;
    use std::path::{Path, PathBuf};

    use chrono::prelude::*;

    use super::*;
    use crate::account::model::*;
    use crate::mime::grovel;
    use crate::support::error::Error;

    fn parse(message: &str) -> BodyStructure {
        let message = message.replace('\n', "\r\n");
        grovel::grovel(
            &grovel::SimpleAccessor {
                data: message.into(),
                ..grovel::SimpleAccessor::default()
            },
            BodyStructureFetcher::new(),
        )
        .unwrap()
    }

    // NB These tests double as the unit tests for `grovel`.
    #[test]
    fn parse_simple() {
        let bs = parse(
            "\
From: foo@bar.com

hello world
",
        );
        assert_eq!(
            vec![EnvelopeAddress {
                name: None,
                routing: None,
                local: Some("foo".to_owned()),
                domain: Some("bar.com".to_owned()),
            }],
            bs.envelope.from
        );

        assert_eq!("text", bs.content_type.0);
        assert_eq!("plain", bs.content_type.1);
        assert_eq!(None, bs.content_transfer_encoding);
        assert_eq!(13, bs.size_octets);
        assert_eq!(1, bs.size_lines);
        assert_eq!("a0f2a3c1dcd5b1cac71bf0c03f2ff1bd", bs.md5);
    }

    #[test]
    fn parse_simple_multipart() {
        let bs = parse(
            "\
From: foo@bar.com
Content-Type: multipart/alternative; boundary=\"bound\"

This is the prologue.

--bound

hello world

--bound
Content-Type: text/html

<html/>
--bound--

This is the epilogue.
",
        );
        assert_eq!("multipart", bs.content_type.0);
        assert_eq!("alternative", bs.content_type.1);
        assert_eq!(
            vec![("boundary".to_owned(), "bound".to_owned())],
            bs.content_type_parms
        );
        assert_eq!(2, bs.children.len());

        assert_eq!("text", bs.children[0].content_type.0);
        assert_eq!("plain", bs.children[0].content_type.1);
        assert_eq!(13, bs.children[0].size_octets);
        assert_eq!(1, bs.children[0].size_lines);
        assert_eq!("a0f2a3c1dcd5b1cac71bf0c03f2ff1bd", bs.children[0].md5);

        assert_eq!("text", bs.children[1].content_type.0);
        assert_eq!("html", bs.children[1].content_type.1);
        // The CRLF after `<html/>` is not part of that part's content, so
        // there is only a single, incomplete line.
        assert_eq!(7, bs.children[1].size_octets);
        assert_eq!(0, bs.children[1].size_lines);
        assert_eq!("7682d345add5f360f96f3c8f359ca5c7", bs.children[1].md5);
    }

    #[test]
    fn parse_minimal_multipart() {
        let bs = parse(
            "\
From: foo@bar.com
Content-Type: multipart/alternative; boundary=\"bound\"

--bound

hello world

--bound--",
        );
        assert_eq!("multipart", bs.content_type.0);
        assert_eq!("alternative", bs.content_type.1);
        assert_eq!(
            vec![("boundary".to_owned(), "bound".to_owned())],
            bs.content_type_parms
        );
        assert_eq!(1, bs.children.len());

        assert_eq!("text", bs.children[0].content_type.0);
        assert_eq!("plain", bs.children[0].content_type.1);
        assert_eq!(13, bs.children[0].size_octets);
        assert_eq!(1, bs.children[0].size_lines);
        assert_eq!("a0f2a3c1dcd5b1cac71bf0c03f2ff1bd", bs.children[0].md5);
    }

    #[test]
    fn parse_simple_embedded_message() {
        let bs = parse(
            "\
From: foo@bar.com
Content-Type: message/rfc822

From: bar@foo.com

hello world
",
        );
        assert_eq!("message", bs.content_type.0);
        assert_eq!("rfc822", bs.content_type.1);
        assert_eq!(1, bs.children.len());

        assert_eq!("text", bs.children[0].content_type.0);
        assert_eq!("plain", bs.children[0].content_type.1);
        assert_eq!(
            vec![EnvelopeAddress {
                name: None,
                routing: None,
                local: Some("bar".to_owned()),
                domain: Some("foo.com".to_owned()),
            }],
            bs.children[0].envelope.from
        );
        assert_eq!(13, bs.children[0].size_octets);
        assert_eq!(1, bs.children[0].size_lines);
        assert_eq!("a0f2a3c1dcd5b1cac71bf0c03f2ff1bd", bs.children[0].md5);
    }

    #[test]
    fn parse_all_headers() {
        let bs = parse(
            "\
content-type: application/xml; charset=\"UTF-8\"
content-disposition: inline; name=\"foo.xml\"
content-language: tlh
content-location: http://example.com/foo
content-id: <contentid@example.com>
content-description: =?us-ascii?q?This_is_a?=
    =?us-ascii?q?=20description?=
content-transfer-encoding: 8bit

<Qapla’/>",
        );

        assert_eq!("application", bs.content_type.0);
        assert_eq!("xml", bs.content_type.1);
        assert_eq!(
            vec![("charset".to_owned(), "UTF-8".to_owned())],
            bs.content_type_parms
        );
        assert_eq!("inline", bs.content_disposition.unwrap());
        assert_eq!(
            vec![("name".to_owned(), "foo.xml".to_owned())],
            bs.content_disposition_parms
        );
        assert_eq!("tlh", bs.content_language.unwrap());
        assert_eq!("http://example.com/foo", bs.content_location.unwrap());
        assert_eq!("<contentid@example.com>", bs.content_id.unwrap());
        assert_eq!("This is a description", bs.content_description.unwrap());
        assert_eq!(Some("8bit".to_owned()), bs.content_transfer_encoding);
    }

    #[test]
    fn parse_nested_multipart() {
        let bs = parse(
            "\
Content-Type: multipart/alternative; boundary=outer

Outer prologue

--outer
Content-Type: multipart/parallel; boundary=inner

Inner 1 prologue

--inner

Content A
--inner

Content B
--inner--
Inner 1 epilogue
--outer
Content-Type: multipart/parallel; boundary=inner

Inner 2 prologue

--inner

Content C
--inner

Content D
--inner--
Inner 2 epilogue
--outer--

Outer epilogue",
        );

        assert_eq!(2, bs.children.len());
        assert_eq!(2, bs.children[0].children.len());
        assert_eq!(
            "0ee839c7c234a29c5072e6469d5054f4",
            bs.children[0].children[0].md5
        );
        assert_eq!(
            "b37336f3bd5b8646798fd9ab65afdde8",
            bs.children[0].children[1].md5
        );
        assert_eq!(2, bs.children[1].children.len());
        assert_eq!(
            "7b8fdf40404049204ed4feb3c8e99480",
            bs.children[1].children[0].md5
        );
        assert_eq!(
            "586fb32b19b9e81470a6e418f22ffa2e",
            bs.children[1].children[1].md5
        );
    }

    #[test]
    fn parse_minimal_nested_multipart() {
        let bs = parse(
            "\
Content-Type: multipart/alternative; boundary=outer

--outer
Content-Type: multipart/parallel; boundary=inner

--inner

Content A
--inner

Content B
--inner--
--outer
Content-Type: multipart/parallel; boundary=inner

--inner

Content C
--inner

Content D
--inner--
--outer--",
        );

        assert_eq!(2, bs.children.len());
        assert_eq!(2, bs.children[0].children.len());
        assert_eq!(
            "0ee839c7c234a29c5072e6469d5054f4",
            bs.children[0].children[0].md5
        );
        assert_eq!(
            "b37336f3bd5b8646798fd9ab65afdde8",
            bs.children[0].children[1].md5
        );
        assert_eq!(2, bs.children[1].children.len());
        assert_eq!(
            "7b8fdf40404049204ed4feb3c8e99480",
            bs.children[1].children[0].md5
        );
        assert_eq!(
            "586fb32b19b9e81470a6e418f22ffa2e",
            bs.children[1].children[1].md5
        );
    }

    #[test]
    fn parse_digest() {
        let bs = parse(
            "\
Content-Type: multipart/digest; boundary=bound

--bound

From: foo@bar.com

Content A

--bound

From: bar@foo.com

Content B

--bound--
",
        );
        assert_eq!(2, bs.children.len());

        assert_eq!("message", bs.children[0].content_type.0);
        assert_eq!("rfc822", bs.children[0].content_type.1);
        assert_eq!(1, bs.children[0].children.len());
        assert_eq!("text", bs.children[0].children[0].content_type.0);
        assert_eq!("plain", bs.children[0].children[0].content_type.1);
        assert_eq!(
            vec![EnvelopeAddress {
                name: None,
                routing: None,
                local: Some("foo".to_owned()),
                domain: Some("bar.com".to_owned()),
            }],
            bs.children[0].children[0].envelope.from
        );
        assert_eq!(
            "83dbaf5d87b23cb7849cf36db562365a",
            bs.children[0].children[0].md5
        );

        assert_eq!("message", bs.children[1].content_type.0);
        assert_eq!("rfc822", bs.children[1].content_type.1);
        assert_eq!(1, bs.children[1].children.len());
        assert_eq!("text", bs.children[1].children[0].content_type.0);
        assert_eq!("plain", bs.children[1].children[0].content_type.1);
        assert_eq!(
            vec![EnvelopeAddress {
                name: None,
                routing: None,
                local: Some("bar".to_owned()),
                domain: Some("foo.com".to_owned()),
            }],
            bs.children[1].children[0].envelope.from
        );
        assert_eq!(
            "7182af2fa6079e8d616316f4a6df7cbe",
            bs.children[1].children[0].md5
        );
    }

    #[test]
    fn strict_binary_boundary_handling() {
        let body0 = "a".repeat(grovel::MAX_BUFFER - 3);
        let body1 = "b".repeat(grovel::MAX_BUFFER - 2);
        let body2 = "c".repeat(grovel::MAX_BUFFER - 1);
        let body3 = "d".repeat(grovel::MAX_BUFFER);
        let body4 = "e".repeat(grovel::MAX_BUFFER + 1);
        let body5 = "\r".repeat(grovel::MAX_BUFFER + 1);

        let bs = parse(&format!(
            "\
Content-Type: multipart/alternative; boundary=bound

--bound
Content-Transfer-Encoding: binary

{}
--bound
Content-Transfer-Encoding: binary

{}
--bound
Content-Transfer-Encoding: binary

{}
--bound
Content-Transfer-Encoding: binary

{}
--bound
Content-Transfer-Encoding: binary

{}
--bound
Content-Transfer-Encoding: binary

{}
--bound--
",
            body0, body1, body2, body3, body4, body5
        ));

        assert_eq!(6, bs.children.len());
        assert_eq!(grovel::MAX_BUFFER - 3, bs.children[0].size_octets as usize);
        assert_eq!(grovel::MAX_BUFFER - 2, bs.children[1].size_octets as usize);
        assert_eq!(grovel::MAX_BUFFER - 1, bs.children[2].size_octets as usize);
        assert_eq!(grovel::MAX_BUFFER, bs.children[3].size_octets as usize);
        assert_eq!(grovel::MAX_BUFFER + 1, bs.children[4].size_octets as usize);
        assert_eq!(grovel::MAX_BUFFER + 1, bs.children[5].size_octets as usize);
    }

    #[test]
    fn parse_truncated_top_level_multipart() {
        let bs = parse(
            "\
Content-Type: multipart/alternative; boundary=bound

--bound

hello world
",
        );
        assert_eq!(1, bs.children.len());
        // Whether the final CRLF is part of the content is undefined; we don't
        // know if there was going to be a boundary immediately after or more
        // content. This implementation happens to exclude it.
        assert_eq!("5eb63bbbe01eeed093cb22bb8f5acdc3", bs.children[0].md5);
    }

    #[test]
    fn parse_truncated_top_nested_multipart() {
        let bs = parse(
            "\
Content-Type: multipart/alternative; boundary=outer

--outer
Content-Type: multipart/alternative; boundary = inner

--inner

hello world
--outer--
",
        );
        assert_eq!(1, bs.children.len());
        assert_eq!(1, bs.children[0].children.len());
        // Whether the final CRLF is part of the content is undefined; we don't
        // know if there was going to be a boundary immediately after or more
        // content. This implementation happens to exclude it.
        assert_eq!(
            "5eb63bbbe01eeed093cb22bb8f5acdc3",
            bs.children[0].children[0].md5
        );
    }

    #[test]
    fn test_recursion_limit() {
        let bs = parse(
            "\
Content-Type: multipart/alternative; boundary=b00

--b00
Content-Type: multipart/alternative; boundary=b01

--b01
Content-Type: multipart/alternative; boundary=b02

--b02
Content-Type: multipart/alternative; boundary=b03

--b03
Content-Type: multipart/alternative; boundary=b04

--b04
Content-Type: multipart/alternative; boundary=b05

--b05
Content-Type: multipart/alternative; boundary=b06

--b06
Content-Type: multipart/alternative; boundary=b07

--b07
Content-Type: multipart/alternative; boundary=b08

--b08
Content-Type: multipart/alternative; boundary=b09

--b09
Content-Type: multipart/alternative; boundary=b10

--b10
Content-Type: multipart/alternative; boundary=b11

--b11
Content-Type: multipart/alternative; boundary=b12

--b12
Content-Type: multipart/alternative; boundary=b13

--b13
Content-Type: multipart/alternative; boundary=b14

--b14
Content-Type: multipart/alternative; boundary=b15

--b15
Content-Type: multipart/alternative; boundary=b16

--b16
Content-Type: multipart/alternative; boundary=b17

--b17
Content-Type: multipart/alternative; boundary=b18

--b18
Content-Type: multipart/alternative; boundary=b19

--b19
Content-Type: multipart/alternative; boundary=b20

--b20
Content-Type: multipart/alternative; boundary=b21

--b21
Content-Type: multipart/alternative; boundary=b22

--b22
Content-Type: multipart/alternative; boundary=b23

--b23
Content-Type: multipart/alternative; boundary=b24

--b24
Content-Type: multipart/alternative; boundary=b25

--b25
Content-Type: multipart/alternative; boundary=b26

--b26
Content-Type: multipart/alternative; boundary=b27

--b27
Content-Type: multipart/alternative; boundary=b28

--b28
Content-Type: multipart/alternative; boundary=b29

--b29
Content-Type: text/plain

hello world
",
        );

        let mut part = Some(&bs);
        while let Some(p) = part.take() {
            assert_ne!("text", p.content_type.0);
            part = p.children.first();
        }
    }

    #[test]
    fn test_part_limit() {
        let mut content = "\
Content-Type: multipart/alternative; boundary=outer

"
        .to_owned();

        for outer in 0..20 {
            content.push_str(&format!(
                "\
--outer
Content-Type: multipart/alternative; boundary=inner{:02}

",
                outer
            ));

            for _inner in 0..200 {
                content.push_str(&format!(
                    "\
--inner{:02}

hello world
",
                    outer
                ));
            }

            content.push_str(&format!("--inner{:02}--\n", outer));
        }

        content.push_str("--outer--\n");

        let bs = parse(&content);
        assert!(bs.children.len() < 20);
    }

    #[test]
    fn torture_test() {
        // Text after > comes from a mailing list post by Mark Crispin on
        // 2007-11-19.
        // > That message has a body structure numbering regime looking like:
        let bs = grovel::grovel(
            &grovel::SimpleAccessor {
                data: crate::test_data::TORTURE_TEST.to_owned().into(),
                ..grovel::SimpleAccessor::default()
            },
            BodyStructureFetcher::new(),
        )
        .unwrap();
        // > 1 TEXT/PLAIN (Explanation);CHARSET=US-ASCII (3 lines)
        // Here and in other parts below, the CHARSET=US-ASCII part is a result
        // of Crispin believing that the IMAP server should insert this as a
        // default. This is neither required by RFC 3501 nor "common sense",
        // since we have no reason to believe the content type is actually
        // ASCII. Thus, we don't check for such defaulting.
        let part = &bs.children[0];
        assert_eq!("TEXT", part.content_type.0);
        assert_eq!("PLAIN", part.content_type.1);
        assert_eq!("Explanation", part.content_description.as_ref().unwrap());
        assert_eq!(3, part.size_lines);
        // > 2 MESSAGE/RFC822 (Rich Text demo) (106 lines)
        // NB Here and below, in our model message/rfc822 is not transparent,
        // so there'll be an extra layer of .children[0]
        let part = &bs.children[1];
        assert_eq!("MESSAGE", part.content_type.0);
        assert_eq!("RFC822", part.content_type.1);
        assert_eq!(
            "Rich Text demo",
            part.content_description.as_ref().unwrap()
        );
        assert_eq!(106, part.size_lines);
        // > 2.1 TEXT/PLAIN;CHARSET=US-ASCII (16 lines)
        let part = &bs.children[1].children[0].children[0];
        assert_eq!("text", part.content_type.0);
        assert_eq!("plain", part.content_type.1);
        assert_eq!(None, part.content_description);
        assert_eq!(16, part.size_lines);
        // > 2.2.1 TEXT/RICHTEXT;CHARSET=US-ASCII (13 lines)
        let part = &bs.children[1].children[0].children[1].children[0];
        assert_eq!("text", part.content_type.0);
        assert_eq!("richtext", part.content_type.1);
        assert_eq!(13, part.size_lines);
        // > 2.3 APPLICATION/ANDREW-INSET (917 bytes)
        let part = &bs.children[1].children[0].children[2];
        assert_eq!("application", part.content_type.0);
        assert_eq!("andrew-inset", part.content_type.1);
        assert_eq!(917, part.size_octets);
        // > 3 MESSAGE/RFC822 (Voice Mail demo) (7605 lines)
        let part = &bs.children[2];
        assert_eq!("MESSAGE", part.content_type.0);
        assert_eq!("RFC822", part.content_type.1);
        assert_eq!(
            "Voice Mail demo",
            part.content_description.as_ref().unwrap()
        );
        assert_eq!(7605, part.size_lines);
        // > 3.1 AUDIO/BASIC (Hi Mark) (561308 bytes)
        // There's no extra .children[0] here since the message is not a
        // multipart.
        let part = &bs.children[2].children[0];
        assert_eq!("audio", part.content_type.0);
        assert_eq!("basic", part.content_type.1);
        assert_eq!("Hi Mark", part.content_description.as_ref().unwrap());
        assert_eq!(561308, part.size_octets);
        // > 4 AUDIO/BASIC (Flint phone) (36234 bytes)
        let part = &bs.children[3];
        assert_eq!("audio", part.content_type.0);
        assert_eq!("basic", part.content_type.1);
        assert_eq!("Flint phone", part.content_description.as_ref().unwrap());
        assert_eq!(36234, part.size_octets);
        // > 5 IMAGE/PBM (MTR's photo) (1814 bytes)
        let part = &bs.children[4];
        assert_eq!("image", part.content_type.0);
        assert_eq!("pbm", part.content_type.1);
        assert_eq!("MTR's photo", part.content_description.as_ref().unwrap());
        assert_eq!(1814, part.size_octets);
        // > 6 MESSAGE/RFC822 (Star Trek Party) (4565 lines)
        let part = &bs.children[5];
        assert_eq!("MESSAGE", part.content_type.0);
        assert_eq!("RFC822", part.content_type.1);
        assert_eq!(
            "Star Trek Party",
            part.content_description.as_ref().unwrap()
        );
        assert_eq!(4565, part.size_lines);
        // > 6.1.1 TEXT/PLAIN;CHARSET=US-ASCII (16 lines)
        let part = &bs.children[5].children[0].children[0].children[0];
        assert_eq!("text", part.content_type.0);
        assert_eq!("plain", part.content_type.1);
        assert_eq!(16, part.size_lines);
        // > 6.1.2 AUDIO/X-SUN (He's dead, Jim) (31472 bytes)
        let part = &bs.children[5].children[0].children[0].children[1];
        assert_eq!("audio", part.content_type.0);
        assert_eq!("x-sun", part.content_type.1);
        assert_eq!(
            "He's dead, Jim",
            part.content_description.as_ref().unwrap()
        );
        assert_eq!(31472, part.size_octets);
        // > 6.2.1 IMAGE/GIF (Kirk/Spock/McCoy) (26000 bytes)
        let part = &bs.children[5].children[0].children[1].children[0];
        assert_eq!("image", part.content_type.0);
        assert_eq!("gif", part.content_type.1);
        assert_eq!(
            "Kirk/Spock/McCoy",
            part.content_description.as_ref().unwrap()
        );
        assert_eq!(26000, part.size_octets);
        // > 6.2.2 IMAGE/GIF (Star Trek Next Generation) (18666 bytes)
        let part = &bs.children[5].children[0].children[1].children[1];
        assert_eq!("image", part.content_type.0);
        assert_eq!("gif", part.content_type.1);
        assert_eq!(
            "Star Trek Next Generation",
            part.content_description.as_ref().unwrap()
        );
        assert_eq!(18666, part.size_octets);
        // > 6.2.3 APPLICATION/X-BE2;VERSION=12 (46125 bytes)
        let part = &bs.children[5].children[0].children[1].children[2];
        assert_eq!("APPLICATION", part.content_type.0);
        assert_eq!("X-BE2", part.content_type.1);
        assert_eq!(
            vec![("version".to_owned(), "12".to_owned())],
            part.content_type_parms
        );
        assert_eq!(46125, part.size_octets);
        // > 6.2.4 APPLICATION/ATOMICMAIL;VERSION=1.12 (9203 bytes)
        let part = &bs.children[5].children[0].children[1].children[3];
        assert_eq!("application", part.content_type.0);
        assert_eq!("atomicmail", part.content_type.1);
        assert_eq!(
            vec![("version".to_owned(), "1.12".to_owned())],
            part.content_type_parms
        );
        assert_eq!(9203, part.size_octets);
        // > 6.3 AUDIO/X-SUN (Distress calls) (47822 bytes)
        let part = &bs.children[5].children[0].children[2];
        assert_eq!("audio", part.content_type.0);
        assert_eq!("x-sun", part.content_type.1);
        assert_eq!(
            "Distress calls",
            part.content_description.as_ref().unwrap()
        );
        assert_eq!(47822, part.size_octets);
        // > 7 MESSAGE/RFC822 (Digitizer test) (483 lines)
        let part = &bs.children[6];
        assert_eq!("MESSAGE", part.content_type.0);
        assert_eq!("RFC822", part.content_type.1);
        assert_eq!(
            "Digitizer test",
            part.content_description.as_ref().unwrap()
        );
        // > 7.1 TEXT/PLAIN;CHARSET=US-ASCII (0 lines)
        let part = &bs.children[6].children[0].children[0];
        assert_eq!("text", part.content_type.0);
        assert_eq!("plain", part.content_type.1);
        assert_eq!(0, part.size_lines);
        // > 7.2 IMAGE/PGM (Bellcore mug) (84174 bytes)
        let part = &bs.children[6].children[0].children[1];
        assert_eq!("image", part.content_type.0);
        assert_eq!("pgm", part.content_type.1);
        assert_eq!("Bellcore mug", part.content_description.as_ref().unwrap());
        assert_eq!(84174, part.size_octets);
        // > 7.3 TEXT/PLAIN;CHARSET=US-ASCII (8 lines)
        let part = &bs.children[6].children[0].children[2];
        assert_eq!("text", part.content_type.0);
        assert_eq!("plain", part.content_type.1);
        assert_eq!(8, part.size_lines);
        // > 8 MESSAGE/RFC822 (More Imagery) (431 lines)
        let part = &bs.children[7];
        assert_eq!("MESSAGE", part.content_type.0);
        assert_eq!("RFC822", part.content_type.1);
        assert_eq!("More Imagery", part.content_description.as_ref().unwrap());
        assert_eq!(431, part.size_lines);
        // > 8.1 TEXT/PLAIN;CHARSET=US-ASCII (26 lines)
        let part = &bs.children[7].children[0].children[0];
        assert_eq!("text", part.content_type.0);
        assert_eq!("plain", part.content_type.1);
        assert_eq!(26, part.size_lines);
        // > 8.2 IMAGE/PBM (Mail architecture slide) (71686 bytes)
        let part = &bs.children[7].children[0].children[1];
        assert_eq!("image", part.content_type.0);
        assert_eq!("pbm", part.content_type.1);
        assert_eq!(
            "Mail architecture slide",
            part.content_description.as_ref().unwrap()
        );
        assert_eq!(71686, part.size_octets);
        // > 9 MESSAGE/RFC822 (PostScript demo) (6438 lines)
        let part = &bs.children[8];
        assert_eq!("MESSAGE", part.content_type.0);
        assert_eq!("RFC822", part.content_type.1);
        assert_eq!(
            "PostScript demo",
            part.content_description.as_ref().unwrap()
        );
        assert_eq!(6438, part.size_lines);
        // > 9.1 APPLICATION/POSTSCRIPT (Captain Picard) (397154 bytes)
        // This is another non-multipart message, so no extra .children[0]
        let part = &bs.children[8].children[0];
        assert_eq!("application", part.content_type.0);
        assert_eq!("postscript", part.content_type.1);
        assert_eq!(
            "Captain Picard",
            part.content_description.as_ref().unwrap()
        );
        assert_eq!(397154, part.size_octets);
        // > 10 IMAGE/GIF (Quoted-Printable test) (78302 bytes)
        let part = &bs.children[9];
        assert_eq!("image", part.content_type.0);
        assert_eq!("gif", part.content_type.1);
        assert_eq!(
            "Quoted-Printable test",
            part.content_description.as_ref().unwrap()
        );
        assert_eq!(78302, part.size_octets);
        // > 11 MESSAGE/RFC822 (q-p vs. base64 test) (1382 lines)
        let part = &bs.children[10];
        assert_eq!("MESSAGE", part.content_type.0);
        assert_eq!("RFC822", part.content_type.1);
        assert_eq!(
            "q-p vs. base64 test",
            part.content_description.as_ref().unwrap()
        );
        assert_eq!(1382, part.size_lines);
        // > 11.1 AUDIO/BASIC (I'm sorry, Dave (q-p)) (62094 bytes)
        let part = &bs.children[10].children[0].children[0];
        assert_eq!("AUDIO", part.content_type.0);
        assert_eq!("BASIC", part.content_type.1);
        assert_eq!(
            "I'm sorry, Dave (q-p)",
            part.content_description.as_ref().unwrap()
        );
        assert_eq!(62094, part.size_octets);
        // > 11.2 AUDIO/BASIC (I'm sorry, Dave (BASE64)) (40634 bytes)
        let part = &bs.children[10].children[0].children[1];
        assert_eq!("AUDIO", part.content_type.0);
        assert_eq!("BASIC", part.content_type.1);
        assert_eq!(
            "I'm sorry, Dave (BASE64)",
            part.content_description.as_ref().unwrap()
        );
        assert_eq!(40634, part.size_octets);
        // > 12 MESSAGE/RFC822 (Multiple encapsulation) (3282 lines)
        let part = &bs.children[11];
        assert_eq!("MESSAGE", part.content_type.0);
        assert_eq!("RFC822", part.content_type.1);
        assert_eq!(
            "Multiple encapsulation",
            part.content_description.as_ref().unwrap()
        );
        assert_eq!(3282, part.size_lines);
        // > 12.1 APPLICATION/POSTSCRIPT (The Simpsons!!) (53346 bytes)
        let part = &bs.children[11].children[0].children[0];
        assert_eq!("APPLICATION", part.content_type.0);
        assert_eq!("POSTSCRIPT", part.content_type.1);
        assert_eq!(
            "The Simpsons!!",
            part.content_description.as_ref().unwrap()
        );
        assert_eq!(53346, part.size_octets);
        // > 12.2 BINARY/UNKNOWN (Alice's PDP-10 w/ TECO & DDT);NAME=Alices_PDP-10 (18530 bytes)
        // Crispin expects the content type to be BINARY/UNKNOWN, but the raw
        // message just has
        //    Content-Type: BINARY;name="Alices_PDP-10"
        // RFC 2045 makes the content subtype MANDATORY, and text/plain is set
        // as the default for syntactically-invalid Content-Type headers.
        let part = &bs.children[11].children[0].children[1];
        assert_eq!("text", part.content_type.0);
        assert_eq!("plain", part.content_type.1);
        assert_eq!(
            "Alice's PDP-10 w/ TECO & DDT",
            part.content_description.as_ref().unwrap()
        );
        assert_eq!(18530, part.size_octets);
        // > 12.3 MESSAGE/RFC822 (Going deeper) (2094 lines)
        let part = &bs.children[11].children[0].children[2];
        assert_eq!("MESSAGE", part.content_type.0);
        assert_eq!("RFC822", part.content_type.1);
        assert_eq!("Going deeper", part.content_description.as_ref().unwrap());
        assert_eq!(2094, part.size_lines);
        // > 12.3.1 TEXT/PLAIN;CHARSET=US-ASCII (7 lines)
        let part =
            &bs.children[11].children[0].children[2].children[0].children[0];
        assert_eq!("text", part.content_type.0);
        assert_eq!("plain", part.content_type.1);
        assert_eq!(7, part.size_lines);
        // > 12.3.2.1 IMAGE/GIF (Bunny) (3276 bytes)
        let part = &bs.children[11].children[0].children[2].children[0]
            .children[1]
            .children[0];
        assert_eq!("image", part.content_type.0);
        assert_eq!("gif", part.content_type.1);
        assert_eq!("Bunny", part.content_description.as_ref().unwrap());
        assert_eq!(3276, part.size_octets);
        // > 12.3.2.2 AUDIO/BASIC (TV Theme songs) (156706 bytes)
        let part = &bs.children[11].children[0].children[2].children[0]
            .children[1]
            .children[1];
        assert_eq!("audio", part.content_type.0);
        assert_eq!("basic", part.content_type.1);
        assert_eq!(
            "TV Theme songs",
            part.content_description.as_ref().unwrap()
        );
        assert_eq!(156706, part.size_octets);
        // > 12.3.3 APPLICATION/ATOMICMAIL (4924 bytes)
        let part =
            &bs.children[11].children[0].children[2].children[0].children[2];
        assert_eq!("application", part.content_type.0);
        assert_eq!("atomicmail", part.content_type.1);
        assert_eq!(4924, part.size_octets);
        // > 12.3.4 MESSAGE/RFC822 (Yet another level deeper...) (1031 lines)
        let part =
            &bs.children[11].children[0].children[2].children[0].children[3];
        assert_eq!("MESSAGE", part.content_type.0);
        assert_eq!("RFC822", part.content_type.1);
        assert_eq!(
            "Yet another level deeper...",
            part.content_description.as_ref().unwrap()
        );
        assert_eq!(1031, part.size_lines);
        // > 12.3.4.1 AUDIO/X-SUN (I'm Twying...) (75682 bytes)
        // Non-multipart, so only one .children[0]
        let part = &bs.children[11].children[0].children[2].children[0]
            .children[3]
            .children[0];
        assert_eq!("AUDIO", part.content_type.0);
        assert_eq!("X-SUN", part.content_type.1);
        assert_eq!("I'm Twying...", part.content_description.as_ref().unwrap());
        assert_eq!(75682, part.size_octets);
    }

    // Ignored -- Corpus not included.
    // Comment #[ignore] and set BODYSTRUCTURE_CORPUS=/path/to/corpus to test.
    // This just tests that all the messages can be parsed without panicking.
    // It also acts as a sort of rough benchmark.
    #[test]
    #[ignore]
    fn test_corpus() {
        do_test_corpus(std::env::var("BODYSTRUCTURE_CORPUS").unwrap());
    }

    fn do_test_corpus(dir: impl AsRef<Path>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                println!("Testing {}...", path.display());

                struct Accessor(PathBuf);
                impl grovel::MessageAccessor for Accessor {
                    type Reader = std::io::BufReader<fs::File>;

                    fn uid(&self) -> Uid {
                        Uid::MIN
                    }

                    fn email_id(&self) -> Option<String> {
                        None
                    }

                    fn last_modified(&self) -> Modseq {
                        Modseq::MIN
                    }

                    fn savedate(&self) -> Option<DateTime<Utc>> {
                        None
                    }

                    fn is_recent(&self) -> bool {
                        false
                    }

                    fn flags(&self) -> Vec<Flag> {
                        vec![]
                    }

                    fn rfc822_size(&self) -> Option<u32> {
                        None
                    }

                    fn open(
                        &self,
                    ) -> Result<(MessageMetadata, Self::Reader), Error>
                    {
                        Ok((
                            MessageMetadata::default(),
                            std::io::BufReader::new(
                                fs::File::open(&self.0).unwrap(),
                            ),
                        ))
                    }
                }

                grovel::grovel(&Accessor(path), BodyStructureFetcher::new())
                    .unwrap();
            } else if path.is_dir() {
                do_test_corpus(path);
            }
        }
    }
}
