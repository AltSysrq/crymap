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
    pub content_transfer_encoding: header::ContentTransferEncoding,
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

    fn header(&mut self, name: &str, value: &[u8]) -> Result<(), Self::Output> {
        self.on_envelope(|e| e.header(name, value));

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
        // value for things that aren't line-oriented.
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

        mem::replace(&mut self.bs, BodyStructure::default())
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
            header::parse_content_transfer_encoding(value)
                .unwrap_or(header::ContentTransferEncoding::Binary);
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
    use super::*;
    use crate::mime::grovel;

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
                routing: (),
                local: Some("foo".to_owned()),
                domain: Some("bar.com".to_owned()),
            }],
            bs.envelope.from
        );

        assert_eq!("text", bs.content_type.0);
        assert_eq!("plain", bs.content_type.1);
        assert_eq!(
            header::ContentTransferEncoding::SevenBit,
            bs.content_transfer_encoding
        );
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
                routing: (),
                local: Some("bar".to_owned()),
                domain: Some("foo.com".to_owned()),
            }],
            bs.children[0].envelope.from
        );
        assert_eq!(13, bs.children[0].size_octets);
        assert_eq!(1, bs.children[0].size_lines);
        assert_eq!("a0f2a3c1dcd5b1cac71bf0c03f2ff1bd", bs.children[0].md5);
    }
}
