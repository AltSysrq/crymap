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

use super::envelope::*;
use crate::mime::header::*;

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
    pub content_transfer_encoding: ContentTransferEncoding,
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
