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

//! Everything needed to implement the IMAP `FETCH` operation.
//!
//! ## Regarding message layout
//!
//! IMAP defines a mechanism to access parts of a message based on its
//! multipart hierarchy. Each part of a multipart is assigned a number,
//! starting at 1. Parts can be addressed by multiple subscripts, such that,
//! e.g., `2.3` is the third sub-part of the second part. A non-multipart
//! element has subscript 1.
//!
//! IMAP also allows traversing `message/rfc822` parts by this mechanism,
//! though in an inconsistent and poorly-defined way.
//!
//! After zero or more subscripts, we get a final subsection specifier. This
//! can be one of:
//!
//! - Nothing. At top level, this fetches the whole message. For any other
//!   part, it fetches the part content.
//!
//! - `HEADERS`. At top level, this fetches the headers. For any other part, it
//!   ignores the actual headers and instead fetches the headers of an embedded
//!   `message/rfc822` part. This specifier also allows filtering headers based
//!   on a whitelist or blacklist.
//!
//! - `MIME`. Invalid at top level. For any other part, it fetches the headers
//!   of the part.
//!
//! - `TEXT`. At top level, this fetches the content of the message. For any
//!   other part, fetches the content of an embedded `message/rfc822` part.
//!
//! RFC 3501 provides no guidance on what to do if the top level component of a
//! `message/rfc822` is another `message/rfc822`.
//!
//! In our model, a `message/rfc822` part is treated as a multipart with one
//! child, that child being the embedded message itself. We recognise only
//! three subsection specifiers:
//!
//! - `Full`. Fetch the full part.
//!
//! - `Headers`. Fetch the headers, possibly filtered.
//!
//! - `Content`. Fetch the content.
//!
//! The `HEADERS` and `TEXT` specifiers let us predict the existence of
//! `message/rfc822` parts before scanning, which lets us handle them by
//! transformation:
//!
//! - `HEADERS` at non-top-level becomes `0.Headers`, i.e., traverse one level
//!   down and then do normal headers processing.
//!
//! - `TEXT` at non-top-level becomes `0.Content`.
//!
//! - `TEXT` at top-level becomes `Content`.
//!
//! - Nothing at non-top-level becomes `Content`.
//!
//! - Nothing at top-level becomes `Full`.
//!
//! - `MIME` becomes `Headers`.
//!
//! We also need to deal with the situation when we are processing a message
//! and discover that we need to subscript a part of type `message/rfc822`. The
//! rules for this are simple. The virtual part that is the `message/rfc822`
//! has index 0 in its parent. If we attempt to subscript an embedded message
//! with a positive index (since RFC 3501 indices start at 1), we implicitly
//! add a 0 to the subscript to start looking for more parts inside the
//! message.
//!
//! Both transformations are easy to reverse to the RFC 3501 form:
//!
//! - For the subsection, delete `Full` or `Content` following a positive
//!   subscript. Replace `Headers` after a positive subscript with `MIME`.
//!   Replace any remaining `Content` with `TEXT` and any remaining `Headers`
//!   with `HEADERS`.
//!
//! - For the subscripts, delete any non-positive subscript.
//!
//! Regarding the case where one message is directly nested in another, this
//! causes subscripts to transparently pass through all levels of
//! directly-nested messages, while the subsection specifiers will continue to
//! access the data from the top-most of these messages. This probably isn't
//! ideal but IMAP gives us no way to talk to the client about the messages so
//! there isn't much sane we can do either way.
//!
//! If we encounter a subscript on a non-multipart part, we simply drop the
//! rest of the subscripts and process that part.

pub mod addressing;
pub mod bodystructure;
pub mod envelope;
mod strings;
