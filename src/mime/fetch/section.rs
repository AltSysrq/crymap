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

//! ## Regarding message layout
//!
//! IMAP defines a mechanism to access parts of a message based on its
//! multipart hierarchy. Each part of a multipart is assigned a number,
//! starting at 1. Parts can be addressed by multiple subscripts, such that,
//! e.g., `2.3` is the third sub-part of the second part.
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
//! `message/rfc822` is another `message/rfc822`, and by all appearances, this
//! situation is impossible to handle unambiguously.
//!
//! Another issue is the case where an embedded `message/rfc822` is *not* a
//! multipart. The transparency implied by RFC 3501 would imply that there are
//! no subscripts to the message, and `.TEXT` accesses the content. However, in
//! Crispin's example "torture test" (see the test that uses it in
//! `bodystructure.rs`), he gives the content of a non-multipart message a
//! subscript of 1 (but uses all subscripts to refer to content instead of
//! whole parts). The implementation currently reflects what RFC 3501 implies,
//! i.e., that there is no subscript to access the content of a non-multipart
//! message.
//!
//! TODO A message from Crispin in 2011-04 indicates that a subscript 1 on a
//! non-multipart must be equivalent to `TEXT`.

use std::fmt;
use std::io::{self, Write};
use std::sync::Arc;

use crate::account::model::CommonPaths;
use crate::mime::grovel::Visitor;
use crate::mime::header;
use crate::support::buffer::*;
use crate::support::error::Error;

/// Describes which portion of a part to process.
///
/// The semantics of the values match IMAP's, and as a result are wonky and
/// fraught with special cases.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LeafType {
    /// Process the entire part, headers and all.
    ///
    /// No special handling for `message/rfc822`.
    Full,
    /// At top-level, process the headers.
    ///
    /// For others, process the headers of the first child. This is a special
    /// case for `message/rfc822`, but we don't check for that type
    /// specifically since the query is not valid for any other type of
    /// content.
    Headers,
    /// Process the headers of the part.
    ///
    /// No special case for `message/rfc822`.
    Mime,
    /// Process the content of the part.
    ///
    /// No special case for `message/rfc822`.
    Content,
    /// At top level, process the content of the part.
    ///
    /// For others, process the content of the first child. This is a special
    /// case for `message/rfc822`, but we don't check for that type
    /// specifically since the query is not valid for any other type.
    Text,
}

impl LeafType {
    fn include_headers(self) -> bool {
        match self {
            Self::Full | Self::Headers | Self::Mime => true,
            Self::Content | Self::Text => false,
        }
    }

    fn include_content(self) -> bool {
        match self {
            Self::Full | Self::Content | Self::Text => true,
            Self::Headers | Self::Mime => false,
        }
    }

    fn act_on_first_child(self, is_top_level: bool) -> bool {
        match self {
            Self::Full | Self::Mime | Self::Content => false,
            Self::Headers | Self::Text => !is_top_level,
        }
    }
}

/// Identifies a particular portion of the body to fetch.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BodySection {
    /// Which subscripts to traverse to find the part in question.
    pub subscripts: Vec<u32>,
    /// Which subsection of the part to read.
    pub leaf_type: LeafType,
    /// Apply filtering to these header names.
    pub header_filter: Vec<String>,
    /// If true, discard headers matching `header_filter`.
    ///
    /// If false, keep only headers matching that filter.
    pub discard_matching_headers: bool,
    /// If set, slice the binary data produced by the above to this range,
    /// clamping each endpoint.
    pub partial: Option<(u64, u64)>,
    /// If set, report this section using the given legacy IMAP2 name (e.g.
    /// `RFC822.HEADER` instead of `BODY[HEADER]`).
    pub report_as_legacy: Option<Imap2Section>,
}

impl Default for BodySection {
    fn default() -> Self {
        BodySection {
            subscripts: vec![],
            leaf_type: LeafType::Full,
            header_filter: vec![],
            discard_matching_headers: false,
            partial: None,
            report_as_legacy: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Imap2Section {
    Rfc822,
    Rfc822Header,
    Rfc822Text,
}

/// A type which can be passed to `grovel` to produce `FetchedBodySection`
/// values.
pub type Fetcher = Box<dyn Visitor<Output = Output>>;

/// Overlays a `Fetcher` to modify content or headers.
pub type ContentFilter = Box<dyn FnMut(Fetcher) -> Fetcher>;

/// The output type from a section `Fetcher`.
///
/// Any errors encountered during the fetch process are reported through the
/// output (i.e., in `Ok(Err(..))` returned from `grovel`).
pub type Output = (BodySection, Result<FetchedBodySection, Error>);

impl BodySection {
    /// Create a fetcher for this body section.
    ///
    /// `content_filter` is a function which optionally wraps the bottom-level
    /// fetcher so as to modify its content or headers.
    ///
    /// `common_paths` is used for allocating temporary files as needed.
    pub fn fetcher(
        self,
        mut content_filter: ContentFilter,
        common_paths: Arc<CommonPaths>,
    ) -> Fetcher {
        if self.subscripts.is_empty() {
            content_filter(Box::new(SectionFetcher::new(self, common_paths)))
        } else {
            Box::new(SectionLocator {
                target: Some(self),
                level: 0,
                curr_part_number: 0,
                common_paths,
                is_message_rfc822: false,
                content_filter: Some(content_filter),
            })
        }
    }
}

/// A section which was successfully fetched.
pub struct FetchedBodySection {
    /// The data from this section.
    pub buffer: BufferReader,
    /// Whether this section contains a NUL byte.
    ///
    /// RFC 3516 recommends only using the literal8 syntax when there is at
    /// least one NUL byte.
    pub contains_nul: bool,
}

impl fmt::Debug for FetchedBodySection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("FetchedBodySection")
            .field("buffer", &self.buffer.len())
            .field("contains_nul", &self.contains_nul)
            .finish()
    }
}

struct SectionLocator {
    target: Option<BodySection>,
    level: usize,
    curr_part_number: u32,
    common_paths: Arc<CommonPaths>,
    is_message_rfc822: bool,
    content_filter: Option<ContentFilter>,
}

impl fmt::Debug for SectionLocator {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("SectionLocator")
            .field("target", &self.target)
            .field("level", &self.level)
            .field("curr_part_number", &self.curr_part_number)
            .field("common_paths", &self.common_paths)
            .field("is_message_rfc822", &self.is_message_rfc822)
            .field("content_filter", &"Fn")
            .finish()
    }
}

impl Visitor for SectionLocator {
    type Output = Output;

    fn content_type(
        &mut self,
        ct: &header::ContentType<'_>,
    ) -> Result<(), Output> {
        self.is_message_rfc822 =
            ct.is_type("message") && ct.is_subtype("rfc822");
        Ok(())
    }

    fn start_part(&mut self) -> Option<Fetcher> {
        enum NextLevel {
            NoMatch,
            Final,
            Recurse(usize),
        }

        // The logic to determine whether to descend and how to handle
        // subscripting is made unnecessarily complicated by RFC 3501's special
        // cases and making of `message/rfc822` semi-transparent.
        //
        // The content-type we know here is the content-type declared in the
        // MIME container. I.e., is_message_rfc822 means that the first child
        // is going to be a message/rfc822, not the current object.
        //
        // Basically, a container of type message/rfc822 is modelled as having
        // one child with subscript 1. However, that subscript is not notated
        // in IMAP.
        let next_level = if let Some(target) = self.target.as_ref() {
            self.curr_part_number += 1;

            if self.level >= target.subscripts.len() {
                // If we are beyond the end of the subscript list, we are doing
                // the `Headers` or `Text` special-case. In this case, we
                // always take the first child and terminate there.
                NextLevel::Final
            } else if self.is_message_rfc822 {
                // We haven't hit the final subscript, which means we're still
                // looking for numbered sections. message/rfc822 is transparent
                // to these, so we always take the first child and don't
                // advance the subscript level.
                NextLevel::Recurse(self.level)
            } else if self.curr_part_number != target.subscripts[self.level] {
                // We're looking for numbered parts at this level, and this
                // isn't the one we're looking for.
                NextLevel::NoMatch
            } else if self.level + 1 < target.subscripts.len() {
                // We found the part we're looking for, and there's another
                // subscript level to go before we can run into any special
                // cases, so just advance to the next level.
                NextLevel::Recurse(self.level + 1)
            } else if target.leaf_type.act_on_first_child(false) {
                // We're on the final subscript, but the leaf type has a
                // special case that makes it go to the first child
                // unconditionally, which we represent by advancing beyond the
                // end of the subscript list.
                NextLevel::Recurse(self.level + 1)
            } else {
                // This is the final subscript, and there's no special case, so
                // we're done.
                NextLevel::Final
            }
        } else {
            NextLevel::NoMatch
        };

        match next_level {
            NextLevel::NoMatch => None,

            NextLevel::Final => {
                let leaf: Fetcher = Box::new(SectionFetcher::new(
                    self.target.take().unwrap(),
                    Arc::clone(&self.common_paths),
                ));
                if let Some(content_filter) = self.content_filter.as_mut() {
                    Some(content_filter(leaf))
                } else {
                    Some(leaf)
                }
            }

            NextLevel::Recurse(next_level) => Some(Box::new(SectionLocator {
                target: self.target.take(),
                level: next_level,
                curr_part_number: 0,
                content_filter: self.content_filter.take(),
                common_paths: Arc::clone(&self.common_paths),
                is_message_rfc822: false,
            })),
        }
    }

    fn child_result(&mut self, result: Output) -> Result<(), Output> {
        Err(result)
    }

    fn end(&mut self) -> Output {
        // Per a message from Crispin in 2008-03, we need to return an
        // empty string here.
        (
            self.target.take().unwrap(),
            Ok(FetchedBodySection {
                buffer: BufferReader::new(vec![]),
                contains_nul: false,
            }),
        )
    }
}

struct SectionFetcher {
    target: Option<BodySection>,
    buffer: Option<io::BufWriter<BufferWriter>>,
    contains_nul: bool,
    skipped: u64,
    processed: u64,
    desired_range: (u64, u64),
    leaf_type: LeafType,
}

impl fmt::Debug for SectionFetcher {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("SectionFetcher")
            .field("target", &self.target)
            .field("buffer", &"BufferWriter")
            .field("contains_nul", &self.contains_nul)
            .field("skipped", &self.skipped)
            .field("processed", &self.processed)
            .field("desired_range", &self.desired_range)
            .field("leaf_type", &self.leaf_type)
            .finish()
    }
}

impl SectionFetcher {
    fn new(target: BodySection, common_paths: Arc<CommonPaths>) -> Self {
        SectionFetcher {
            contains_nul: false,
            skipped: 0,
            processed: 0,
            desired_range: target.partial.unwrap_or((0, u64::MAX)),
            leaf_type: target.leaf_type,
            buffer: Some(io::BufWriter::new(BufferWriter::new(common_paths))),
            target: Some(target),
        }
    }

    fn write(&mut self, data: &[u8]) -> Result<(), Output> {
        let to_process =
            (self.desired_range.1 - self.processed).min(data.len() as u64);
        let data = &data[..to_process as usize];
        self.processed += to_process;

        let to_skip =
            (self.desired_range.0 - self.skipped).min(data.len() as u64);
        let data = &data[to_skip as usize..];
        self.skipped += to_skip;

        if !data.is_empty() {
            self.contains_nul |= memchr::memchr(0, data).is_some();
            if let Err(e) = self
                .buffer
                .as_mut()
                .expect("Write to SectionFetcher after end")
                .write_all(data)
            {
                return Err((self.target.take().unwrap(), Err(e.into())));
            }
        }

        if self.processed < self.desired_range.1 {
            Ok(())
        } else {
            Err(self.end())
        }
    }

    fn end_buffer(&mut self) -> Result<FetchedBodySection, Error> {
        let buffer = self.buffer.take().unwrap();
        let buffer = buffer
            .into_inner()
            .map_err(|e| io::Error::from(e))?
            .flip()?;
        Ok(FetchedBodySection {
            buffer,
            contains_nul: self.contains_nul,
        })
    }
}

impl Visitor for SectionFetcher {
    type Output = Output;

    fn header(
        &mut self,
        raw: &[u8],
        name: &str,
        _value: &[u8],
    ) -> Result<(), Output> {
        if !self.leaf_type.include_headers() {
            return Ok(());
        }

        {
            let target = self
                .target
                .as_ref()
                .expect("SectionFetcher::header after end");
            let matches_filter = target
                .header_filter
                .iter()
                .any(|h| name.eq_ignore_ascii_case(h));

            if !target.header_filter.is_empty()
                && matches_filter == target.discard_matching_headers
            {
                return Ok(());
            }
        }

        self.write(raw)?;
        // Lines may be truncated due to length limits
        if !raw.ends_with(b"\n") {
            if raw.ends_with(b"\r") {
                self.write(b"\n")?;
            } else {
                self.write(b"\r\n")?;
            }
        }

        Ok(())
    }

    fn start_content(&mut self) -> Result<(), Output> {
        if self.leaf_type.include_headers() {
            self.write(b"\r\n")?;
        }

        if !self.leaf_type.include_content() {
            Err(self.end())
        } else {
            Ok(())
        }
    }

    fn content(&mut self, data: &[u8]) -> Result<(), Output> {
        self.write(data)
    }

    fn end(&mut self) -> Output {
        let target = self.target.take().unwrap();
        let fetched = self.end_buffer();
        (target, fetched)
    }
}

#[cfg(test)]
mod test {
    use std::io::Read;

    use super::*;
    use crate::mime::grovel;

    fn do_fetch(message: &str, section: BodySection) -> String {
        let message = message.replace('\n', "\r\n");
        do_fetch_bytes(message.into(), section)
    }

    fn do_fetch_sample(section: BodySection) -> String {
        do_fetch_bytes(crate::test_data::RFC3501_P56.to_owned(), section)
    }

    fn do_fetch_bytes(message: Vec<u8>, section: BodySection) -> String {
        let (_, result) = grovel::grovel(
            &grovel::SimpleAccessor {
                data: message.into(),
                ..grovel::SimpleAccessor::default()
            },
            section.fetcher(
                Box::new(|v| v),
                Arc::new(CommonPaths {
                    tmp: std::env::temp_dir(),
                    garbage: std::env::temp_dir(),
                }),
            ),
        )
        .unwrap();
        let mut result = result.unwrap();

        let mut ret = String::new();
        result.buffer.read_to_string(&mut ret).unwrap();
        ret
    }

    #[test]
    fn fetch_full() {
        let fetched = do_fetch_sample(BodySection::default());
        assert!(fetched.starts_with("Remark:"));
        assert!(fetched.ends_with("--toplevel--\r\n"));
    }

    #[test]
    fn fetch_toplevel_header() {
        let fetched = do_fetch_sample(BodySection {
            leaf_type: LeafType::Headers,
            ..BodySection::default()
        });
        assert!(fetched.starts_with("Remark:"));
        assert!(fetched.ends_with("boundary=toplevel\r\n\r\n"));
    }

    #[test]
    fn fetch_toplevel_text() {
        let fetched = do_fetch_sample(BodySection {
            leaf_type: LeafType::Text,
            ..BodySection::default()
        });
        assert!(fetched.starts_with("--toplevel\r\n"));
        assert!(fetched.ends_with("--toplevel--\r\n"));
    }

    #[test]
    fn fetch_1_content() {
        let fetched = do_fetch_sample(BodySection {
            subscripts: vec![1],
            leaf_type: LeafType::Content,
            ..BodySection::default()
        });
        assert_eq!("Part 1\r\n", fetched);
    }

    #[test]
    fn fetch_2_content() {
        let fetched = do_fetch_sample(BodySection {
            subscripts: vec![2],
            leaf_type: LeafType::Content,
            ..BodySection::default()
        });
        assert_eq!("Part 2\r\n", fetched);
    }

    #[test]
    fn fetch_3_content() {
        let fetched = do_fetch_sample(BodySection {
            subscripts: vec![3],
            leaf_type: LeafType::Content,
            ..BodySection::default()
        });
        assert!(fetched.starts_with("Subject: Part 3\r\n"));
        assert!(fetched.ends_with("--part3--"));
    }

    #[test]
    fn fetch_3_header() {
        let fetched = do_fetch_sample(BodySection {
            subscripts: vec![3],
            leaf_type: LeafType::Headers,
            ..BodySection::default()
        });
        assert!(fetched.starts_with("Subject: Part 3\r\n"));
        assert!(fetched.ends_with("boundary=part3\r\n\r\n"));
    }

    #[test]
    fn fetch_3_text() {
        let fetched = do_fetch_sample(BodySection {
            subscripts: vec![3],
            leaf_type: LeafType::Text,
            ..BodySection::default()
        });
        assert!(fetched.starts_with("--part3\r\n"));
        assert!(fetched.ends_with("--part3--"));
    }

    #[test]
    fn fetch_3_1_content() {
        let fetched = do_fetch_sample(BodySection {
            subscripts: vec![3, 1],
            leaf_type: LeafType::Content,
            ..BodySection::default()
        });
        assert_eq!("Part 3.1\r\n", fetched);
    }

    #[test]
    fn fetch_3_2_content() {
        let fetched = do_fetch_sample(BodySection {
            subscripts: vec![3, 2],
            leaf_type: LeafType::Content,
            ..BodySection::default()
        });
        assert_eq!("Part 3.2\r\n", fetched);
    }

    #[test]
    fn fetch_4_content() {
        let fetched = do_fetch_sample(BodySection {
            subscripts: vec![4],
            leaf_type: LeafType::Content,
            ..BodySection::default()
        });
        assert!(fetched.starts_with("--part4\r\n"));
        assert!(fetched.ends_with("--part4--"));
    }

    #[test]
    fn fetch_4_1_content() {
        let fetched = do_fetch_sample(BodySection {
            subscripts: vec![4, 1],
            leaf_type: LeafType::Content,
            ..BodySection::default()
        });
        assert_eq!("Part 4.1\r\n", fetched);
    }

    #[test]
    fn fetch_4_1_mime() {
        let fetched = do_fetch_sample(BodySection {
            subscripts: vec![4, 1],
            leaf_type: LeafType::Mime,
            ..BodySection::default()
        });
        assert_eq!(
            "Content-Id: 4.1\r\nContent-Type: image/gif\r\n\r\n",
            fetched
        );
    }

    #[test]
    fn fetch_4_2_content() {
        let fetched = do_fetch_sample(BodySection {
            subscripts: vec![4, 2],
            leaf_type: LeafType::Content,
            ..BodySection::default()
        });
        assert!(fetched.starts_with("Subject: Part 4.2\r\n"));
        assert!(fetched.ends_with("--subpart42--"));
    }

    #[test]
    fn fetch_4_2_header() {
        let fetched = do_fetch_sample(BodySection {
            subscripts: vec![4, 2],
            leaf_type: LeafType::Headers,
            ..BodySection::default()
        });
        assert!(fetched.starts_with("Subject: Part 4.2\r\n"));
        assert!(fetched.ends_with("boundary=subpart42\r\n\r\n"));
    }

    #[test]
    fn fetch_4_2_text() {
        let fetched = do_fetch_sample(BodySection {
            subscripts: vec![4, 2],
            leaf_type: LeafType::Text,
            ..BodySection::default()
        });
        assert!(fetched.starts_with("--subpart42\r\n"));
        assert!(fetched.ends_with("--subpart42--"));
    }

    #[test]
    fn fetch_4_2_1_content() {
        let fetched = do_fetch_sample(BodySection {
            subscripts: vec![4, 2, 1],
            leaf_type: LeafType::Content,
            ..BodySection::default()
        });
        assert_eq!("Part 4.2.1\r\n", fetched);
    }

    #[test]
    fn fetch_4_2_2_content() {
        let fetched = do_fetch_sample(BodySection {
            subscripts: vec![4, 2, 2],
            leaf_type: LeafType::Content,
            ..BodySection::default()
        });
        assert!(fetched.starts_with("--subsubpart422\r\n"));
        assert!(fetched.ends_with("--subsubpart422--"));
    }

    #[test]
    fn fetch_4_2_2_1_content() {
        let fetched = do_fetch_sample(BodySection {
            subscripts: vec![4, 2, 2, 1],
            leaf_type: LeafType::Content,
            ..BodySection::default()
        });
        assert_eq!("Part 4.2.2.1\r\n", fetched);
    }

    #[test]
    fn fetch_4_2_2_2_content() {
        let fetched = do_fetch_sample(BodySection {
            subscripts: vec![4, 2, 2, 2],
            leaf_type: LeafType::Content,
            ..BodySection::default()
        });
        assert_eq!("Part 4.2.2.2\r\n", fetched);
    }

    #[test]
    fn fetch_out_of_bounds_section() {
        let fetched = do_fetch_sample(BodySection {
            subscripts: vec![10],
            leaf_type: LeafType::Content,
            ..BodySection::default()
        });
        assert_eq!("", fetched);
    }

    #[test]
    fn header_filter_retain() {
        let fetched = do_fetch(
            "fOo : foo\nBar: bar\nBaz: baz\n\nContent",
            BodySection {
                leaf_type: LeafType::Headers,
                header_filter: vec!["Foo".to_owned(), "Baz".to_owned()],
                discard_matching_headers: false,
                ..BodySection::default()
            },
        );

        assert_eq!("fOo : foo\r\nBaz: baz\r\n\r\n", fetched);
    }

    #[test]
    fn header_filter_remove() {
        let fetched = do_fetch(
            "fOo : foo\nBar: bar\nBaz: baz\n\nContent",
            BodySection {
                leaf_type: LeafType::Headers,
                header_filter: vec!["Foo".to_owned(), "Baz".to_owned()],
                discard_matching_headers: true,
                ..BodySection::default()
            },
        );

        assert_eq!("Bar: bar\r\n\r\n", fetched);
    }

    #[test]
    fn header_incomplete_line() {
        let fetched = do_fetch(
            "Foo: bar",
            BodySection {
                leaf_type: LeafType::Headers,
                ..BodySection::default()
            },
        );
        // Not having a trailing blank line is correct --- RFC 3501 specifies
        // that the line is omitted if the source also lacks it.
        assert_eq!("Foo: bar\r\n", fetched);
    }

    #[test]
    fn header_incomplete_line_cr() {
        let fetched = do_fetch(
            "Foo: bar\r",
            BodySection {
                leaf_type: LeafType::Headers,
                ..BodySection::default()
            },
        );
        assert_eq!("Foo: bar\r\n", fetched);
    }

    #[test]
    fn simple_partial() {
        let fetched = do_fetch_sample(BodySection {
            subscripts: vec![4, 1],
            leaf_type: LeafType::Content,
            partial: Some((1, 8)),
            ..BodySection::default()
        });
        assert_eq!("art 4.1", fetched);
    }

    #[test]
    fn overlength_partial() {
        let fetched = do_fetch_sample(BodySection {
            subscripts: vec![4, 1],
            leaf_type: LeafType::Content,
            partial: Some((1, 800)),
            ..BodySection::default()
        });
        assert_eq!("art 4.1\r\n", fetched);
    }

    #[test]
    fn empty_partial() {
        let fetched = do_fetch_sample(BodySection {
            subscripts: vec![4, 1],
            leaf_type: LeafType::Content,
            partial: Some((1, 1)),
            ..BodySection::default()
        });
        assert_eq!("", fetched);
    }

    #[test]
    fn inverted_partial() {
        let fetched = do_fetch_sample(BodySection {
            subscripts: vec![4, 1],
            leaf_type: LeafType::Content,
            partial: Some((8, 1)),
            ..BodySection::default()
        });
        assert_eq!("", fetched);
    }
}
