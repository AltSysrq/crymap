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

use std::fmt;
use std::mem;

use super::bodystructure;
use super::envelope;
use super::section;
use crate::account::model::*;
use crate::mime::grovel::{Visitor, VisitorMap};
use crate::mime::header;
use crate::support::error::Error;

/// The types that can be fetched in parallel by `MultiFetcher`.
pub enum FetchedItem {
    /// A placeholder for an item not yet fetched.
    ///
    /// This is not supposed to escape `MultiFetcher`.
    Nil,
    Envelope(envelope::Envelope),
    BodyStructure(bodystructure::BodyStructure),
    BodySection(Result<section::FetchedBodySection, Error>),
}

impl FetchedItem {
    pub fn into_envelope(self) -> Option<envelope::Envelope> {
        match self {
            FetchedItem::Envelope(e) => Some(e),
            _ => None,
        }
    }

    pub fn into_body_structure(self) -> Option<bodystructure::BodyStructure> {
        match self {
            FetchedItem::BodyStructure(s) => Some(s),
            _ => None,
        }
    }

    pub fn into_body_section(
        self,
    ) -> Option<Result<section::FetchedBodySection, Error>> {
        match self {
            FetchedItem::BodySection(s) => Some(s),
            _ => None,
        }
    }
}

impl fmt::Debug for FetchedItem {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &FetchedItem::Nil => write!(f, "Nil"),
            &FetchedItem::Envelope(ref e) => write!(f, "Envelope({:?})", e),
            &FetchedItem::BodyStructure(ref s) => {
                write!(f, "BodyStructure({:?})", s)
            }
            &FetchedItem::BodySection(_) => write!(f, "BodySection(..)"),
        }
    }
}

type Fetcher = Box<dyn Visitor<Output = FetchedItem>>;

/// Performs multiple fetch operations in parallel, i.e., by distributing the
/// parse events to multiple sub-fetchers (nothing to do with concurrency).
///
/// The fetch output is a `Vec<FetchedItem>` which is parallel to the input
/// fetcher list.
#[derive(Debug, Default)]
pub struct MultiFetcher {
    fetchers: Vec<Option<Fetcher>>,
    results: Vec<FetchedItem>,
    remaining: usize,
}

impl MultiFetcher {
    /// Create a new, empty `MultiFetcher`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an `EnvelopeFetcher` as a sub-fetcher.
    pub fn add_envelope(&mut self) {
        self.add_fetcher(Box::new(VisitorMap::new(
            Box::new(envelope::EnvelopeFetcher::new()),
            FetchedItem::Envelope,
            FetchedItem::into_envelope,
        )));
    }

    /// Add a `BodyStructureFetcher` as a sub-fetcher.
    pub fn add_body_structure(&mut self) {
        self.add_fetcher(Box::new(VisitorMap::new(
            Box::new(bodystructure::BodyStructureFetcher::new()),
            FetchedItem::BodyStructure,
            FetchedItem::into_body_structure,
        )));
    }

    /// Add the given `BodySection` fetcher as a sub-fetcher.
    pub fn add_section(&mut self, section: section::Fetcher) {
        self.add_fetcher(Box::new(VisitorMap::new(
            section,
            FetchedItem::BodySection,
            FetchedItem::into_body_section,
        )));
    }

    fn add_fetcher(&mut self, fetcher: Fetcher) {
        self.fetchers.push(Some(fetcher));
        self.results.push(FetchedItem::Nil);
        self.remaining += 1;
    }

    fn on_fetchers(
        &mut self,
        mut f: impl FnMut(&mut Fetcher) -> Result<(), FetchedItem>,
    ) -> Result<(), Vec<FetchedItem>> {
        for i in 0..self.fetchers.len() {
            let result =
                self.fetchers[i].as_mut().map(|v| f(v)).unwrap_or(Ok(()));
            if let Err(result) = result {
                self.results[i] = result;
                self.fetchers[i] = None;
                self.remaining -= 1;
            }
        }

        if 0 == self.remaining {
            Err(mem::replace(&mut self.results, Vec::new()))
        } else {
            Ok(())
        }
    }
}

impl Visitor for MultiFetcher {
    type Output = Vec<FetchedItem>;

    fn uid(&mut self, uid: Uid) -> Result<(), Self::Output> {
        self.on_fetchers(|fetcher| fetcher.uid(uid))
    }

    fn last_modified(&mut self, modseq: Modseq) -> Result<(), Self::Output> {
        self.on_fetchers(|fetcher| fetcher.last_modified(modseq))
    }

    fn want_flags(&self) -> bool {
        self.fetchers
            .iter()
            .filter_map(Option::as_ref)
            .any(|fetcher| fetcher.want_flags())
    }

    fn flags(&mut self, flags: &[Flag]) -> Result<(), Self::Output> {
        self.on_fetchers(|fetcher| fetcher.flags(flags))
    }

    fn recent(&mut self) -> Result<(), Self::Output> {
        self.on_fetchers(|fetcher| fetcher.recent())
    }

    fn end_flags(&mut self) -> Result<(), Self::Output> {
        self.on_fetchers(|fetcher| fetcher.end_flags())
    }

    fn metadata(
        &mut self,
        metadata: &MessageMetadata,
    ) -> Result<(), Self::Output> {
        self.on_fetchers(|fetcher| fetcher.metadata(metadata))
    }

    fn raw_line(&mut self, line: &[u8]) -> Result<(), Self::Output> {
        self.on_fetchers(|fetcher| fetcher.raw_line(line))
    }

    fn header(
        &mut self,
        raw: &[u8],
        name: &str,
        value: &[u8],
    ) -> Result<(), Self::Output> {
        self.on_fetchers(|fetcher| fetcher.header(raw, name, value))
    }

    fn content_type(
        &mut self,
        ct: &header::ContentType<'_>,
    ) -> Result<(), Self::Output> {
        self.on_fetchers(|fetcher| fetcher.content_type(ct))
    }

    fn start_content(&mut self) -> Result<(), Self::Output> {
        self.on_fetchers(|fetcher| fetcher.start_content())
    }

    fn content(&mut self, data: &[u8]) -> Result<(), Self::Output> {
        self.on_fetchers(|fetcher| fetcher.content(data))
    }

    fn start_part(
        &mut self,
    ) -> Option<Box<dyn Visitor<Output = Self::Output>>> {
        let mut sub = Self::new();
        for fetcher in &mut self.fetchers {
            let sub_fetcher =
                fetcher.as_mut().and_then(|fetcher| fetcher.start_part());
            if sub_fetcher.is_some() {
                sub.remaining += 1;
            }
            sub.fetchers.push(sub_fetcher);
            sub.results.push(FetchedItem::Nil);
        }

        if sub.remaining > 0 {
            Some(Box::new(sub))
        } else {
            None
        }
    }

    fn child_result(
        &mut self,
        mut child_result: Self::Output,
    ) -> Result<(), Self::Output> {
        for i in 0..self.fetchers.len() {
            let result = if let Some(fetcher) = self.fetchers[i].as_mut() {
                fetcher.child_result(mem::replace(
                    &mut child_result[i],
                    FetchedItem::Nil,
                ))
            } else {
                Ok(())
            };

            if let Err(result) = result {
                self.results[i] = result;
                self.fetchers[i] = None;
                self.remaining -= 1;
            }
        }

        if 0 == self.remaining {
            Err(mem::replace(&mut self.results, Vec::new()))
        } else {
            Ok(())
        }
    }

    fn end(&mut self) -> Self::Output {
        self.on_fetchers(|fetcher| Err(fetcher.end()))
            .err()
            .expect("Failed to complete MultiFetcher.end()")
    }
}

#[cfg(test)]
mod test {
    use std::io::Read;
    use std::sync::Arc;

    use super::*;
    use crate::mime::grovel;

    static SAMPLE_MESSAGE: &str = include_str!("rfc3501_p56.eml");

    #[test]
    fn test_multi_fetch() {
        let common_paths = Arc::new(CommonPaths {
            tmp: std::env::temp_dir(),
            garbage: std::env::temp_dir(),
        });

        let mut fetcher = MultiFetcher::new();
        fetcher.add_envelope();
        fetcher.add_section(
            section::BodySection {
                subscripts: vec![3, 1],
                leaf_type: section::LeafType::Content,
                ..section::BodySection::default()
            }
            .fetcher(Box::new(|v| v), Arc::clone(&common_paths)),
        );
        fetcher.add_section(
            section::BodySection {
                subscripts: vec![2],
                leaf_type: section::LeafType::Mime,
                ..section::BodySection::default()
            }
            .fetcher(Box::new(|v| v), Arc::clone(&common_paths)),
        );
        fetcher.add_section(
            section::BodySection {
                subscripts: vec![4, 2, 2, 1],
                leaf_type: section::LeafType::Content,
                ..section::BodySection::default()
            }
            .fetcher(Box::new(|v| v), Arc::clone(&common_paths)),
        );

        let message = include_str!("rfc3501_p56.eml").replace('\n', "\r\n");
        let mut result = grovel::grovel(
            &grovel::SimpleAccessor {
                data: message.into(),
                ..grovel::SimpleAccessor::default()
            },
            fetcher,
        )
        .unwrap();

        assert_eq!(4, result.len());

        match &result[0] {
            &FetchedItem::Envelope(ref envelope) => {
                assert_eq!("RFC 3501", envelope.subject.as_ref().unwrap());
            }
            r => panic!("Unexpected envelope result: {:#?}", r),
        }

        match &mut result[1] {
            &mut FetchedItem::BodySection(Ok(ref mut bs)) => {
                let mut content = String::new();
                bs.buffer.read_to_string(&mut content).unwrap();
                assert_eq!("Part 3.1\r\n", content);
            }
            r => panic!("Unexpected [3.1] result: {:#?}", r),
        }

        match &mut result[2] {
            &mut FetchedItem::BodySection(Ok(ref mut bs)) => {
                let mut content = String::new();
                bs.buffer.read_to_string(&mut content).unwrap();
                assert!(content.starts_with("Content-Id: 2"));
            }
            r => panic!("Unexpected [2] result: {:#?}", r),
        }

        match &mut result[3] {
            &mut FetchedItem::BodySection(Ok(ref mut bs)) => {
                let mut content = String::new();
                bs.buffer.read_to_string(&mut content).unwrap();
                assert_eq!("Part 4.2.2.1\r\n", content);
            }
            r => panic!("Unexpected [4.2.2.1] result: {:#?}", r),
        }
    }
}
