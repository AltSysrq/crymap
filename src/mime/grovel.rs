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

use crate::account::model::*;

/// A visitor which receives events from the push parser.
///
/// In general, the visitor is permitted to emit an output at any step, at
/// which point parsing is considered complete. Once a visitor returns `Some`,
/// no more methods will be called on it.
///
/// Methods are declared in the order they are usually called.
#[allow(unused_variables)]
pub trait Visitor: Sized {
    type Output;

    /// Receives the UID of the message being processed.
    fn uid(&mut self, uid: Uid) -> Option<Self::Output> {
        None
    }

    /// Receives the `MessageMetadata` of the message being processed.
    fn metadata(&mut self, metadata: &MessageMetadata) -> Option<Self::Output> {
        None
    }

    /// Indicates whether loading the flags for the message would be useful.
    fn want_flags(&self) -> bool {
        false
    }

    /// Receives the flags on the current message.
    fn flags(&mut self, flags: &[&Flag]) -> Option<Self::Output> {
        None
    }

    /// Called once for every line which passes through the parser, in its raw
    /// form.
    ///
    /// `line` typically ends with "\r\n", but may also end with a bare "\n" or
    /// nothing at all when scanning binary payloads or over-long lines.
    ///
    /// This is called before more specific methods relating to the line.
    fn raw_line(&mut self, line: &[u8]) -> Option<Self::Output> {
        None
    }

    /// Called for each header found.
    ///
    /// `name` and `value` are in their raw form.
    ///
    /// Only called for headers that pass rudimentary validity checks (valid
    /// UTF-8, not too long).
    fn header(&mut self, name: &str, value: &str) -> Option<Self::Output> {
        None
    }

    /// Called upon reaching the blank line that terminates the message
    /// headers.
    fn end_headers(&mut self) -> Option<Self::Output> {
        None
    }

    /// Indicates that the start of "text" has been reached and will run to the
    /// end of this segment.
    ///
    /// Multipart segments also have "text", which is simply their raw
    /// representation.
    fn start_text(&mut self) -> Option<Self::Output> {
        None
    }

    /// Indicates that the start of a multipart part has been encountered.
    ///
    /// If the visitor wishes to receive details of what is inside, it can
    /// return a new instance of itself.
    ///
    /// While scanning a part, raw lines are still fed to the "parent" visitor,
    /// while details such as headers or further nested parts are fed to the
    /// "child".
    fn start_part(&mut self) -> Option<Self> {
        None
    }

    /// Indicates that a multipart part has completed.
    ///
    /// `body_result` is invoked with the final result emitted by the child, if
    /// there was a child.
    fn end_part(
        &mut self,
        body_result: Option<Self::Output>,
    ) -> Option<Self::Output> {
        None
    }

    /// Indicates that the end of the segment has been reached.
    ///
    /// This is always the last method to be called. It takes `&mut self` to
    /// keep the trait object-safe.
    fn end(&mut self) -> Option<Self::Output> {
        None
    }
}

/// A push-parser which descends through a MIME message.
///
/// It is designed to be robust moreso than strictly correct. That is, it will
/// accept wildly malformed data but will still do its best to carry on, even
/// in the face of things that are invalid per the standard. It is also very
/// conservative as to what quantity of data it will load into memory.
///
/// The implementation does not know much about the subtleties of headers
/// except Content-Type (the one header it needs to know about to do its job)
/// and does not handle character encoding or transfer encoding. Any 8-bit
/// characters are required to be UTF-8 to be considered as text.
#[derive(Debug, Clone)]
pub struct Groveller<V> {
    visitor: V,
    //state: State,
    buffered_header: String,
    child: Option<Box<Self>>,
    boundary: Option<Vec<u8>>,
    recursion_depth: u32,
}
