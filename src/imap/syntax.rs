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

//! Code for reading and writing IMAP requests and responses.
//!
//! Most of this is based on a set of macros which automatically generate AST
//! structs, parsers, and writer code, so that the three remain in sync and
//! have a natural correspondence to the standards' formal syntaxes.
//!
//! The code here is mainly oriented at the Crymap server. You could use it to
//! implement a primitive client of sorts too (and this is what is used for
//! testing Crymap), but it is not entirely suitable for that:
//!
//! - Parsing only happens in a sort of "Unicode-semi-aware" mode. This is fine
//!   for the server since the only places it matters have built-in indications
//!   of encoding, but if the client does not enable Unicode-aware mode, the
//!   repair strategies will pass through instead of being decoded.
//!
//! - Messages are generated all-at-once. This forces a client to use LITERAL+.
//!
//! - The response parser is sensitive to order where it shouldn't be (e.g.
//!   with respect to \Recent relative to real flags in the same list) and
//!   requires syntax it shouldn't (e.g. `PERMANENTFLAGS` won't parse without
//!   `\*`).
//!
//! `APPEND` is not handled directly. This file provides code to recognise it
//! and parse its parts, but the full command is handled at the protocol level.
//!
//! Sequence sets are not parsed by this code. They are recognised at an
//! extremely primitive level, but full interpretation requires context outside
//! of the parser, so they are simply returned as strings.
//!
//! ## Overview of the syntax in this file
//!
//! To keep parsing and generation in sync, all complex structures are defined
//! through macros that directly bind syntax annotations onto structs and
//! enums.
//!
//! The simplest is `simple_enum!`, which simply declares a C-like enum which
//! maps from case-insensitive tags (not requiring atom syntax) to enum values.
//!
//! `syntax_rule!` is much more complicated. It takes one of two forms:
//!
//! ```rust,no_run
//! #[modifiers...]
//! struct StructName<'a> {
//!   #[field modifiers...]
//!   #[field form]
//!   field_name: FieldType,
//!   ...
//! }
//! ```
//!
//! ```rust,no_run
//! #[modifiers]
//! enum EnumName<'a> {
//!   #[case modifiers...]
//!   #[case form]
//!   CaseName(CaseType),
//!   ...
//! }
//! ```
//!
//! Note that the `enum` form is strictly limited to what is shown: every
//! variant contains one value in parenthesis notation.
//!
//! The "form" attributes indicate how to handle the "root" type. It can be one
//! of the following:
//!
//! - `primitive(serialise_method, deserialise_function)`. Use
//!   `LexWriter::serialise_method` to write the type to the stream. Use
//!   `deserialise_function` (defined in this file) to parse the value.
//!
//! - `delegate`. Invoke `Type::parse` and `Type::write_to` to deserialise and
//!   serialise the value, where `Type` is the declared type of the field or
//!   case.
//!
//! - `delegate(Type)`. Invoke `Type::parse` and `Type::write_to` to
//!   deserialise and serialise the value, with an explicitly given type.
//!
//! - `tag(str)`. Map `str` to `()` at read. Ignore value and write `str` on
//!   write.
//!
//! - `cond(str)`. Map `str` to `true` and absence to `false` at read. Write
//! ` str` on `true` and nothing on `false`.
//!
//! - `phantom`. Map between nothingness and `PhantomData`.
//!
//! "modifiers" are more diverse. More than one can be chained together. When
//! there is more than one, they apply left to right. E.g., `suffix(" ") opt`
//! will always add/expect a space regardless of whether the value is present,
//! while `opt suffix(" ")` will only add/expect the suffix as part of the
//! inner value. The modifiers are:
//!
//! - `prefix(s)`: Add/expect the given prefix
//! - `suffix(s)`: Add/expect the given suffix
//! - `surrounded(a,b)`: Add/expect the given prefix and suffix
//! - `nil`: Map between `NIL` and `None`, other values to `Some`
//! - `nil_if_empty`: Map `.is_empty()` to `NIL` and `NIL` to `default()`
//! - `opt`: Map `None` to nothing and absence to `None`
//! - `marked_opt`: Map between `None` and some fixed tag
//! - `0*`: Repetition into a `Vec`, any number.
//! - `1*`: Repetition into a `Vec`, at least one occurrence.
//! - `0*(sep)`: Repetition into a `Vec`, any number. `sep` (a `&[u8]`) is
//!   inserted between items.
//! - `0*(sep)`: Repetition into a `Vec`, at least one occurrence. `sep` (a
//!   `&[u8]`) is inserted between items.
//! - `box`: Wrap/unwrap a `Box`.

use std::borrow::Cow;
use std::io::{self, Write};
use std::marker::PhantomData;
use std::str;

use chrono::prelude::*;
use nom::{
    branch::alt,
    bytes::complete::{is_a, is_not, tag, tag_no_case as kw},
    combinator::{map, map_opt, opt},
    *,
};

use super::lex::LexWriter;
use super::literal_source::LiteralSource;
use crate::account::model::Flag;
use crate::mime::encoded_word::ew_decode;
use crate::mime::utf7;

include!("syntax-macros.rs");

syntax_rule! {
    #[prefix("CAPABILITY")]
    struct CapabilityData<'a> {
        #[1* prefix(" ")]
        #[primitive(verbatim, normal_atom)]
        capabilities: Vec<Cow<'a, str>>,
    }
}

simple_enum! {
    enum RespCondType {
        Ok("OK"),
        No("NO"),
        Bad("BAD"),
        Bye("BYE"),
        Preauth("PREAUTH"),
    }
}

syntax_rule! {
    #[]
    struct CondResponse<'a> {
        #[marked_opt("*") suffix(" ")]
        #[primitive(verbatim, tag_atom)]
        tag: Option<Cow<'a, str>>,
        #[suffix(" ")]
        #[delegate]
        cond: RespCondType,
        // TODO Response data
        #[]
        #[primitive(verbatim, text)]
        quip: Cow<'a, str>,
    }
}

syntax_rule! {
    #[surrounded("(", ")")]
    struct Envelope<'a> {
        #[suffix(" ")]
        #[primitive(censored_nstring, nstring)]
        date: Option<Cow<'a, str>>,
        #[suffix(" ")]
        #[primitive(encoded_nstring, nstring)]
        subject: Option<Cow<'a, str>>,
        #[suffix(" ") nil_if_empty surrounded("(", ")") 1*]
        #[delegate(Address)]
        from: Vec<Address<'a>>,
        #[suffix(" ") nil_if_empty surrounded("(", ")") 1*]
        #[delegate(Address)]
        sender: Vec<Address<'a>>,
        #[suffix(" ") nil_if_empty surrounded("(", ")") 1*]
        #[delegate(Address)]
        reply_to: Vec<Address<'a>>,
        #[suffix(" ") nil_if_empty surrounded("(", ")") 1*]
        #[delegate(Address)]
        to: Vec<Address<'a>>,
        #[suffix(" ") nil_if_empty surrounded("(", ")") 1*]
        #[delegate(Address)]
        cc: Vec<Address<'a>>,
        #[suffix(" ") nil_if_empty surrounded("(", ")") 1*]
        #[delegate(Address)]
        bcc: Vec<Address<'a>>,
        #[suffix(" ")]
        #[primitive(censored_nstring, nstring)]
        in_reply_to: Option<Cow<'a, str>>,
        #[]
        #[primitive(censored_nstring, nstring)]
        message_id: Option<Cow<'a, str>>,
    }
}

// The RealAddress/GroupDelimiter distinction is not part of RFC 3501 syntax.
// However, since it puts the display name of groups into the "local part" of
// the delimiter, we need different cases since the group names can contain
// encoded words but a real local part can't.
syntax_rule! {
    #[surrounded("(", ")")]
    enum Address<'a> {
        #[]
        #[delegate]
        Real(RealAddress<'a>),
        // Groups never have a display name, routing, or domain
        #[surrounded("NIL NIL ", " NIL")]
        #[primitive(encoded_nstring, nstring)]
        GroupDelim(Option<Cow<'a, str>>),
    }
}

syntax_rule! {
    #[]
    struct RealAddress<'a> {
        #[suffix(" ")]
        #[primitive(encoded_nstring, nstring)]
        display_name: Option<Cow<'a, str>>,
        #[suffix(" ")]
        #[primitive(censored_nstring, nstring)]
        routing: Option<Cow<'a, str>>,
        // These are nstrings in the RFC 3501 syntax, but we handle that with
        // the separate GroupDelim case.
        #[suffix(" ")]
        #[primitive(censored_string, string)]
        local_part: Cow<'a, str>,
        #[]
        #[primitive(censored_string, string)]
        domain: Cow<'a, str>,
    }
}

syntax_rule! {
    #[surrounded("(", ")")]
    enum Body<'a> {
        #[]
        #[delegate]
        Multipart(BodyTypeMPart<'a>),
        #[]
        #[delegate]
        SinglePart(BodyType1Part<'a>),
    }
}

syntax_rule! {
    #[]
    struct BodyTypeMPart<'a> {
        // RFC 3501 makes this 1*, but in doing so disregards the possibility
        // of a multipart with no parts. We simply change the grammar to 0* to
        // represent this (which means that it is notated effectively by a
        // leading space, which is gross, but such is IMAP syntax).
        #[suffix(" ") 0*]
        #[delegate(Body)]
        bodies: Vec<Body<'a>>,
        #[]
        #[primitive(censored_string, string)]
        media_subtype: Cow<'a, str>,
        #[opt prefix(" ")]
        #[delegate(BodyExtMPart)]
        ext: Option<BodyExtMPart<'a>>,
    }
}

syntax_rule! {
    #[]
    struct BodyExtMPart<'a> {
        // This is suitable only for Crymap's own use; it doesn't handle extra
        // extension fields on the end, and requires all of the defined ones to
        // be present.
        #[suffix(" ") nil_if_empty surrounded("(", ")") 1*(" ")]
        #[primitive(censored_string, string)]
        content_type_parms: Vec<Cow<'a, str>>,
        #[suffix(" ") nil]
        #[delegate(ContentDisposition)]
        content_disposition: Option<ContentDisposition<'a>>,
        #[suffix(" ")]
        #[primitive(censored_nstring, nstring)]
        content_language: Option<Cow<'a, str>>,
        #[]
        #[primitive(censored_nstring, nstring)]
        content_location: Option<Cow<'a, str>>,
    }
}

syntax_rule! {
    #[]
    struct BodyType1Part<'a> {
        #[]
        #[delegate]
        core: ClassifiedBodyType1Part<'a>,
        #[opt prefix(" ")]
        #[delegate(BodyExt1Part)]
        ext: Option<BodyExt1Part<'a>>,
    }
}

syntax_rule! {
    #[]
    enum ClassifiedBodyType1Part<'a> {
        #[]
        #[delegate]
        Message(BodyTypeMsg<'a>),
        #[]
        #[delegate]
        Text(BodyTypeText<'a>),
        // Must come last so that greedy parsing has an opportunity to match
        // the content-type prefixes of the prior two.
        #[]
        #[delegate]
        Basic(BodyTypeBasic<'a>),
    }
}

syntax_rule! {
    #[]
    struct BodyTypeBasic<'a> {
        #[suffix(" ")]
        #[primitive(censored_string, string)]
        media_type: Cow<'a, str>,
        #[suffix(" ")]
        #[primitive(censored_string, string)]
        media_subtype: Cow<'a, str>,
        #[]
        #[delegate]
        body_fields: BodyFields<'a>,
    }
}

syntax_rule! {
    #[prefix("\"MESSAGE\" \"RFC822\" ")]
    struct BodyTypeMsg<'a> {
        #[suffix(" ")]
        #[delegate]
        body_fields: BodyFields<'a>,
        #[suffix(" ")]
        #[delegate]
        envelope: Envelope<'a>,
        #[suffix(" ") box]
        #[delegate(Body)]
        body: Box<Body<'a>>,
        #[]
        #[primitive(num_u32, number)]
        size_lines: u32,
    }
}

syntax_rule! {
    #[prefix("\"TEXT\" ")]
    struct BodyTypeText<'a> {
        #[suffix(" ")]
        #[primitive(censored_string, string)]
        media_subtype: Cow<'a, str>,
        #[suffix(" ")]
        #[delegate]
        body_fields: BodyFields<'a>,
        #[]
        #[primitive(num_u32, number)]
        size_lines: u32,
    }
}

syntax_rule! {
    #[]
    struct BodyFields<'a> {
        #[suffix(" ") nil_if_empty surrounded("(", ")") 1*(" ")]
        #[primitive(censored_string, string)]
        content_type_parms: Vec<Cow<'a, str>>,
        #[suffix(" ")]
        #[primitive(censored_nstring, nstring)]
        content_id: Option<Cow<'a, str>>,
        #[suffix(" ")]
        #[primitive(encoded_nstring, nstring)]
        content_description: Option<Cow<'a, str>>,
        #[suffix(" ")]
        #[primitive(censored_string, string)]
        content_transfer_encoding: Cow<'a, str>,
        #[]
        #[primitive(num_u32, number)]
        size_octets: u32,
    }
}

syntax_rule! {
    #[]
    struct BodyExt1Part<'a> {
        // This is suitable only for Crymap's own use; it doesn't handle extra
        // extension fields on the end, and requires all of the defined ones to
        // be present.
        #[suffix(" ")]
        #[primitive(censored_nstring, nstring)]
        md5: Option<Cow<'a, str>>,
        #[suffix(" ") nil]
        #[delegate(ContentDisposition)]
        content_disposition: Option<ContentDisposition<'a>>,
        #[suffix(" ")]
        #[primitive(censored_nstring, nstring)]
        content_language: Option<Cow<'a, str>>,
        #[]
        #[primitive(censored_nstring, nstring)]
        content_location: Option<Cow<'a, str>>,
    }
}

syntax_rule! {
    #[surrounded("(", ")")]
    struct ContentDisposition<'a> {
        #[suffix(" ")]
        #[primitive(censored_string, string)]
        disposition: Cow<'a, str>,
        #[nil_if_empty surrounded("(", ")") 1*(" ")]
        #[primitive(censored_string, string)]
        parms: Vec<Cow<'a, str>>,
    }
}

syntax_rule! {
    #[prefix("LIST ")]
    struct ListCommand<'a> {
        #[suffix(" ")]
        #[primitive(mailbox, mailbox)]
        reference: Cow<'a, str>,
        #[]
        #[primitive(mailbox, list_mailbox)]
        pattern: Cow<'a, str>,
    }
}

syntax_rule! {
    #[prefix("LSUB ")]
    struct LsubCommand<'a> {
        #[suffix(" ")]
        #[primitive(mailbox, mailbox)]
        reference: Cow<'a, str>,
        #[]
        #[primitive(mailbox, list_mailbox)]
        pattern: Cow<'a, str>,
    }
}

syntax_rule! {
    #[]
    struct MailboxList<'a> {
        // Note that we're also encoding the hierarchy delimiter field into
        // the suffix.
        #[surrounded("(", ") \"/\" ") 0*(" ")]
        #[primitive(verbatim, backslash_atom)]
        flags: Vec<Cow<'a, str>>,
        #[]
        #[primitive(mailbox, mailbox)]
        name: Cow<'a, str>,
    }
}

syntax_rule! {
    #[prefix("FETCH ")]
    struct FetchCommand<'a> {
        #[suffix(" ")]
        #[primitive(verbatim, sequence_set)]
        sequence_set: Cow<'a, str>,
        #[]
        #[delegate]
        target: FetchCommandTarget<'a>,
    }
}

syntax_rule! {
    #[]
    enum FetchCommandTarget<'a> {
        #[]
        #[tag("ALL")]
        All(()),
        #[]
        #[tag("FULL")]
        Full(()),
        #[]
        #[tag("FAST")]
        Fast(()),
        #[]
        #[delegate]
        Single(FetchAtt<'a>),
        #[surrounded("(", ")") 1*(" ")]
        #[delegate(FetchAtt)]
        Multi(Vec<FetchAtt<'a>>),
    }
}

syntax_rule! {
    #[]
    enum FetchAtt<'a> {
        #[]
        #[tag("ENVELOPE")]
        Envelope(()),
        #[]
        #[tag("FLAGS")]
        Flags(()),
        #[]
        #[tag("INTERNALDATE")]
        InternalDate(()),
        #[prefix("RFC822") opt]
        #[delegate(FetchAttRfc822)]
        Rfc822(Option<FetchAttRfc822>),
        // Must come before the body structure stuff to resolve the ambiguity
        // the correct way.
        #[prefix("BODY")]
        #[delegate]
        Body(FetchAttBody<'a>),
        #[]
        #[tag("BODYSTRUCTURE")]
        ExtendedBodyStructure(()),
        #[]
        #[tag("BODY")]
        ShortBodyStructure(()),
        #[]
        #[tag("UID")]
        Uid(()),
    }
}

simple_enum! {
    enum FetchAttRfc822 {
        Header(".HEADER"),
        Size(".SIZE"),
        Text(".TEXT"),
    }
}

syntax_rule! {
    #[]
    struct FetchAttBody<'a> {
        #[]
        #[cond(".PEEK")]
        peek: bool,
        #[surrounded("[", "]") opt]
        #[delegate(SectionSpec)]
        section: Option<SectionSpec<'a>>,
        #[opt]
        #[delegate(FetchAttBodySlice)]
        slice: Option<FetchAttBodySlice<'a>>,
    }
}

syntax_rule! {
    #[]
    enum SectionSpec<'a> {
        #[]
        #[delegate]
        TopLevel(SectionText<'a>),
        #[]
        #[delegate]
        Sub(SubSectionSpec<'a>),
    }
}

syntax_rule! {
    #[]
    struct SubSectionSpec<'a> {
        #[1*(".")]
        #[primitive(num_u32, number)]
        subscripts: Vec<u32>,
        #[opt prefix(".")]
        #[delegate(SectionText)]
        text: Option<SectionText<'a>>,
    }
}

syntax_rule! {
    #[]
    enum SectionText<'a> {
        #[prefix("HEADER.FIELDS")]
        #[delegate]
        HeaderFields(SectionTextHeaderField<'a>),
        #[]
        #[tag("HEADER")]
        Header(()),
        #[]
        #[tag("TEXT")]
        Text(()),
        #[]
        #[tag("MIME")]
        Mime(()),
    }
}

syntax_rule! {
    #[]
    struct SectionTextHeaderField<'a> {
        #[suffix(" ")]
        #[cond(".NOT")]
        negative: bool,
        #[surrounded("(", ")") 1*(" ")]
        #[primitive(censored_astring, astring)]
        headers: Vec<Cow<'a, str>>,
    }
}

syntax_rule! {
    #[surrounded("<", ">")]
    struct FetchAttBodySlice<'a> {
        #[suffix(".")]
        #[primitive(num_u32, number)]
        start: u32,
        #[]
        #[primitive(num_u32, number)]
        length: u32,
        #[]
        #[phantom]
        _marker: PhantomData<&'a ()>,
    }
}

// The RFC 3501 formal syntax is very awkward here since it lumps FETCH and
// EXPUNGE together because they both start with an nznumber. We follow suit
// in this case because it is more likely that extensions will want to patch
// these themselves.
//
// However, we don't do RFC 3501's very awkward split between `msg-att-dynamic`
// and `msg-att-static` because there is no reason to distinguish them
// grammatically. `msg_att` is renamed to `msg_atts` because it is not one
// attribute.
syntax_rule! {
    #[surrounded("(", ")")]
    struct MsgAtts<'a> {
        #[1*(" ")]
        #[delegate(MsgAtt)]
        atts: Vec<MsgAtt<'a>>,
    }
}

syntax_rule! {
    #[]
    enum MsgAtt<'a> {
        #[prefix("ENVELOPE ")]
        #[delegate]
        Envelope(Envelope<'a>),
        #[prefix("INTERNALDATE ")]
        #[primitive(datetime, datetime)]
        InternalDate(DateTime<FixedOffset>),
        // The formal grammar permits NIL for all these literals, but the
        // recommendation on the mailing list generally seems to be to never do
        // that and return empty strings instead, so we don't consider the NIL
        // case here.
        #[prefix("RFC822 ")]
        #[primitive(literal_source, literal_source)]
        Rfc822Full(LiteralSource),
        #[prefix("RFC822.HEADER ")]
        #[primitive(literal_source, literal_source)]
        Rfc822Header(LiteralSource),
        #[prefix("RFC822.TEXT ")]
        #[primitive(literal_source, literal_source)]
        Rfc822Text(LiteralSource),
        #[prefix("RFC822.SIZE ")]
        #[primitive(num_u32, number)]
        Rfc822Size(u32),
        #[prefix("BODY ")]
        #[delegate]
        ShortBodyStructure(Body<'a>),
        #[prefix("BODYSTRUCTURE ")]
        #[delegate]
        ExtendedBodyStructure(Body<'a>),
        #[prefix("BODY")]
        #[delegate]
        Body(MsgAttBody<'a>),
        #[prefix("UID ")]
        #[primitive(num_u32, number)]
        Uid(u32),
        #[surrounded("FLAGS (", ")")]
        #[delegate(FlagsFetch)]
        Flags(FlagsFetch<'a>),
    }
}

syntax_rule! {
    #[]
    struct MsgAttBody<'a> {
        #[surrounded("[", "]") opt]
        #[delegate(SectionSpec)]
        section: Option<SectionSpec<'a>>,
        #[opt surrounded("<", ">")]
        #[primitive(num_u32, number)]
        slice_origin: Option<u32>,
        #[prefix(" ")]
        #[primitive(literal_source, literal_source)]
        data: LiteralSource,
    }
}

syntax_rule! {
    // This somewhat awkward struct accounts for the fact that we don't treat
    // \Recent as a flag. The FLAGS part of the FETCH response is the only
    // place where \Recent can occur conditionally, so instead of adding
    // another layer to represent \Recent, we just have this contortion that
    // ensures that the correct number of spaces occur.
    //
    // This is another case where the definitions here are unsuitable for a
    // non-Crymap client, since it can only parse the list if \Recent is the
    // first item.
    #[]
    enum FlagsFetch<'a> {
        #[prefix("\\Recent") 0* prefix(" ")]
        #[primitive(flag, flag)]
        Recent(Vec<Flag>),
        #[0*(" ")]
        #[primitive(flag, flag)]
        NotRecent(Vec<Flag>),
        // We never actually parse FlagsFetch in the server so this marker case
        // is moot.
        #[prefix("\x00")]
        #[phantom]
        _Marker(PhantomData<&'a ()>),
    }
}

// SearchKey is broken into several smaller parts to prevent alt() expansions
// from getting too large.
simple_enum! {
    enum SimpleSearchKey {
        All("ALL"),
        Answered("ANSWERED"),
        Deleted("DELETED"),
        Flagged("FLAGGED"),
        New("NEW"),
        Old("OLD"),
        Recent("RECENT"),
        Seen("SEEN"),
        Unanswered("UNANSWERED"),
        Undeleted("UNDELETED"),
        Unflagged("UNFLAGGED"),
        Unseen("UNSEEN"),
        Draft("DRAFT"),
        Undraft("UNDRAFT"),
    }
}

syntax_rule! {
    #[]
    struct TextSearchKey<'a> {
        #[suffix(" ")]
        #[delegate]
        typ: TextSearchKeyType,
        #[]
        #[primitive(unicode_astring, astring)]
        value: Cow<'a, str>,
    }
}

simple_enum! {
    enum TextSearchKeyType {
        Bcc("BCC"),
        Body("BODY"),
        Cc("CC"),
        From("FROM"),
        Subject("SUBJECT"),
        Text("TEXT"),
        To("TO"),
    }
}

syntax_rule! {
    #[]
    struct DateSearchKey<'a> {
        #[suffix(" ")]
        #[delegate]
        typ: DateSearchKeyType,
        #[]
        #[primitive(date, date)]
        date: NaiveDate,
        #[]
        #[phantom]
        _marker: PhantomData<&'a ()>,
    }
}

simple_enum! {
    enum DateSearchKeyType {
        Before("BEFORE"),
        On("ON"),
        Since("SINCE"),
        SentBefore("SENTBEFORE"),
        SentOn("SENTON"),
        SentSince("SENTSINCE"),
    }
}

syntax_rule! {
    #[prefix("SEARCH ")]
    struct SearchCommand<'a> {
        #[opt surrounded("CHARSET ", " ")]
        #[primitive(censored_astring, astring)]
        charset: Option<Cow<'a, str>>,
        #[1*(" ")]
        #[delegate(SearchKey)]
        keys: Vec<SearchKey<'a>>,
    }
}

syntax_rule! {
    #[]
    enum SearchKey<'a> {
        #[]
        #[delegate]
        Simple(SimpleSearchKey),
        #[]
        #[delegate]
        Text(TextSearchKey<'a>),
        #[]
        #[delegate]
        Date(DateSearchKey<'a>),
        #[prefix("KEYWORD ")]
        #[primitive(flag, keyword)]
        Keyword(Flag),
        #[prefix("UNKEYWORD ")]
        #[primitive(flag, keyword)]
        Unkeyword(Flag),
        #[prefix("HEADER ")]
        #[delegate]
        Header(SearchKeyHeader<'a>),
        #[prefix("LARGER ")]
        #[primitive(num_u32, number)]
        Larger(u32),
        #[prefix("NOT ") box]
        #[delegate(SearchKey)]
        Not(Box<SearchKey<'a>>),
        #[prefix("OR ")]
        #[delegate]
        Or(SearchKeyOr<'a>),
        #[prefix("SMALLER ")]
        #[primitive(num_u32, number)]
        Smaller(u32),
        #[prefix("UID ")]
        #[primitive(verbatim, sequence_set)]
        Uid(Cow<'a, str>),
        #[]
        #[primitive(verbatim, sequence_set)]
        Seqnum(Cow<'a, str>),
        #[surrounded("(", ")") 1*(" ")]
        #[delegate(SearchKey)]
        And(Vec<SearchKey<'a>>),
    }
}

syntax_rule! {
    #[]
    struct SearchKeyHeader<'a> {
        #[suffix(" ")]
        #[primitive(censored_astring, astring)]
        header: Cow<'a, str>,
        #[]
        #[primitive(unicode_astring, astring)]
        value: Cow<'a, str>,
    }
}

syntax_rule! {
    #[]
    struct SearchKeyOr<'a> {
        #[suffix(" ") box]
        #[delegate(SearchKey)]
        a: Box<SearchKey<'a>>,
        #[box]
        #[delegate(SearchKey)]
        b: Box<SearchKey<'a>>,
    }
}

syntax_rule! {
    #[prefix("CREATE ")]
    struct CreateCommand<'a> {
        #[]
        #[primitive(mailbox, mailbox)]
        mailbox: Cow<'a, str>,
    }
}

syntax_rule! {
    #[prefix("DELETE ")]
    struct DeleteCommand<'a> {
        #[]
        #[primitive(mailbox, mailbox)]
        mailbox: Cow<'a, str>,
    }
}

syntax_rule! {
    #[prefix("EXAMINE ")]
    struct ExamineCommand<'a> {
        #[]
        #[primitive(mailbox, mailbox)]
        mailbox: Cow<'a, str>,
    }
}

syntax_rule! {
    #[prefix("RENAME ")]
    struct RenameCommand<'a> {
        #[suffix(" ")]
        #[primitive(mailbox, mailbox)]
        src: Cow<'a, str>,
        #[]
        #[primitive(mailbox, mailbox)]
        dst: Cow<'a, str>,
    }
}

syntax_rule! {
    #[prefix("SELECT ")]
    struct SelectCommand<'a> {
        #[]
        #[primitive(mailbox, mailbox)]
        mailbox: Cow<'a, str>,
    }
}

syntax_rule! {
    #[prefix("STATUS ")]
    struct StatusCommand<'a> {
        #[suffix(" ")]
        #[primitive(mailbox, mailbox)]
        mailbox: Cow<'a, str>,
        #[surrounded("(", ")") 1*(" ")]
        #[delegate(StatusAtt)]
        atts: Vec<StatusAtt>,
    }
}

simple_enum! {
    enum StatusAtt {
        Messages("MESSAGES"),
        Recent("RECENT"),
        UidNext("UIDNEXT"),
        UidValidity("UIDVALIDITY"),
        Unseen("UNSEEN"),
    }
}

syntax_rule! {
    #[prefix("SUBSCRIBE ")]
    struct SubscribeCommand<'a> {
        #[]
        #[primitive(mailbox, mailbox)]
        mailbox: Cow<'a, str>,
    }
}

syntax_rule! {
    #[prefix("UNSUBSCRIBE ")]
    struct UnsubscribeCommand<'a> {
        #[]
        #[primitive(mailbox, mailbox)]
        mailbox: Cow<'a, str>,
    }
}

// ==================== PRIMITIVE PARSERS ====================

fn normal_atom(i: &[u8]) -> IResult<&[u8], Cow<str>> {
    map(
        bytes::complete::take_while1(|b| match b {
            0..=b' ' => false,
            127..=255 => false,
            b'(' | b')' | b'{' | b'*' | b'%' | b'\\' | b'"' | b']' => false,
            _ => true,
        }),
        String::from_utf8_lossy,
    )(i)
}

// This isn't formally part of the IMAP syntax definition. It makes our lives
// easier since we can keep the backslash prefix throughout. It does mean the
// parser will initially accept garbage like "foo\bar", but we eventually
// reject it when a later stage tries to coerce the value into an enum or safe
// name. The formal syntax never also requires us to break tokens on backslash,
// so including it here also won't break any valid syntax.
fn backslash_atom(i: &[u8]) -> IResult<&[u8], Cow<str>> {
    map(
        bytes::complete::take_while1(|b| match b {
            0..=b' ' => false,
            127..=255 => false,
            b'(' | b')' | b'{' | b'*' | b'%' | b'"' | b']' => false,
            _ => true,
        }),
        String::from_utf8_lossy,
    )(i)
}

fn astring_atom(i: &[u8]) -> IResult<&[u8], Cow<str>> {
    map(
        bytes::complete::take_while1(|b| match b {
            0..=b' ' => false,
            127..=255 => false,
            b'(' | b')' | b'{' | b'*' | b'%' | b'\\' | b'"' => false,
            _ => true,
        }),
        String::from_utf8_lossy,
    )(i)
}

fn tag_atom(i: &[u8]) -> IResult<&[u8], Cow<str>> {
    map(
        bytes::complete::take_while1(|b| match b {
            0..=b' ' => false,
            127..=255 => false,
            b'(' | b')' | b'{' | b'*' | b'%' | b'\\' | b'"' | b'+' => false,
            _ => true,
        }),
        String::from_utf8_lossy,
    )(i)
}

fn list_mailbox_atom(i: &[u8]) -> IResult<&[u8], Cow<str>> {
    map(
        bytes::complete::take_while1(|b| match b {
            0..=b' ' => false,
            127..=255 => false,
            b'(' | b')' | b'{' | b'\\' | b'"' => false,
            _ => true,
        }),
        String::from_utf8_lossy,
    )(i)
}

fn number(i: &[u8]) -> IResult<&[u8], u32> {
    map_opt(character::complete::digit1, |s| {
        str::from_utf8(s).ok().and_then(|s| s.parse::<u32>().ok())
    })(i)
}

fn literal(i: &[u8]) -> IResult<&[u8], &[u8]> {
    let (i, len) = sequence::delimited(
        alt((tag("~{"), tag("{"))),
        number,
        alt((tag("+}\r\n"), tag("}\r\n"))),
    )(i)?;
    bytes::complete::take(len)(i)
}

// Only used to re-read fetch responses.
fn literal_source(i: &[u8]) -> IResult<&[u8], LiteralSource> {
    alt((
        literal_literal_source,
        map(quoted, |s| {
            let len = s.len();
            let data: Vec<u8> = s.into_owned().into();

            LiteralSource::of_reader(io::Cursor::new(data), len as u64, false)
        }),
    ))(i)
}

fn literal_literal_source(i: &[u8]) -> IResult<&[u8], LiteralSource> {
    let (i, prefix) = alt((tag("~{"), tag("{")))(i)?;
    let binary = prefix.starts_with(b"~");
    let (i, len) =
        sequence::terminated(number, alt((tag("+}\r\n"), tag("}\r\n"))))(i)?;
    let (i, data) = bytes::complete::take(len)(i)?;

    Ok((
        i,
        LiteralSource::of_reader(
            io::Cursor::new(data.to_owned()),
            len as u64,
            binary,
        ),
    ))
}

fn quoted_char(i: &[u8]) -> IResult<&[u8], &[u8]> {
    sequence::preceded(tag("\\"), alt((tag("\\"), tag("\""))))(i)
}

fn quoted_string_content(i: &[u8]) -> IResult<&[u8], &[u8]> {
    alt((quoted_char, is_not("\r\n\"\\")))(i)
}

fn quoted(i: &[u8]) -> IResult<&[u8], Cow<str>> {
    sequence::delimited(
        tag("\""),
        multi::fold_many0(
            map(quoted_string_content, String::from_utf8_lossy),
            Cow::Owned(String::new()),
            |mut accum: Cow<str>, piece| {
                if accum.is_empty() {
                    piece
                } else {
                    Cow::to_mut(&mut accum).push_str(&piece);
                    accum
                }
            },
        ),
        tag("\""),
    )(i)
}

fn string(i: &[u8]) -> IResult<&[u8], Cow<str>> {
    alt((quoted, map(literal, String::from_utf8_lossy)))(i)
}

fn astring(i: &[u8]) -> IResult<&[u8], Cow<str>> {
    alt((astring_atom, string))(i)
}

fn nstring(i: &[u8]) -> IResult<&[u8], Option<Cow<str>>> {
    alt((map(kw("NIL"), |_| None), map(string, Some)))(i)
}

// Read: "mailbox as used by LIST and LSUB"
// Because naturally we need different syntax for that than other uses of
// mailbox names.
fn list_mailbox(i: &[u8]) -> IResult<&[u8], Cow<str>> {
    map(alt((list_mailbox_atom, string)), |raw| match raw {
        Cow::Owned(s) => Cow::Owned(utf7::IMAP.decode(&s).into_owned()),
        Cow::Borrowed(s) => utf7::IMAP.decode(s),
    })(i)
}

// TODO We should make this more sophisticated so that we don't butcher mailbox
// names that happen to contain `&` but were submitted by Unicode-aware
// clients. That probably means making a `MailboxName` struct that contains
// both the raw and decoded form so that the higher level can decide which to
// use.
//
// RFC 6855 is actually horribly vague on this point:
//
//   All IMAP servers that support "UTF8=ACCEPT" SHOULD accept UTF-8 in
//   mailbox names, and those that also support the Mailbox International
//   Naming Convention described in RFC 3501, Section 5.1.3, MUST accept
//   UTF8-quoted mailbox names and convert them to the appropriate
//   internal format.  Mailbox names MUST comply with the Net-Unicode
//   Definition ([RFC5198], Section 2) with the specific exception that
//   they MUST NOT contain control characters (U+0000-U+001F and U+0080-U+
//   009F), a delete character (U+007F), a line separator (U+2028), or a
//   paragraph separator (U+2029).
//
// We MUST support UTF-8 mailbox names, as expected, it doesn't say whether we
// are expected to stop MUTF7 or keep doing it.
//
// The IMAP4rev2 draft doesn't provide guidance here either:
//
//   Support for the Mailbox International Naming Convention described in
//   this section is not required for IMAP4rev2-only clients and servers.
//
//   By convention, international mailbox names in IMAP4rev1 are specified
//   using a modified version of the UTF-7 encoding described in [UTF-7].
//   Modified UTF-7 may also be usable in servers that implement an
//   earlier version of this protocol.
//
// All that follows is a description of how MUTF7 works.
//
// Maybe the best solution is to just make MUTF7 handling much stricter
// (require terminating '-', don't deal with bad base64) to minimise the
// chances of a user accidentally typing in a mailbox name that gets handled as
// MUTF7 into a UTF-8-only client that doesn't add its own layer of MUTF7.
// Overall, this is a pretty bad situation, since clients have a choice of
// turning `&` into `&-` and risking creating a different mailbox than the user
// typed in, or leaving `&` alone and risking MUTF7.
//
// TODO The current approach of not encoding anything out the door for
// Unicode-aware clients also has its problems, since we could, for example,
// return an unencoded name that looks like an encoded name, and then when the
// client tries to use that unencoded name, we "decode" it and try to access a
// different mailbox. In other words, the resolution here is pretty clearly "no
// MUTF7 at all for Unicode clients".
fn mailbox(i: &[u8]) -> IResult<&[u8], Cow<str>> {
    map(astring, |raw| match raw {
        Cow::Owned(s) => Cow::Owned(utf7::IMAP.decode(&s).into_owned()),
        Cow::Borrowed(s) => utf7::IMAP.decode(s),
    })(i)
}

fn sequence_set(i: &[u8]) -> IResult<&[u8], Cow<str>> {
    map(is_a("0123456789:*,"), String::from_utf8_lossy)(i)
}

fn text(i: &[u8]) -> IResult<&[u8], Cow<str>> {
    map(is_not("\r\n"), String::from_utf8_lossy)(i)
}

fn keyword(i: &[u8]) -> IResult<&[u8], Flag> {
    map_opt(normal_atom, |a| {
        ew_decode(&a)
            .map(Cow::Owned)
            .unwrap_or(a)
            .parse::<Flag>()
            .ok()
    })(i)
}

fn flag(i: &[u8]) -> IResult<&[u8], Flag> {
    alt((keyword, map_opt(backslash_atom, |s| s.parse::<Flag>().ok())))(i)
}

fn parse_u32_infallible(i: &[u8]) -> u32 {
    str::from_utf8(i).unwrap().parse::<u32>().unwrap()
}

fn one_digit(i: &[u8]) -> IResult<&[u8], u32> {
    combinator::map(
        bytes::complete::take_while_m_n(1, 1, character::is_digit),
        parse_u32_infallible,
    )(i)
}

fn two_digit(i: &[u8]) -> IResult<&[u8], u32> {
    combinator::map(
        bytes::complete::take_while_m_n(2, 2, character::is_digit),
        parse_u32_infallible,
    )(i)
}

fn four_digit(i: &[u8]) -> IResult<&[u8], u32> {
    combinator::map(
        bytes::complete::take_while_m_n(4, 4, character::is_digit),
        parse_u32_infallible,
    )(i)
}

fn time_of_day(i: &[u8]) -> IResult<&[u8], (u32, u32, u32)> {
    sequence::tuple((
        two_digit,
        sequence::preceded(tag(":"), two_digit),
        sequence::preceded(tag(":"), two_digit),
    ))(i)
}

fn numeric_zone(i: &[u8]) -> IResult<&[u8], i32> {
    map(
        sequence::pair(
            alt((tag("+"), tag("-"))),
            sequence::pair(two_digit, two_digit),
        ),
        |(sign, (h, m))| {
            let n = (h * 60 + m) as i32;
            if b"-" == sign {
                -n
            } else {
                n
            }
        },
    )(i)
}

static MONTH_NAMES: [&str; 12] = [
    "jan", "fe", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov",
    "dec",
];
fn month(i: &[u8]) -> IResult<&[u8], u32> {
    map_opt(bytes::complete::take(3usize), |name| {
        str::from_utf8(name).ok().and_then(|name| {
            MONTH_NAMES
                .iter()
                .enumerate()
                .filter(|&(_, n)| n.eq_ignore_ascii_case(name))
                .map(|(ix, _)| ix as u32 + 1)
                .next()
        })
    })(i)
}

fn date_text(i: &[u8]) -> IResult<&[u8], NaiveDate> {
    map_opt(
        sequence::tuple((
            sequence::terminated(alt((two_digit, one_digit)), tag("-")),
            sequence::terminated(month, tag("-")),
            four_digit,
        )),
        |(d, m, y)| NaiveDate::from_ymd_opt(y as i32, m, d),
    )(i)
}

fn date(i: &[u8]) -> IResult<&[u8], NaiveDate> {
    alt((
        date_text,
        sequence::delimited(tag("\""), date_text, tag("\"")),
    ))(i)
}

fn datetime_date(i: &[u8]) -> IResult<&[u8], NaiveDate> {
    map_opt(
        sequence::tuple((
            sequence::terminated(
                alt((two_digit, sequence::preceded(tag(" "), one_digit))),
                tag("-"),
            ),
            sequence::terminated(month, tag("-")),
            four_digit,
        )),
        |(d, m, y)| NaiveDate::from_ymd_opt(y as i32, m, d),
    )(i)
}

fn datetime(i: &[u8]) -> IResult<&[u8], DateTime<FixedOffset>> {
    map_opt(
        sequence::delimited(
            tag("\""),
            sequence::tuple((
                sequence::terminated(datetime_date, tag(" ")),
                sequence::terminated(time_of_day, tag(" ")),
                numeric_zone,
            )),
            tag("\""),
        ),
        |(date, (h, m, s), zone)| {
            FixedOffset::east_opt(zone * 60).and_then(|offset| {
                date.and_hms_opt(h, m, s).and_then(|datetime| {
                    offset.from_local_datetime(&datetime).latest()
                })
            })
        },
    )(i)
}

#[cfg(test)]
mod test {
    use super::*;

    macro_rules! assert_reversible {
        ($ty:ty, $expected_text:expr, $value:expr) => {
            assert_reversible!(true, $ty, $expected_text, $value);
        };
        ($unicode:expr, $ty:ty, $expected_text:expr, $value:expr) => {{
            let value = &mut $value;
            let mut lex = LexWriter::new(Vec::<u8>::new(), $unicode, false);
            value.write_to(&mut lex).unwrap();
            let text = lex.into_inner();
            let text = str::from_utf8(&text).unwrap();
            if $expected_text != text {
                panic!(
                    "Didn't generate correct string\n\
                        Expected: {}\n\
                        Actual:   {}\n\
                        Diff:     {}\n",
                    $expected_text,
                    text,
                    diff($expected_text, text)
                );
            }

            let (trailing, read) = match <$ty>::parse(text.as_bytes()) {
                Ok(read) => read,
                Err(e) => panic!("Failed to parse `{}`: {}`", text, e),
            };

            if !trailing.is_empty() {
                panic!(
                    "Didn't parse all of `{}`, `{}` remained",
                    text,
                    String::from_utf8_lossy(trailing)
                );
            }
            assert_eq!(value, &read);
        }};
    }

    macro_rules! assert_non_unicode_as {
        ($expected_text:expr, $value: expr) => {{
            let value = &mut $value;
            let mut lex = LexWriter::new(Vec::<u8>::new(), false, false);
            value.write_to(&mut lex).unwrap();
            let text = lex.into_inner();
            let text = str::from_utf8(&text).unwrap();
            if $expected_text != text {
                panic!(
                    "Didn't generate correct string\n\
                        Expected: {}\n\
                        Actual:   {}\n\
                        Diff:     {}\n",
                    $expected_text,
                    text,
                    diff($expected_text, text)
                );
            }
        }};
    }

    fn diff(a: &str, b: &str) -> String {
        let mut accum = String::new();
        for (a, b) in a.chars().zip(b.chars()) {
            if a == b {
                accum.push(' ');
            } else {
                accum.push('^');
            }
        }

        accum
    }

    fn s(s: &str) -> Cow<'static, str> {
        Cow::Owned(s.to_owned())
    }

    fn ns(ns: &str) -> Option<Cow<'static, str>> {
        Some(s(ns))
    }

    #[test]
    fn envelope_syntax() {
        // RFC 3501 section 8 example
        assert_reversible!(
            Envelope,
            // NB Sending this date string violates RFC 5322 (and the earlier
            // RFCs) since `(PDT)` is not part of the date, but that doesn't
            // really concern us here.
            "(\"Wed, 17 Jul 1996 02:23:25 -0700 (PDT)\" \
             \"IMAP4rev1 WG mtg summary and minutes\" \
             ((\"Terry Gray\" NIL \"gray\" \"cac.washington.edu\")) \
             ((\"Terry Gray\" NIL \"gray\" \"cac.washington.edu\")) \
             ((\"Terry Gray\" NIL \"gray\" \"cac.washington.edu\")) \
             ((NIL NIL \"imap\" \"cac.washington.edu\")) \
             ((NIL NIL \"minutes\" \"CNRI.Reston.VA.US\")\
             (\"John Klensin\" NIL \"KLENSIN\" \"MIT.EDU\")) NIL NIL \
             \"<B27397-0100000@cac.washington.edu>\")",
            Envelope {
                date: ns("Wed, 17 Jul 1996 02:23:25 -0700 (PDT)"),
                subject: ns("IMAP4rev1 WG mtg summary and minutes"),
                from: vec![Address::Real(RealAddress {
                    display_name: ns("Terry Gray"),
                    routing: None,
                    local_part: s("gray"),
                    domain: s("cac.washington.edu"),
                })],
                sender: vec![Address::Real(RealAddress {
                    display_name: ns("Terry Gray"),
                    routing: None,
                    local_part: s("gray"),
                    domain: s("cac.washington.edu"),
                })],
                reply_to: vec![Address::Real(RealAddress {
                    display_name: ns("Terry Gray"),
                    routing: None,
                    local_part: s("gray"),
                    domain: s("cac.washington.edu"),
                })],
                to: vec![Address::Real(RealAddress {
                    display_name: None,
                    routing: None,
                    local_part: s("imap"),
                    domain: s("cac.washington.edu"),
                })],
                cc: vec![
                    Address::Real(RealAddress {
                        display_name: None,
                        routing: None,
                        local_part: s("minutes"),
                        domain: s("CNRI.Reston.VA.US"),
                    }),
                    Address::Real(RealAddress {
                        display_name: ns("John Klensin"),
                        routing: None,
                        local_part: s("KLENSIN"),
                        domain: s("MIT.EDU"),
                    })
                ],
                bcc: vec![],
                in_reply_to: None,
                message_id: ns("<B27397-0100000@cac.washington.edu>"),
            }
        );

        let mut with_unicode_and_groups = Envelope {
            date: None,
            subject: ns("föö"),
            from: vec![
                Address::GroupDelim(ns("Gröüp")),
                Address::Real(RealAddress {
                    display_name: ns("Zoë"),
                    routing: None,
                    local_part: s("zoë"),
                    domain: s("zoë.com"),
                }),
                Address::GroupDelim(None),
            ],
            sender: vec![],
            reply_to: vec![],
            to: vec![],
            cc: vec![],
            bcc: vec![],
            in_reply_to: None,
            message_id: None,
        };

        assert_reversible!(
            Envelope,
            "(NIL \"föö\" \
             ((NIL NIL \"Gröüp\" NIL)\
             (\"Zoë\" NIL \"zoë\" \"zoë.com\")\
             (NIL NIL NIL NIL)) \
             NIL NIL NIL NIL NIL NIL NIL)",
            with_unicode_and_groups.clone()
        );

        assert_non_unicode_as!(
            "(NIL \"=?utf-8?b?ZsO2w7Y?=\" \
             ((NIL NIL \"=?utf-8?b?R3LDtsO8cA?=\" NIL)\
             (\"=?utf-8?b?Wm/Dqw?=\" NIL \"zoX\" \"zoX.com\")\
             (NIL NIL NIL NIL)) \
             NIL NIL NIL NIL NIL NIL NIL)",
            with_unicode_and_groups
        );
    }

    #[test]
    fn body_structure_syntax() {
        // RFC 3501 section 8 example
        assert_reversible!(
            Body,
            r#"("TEXT" "PLAIN" ("CHARSET" "US-ASCII") NIL NIL "7BIT" 3028 92)"#,
            Body::SinglePart(BodyType1Part {
                core: ClassifiedBodyType1Part::Text(BodyTypeText {
                    media_subtype: s("PLAIN"),
                    body_fields: BodyFields {
                        content_type_parms: vec![s("CHARSET"), s("US-ASCII")],
                        content_id: None,
                        content_description: None,
                        content_transfer_encoding: s("7BIT"),
                        size_octets: 3028,
                    },
                    size_lines: 92,
                }),
                ext: None,
            })
        );

        // First example from
        // http://sgerwk.altervista.org/imapbodystructure.html
        assert_reversible!(
            Body,
            "(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"iso-8859-1\") \
             NIL NIL \"QUOTED-PRINTABLE\" 1315 42 NIL NIL NIL NIL)",
            Body::SinglePart(BodyType1Part {
                core: ClassifiedBodyType1Part::Text(BodyTypeText {
                    media_subtype: s("PLAIN"),
                    body_fields: BodyFields {
                        content_type_parms: vec![s("CHARSET"), s("iso-8859-1")],
                        content_id: None,
                        content_description: None,
                        content_transfer_encoding: s("QUOTED-PRINTABLE"),
                        size_octets: 1315,
                    },
                    size_lines: 42,
                }),
                ext: Some(BodyExt1Part {
                    md5: None,
                    content_disposition: None,
                    content_language: None,
                    content_location: None,
                }),
            })
        );

        // Next example from the same page
        assert_reversible!(
            Body,
            "((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"iso-8859-1\") \
             NIL NIL \"QUOTED-PRINTABLE\" 2234 63 NIL NIL NIL NIL)\
             (\"TEXT\" \"HTML\" (\"CHARSET\" \"iso-8859-1\") NIL NIL \
             \"QUOTED-PRINTABLE\" 2987 52 NIL NIL NIL NIL) \
             \"ALTERNATIVE\" (\"BOUNDARY\" \"d3438gr7324\") NIL NIL NIL)",
            Body::Multipart(BodyTypeMPart {
                bodies: vec![
                    Body::SinglePart(BodyType1Part {
                        core: ClassifiedBodyType1Part::Text(BodyTypeText {
                            media_subtype: s("PLAIN"),
                            body_fields: BodyFields {
                                content_type_parms: vec![
                                    s("CHARSET"),
                                    s("iso-8859-1"),
                                ],
                                content_id: None,
                                content_description: None,
                                content_transfer_encoding: s(
                                    "QUOTED-PRINTABLE"
                                ),
                                size_octets: 2234,
                            },
                            size_lines: 63,
                        }),
                        ext: Some(BodyExt1Part {
                            md5: None,
                            content_disposition: None,
                            content_language: None,
                            content_location: None,
                        }),
                    }),
                    Body::SinglePart(BodyType1Part {
                        core: ClassifiedBodyType1Part::Text(BodyTypeText {
                            media_subtype: s("HTML"),
                            body_fields: BodyFields {
                                content_type_parms: vec![
                                    s("CHARSET"),
                                    s("iso-8859-1"),
                                ],
                                content_id: None,
                                content_description: None,
                                content_transfer_encoding: s(
                                    "QUOTED-PRINTABLE"
                                ),
                                size_octets: 2987,
                            },
                            size_lines: 52,
                        }),
                        ext: Some(BodyExt1Part {
                            md5: None,
                            content_disposition: None,
                            content_language: None,
                            content_location: None,
                        }),
                    }),
                ],
                media_subtype: s("ALTERNATIVE"),
                ext: Some(BodyExtMPart {
                    content_type_parms: vec![s("BOUNDARY"), s("d3438gr7324")],
                    content_disposition: None,
                    content_language: None,
                    content_location: None,
                }),
            })
        );

        // "mail with images" example on the same page
        // Note that the example omits the (optional) content_location field in
        // the extended data for all the parts; those were added in by hand.
        assert_reversible!(
            Body,
            "((\"TEXT\" \"HTML\" (\"CHARSET\" \"US-ASCII\") \
             NIL NIL \"7BIT\" 119 2 NIL (\"INLINE\" NIL) NIL NIL)\
             (\"IMAGE\" \"JPEG\" (\"NAME\" \"4356415.jpg\") \
             \"<0__=rhksjt>\" NIL \"BASE64\" 143804 NIL \
             (\"INLINE\" (\"FILENAME\" \"4356415.jpg\")) NIL NIL) \
             \"RELATED\" (\"BOUNDARY\" \"0__=5tgd3d\") (\"INLINE\" NIL) \
             NIL NIL)",
            Body::Multipart(BodyTypeMPart {
                bodies: vec![
                    Body::SinglePart(BodyType1Part {
                        core: ClassifiedBodyType1Part::Text(BodyTypeText {
                            media_subtype: s("HTML"),
                            body_fields: BodyFields {
                                content_type_parms: vec![
                                    s("CHARSET"),
                                    s("US-ASCII"),
                                ],
                                content_id: None,
                                content_description: None,
                                content_transfer_encoding: s("7BIT"),
                                size_octets: 119,
                            },
                            size_lines: 2,
                        }),
                        ext: Some(BodyExt1Part {
                            md5: None,
                            content_disposition: Some(ContentDisposition {
                                disposition: s("INLINE"),
                                parms: vec![],
                            }),
                            content_language: None,
                            content_location: None,
                        }),
                    }),
                    Body::SinglePart(BodyType1Part {
                        core: ClassifiedBodyType1Part::Basic(BodyTypeBasic {
                            media_type: s("IMAGE"),
                            media_subtype: s("JPEG"),
                            body_fields: BodyFields {
                                content_type_parms: vec![
                                    s("NAME"),
                                    s("4356415.jpg"),
                                ],
                                content_id: ns("<0__=rhksjt>"),
                                content_description: None,
                                content_transfer_encoding: s("BASE64"),
                                size_octets: 143804,
                            },
                        }),
                        ext: Some(BodyExt1Part {
                            md5: None,
                            content_disposition: Some(ContentDisposition {
                                disposition: s("INLINE"),
                                parms: vec![s("FILENAME"), s("4356415.jpg")],
                            }),
                            content_language: None,
                            content_location: None,
                        }),
                    }),
                ],
                media_subtype: s("RELATED"),
                ext: Some(BodyExtMPart {
                    content_type_parms: vec![s("BOUNDARY"), s("0__=5tgd3d")],
                    content_disposition: Some(ContentDisposition {
                        disposition: s("INLINE"),
                        parms: vec![],
                    }),
                    content_language: None,
                    content_location: None,
                }),
            })
        );

        // Couldn't find any examples of the MESSAGE/RFC822 special case. This
        // was written by hand.
        assert_reversible!(
            Body,
            "(\"MESSAGE\" \"RFC822\" (\"parm\" \"foo\") \
             \"<ContentID>\" \"Content Description\" \
             \"8bit\" 1234 \
             (\"04 Jul 2020 16:31:00 +0000\" \
             \"Subject\" NIL NIL NIL NIL NIL NIL NIL \"<MessageID>\") \
             (\"TEXT\" \"PLAIN\" (\"CHARSET\" \"US-ASCII\") \
             NIL NIL \"7BIT\" 3028 92) \
             64)",
            Body::SinglePart(BodyType1Part {
                core: ClassifiedBodyType1Part::Message(BodyTypeMsg {
                    body_fields: BodyFields {
                        content_type_parms: vec![s("parm"), s("foo")],
                        content_id: ns("<ContentID>"),
                        content_description: ns("Content Description"),
                        content_transfer_encoding: s("8bit"),
                        size_octets: 1234,
                    },
                    envelope: Envelope {
                        date: ns("04 Jul 2020 16:31:00 +0000"),
                        subject: ns("Subject"),
                        from: vec![],
                        sender: vec![],
                        reply_to: vec![],
                        to: vec![],
                        cc: vec![],
                        bcc: vec![],
                        in_reply_to: None,
                        message_id: ns("<MessageID>"),
                    },
                    body: Box::new(Body::SinglePart(BodyType1Part {
                        core: ClassifiedBodyType1Part::Text(BodyTypeText {
                            media_subtype: s("PLAIN"),
                            body_fields: BodyFields {
                                content_type_parms: vec![
                                    s("CHARSET"),
                                    s("US-ASCII"),
                                ],
                                content_id: None,
                                content_description: None,
                                content_transfer_encoding: s("7BIT"),
                                size_octets: 3028,
                            },
                            size_lines: 92,
                        }),
                        ext: None,
                    })),
                    size_lines: 64,
                }),
                ext: None,
            })
        );
    }

    #[test]
    fn list_lsub_syntax() {
        assert_reversible!(
            ListCommand,
            r#"LIST "" INBOX"#,
            ListCommand {
                reference: s(""),
                pattern: s("INBOX"),
            }
        );
        assert_reversible!(
            LsubCommand,
            r#"LSUB foo bar"#,
            LsubCommand {
                reference: s("foo"),
                pattern: s("bar"),
            }
        );

        assert_reversible!(
            true,
            ListCommand,
            r#"LIST "" "föö""#,
            ListCommand {
                reference: s(""),
                pattern: s("föö"),
            }
        );
        assert_reversible!(
            false,
            ListCommand,
            r#"LIST "" "~peter/mail/&U,BTFw-/&ZeVnLIqe-""#,
            ListCommand {
                reference: s(""),
                pattern: s("~peter/mail/台北/日本語"),
            }
        );

        assert_reversible!(
            true,
            MailboxList,
            r#"() "/" "~peter/mail/台北/日本語""#,
            MailboxList {
                flags: vec![],
                name: s("~peter/mail/台北/日本語"),
            }
        );
        assert_reversible!(
            true,
            MailboxList,
            r#"(\Noinferiors) "/" "~peter/mail/台北/日本語""#,
            MailboxList {
                flags: vec![s("\\Noinferiors")],
                name: s("~peter/mail/台北/日本語"),
            }
        );
        assert_reversible!(
            true,
            MailboxList,
            r#"(\Noinferiors \Marked) "/" "~peter/mail/台北/日本語""#,
            MailboxList {
                flags: vec![s("\\Noinferiors"), s("\\Marked")],
                name: s("~peter/mail/台北/日本語"),
            }
        );
        assert_reversible!(
            false,
            MailboxList,
            r#"(\Noinferiors \Marked) "/" "~peter/mail/&U,BTFw-/&ZeVnLIqe-""#,
            MailboxList {
                flags: vec![s("\\Noinferiors"), s("\\Marked")],
                name: s("~peter/mail/台北/日本語"),
            }
        );
    }

    #[test]
    fn fetch_command_syntax() {
        assert_reversible!(
            FetchCommand,
            "FETCH 1:2,3:* ALL",
            FetchCommand {
                sequence_set: s("1:2,3:*"),
                target: FetchCommandTarget::All(()),
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1:2,3 FULL",
            FetchCommand {
                sequence_set: s("1:2,3"),
                target: FetchCommandTarget::Full(()),
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1:2,3 FAST",
            FetchCommand {
                sequence_set: s("1:2,3"),
                target: FetchCommandTarget::Fast(()),
            }
        );

        assert_reversible!(
            FetchCommand,
            "FETCH 1 ENVELOPE",
            FetchCommand {
                sequence_set: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Envelope(())),
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 FLAGS",
            FetchCommand {
                sequence_set: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Flags(())),
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 INTERNALDATE",
            FetchCommand {
                sequence_set: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::InternalDate(())),
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 BODY",
            FetchCommand {
                sequence_set: s("1"),
                target: FetchCommandTarget::Single(
                    FetchAtt::ShortBodyStructure(())
                ),
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 BODYSTRUCTURE",
            FetchCommand {
                sequence_set: s("1"),
                target: FetchCommandTarget::Single(
                    FetchAtt::ExtendedBodyStructure(())
                ),
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 RFC822",
            FetchCommand {
                sequence_set: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Rfc822(None)),
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 RFC822.SIZE",
            FetchCommand {
                sequence_set: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Rfc822(Some(
                    FetchAttRfc822::Size
                ))),
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 RFC822.HEADER",
            FetchCommand {
                sequence_set: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Rfc822(Some(
                    FetchAttRfc822::Header
                ))),
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 RFC822.TEXT",
            FetchCommand {
                sequence_set: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Rfc822(Some(
                    FetchAttRfc822::Text
                ))),
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 UID",
            FetchCommand {
                sequence_set: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Uid(())),
            }
        );

        assert_reversible!(
            FetchCommand,
            "FETCH 1 (FLAGS)",
            FetchCommand {
                sequence_set: s("1"),
                target: FetchCommandTarget::Multi(vec![FetchAtt::Flags(())]),
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 (FLAGS UID)",
            FetchCommand {
                sequence_set: s("1"),
                target: FetchCommandTarget::Multi(vec![
                    FetchAtt::Flags(()),
                    FetchAtt::Uid(()),
                ]),
            }
        );

        assert_reversible!(
            FetchCommand,
            "FETCH 1 BODY[]",
            FetchCommand {
                sequence_set: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Body(
                    FetchAttBody {
                        peek: false,
                        section: None,
                        slice: None,
                    }
                )),
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 BODY.PEEK[]",
            FetchCommand {
                sequence_set: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Body(
                    FetchAttBody {
                        peek: true,
                        section: None,
                        slice: None,
                    }
                )),
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 BODY[]<42.56>",
            FetchCommand {
                sequence_set: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Body(
                    FetchAttBody {
                        peek: false,
                        section: None,
                        slice: Some(FetchAttBodySlice {
                            start: 42,
                            length: 56,
                            _marker: PhantomData,
                        }),
                    }
                )),
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 BODY[HEADER]",
            FetchCommand {
                sequence_set: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Body(
                    FetchAttBody {
                        peek: false,
                        section: Some(SectionSpec::TopLevel(
                            SectionText::Header(())
                        )),
                        slice: None,
                    }
                )),
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 BODY[TEXT]",
            FetchCommand {
                sequence_set: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Body(
                    FetchAttBody {
                        peek: false,
                        section: Some(SectionSpec::TopLevel(
                            SectionText::Text(())
                        )),
                        slice: None,
                    }
                )),
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 BODY[HEADER.FIELDS (Foo)]",
            FetchCommand {
                sequence_set: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Body(
                    FetchAttBody {
                        peek: false,
                        section: Some(SectionSpec::TopLevel(
                            SectionText::HeaderFields(SectionTextHeaderField {
                                negative: false,
                                headers: vec![s("Foo")],
                            })
                        )),
                        slice: None,
                    }
                )),
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 BODY[HEADER.FIELDS.NOT (Foo)]",
            FetchCommand {
                sequence_set: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Body(
                    FetchAttBody {
                        peek: false,
                        section: Some(SectionSpec::TopLevel(
                            SectionText::HeaderFields(SectionTextHeaderField {
                                negative: true,
                                headers: vec![s("Foo")],
                            })
                        )),
                        slice: None,
                    }
                )),
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 BODY[HEADER.FIELDS (Foo Bar)]",
            FetchCommand {
                sequence_set: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Body(
                    FetchAttBody {
                        peek: false,
                        section: Some(SectionSpec::TopLevel(
                            SectionText::HeaderFields(SectionTextHeaderField {
                                negative: false,
                                headers: vec![s("Foo"), s("Bar")],
                            })
                        )),
                        slice: None,
                    }
                )),
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 BODY[HEADER.FIELDS.NOT (Foo Bar)]",
            FetchCommand {
                sequence_set: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Body(
                    FetchAttBody {
                        peek: false,
                        section: Some(SectionSpec::TopLevel(
                            SectionText::HeaderFields(SectionTextHeaderField {
                                negative: true,
                                headers: vec![s("Foo"), s("Bar")],
                            })
                        )),
                        slice: None,
                    }
                )),
            }
        );

        assert_reversible!(
            FetchCommand,
            "FETCH 1 BODY[1]",
            FetchCommand {
                sequence_set: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Body(
                    FetchAttBody {
                        peek: false,
                        section: Some(SectionSpec::Sub(SubSectionSpec {
                            subscripts: vec![1],
                            text: None,
                        })),
                        slice: None,
                    }
                )),
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 BODY[1.2.3]",
            FetchCommand {
                sequence_set: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Body(
                    FetchAttBody {
                        peek: false,
                        section: Some(SectionSpec::Sub(SubSectionSpec {
                            subscripts: vec![1, 2, 3],
                            text: None,
                        })),
                        slice: None,
                    }
                )),
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 BODY[1.MIME]",
            FetchCommand {
                sequence_set: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Body(
                    FetchAttBody {
                        peek: false,
                        section: Some(SectionSpec::Sub(SubSectionSpec {
                            subscripts: vec![1],
                            text: Some(SectionText::Mime(())),
                        })),
                        slice: None,
                    }
                )),
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 BODY[1.HEADER]",
            FetchCommand {
                sequence_set: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Body(
                    FetchAttBody {
                        peek: false,
                        section: Some(SectionSpec::Sub(SubSectionSpec {
                            subscripts: vec![1],
                            text: Some(SectionText::Header(())),
                        })),
                        slice: None,
                    }
                )),
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 BODY[1.TEXT]",
            FetchCommand {
                sequence_set: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Body(
                    FetchAttBody {
                        peek: false,
                        section: Some(SectionSpec::Sub(SubSectionSpec {
                            subscripts: vec![1],
                            text: Some(SectionText::Text(())),
                        })),
                        slice: None,
                    }
                )),
            }
        );
    }

    #[test]
    fn msg_att_syntax() {
        assert_reversible!(
            MsgAtt,
            "ENVELOPE (\"04 Jul 2020 16:31:00 +0000\" \
             \"Subject\" NIL NIL NIL NIL NIL NIL NIL \"<MessageID>\")",
            MsgAtt::Envelope(Envelope {
                date: ns("04 Jul 2020 16:31:00 +0000"),
                subject: ns("Subject"),
                from: vec![],
                sender: vec![],
                reply_to: vec![],
                to: vec![],
                cc: vec![],
                bcc: vec![],
                in_reply_to: None,
                message_id: ns("<MessageID>"),
            })
        );

        assert_reversible!(
            MsgAtt,
            "INTERNALDATE \" 4-Jul-2020 16:31:00 +0100\"",
            MsgAtt::InternalDate(
                FixedOffset::east(3600).ymd(2020, 7, 4).and_hms(16, 31, 0)
            )
        );

        assert_reversible!(
            MsgAtt,
            "RFC822 {3}\r\nfoo",
            MsgAtt::Rfc822Full(LiteralSource::of_data(b"foo", false))
        );
        assert_reversible!(
            MsgAtt,
            "RFC822.HEADER {3}\r\nfoo",
            MsgAtt::Rfc822Header(LiteralSource::of_data(b"foo", false))
        );
        assert_reversible!(
            MsgAtt,
            "RFC822.TEXT {3}\r\nfoo",
            MsgAtt::Rfc822Text(LiteralSource::of_data(b"foo", false))
        );
        assert_reversible!(
            MsgAtt,
            "RFC822.SIZE 1234",
            MsgAtt::Rfc822Size(1234)
        );

        assert_reversible!(
            MsgAtt,
            "BODY (\"TEXT\" \"PLAIN\" (\"CHARSET\" \"iso-8859-1\") \
             NIL NIL \"QUOTED-PRINTABLE\" 1315 42)",
            MsgAtt::ShortBodyStructure(Body::SinglePart(BodyType1Part {
                core: ClassifiedBodyType1Part::Text(BodyTypeText {
                    media_subtype: s("PLAIN"),
                    body_fields: BodyFields {
                        content_type_parms: vec![s("CHARSET"), s("iso-8859-1")],
                        content_id: None,
                        content_description: None,
                        content_transfer_encoding: s("QUOTED-PRINTABLE"),
                        size_octets: 1315,
                    },
                    size_lines: 42,
                }),
                ext: None,
            }))
        );
        assert_reversible!(
            MsgAtt,
            "BODYSTRUCTURE (\"TEXT\" \"PLAIN\" (\"CHARSET\" \"iso-8859-1\") \
             NIL NIL \"QUOTED-PRINTABLE\" 1315 42 NIL NIL NIL NIL)",
            MsgAtt::ExtendedBodyStructure(Body::SinglePart(BodyType1Part {
                core: ClassifiedBodyType1Part::Text(BodyTypeText {
                    media_subtype: s("PLAIN"),
                    body_fields: BodyFields {
                        content_type_parms: vec![s("CHARSET"), s("iso-8859-1")],
                        content_id: None,
                        content_description: None,
                        content_transfer_encoding: s("QUOTED-PRINTABLE"),
                        size_octets: 1315,
                    },
                    size_lines: 42,
                }),
                ext: Some(BodyExt1Part {
                    md5: None,
                    content_disposition: None,
                    content_language: None,
                    content_location: None,
                }),
            }))
        );

        assert_reversible!(
            MsgAtt,
            "BODY[] {3}\r\nfoo",
            MsgAtt::Body(MsgAttBody {
                section: None,
                slice_origin: None,
                data: LiteralSource::of_data(b"foo", false),
            })
        );
        assert_reversible!(
            MsgAtt,
            "BODY[HEADER] {3}\r\nfoo",
            MsgAtt::Body(MsgAttBody {
                section: Some(SectionSpec::TopLevel(SectionText::Header(()))),
                slice_origin: None,
                data: LiteralSource::of_data(b"foo", false),
            })
        );
        assert_reversible!(
            MsgAtt,
            "BODY[HEADER.FIELDS (Foo)] {3}\r\nfoo",
            MsgAtt::Body(MsgAttBody {
                section: Some(SectionSpec::TopLevel(
                    SectionText::HeaderFields(SectionTextHeaderField {
                        negative: false,
                        headers: vec![s("Foo")],
                    })
                )),
                slice_origin: None,
                data: LiteralSource::of_data(b"foo", false),
            })
        );
        assert_reversible!(
            MsgAtt,
            "BODY[TEXT] {3}\r\nfoo",
            MsgAtt::Body(MsgAttBody {
                section: Some(SectionSpec::TopLevel(SectionText::Text(()))),
                slice_origin: None,
                data: LiteralSource::of_data(b"foo", false),
            })
        );
        assert_reversible!(
            MsgAtt,
            "BODY[1.2.MIME] {3}\r\nfoo",
            MsgAtt::Body(MsgAttBody {
                section: Some(SectionSpec::Sub(SubSectionSpec {
                    subscripts: vec![1, 2],
                    text: Some(SectionText::Mime(())),
                })),
                slice_origin: None,
                data: LiteralSource::of_data(b"foo", false),
            })
        );
        assert_reversible!(
            MsgAtt,
            "BODY[]<42> {3}\r\nfoo",
            MsgAtt::Body(MsgAttBody {
                section: None,
                slice_origin: Some(42),
                data: LiteralSource::of_data(b"foo", false),
            })
        );

        assert_reversible!(MsgAtt, "UID 42", MsgAtt::Uid(42));

        assert_reversible!(
            MsgAtt,
            "FLAGS ()",
            MsgAtt::Flags(FlagsFetch::NotRecent(vec![]))
        );
        assert_reversible!(
            MsgAtt,
            "FLAGS (\\Recent)",
            MsgAtt::Flags(FlagsFetch::Recent(vec![]))
        );
        assert_reversible!(
            MsgAtt,
            "FLAGS (\\Flagged)",
            MsgAtt::Flags(FlagsFetch::NotRecent(vec![Flag::Flagged]))
        );
        assert_reversible!(
            MsgAtt,
            "FLAGS (\\Recent \\Flagged)",
            MsgAtt::Flags(FlagsFetch::Recent(vec![Flag::Flagged]))
        );
        assert_reversible!(
            MsgAtt,
            "FLAGS (\\Flagged \\Seen)",
            MsgAtt::Flags(FlagsFetch::NotRecent(vec![
                Flag::Flagged,
                Flag::Seen
            ]))
        );
        assert_reversible!(
            MsgAtt,
            "FLAGS (\\Recent \\Flagged \\Seen)",
            MsgAtt::Flags(FlagsFetch::Recent(vec![Flag::Flagged, Flag::Seen]))
        );
        assert_reversible!(
            MsgAtt,
            "FLAGS (keyword)",
            MsgAtt::Flags(FlagsFetch::NotRecent(vec![Flag::Keyword(
                "keyword".to_owned()
            )]))
        );
        assert_reversible!(
            MsgAtt,
            "FLAGS (=?utf-8?q?With_Space?=)",
            MsgAtt::Flags(FlagsFetch::NotRecent(vec![Flag::Keyword(
                "With Space".to_owned()
            )]))
        );
        assert_reversible!(
            MsgAtt,
            "FLAGS (=?utf-8?q?With=2AStar?=)",
            MsgAtt::Flags(FlagsFetch::NotRecent(vec![Flag::Keyword(
                "With*Star".to_owned()
            )]))
        );
    }

    #[test]
    fn msg_atts_syntax() {
        assert_reversible!(
            MsgAtts,
            "(UID 42)",
            MsgAtts {
                atts: vec![MsgAtt::Uid(42)],
            }
        );
        assert_reversible!(
            MsgAtts,
            "(UID 42 FLAGS ())",
            MsgAtts {
                atts: vec![
                    MsgAtt::Uid(42),
                    MsgAtt::Flags(FlagsFetch::NotRecent(vec![]))
                ],
            }
        );
    }

    #[test]
    fn search_key_syntax() {
        assert_reversible!(
            SearchKey,
            "ALL",
            SearchKey::Simple(SimpleSearchKey::All)
        );
        assert_reversible!(
            SearchKey,
            "ANSWERED",
            SearchKey::Simple(SimpleSearchKey::Answered)
        );
        assert_reversible!(
            SearchKey,
            "BCC \"foo@bar.com\"",
            SearchKey::Text(TextSearchKey {
                typ: TextSearchKeyType::Bcc,
                value: s("foo@bar.com"),
            })
        );
        assert_reversible!(
            SearchKey,
            "BEFORE \"4-Jul-2020\"",
            SearchKey::Date(DateSearchKey {
                typ: DateSearchKeyType::Before,
                date: NaiveDate::from_ymd(2020, 7, 4),
                _marker: PhantomData,
            })
        );
        assert_reversible!(
            SearchKey,
            "BODY needle",
            SearchKey::Text(TextSearchKey {
                typ: TextSearchKeyType::Body,
                value: s("needle"),
            })
        );
        assert_reversible!(
            SearchKey,
            "CC \"foo@bar.com\"",
            SearchKey::Text(TextSearchKey {
                typ: TextSearchKeyType::Cc,
                value: s("foo@bar.com"),
            })
        );
        assert_reversible!(
            SearchKey,
            "DELETED",
            SearchKey::Simple(SimpleSearchKey::Deleted)
        );
        assert_reversible!(
            SearchKey,
            "FLAGGED",
            SearchKey::Simple(SimpleSearchKey::Flagged)
        );
        assert_reversible!(
            SearchKey,
            "FROM \"foo@bar.com\"",
            SearchKey::Text(TextSearchKey {
                typ: TextSearchKeyType::From,
                value: s("foo@bar.com"),
            })
        );
        assert_reversible!(
            SearchKey,
            "KEYWORD foo",
            SearchKey::Keyword(Flag::Keyword("foo".to_owned()))
        );
        assert_reversible!(
            SearchKey,
            "NEW",
            SearchKey::Simple(SimpleSearchKey::New)
        );
        assert_reversible!(
            SearchKey,
            "OLD",
            SearchKey::Simple(SimpleSearchKey::Old)
        );
        assert_reversible!(
            SearchKey,
            "ON \"4-Jul-2020\"",
            SearchKey::Date(DateSearchKey {
                typ: DateSearchKeyType::On,
                date: NaiveDate::from_ymd(2020, 7, 4),
                _marker: PhantomData,
            })
        );
        assert_reversible!(
            SearchKey,
            "RECENT",
            SearchKey::Simple(SimpleSearchKey::Recent)
        );
        assert_reversible!(
            SearchKey,
            "SEEN",
            SearchKey::Simple(SimpleSearchKey::Seen)
        );
        assert_reversible!(
            SearchKey,
            "SINCE \"4-Jul-2020\"",
            SearchKey::Date(DateSearchKey {
                typ: DateSearchKeyType::Since,
                date: NaiveDate::from_ymd(2020, 7, 4),
                _marker: PhantomData,
            })
        );
        assert_reversible!(
            SearchKey,
            "SUBJECT needle",
            SearchKey::Text(TextSearchKey {
                typ: TextSearchKeyType::Subject,
                value: s("needle"),
            })
        );
        assert_reversible!(
            SearchKey,
            "TEXT needle",
            SearchKey::Text(TextSearchKey {
                typ: TextSearchKeyType::Text,
                value: s("needle"),
            })
        );
        assert_reversible!(
            SearchKey,
            "TO \"foo@bar.com\"",
            SearchKey::Text(TextSearchKey {
                typ: TextSearchKeyType::To,
                value: s("foo@bar.com"),
            })
        );
        assert_reversible!(
            SearchKey,
            "UNANSWERED",
            SearchKey::Simple(SimpleSearchKey::Unanswered)
        );
        assert_reversible!(
            SearchKey,
            "UNDELETED",
            SearchKey::Simple(SimpleSearchKey::Undeleted)
        );
        assert_reversible!(
            SearchKey,
            "UNFLAGGED",
            SearchKey::Simple(SimpleSearchKey::Unflagged)
        );
        assert_reversible!(
            SearchKey,
            "UNKEYWORD foo",
            SearchKey::Unkeyword(Flag::Keyword("foo".to_owned()))
        );
        assert_reversible!(
            SearchKey,
            "UNSEEN",
            SearchKey::Simple(SimpleSearchKey::Unseen)
        );

        assert_reversible!(
            SearchKey,
            "DRAFT",
            SearchKey::Simple(SimpleSearchKey::Draft)
        );
        assert_reversible!(
            SearchKey,
            "HEADER Foo Bar",
            SearchKey::Header(SearchKeyHeader {
                header: s("Foo"),
                value: s("Bar"),
            })
        );
        assert_reversible!(SearchKey, "LARGER 42", SearchKey::Larger(42));
        assert_reversible!(
            SearchKey,
            "NOT LARGER 42",
            SearchKey::Not(Box::new(SearchKey::Larger(42)))
        );
        assert_reversible!(
            SearchKey,
            "OR LARGER 42 DRAFT",
            SearchKey::Or(SearchKeyOr {
                a: Box::new(SearchKey::Larger(42)),
                b: Box::new(SearchKey::Simple(SimpleSearchKey::Draft)),
            })
        );
        assert_reversible!(
            SearchKey,
            "SENTBEFORE \"4-Jul-2020\"",
            SearchKey::Date(DateSearchKey {
                typ: DateSearchKeyType::SentBefore,
                date: NaiveDate::from_ymd(2020, 7, 4),
                _marker: PhantomData,
            })
        );
        assert_reversible!(
            SearchKey,
            "SENTON \"4-Jul-2020\"",
            SearchKey::Date(DateSearchKey {
                typ: DateSearchKeyType::SentOn,
                date: NaiveDate::from_ymd(2020, 7, 4),
                _marker: PhantomData,
            })
        );
        assert_reversible!(
            SearchKey,
            "SENTSINCE \"4-Jul-2020\"",
            SearchKey::Date(DateSearchKey {
                typ: DateSearchKeyType::SentSince,
                date: NaiveDate::from_ymd(2020, 7, 4),
                _marker: PhantomData,
            })
        );
        assert_reversible!(SearchKey, "SMALLER 42", SearchKey::Smaller(42));
        assert_reversible!(
            SearchKey,
            "UID 1:2,3:*",
            SearchKey::Uid(s("1:2,3:*"))
        );
        assert_reversible!(
            SearchKey,
            "UNDRAFT",
            SearchKey::Simple(SimpleSearchKey::Undraft)
        );
        assert_reversible!(
            SearchKey,
            "1:2,3:*",
            SearchKey::Seqnum(s("1:2,3:*"))
        );
        assert_reversible!(
            SearchKey,
            "(LARGER 42)",
            SearchKey::And(vec![SearchKey::Larger(42)])
        );
        assert_reversible!(
            SearchKey,
            "(LARGER 42 SMALLER 56)",
            SearchKey::And(vec![SearchKey::Larger(42), SearchKey::Smaller(56)])
        );
    }

    #[test]
    fn search_command_syntax() {
        assert_reversible!(
            SearchCommand,
            "SEARCH LARGER 42",
            SearchCommand {
                charset: None,
                keys: vec![SearchKey::Larger(42)],
            }
        );
        assert_reversible!(
            SearchCommand,
            "SEARCH LARGER 42 SMALLER 56",
            SearchCommand {
                charset: None,
                keys: vec![SearchKey::Larger(42), SearchKey::Smaller(56)],
            }
        );
        assert_reversible!(
            SearchCommand,
            "SEARCH CHARSET utf-8 LARGER 42",
            SearchCommand {
                charset: ns("utf-8"),
                keys: vec![SearchKey::Larger(42)],
            }
        );
    }

    #[test]
    fn mailbox_management_commands() {
        assert_reversible!(
            CreateCommand,
            "CREATE mailbox",
            CreateCommand {
                mailbox: s("mailbox"),
            }
        );
        assert_reversible!(
            true,
            CreateCommand,
            "CREATE \"föö\"",
            CreateCommand {
                mailbox: s("föö")
            }
        );
        assert_reversible!(
            false,
            CreateCommand,
            "CREATE \"f&APYA9g-\"",
            CreateCommand {
                mailbox: s("föö")
            }
        );
        assert_reversible!(
            DeleteCommand,
            "DELETE mailbox",
            DeleteCommand {
                mailbox: s("mailbox"),
            }
        );
        assert_reversible!(
            true,
            DeleteCommand,
            "DELETE \"föö\"",
            DeleteCommand {
                mailbox: s("föö")
            }
        );
        assert_reversible!(
            false,
            DeleteCommand,
            "DELETE \"f&APYA9g-\"",
            DeleteCommand {
                mailbox: s("föö")
            }
        );
        assert_reversible!(
            ExamineCommand,
            "EXAMINE mailbox",
            ExamineCommand {
                mailbox: s("mailbox"),
            }
        );
        assert_reversible!(
            true,
            ExamineCommand,
            "EXAMINE \"föö\"",
            ExamineCommand {
                mailbox: s("föö")
            }
        );
        assert_reversible!(
            false,
            ExamineCommand,
            "EXAMINE \"f&APYA9g-\"",
            ExamineCommand {
                mailbox: s("föö")
            }
        );
        assert_reversible!(
            RenameCommand,
            "RENAME mailbox dst",
            RenameCommand {
                src: s("mailbox"),
                dst: s("dst"),
            }
        );
        assert_reversible!(
            true,
            RenameCommand,
            "RENAME \"föö\" dst",
            RenameCommand {
                src: s("föö"),
                dst: s("dst"),
            }
        );
        assert_reversible!(
            false,
            RenameCommand,
            "RENAME \"f&APYA9g-\" dst",
            RenameCommand {
                src: s("föö"),
                dst: s("dst"),
            }
        );
        assert_reversible!(
            SelectCommand,
            "SELECT mailbox",
            SelectCommand {
                mailbox: s("mailbox"),
            }
        );
        assert_reversible!(
            true,
            SelectCommand,
            "SELECT \"föö\"",
            SelectCommand {
                mailbox: s("föö")
            }
        );
        assert_reversible!(
            false,
            SelectCommand,
            "SELECT \"f&APYA9g-\"",
            SelectCommand {
                mailbox: s("föö")
            }
        );
        assert_reversible!(
            StatusCommand,
            "STATUS foo (MESSAGES)",
            StatusCommand {
                mailbox: s("foo"),
                atts: vec![StatusAtt::Messages],
            }
        );
        assert_reversible!(
            StatusCommand,
            "STATUS foo (MESSAGES RECENT UIDNEXT UIDVALIDITY UNSEEN)",
            StatusCommand {
                mailbox: s("foo"),
                atts: vec![
                    StatusAtt::Messages,
                    StatusAtt::Recent,
                    StatusAtt::UidNext,
                    StatusAtt::UidValidity,
                    StatusAtt::Unseen
                ],
            }
        );
        assert_reversible!(
            SubscribeCommand,
            "SUBSCRIBE mailbox",
            SubscribeCommand {
                mailbox: s("mailbox"),
            }
        );
        assert_reversible!(
            true,
            SubscribeCommand,
            "SUBSCRIBE \"föö\"",
            SubscribeCommand {
                mailbox: s("föö")
            }
        );
        assert_reversible!(
            false,
            SubscribeCommand,
            "SUBSCRIBE \"f&APYA9g-\"",
            SubscribeCommand {
                mailbox: s("föö")
            }
        );
        assert_reversible!(
            UnsubscribeCommand,
            "UNSUBSCRIBE mailbox",
            UnsubscribeCommand {
                mailbox: s("mailbox"),
            }
        );
        assert_reversible!(
            true,
            UnsubscribeCommand,
            "UNSUBSCRIBE \"föö\"",
            UnsubscribeCommand {
                mailbox: s("föö")
            }
        );
        assert_reversible!(
            false,
            UnsubscribeCommand,
            "UNSUBSCRIBE \"f&APYA9g-\"",
            UnsubscribeCommand {
                mailbox: s("föö")
            }
        );
    }
}
