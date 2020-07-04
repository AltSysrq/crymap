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
//! there is more than one, they apply left to right. E.g., `suffix(b" ") opt`
//! will always add/expect a space regardless of whether the value is present,
//! while `opt suffix(b" ")` will only add/expect the suffix as part of the
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
use crate::account::model::{Flag, Seqnum, Uid};
use crate::mime::encoded_word::ew_decode;
use crate::mime::utf7;

include!("syntax-macros.rs");

syntax_rule! {
    #[prefix(b"CAPABILITY")]
    struct CapabilityData<'a> {
        #[1* prefix(b" ")]
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
        #[marked_opt(b"*") suffix(b" ")]
        #[primitive(verbatim, tag_atom)]
        tag: Option<Cow<'a, str>>,
        #[suffix(b" ")]
        #[delegate]
        cond: RespCondType,
        // TODO Response data
        #[]
        #[primitive(verbatim, text)]
        quip: Cow<'a, str>,
    }
}

syntax_rule! {
    #[surrounded(b"(", b")")]
    struct Envelope<'a> {
        #[suffix(b" ")]
        #[primitive(censored_nstring, nstring)]
        date: Option<Cow<'a, str>>,
        #[suffix(b" ")]
        #[primitive(encoded_nstring, nstring)]
        subject: Option<Cow<'a, str>>,
        #[suffix(b" ") nil_if_empty surrounded(b"(", b")") 1*]
        #[delegate(Address)]
        from: Vec<Address<'a>>,
        #[suffix(b" ") nil_if_empty surrounded(b"(", b")") 1*]
        #[delegate(Address)]
        sender: Vec<Address<'a>>,
        #[suffix(b" ") nil_if_empty surrounded(b"(", b")") 1*]
        #[delegate(Address)]
        reply_to: Vec<Address<'a>>,
        #[suffix(b" ") nil_if_empty surrounded(b"(", b")") 1*]
        #[delegate(Address)]
        to: Vec<Address<'a>>,
        #[suffix(b" ") nil_if_empty surrounded(b"(", b")") 1*]
        #[delegate(Address)]
        cc: Vec<Address<'a>>,
        #[suffix(b" ") nil_if_empty surrounded(b"(", b")") 1*]
        #[delegate(Address)]
        bcc: Vec<Address<'a>>,
        #[suffix(b" ")]
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
    #[surrounded(b"(", b")")]
    enum Address<'a> {
        #[]
        #[delegate]
        Real(RealAddress<'a>),
        // Groups never have a display name, routing, or domain
        #[surrounded(b"NIL NIL ", b" NIL")]
        #[primitive(encoded_nstring, nstring)]
        GroupDelim(Option<Cow<'a, str>>),
    }
}

syntax_rule! {
    #[]
    struct RealAddress<'a> {
        #[suffix(b" ")]
        #[primitive(encoded_nstring, nstring)]
        display_name: Option<Cow<'a, str>>,
        #[suffix(b" ")]
        #[primitive(censored_nstring, nstring)]
        routing: Option<Cow<'a, str>>,
        // These are nstrings in the RFC 3501 syntax, but we handle that with
        // the separate GroupDelim case.
        #[suffix(b" ")]
        #[primitive(censored_string, string)]
        local_part: Cow<'a, str>,
        #[]
        #[primitive(censored_string, string)]
        domain: Cow<'a, str>,
    }
}

syntax_rule! {
    #[surrounded(b"(", b")")]
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
        #[suffix(b" ") 0*]
        #[delegate(Body)]
        bodies: Vec<Body<'a>>,
        #[]
        #[primitive(censored_string, string)]
        media_subtype: Cow<'a, str>,
        #[opt prefix(b" ")]
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
        #[suffix(b" ") nil_if_empty surrounded(b"(", b")") 1*(b" ")]
        #[primitive(censored_string, string)]
        content_type_parms: Vec<Cow<'a, str>>,
        #[suffix(b" ") nil]
        #[delegate(ContentDisposition)]
        content_disposition: Option<ContentDisposition<'a>>,
        #[suffix(b" ")]
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
        #[opt prefix(b" ")]
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
        #[suffix(b" ")]
        #[primitive(censored_string, string)]
        media_type: Cow<'a, str>,
        #[suffix(b" ")]
        #[primitive(censored_string, string)]
        media_subtype: Cow<'a, str>,
        #[]
        #[delegate]
        body_fields: BodyFields<'a>,
    }
}

syntax_rule! {
    #[prefix(b"\"MESSAGE\" \"RFC822\" ")]
    struct BodyTypeMsg<'a> {
        #[suffix(b" ")]
        #[delegate]
        body_fields: BodyFields<'a>,
        #[suffix(b" ")]
        #[delegate]
        envelope: Envelope<'a>,
        #[suffix(b" ") box]
        #[delegate(Body)]
        body: Box<Body<'a>>,
        #[]
        #[primitive(num_u32, number)]
        size_lines: u32,
    }
}

syntax_rule! {
    #[prefix(b"\"TEXT\" ")]
    struct BodyTypeText<'a> {
        #[suffix(b" ")]
        #[primitive(censored_string, string)]
        media_subtype: Cow<'a, str>,
        #[suffix(b" ")]
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
        #[suffix(b" ") nil_if_empty surrounded(b"(", b")") 1*(b" ")]
        #[primitive(censored_string, string)]
        content_type_parms: Vec<Cow<'a, str>>,
        #[suffix(b" ")]
        #[primitive(censored_nstring, nstring)]
        content_id: Option<Cow<'a, str>>,
        #[suffix(b" ")]
        #[primitive(encoded_nstring, nstring)]
        content_description: Option<Cow<'a, str>>,
        #[suffix(b" ")]
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
        #[suffix(b" ")]
        #[primitive(censored_nstring, nstring)]
        md5: Option<Cow<'a, str>>,
        #[suffix(b" ") nil]
        #[delegate(ContentDisposition)]
        content_disposition: Option<ContentDisposition<'a>>,
        #[suffix(b" ")]
        #[primitive(censored_nstring, nstring)]
        content_language: Option<Cow<'a, str>>,
        #[]
        #[primitive(censored_nstring, nstring)]
        content_location: Option<Cow<'a, str>>,
    }
}

syntax_rule! {
    #[surrounded(b"(", b")")]
    struct ContentDisposition<'a> {
        #[suffix(b" ")]
        #[primitive(censored_string, string)]
        disposition: Cow<'a, str>,
        #[nil_if_empty surrounded(b"(", b")") 1*(b" ")]
        #[primitive(censored_string, string)]
        parms: Vec<Cow<'a, str>>,
    }
}

syntax_rule! {
    #[prefix(b"LIST ")]
    struct ListCommand<'a> {
        #[suffix(b" ")]
        #[primitive(mailbox, mailbox)]
        reference: Cow<'a, str>,
        #[]
        #[primitive(mailbox, list_mailbox)]
        pattern: Cow<'a, str>,
    }
}

syntax_rule! {
    #[prefix(b"LSUB ")]
    struct LsubCommand<'a> {
        #[suffix(b" ")]
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
        #[surrounded(b"(", b") \"/\" ") 0*(b" ")]
        #[primitive(verbatim, backslash_atom)]
        flags: Vec<Cow<'a, str>>,
        #[]
        #[primitive(mailbox, mailbox)]
        name: Cow<'a, str>,
    }
}

syntax_rule! {
    #[prefix(b"FETCH ")]
    struct FetchCommand<'a> {
        #[suffix(b" ")]
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
        #[tag(b"ALL")]
        All(()),
        #[]
        #[tag(b"FULL")]
        Full(()),
        #[]
        #[tag(b"FAST")]
        Fast(()),
        #[]
        #[delegate]
        Single(FetchAtt<'a>),
        #[surrounded(b"(", b")") 1*(b" ")]
        #[delegate(FetchAtt)]
        Multi(Vec<FetchAtt<'a>>),
    }
}

syntax_rule! {
    #[]
    enum FetchAtt<'a> {
        #[]
        #[tag(b"ENVELOPE")]
        Envelope(()),
        #[]
        #[tag(b"FLAGS")]
        Flags(()),
        #[]
        #[tag(b"INTERNALDATE")]
        InternalDate(()),
        #[prefix(b"RFC822") opt]
        #[delegate(FetchAttRfc822)]
        Rfc822(Option<FetchAttRfc822>),
        // Must come before the body structure stuff to resolve the ambiguity
        // the correct way.
        #[prefix(b"BODY")]
        #[delegate]
        Body(FetchAttBody<'a>),
        #[]
        #[tag(b"BODYSTRUCTURE")]
        ExtendedBodyStructure(()),
        #[]
        #[tag(b"BODY")]
        ShortBodyStructure(()),
        #[]
        #[tag(b"UID")]
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
        #[cond(b".PEEK")]
        peek: bool,
        #[surrounded(b"[", b"]") opt]
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
        #[1*(b".")]
        #[primitive(num_u32, number)]
        subscripts: Vec<u32>,
        #[opt prefix(b".")]
        #[delegate(SectionText)]
        text: Option<SectionText<'a>>,
    }
}

syntax_rule! {
    #[]
    enum SectionText<'a> {
        #[prefix(b"HEADER.FIELDS")]
        #[delegate]
        HeaderFields(SectionTextHeaderField<'a>),
        #[]
        #[tag(b"HEADER")]
        Header(()),
        #[]
        #[tag(b"TEXT")]
        Text(()),
        #[]
        #[tag(b"MIME")]
        Mime(()),
    }
}

syntax_rule! {
    #[]
    struct SectionTextHeaderField<'a> {
        #[suffix(b" ")]
        #[cond(b".NOT")]
        negative: bool,
        #[surrounded(b"(", b")") 1*(b" ")]
        #[primitive(censored_astring, astring)]
        headers: Vec<Cow<'a, str>>,
    }
}

syntax_rule! {
    #[surrounded(b"<", b">")]
    struct FetchAttBodySlice<'a> {
        #[suffix(b".")]
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
        alt((tag(b"~{"), tag(b"{"))),
        number,
        alt((tag(b"+}"), tag(b"}"))),
    )(i)?;
    bytes::complete::take(len)(i)
}

fn quoted_char(i: &[u8]) -> IResult<&[u8], &[u8]> {
    sequence::preceded(tag(b"\\"), alt((tag(b"\\"), tag(b"\""))))(i)
}

fn quoted_string_content(i: &[u8]) -> IResult<&[u8], &[u8]> {
    alt((quoted_char, is_not("\r\n\"\\")))(i)
}

fn quoted(i: &[u8]) -> IResult<&[u8], Cow<str>> {
    sequence::delimited(
        tag(b"\""),
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
        tag(b"\""),
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

fn mailbox(i: &[u8]) -> IResult<&[u8], Cow<str>> {
    map(astring, |raw| match raw {
        Cow::Owned(s) => Cow::Owned(utf7::IMAP.decode(&s).into_owned()),
        Cow::Borrowed(s) => utf7::IMAP.decode(s),
    })(i)
}

fn sequence_set(i: &[u8]) -> IResult<&[u8], Cow<str>> {
    map(is_a("0123456789:*,"), String::from_utf8_lossy)(i)
}

fn seqnum(i: &[u8]) -> IResult<&[u8], Seqnum> {
    map_opt(number, Seqnum::of)(i)
}

fn uid(i: &[u8]) -> IResult<&[u8], Uid> {
    map_opt(number, Uid::of)(i)
}

fn text(i: &[u8]) -> IResult<&[u8], Cow<str>> {
    map(is_not("\r\n"), String::from_utf8_lossy)(i)
}

fn flag(i: &[u8]) -> IResult<&[u8], Flag> {
    map_opt(
        alt((
            sequence::preceded(tag(b"\\"), normal_atom),
            map(normal_atom, |a| ew_decode(&a).map(Cow::Owned).unwrap_or(a)),
        )),
        |s| s.parse::<Flag>().ok(),
    )(i)
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
        sequence::preceded(tag(b":"), two_digit),
        sequence::preceded(tag(b":"), two_digit),
    ))(i)
}

fn numeric_zone(i: &[u8]) -> IResult<&[u8], i32> {
    map(
        sequence::pair(
            alt((tag(b"+"), tag(b"-"))),
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
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct",
    "nov", "dec",
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
            sequence::terminated(alt((two_digit, one_digit)), tag(b"-")),
            sequence::terminated(month, tag(b"-")),
            four_digit,
        )),
        |(d, m, y)| NaiveDate::from_ymd_opt(y as i32, m, d),
    )(i)
}

fn date(i: &[u8]) -> IResult<&[u8], NaiveDate> {
    alt((
        date_text,
        sequence::delimited(tag(b"\""), date_text, tag(b"\"")),
    ))(i)
}

fn datetime_date(i: &[u8]) -> IResult<&[u8], NaiveDate> {
    map_opt(
        sequence::tuple((
            sequence::terminated(
                alt((two_digit, sequence::preceded(tag(b" "), one_digit))),
                tag(b"-"),
            ),
            sequence::terminated(month, tag(b"-")),
            four_digit,
        )),
        |(d, m, y)| NaiveDate::from_ymd_opt(y as i32, m, d),
    )(i)
}

fn datetime(i: &[u8]) -> IResult<&[u8], DateTime<FixedOffset>> {
    map_opt(
        sequence::delimited(
            tag(b"\""),
            sequence::tuple((
                sequence::terminated(datetime_date, tag(b" ")),
                sequence::terminated(time_of_day, tag(b" ")),
                numeric_zone,
            )),
            tag(b"\""),
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
            let value = &$value;
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
            let value = $value;
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

        let with_unicode_and_groups = Envelope {
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
            with_unicode_and_groups
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
                        content_type_parms: vec![s("CHARSET"), s("US-ASCII"),],
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
                        content_type_parms: vec![s("CHARSET"), s("iso-8859-1"),],
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
                    content_type_parms: vec![s("BOUNDARY"), s("d3438gr7324"),],
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
                                parms: vec![s("FILENAME"), s("4356415.jpg"),],
                            }),
                            content_language: None,
                            content_location: None,
                        }),
                    }),
                ],
                media_subtype: s("RELATED"),
                ext: Some(BodyExtMPart {
                    content_type_parms: vec![s("BOUNDARY"), s("0__=5tgd3d"),],
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
                        content_type_parms: vec![s("parm"), s("foo"),],
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
                target: FetchCommandTarget::Multi(vec![FetchAtt::Flags(()),]),
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
                                headers: vec![s("Foo"),],
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
                                headers: vec![s("Foo"),],
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
                                headers: vec![s("Foo"), s("Bar"),],
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
                                headers: vec![s("Foo"), s("Bar"),],
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
}
