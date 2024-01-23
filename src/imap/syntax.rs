//-
// Copyright (c) 2020, 2023, 2024, Jason Lingle
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
//! "modifiers" are more diverse. More than one can be chained together. When
//! there is more than one, they apply left to right. E.g., `suffix(" ") opt`
//! will always add/expect a space regardless of whether the value is present,
//! while `opt suffix(" ")` will only add/expect the suffix as part of the
//! inner value. The modifiers are:
//!
//! - `prefix(s)`: Add/expect the given prefix
//! - `suffix(s)`: Add/expect the given suffix
//! - `surrounded(a,b)`: Add/expect the given prefix and suffix
//! - `maybe_surrounded(a,b)`: Like `surrounded`, but the prefix and suffix are
//!   optional on parse.
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
#![allow(dead_code)]
#![allow(
    clippy::large_enum_variant,
    clippy::derivable_impls,
    clippy::match_like_matches_macro
)]

use std::borrow::Cow;
use std::io;
use std::str;

use chrono::prelude::*;
use nom::{
    branch::alt,
    bytes::complete::{is_a, is_not, tag, tag_no_case as kw},
    combinator::{map, map_opt, opt},
    *,
};

use super::lex::{LexOutput, LexWriter};
use super::literal_source::LiteralSource;
use super::mailbox_name::MailboxName;
use crate::account::model::Flag;

include!("syntax-macros.rs");

syntax_rule! {
    #[]
    struct ResponseLine<'a> {
        #[suffix(" ") marked_opt("*")]
        #[primitive(verbatim, tag_atom)]
        tag: Option<Cow<'a, str>>,
        #[]
        #[delegate]
        response: Response<'a>,
    }
}

syntax_rule! {
    #[]
    enum Response<'a> {
        #[]
        #[delegate]
        Cond(CondResponse<'a>),
        // Note that the formal syntax excludes \Recent from the FLAGS
        // response, so we don't need any way to encode that here.
        #[surrounded("FLAGS (", ")") 0*(" ")]
        #[primitive(flag, flag)]
        Flags(Vec<Flag>),
        #[prefix("LIST ")]
        #[delegate]
        List(MailboxList<'a>),
        #[prefix("LSUB ")]
        #[delegate]
        Lsub(MailboxList<'a>),
        #[prefix("XLIST ")]
        #[delegate]
        Xlist(MailboxList<'a>),
        // The SEARCH prefix cannot include the space because a search response
        // with no results must be simply "SEARCH".
        #[prefix("SEARCH")]
        #[delegate]
        Search(SearchResponse),
        #[prefix("STATUS ")]
        #[delegate]
        Status(StatusResponse<'a>),
        #[suffix(" EXISTS")]
        #[primitive(num_u32, number)]
        Exists(u32),
        #[suffix(" RECENT")]
        #[primitive(num_u32, number)]
        Recent(u32),
        #[suffix(" EXPUNGE")]
        #[primitive(num_u32, number)]
        Expunge(u32),
        #[]
        #[delegate]
        Fetch(FetchResponse<'a>),
        #[]
        #[delegate]
        Capability(CapabilityData<'a>),
        // RFC 2342
        // We don't have namespaces or shared mailboxes, so we can just return
        // this single fixed response.
        #[]
        #[tag(r#"NAMESPACE (("" "/")) NIL NIL"#)]
        Namespace(()),
        // RFC 2971
        #[prefix("ID ") nil_if_empty surrounded("(", ")") 0*(" ")]
        #[primitive(censored_nstring, nstring)]
        Id(Vec<Option<Cow<'a, str>>>),
        // RFC 5161
        #[prefix("ENABLED") 0* prefix(" ")]
        #[primitive(verbatim, normal_atom)]
        Enabled(Vec<Cow<'a, str>>),
        // RFC 7162
        #[]
        #[delegate]
        Vanished(VanishedResponse<'a>),
        // RFC 4466 + RFC 4731
        #[prefix("ESEARCH ")]
        #[delegate]
        Esearch(EsearchResponse<'a>),
        // Crymap extensions
        #[prefix("XCRY USER-CONFIG")]
        #[delegate]
        XCryUserConfig(XCryUserConfigData<'a>),
        #[prefix("XCRY BACKUP-FILE ")]
        #[primitive(unicode_astring, astring)]
        XCryBackupFile(Cow<'a, str>),
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

// This is substantially refactored from the RFC 3501 formal syntax, which is
// quite awkward due to trying to encode state semantics into the grammar.
syntax_rule! {
    #[]
    struct CondResponse<'a> {
        #[suffix(" ")]
        #[delegate]
        cond: RespCondType,
        #[opt surrounded("[", "] ")]
        #[delegate(RespTextCode)]
        code: Option<RespTextCode<'a>>,
        // This value isn't nullable in the formal syntax, there being no
        // special meaning to the character sequence "NIL". However, we usually
        // don't have anything useful to put here, so making it optional
        // simplifies code and gets us an immediately obvious (to a human)
        // "server has nothing interesting to say here" "message".
        //
        // ... or so we thought, but the Dovecot IMAP compliance tester chokes
        // if the response text is "NIL", so we use something else since that
        // probably means other IMAP clients make the same mistake.
        #[marked_opt("K")]
        #[primitive(verbatim, text)]
        quip: Option<Cow<'a, str>>,
    }
}

syntax_rule! {
    #[]
    enum RespTextCode<'a> {
        // RFC 3501
        #[]
        #[tag("ALERT")]
        Alert(()),
        #[surrounded("BADCHARSET (", ")") 1*(" ")]
        #[primitive(censored_astring, astring)]
        BadCharset(Vec<Cow<'a, str>>),
        #[]
        #[delegate]
        Capability(CapabilityData<'a>),
        #[]
        #[tag("PARSE")]
        Parse(()),
        // Another case where the parser is only suitable for Crymap: We can't
        // represent PERMANENTFLAGS without \*, and only allow it in final
        // position.
        #[surrounded("PERMANENTFLAGS (", "\\*)") 0* suffix(" ")]
        #[primitive(flag, flag)]
        PermanentFlags(Vec<Flag>),
        #[]
        #[tag("READ-ONLY")]
        ReadOnly(()),
        #[]
        #[tag("READ-WRITE")]
        ReadWrite(()),
        #[]
        #[tag("TRYCREATE")]
        TryCreate(()),
        #[prefix("UIDNEXT ")]
        #[primitive(num_u32, number)]
        UidNext(u32),
        #[prefix("UIDVALIDITY ")]
        #[primitive(num_u32, number)]
        UidValidity(u32),
        #[prefix("UNSEEN ")]
        #[primitive(num_u32, number)]
        Unseen(u32),
        // RFC 5530
        #[]
        #[tag("UNAVAILABLE")]
        Unavailable(()),
        #[]
        #[tag("AUTHENTICATIONFAILED")]
        AuthenticationFailed(()),
        #[]
        #[tag("AUTHORIZATIONFAILED")]
        AuthorizationFailed(()),
        #[]
        #[tag("EXPIRED")]
        Expired(()),
        #[]
        #[tag("PRIVACYREQUIRED")]
        PrivacyRequired(()),
        #[]
        #[tag("CONTACTADMIN")]
        ContactAdmin(()),
        #[]
        #[tag("NOPERM")]
        NoPerm(()),
        #[]
        #[tag("INUSE")]
        InUse(()),
        #[]
        #[tag("EXPUNGEISSUED")]
        ExpungeIssued(()),
        #[]
        #[tag("CORRUPTION")]
        Corruption(()),
        #[]
        #[tag("SERVERBUG")]
        ServerBug(()),
        #[]
        #[tag("CLIENTBUG")]
        ClientBug(()),
        #[]
        #[tag("CANNOT")]
        Cannot(()),
        #[]
        #[tag("LIMIT")]
        Limit(()),
        #[]
        #[tag("OVERQUOTA")]
        OverQuota(()),
        #[]
        #[tag("ALREADYEXISTS")]
        AlreadyExists(()),
        #[]
        #[tag("NONEXISTENT")]
        Nonexistent(()),
        // RFC 4315
        #[]
        #[tag("UIDNOTSTICKY")]
        UidNotSticky(()),
        #[prefix("APPENDUID ")]
        #[delegate]
        AppendUid(AppendUidData<'a>),
        #[prefix("COPYUID ")]
        #[delegate]
        CopyUid(CopyUidData<'a>),
        // RFC 4469, by proxy of RFC 7889
        #[]
        #[tag("TOOBIG")]
        TooBig(()),
        // RFC 6154
        #[]
        #[tag("USEATTR")]
        UseAttr(()),
        // RFC 4978
        #[]
        #[tag("COMPRESSIONACTIVE")]
        CompressionActive(()),
        // RFC 7162
        #[prefix("HIGHESTMODSEQ ")]
        #[primitive(num_u64, number64)]
        HighestModseq(u64),
        #[]
        #[tag("NOMODSEQ")]
        NoModseq(()),
        #[prefix("MODIFIED ")]
        #[primitive(verbatim, sequence_set)]
        Modified(Cow<'a, str>),
        #[]
        #[tag("CLOSED")]
        Closed(()),
        // RFC 5182
        #[]
        #[tag("NOTSAVED")]
        NotSaved(()),
        // RFC 3516
        #[]
        #[tag("UNKNOWN-CTE")]
        UnknownCte(()),
        // RFC 8474
        #[surrounded("MAILBOXID (", ")")]
        #[primitive(verbatim, normal_atom)]
        MailboxId(Cow<'a, str>),
        // We don't handle unknown response codes, since the server never needs
        // to parse this. Unknown response codes just become part of the text.
    }
}

syntax_rule! {
    #[]
    struct AppendUidData<'a> {
        #[suffix(" ")]
        #[primitive(num_u32, number)]
        uid_validity: u32,
        #[]
        #[primitive(verbatim, sequence_set)]
        uids: Cow<'a, str>,
    }
}

syntax_rule! {
    #[]
    struct CopyUidData<'a> {
        #[suffix(" ")]
        #[primitive(num_u32, number)]
        uid_validity: u32,
        #[suffix(" ")]
        #[primitive(verbatim, sequence_set)]
        from_uids: Cow<'a, str>,
        #[]
        #[primitive(verbatim, sequence_set)]
        to_uids: Cow<'a, str>,
    }
}

syntax_rule! {
    #[]
    struct StatusResponse<'a> {
        #[]
        #[primitive(mailbox, mailbox)]
        mailbox: MailboxName<'a>,
        #[surrounded(" (", ")") 1*(" ")]
        #[delegate(StatusResponseAtt)]
        atts: Vec<StatusResponseAtt<'a>>,
    }
}

syntax_rule! {
    #[]
    enum StatusResponseAtt<'a> {
        #[prefix("MESSAGES ")]
        #[primitive(num_u32, number)]
        Messages(u32),
        #[prefix("RECENT ")]
        #[primitive(num_u32, number)]
        Recent(u32),
        #[prefix("UIDNEXT ")]
        #[primitive(num_u32, number)]
        UidNext(u32),
        #[prefix("UIDVALIDITY ")]
        #[primitive(num_u32, number)]
        UidValidity(u32),
        #[prefix("UNSEEN ")]
        #[primitive(num_u32, number)]
        Unseen(u32),
        #[prefix("HIGHESTMODSEQ ")]
        #[primitive(num_u64, number64)]
        HighestModseq(u64),
        #[surrounded("MAILBOXID (", ")")]
        #[primitive(verbatim, normal_atom)]
        MailboxId(Cow<'a, str>),
        #[prefix("SIZE ")]
        #[primitive(num_u64, number64)]
        Size(u64),
        #[prefix("DELETED ")]
        #[primitive(num_u32, number)]
        Deleted(u32),
    }
}

syntax_rule! {
    #[]
    struct SearchResponse {
        #[0* prefix(" ")]
        #[primitive(num_u32, number)]
        hits: Vec<u32>,
        #[opt surrounded(" (MODSEQ ", ")")]
        #[primitive(num_u64, number64)]
        max_modseq: Option<u64>,
    }
}

syntax_rule! {
    #[]
    struct EsearchResponse<'a> {
        // RFC 4466 makes this optional, but we always include it
        // Yes, it needs to be a string, even though `tag` is a subset of atom.
        // At least it uses the standard string syntax.
        #[surrounded("(TAG ", ")")]
        #[primitive(censored_string, string)]
        tag: Cow<'a, str>,
        #[]
        #[cond(" UID")]
        uid: bool,
        // The search return data is formally allowed to be in any order, but
        // we always return it in this order. The parser generated here also
        // expects it to be in this particular order, but we don't need to
        // parse anyone else's ESEARCH responses.
        #[opt prefix(" MIN ")]
        #[primitive(num_u32, number)]
        min: Option<u32>,
        #[opt prefix(" MAX ")]
        #[primitive(num_u32, number)]
        max: Option<u32>,
        #[opt prefix(" ALL ")]
        #[primitive(verbatim, sequence_set)]
        all: Option<Cow<'a, str>>,
        #[opt prefix(" COUNT ")]
        #[primitive(num_u32, number)]
        count: Option<u32>,
        #[opt prefix(" MODSEQ ")]
        #[primitive(num_u64, number64)]
        modseq: Option<u64>,
    }
}

syntax_rule! {
    #[]
    struct FetchResponse<'a> {
        #[suffix(" FETCH ")]
        #[primitive(num_u32, number)]
        seqnum: u32,
        #[]
        #[delegate]
        atts: MsgAtts<'a>,
    }
}

syntax_rule! {
    #[prefix("CAPABILITY")]
    struct CapabilityData<'a> {
        #[1* prefix(" ")]
        #[primitive(verbatim, normal_atom)]
        capabilities: Vec<Cow<'a, str>>,
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
        // These parameters, as well as those on `Content-Disposition`, present
        // us with quite the conundrum. RFC 2184 describes a way to split one
        // parameter into pieces, as well as a way to do percent-encoding to
        // embed non-ASCII characters. A small corner of the RFC underhands a
        // soft requirement at us:
        //
        // > IMAP4 [RFC-2060] servers SHOULD decode parameter value continuations
        // > when generating the BODY and BODYSTRUCTURE fetch attributes.
        //
        // The IMAP4rev2 draft also includes this as a SHOULD.
        //
        // This requirement is problematic, since one of the main points for
        // that MIME extension is to embed non-ASCII characters, and
        // IMAP4/IMAP4rev1 give us *literally no way to represent them* here.
        //
        // We could, in theory, do that decoding and pass it on when the client
        // has enabled UTF8=ACCEPT or IMAP4rev2, but that would add a decent
        // amount of complexity.
        //
        // For now, we *DO NOT* do that decoding, on several grounds:
        //
        // 1. It is not possible to do the decoding and simultaneously comply
        //    with the hard requirements of the IMAP4rev1 specification.
        //
        // 2. It's only a SHOULD. We're still compliant by not doing it.
        //
        // 3. It's highly likely that most clients that care are already
        //    designed to deal with servers that don't do the decoding, both
        //    since servers are constrained by point (1) and because, as
        //    described in the IMAP4rev2 draft, the suggestion for IMAP servers
        //    to do that decoding was previously hidden away in a completely
        //    unrelated RFC, so many server implementors (and client
        //    implementors, for that matter) would not have expected such
        //    decoding to happen.
        //
        // Non-ASCII characters can still appear through 8BITMIME. For this
        // reason, we still use `censored_string` here to ensure that
        // non-Unicode-aware clients aren't broken.
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
    #[prefix("VANISHED ")]
    struct VanishedResponse<'a> {
        #[]
        #[cond("(EARLIER) ")]
        earlier: bool,
        #[]
        #[primitive(verbatim, sequence_set)]
        uids: Cow<'a, str>,
    }
}

syntax_rule! {
    #[prefix("LIST ")]
    struct ListCommand<'a> {
        #[opt surrounded("(", ") ") 0*(" ")]
        #[delegate(ListSelectOpt)]
        select_opts: Option<Vec<ListSelectOpt>>,
        #[suffix(" ")]
        #[primitive(mailbox, mailbox)]
        reference: MailboxName<'a>,
        #[]
        #[delegate]
        pattern: MboxOrPat<'a>,
        #[opt surrounded(" RETURN (", ")") 0*(" ")]
        #[delegate(ListReturnOpt)]
        return_opts: Option<Vec<ListReturnOpt>>,
    }
}

// For this and ListReturnOpt, RFC 5258 describes formal syntax which would
// have us recognise atoms for as-yet-unknown items. However, in the semantics,
// it describes that encountering such an unknown item should be rejected with
// a BAD, which means that that whole part of the syntax is a waste of time for
// everyone and we can just use simple enum item matching.
simple_enum! {
    enum ListSelectOpt {
        // RFC 5258
        RecursiveMatch("RECURSIVEMATCH"),
        Remote("REMOTE"),
        Subscribed("SUBSCRIBED"),
        // RFC 6154
        SpecialUse("SPECIAL-USE"),
    }
}

syntax_rule! {
    #[]
    enum MboxOrPat<'a> {
        #[]
        #[primitive(mailbox, list_mailbox)]
        Single(MailboxName<'a>),
        #[surrounded("(", ")") 1*(" ")]
        #[primitive(mailbox, list_mailbox)]
        Multi(Vec<MailboxName<'a>>),
    }
}

syntax_rule! {
    #[]
    enum ListReturnOpt {
        // RFC 5258
        #[]
        #[tag("CHILDREN")]
        Children(()),
        #[]
        #[tag("SUBSCRIBED")]
        Subscribed(()),
        // RFC 6154
        #[]
        #[tag("SPECIAL-USE")]
        SpecialUse(()),
        // RFC 5819
        #[surrounded("STATUS (", ")") 1*(" ")]
        #[delegate(StatusAtt)]
        Status(Vec<StatusAtt>),
    }
}

syntax_rule! {
    #[prefix("LSUB ")]
    struct LsubCommand<'a> {
        #[suffix(" ")]
        #[primitive(mailbox, mailbox)]
        reference: MailboxName<'a>,
        #[]
        #[primitive(mailbox, list_mailbox)]
        pattern: MailboxName<'a>,
    }
}

syntax_rule! {
    #[prefix("XLIST ")]
    struct XlistCommand<'a> {
        #[suffix(" ")]
        #[primitive(mailbox, mailbox)]
        reference: MailboxName<'a>,
        #[]
        #[primitive(mailbox, list_mailbox)]
        pattern: MailboxName<'a>,
    }
}

syntax_rule! {
    #[]
    struct MailboxList<'a> {
        // Note that we're also encoding the hierarchy delimiter field into
        // the suffix. Yes, the quotes are required, even though / is legal in
        // atoms and the other fields in this structure are all astrings.
        #[surrounded("(", ") \"/\" ") 0*(" ")]
        #[primitive(verbatim, backslash_atom)]
        flags: Vec<Cow<'a, str>>,
        #[]
        #[primitive(mailbox, mailbox)]
        name: MailboxName<'a>,
        // The formal grammar for the RFC 5258 extended data is appallingly
        // complex and is even infinitely recursive.
        // The only thing we ever need it for is CHILDINFO, so we just
        // hard-code that grammar.
        // It's unclear why these all need to be quoted strings when all
        // possible values are simple atoms.
        #[opt surrounded(r#" ("CHILDINFO" ("#, "))") 1*(" ")]
        #[primitive(censored_string, string)]
        child_info: Option<Vec<Cow<'a, str>>>,
    }
}

syntax_rule! {
    #[prefix("FETCH ")]
    struct FetchCommand<'a> {
        #[suffix(" ")]
        #[primitive(verbatim, sequence_set)]
        messages: Cow<'a, str>,
        #[]
        #[delegate]
        target: FetchCommandTarget<'a>,
        #[opt surrounded(" (", ")") 1*(" ")]
        #[delegate(FetchModifier)]
        modifiers: Option<Vec<FetchModifier>>,
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
        #[]
        #[tag("SAVEDATE")]
        SaveDate(()),
        #[prefix("RFC822") opt]
        #[delegate(FetchAttRfc822)]
        Rfc822(Option<FetchAttRfc822>),
        // Must come before the body structure stuff to resolve the ambiguity
        // the correct way.
        #[]
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
        // RFC 7162
        #[]
        #[tag("MODSEQ")]
        Modseq(()),
        // RFC 8474
        #[]
        #[tag("EMAILID")]
        EmailId(()),
        #[]
        #[tag("THREADID")]
        ThreadId(()),
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
        // This definition allows for some non-standard forms, such as
        // BODY.SIZE, BINARY.PEEK.SIZE, slicing on BINARY.SIZE, and accessing
        // non-content parts through BINARY. However, there doesn't seem to be
        // all that much reason to prevent these since they're not useful.
        #[]
        #[delegate]
        kind: FetchAttBodyKind,
        #[]
        #[cond(".PEEK")]
        peek: bool,
        #[]
        #[cond(".SIZE")]
        size_only: bool,
        #[surrounded("[", "]") opt]
        #[delegate(SectionSpec)]
        section: Option<SectionSpec<'a>>,
        #[opt]
        #[delegate(FetchAttBodySlice)]
        slice: Option<FetchAttBodySlice>,
    }
}

simple_enum! {
    enum FetchAttBodyKind {
        Body("BODY"),
        Binary("BINARY"),
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
    struct FetchAttBodySlice {
        #[suffix(".")]
        #[primitive(num_u32, number)]
        start: u32,
        #[]
        #[primitive(num_u32, number)]
        length: u32,
    }
}

syntax_rule! {
    #[]
    enum FetchModifier {
        #[prefix("CHANGEDSINCE ")]
        #[primitive(num_u64, number64)]
        ChangedSince(u64),
        #[]
        #[tag("VANISHED")]
        Vanished(()),
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
        #[prefix("SAVEDATE ") opt]
        #[primitive(datetime, datetime)]
        SaveDate(Option<DateTime<FixedOffset>>),
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
        #[prefix("BINARY.SIZE")]
        #[delegate]
        BinarySize(MsgAttBinarySize<'a>),
        #[]
        #[delegate]
        Body(MsgAttBody<'a>),
        #[prefix("UID ")]
        #[primitive(num_u32, number)]
        Uid(u32),
        #[surrounded("FLAGS (", ")")]
        #[delegate]
        Flags(FlagsFetch),
        // RFC 7162
        #[surrounded("MODSEQ (", ")")]
        #[primitive(num_u64, number64)]
        Modseq(u64),
        // RFC 8474
        #[surrounded("EMAILID (", ")")]
        #[primitive(verbatim, normal_atom)]
        EmailId(Cow<'a, str>),
        #[]
        #[tag("THREADID NIL")]
        ThreadIdNil(()),
    }
}

syntax_rule! {
    #[]
    struct MsgAttBody<'a> {
        #[]
        #[delegate]
        kind: FetchAttBodyKind,
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
    #[]
    struct MsgAttBinarySize<'a> {
        #[surrounded("[", "]") opt]
        #[delegate(SectionSpec)]
        section: Option<SectionSpec<'a>>,
        #[prefix(" ")]
        #[primitive(num_u32, number)]
        size: u32,
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
    enum FlagsFetch {
        #[prefix("\\Recent") 0* prefix(" ")]
        #[primitive(flag, flag)]
        Recent(Vec<Flag>),
        #[0*(" ")]
        #[primitive(flag, flag)]
        NotRecent(Vec<Flag>),
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
        // RFC 8514
        SaveDateSupported("SAVEDATESUPPORTED"),
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
    struct DateSearchKey {
        #[suffix(" ")]
        #[delegate]
        typ: DateSearchKeyType,
        #[]
        #[primitive(date, date)]
        date: NaiveDate,
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
        // RFC 8514
        SavedBefore("SAVEDBEFORE"),
        SavedOn("SAVEDON"),
        SavedSince("SAVEDSINCE"),
    }
}

syntax_rule! {
    #[prefix("SEARCH ")]
    struct SearchCommand<'a> {
        // RFC 4466 allows a more complex syntax, but RFC 4731 doesn't use it
        // and we can just treat this as a list of atoms.
        #[opt surrounded("RETURN (", ") ") 0*(" ")]
        #[delegate(SearchReturnOpt)]
        return_opts: Option<Vec<SearchReturnOpt>>,
        #[opt surrounded("CHARSET ", " ")]
        #[primitive(censored_astring, astring)]
        charset: Option<Cow<'a, str>>,
        #[1*(" ")]
        #[delegate(SearchKey)]
        keys: Vec<SearchKey<'a>>,
    }
}

simple_enum! {
    enum SearchReturnOpt {
        Min("MIN"),
        Max("MAX"),
        All("ALL"),
        Count("COUNT"),
        Save("SAVE"),
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
        Date(DateSearchKey),
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
        // RFC 7162
        #[prefix("MODSEQ ")]
        #[delegate]
        Modseq(ModseqSearchKey<'a>),
        // RFC 8474
        // Note that unlike in the FETCH and STATUS cases, there is not an
        // extra set of parentheses around the object id.
        #[prefix("EMAILID ")]
        #[primitive(verbatim, normal_atom)]
        EmailId(Cow<'a, str>),
        #[prefix("THREADID ")]
        #[primitive(verbatim, normal_atom)]
        ThreadId(Cow<'a, str>),
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
    #[]
    struct ModseqSearchKey<'a> {
        #[opt suffix(" ")]
        #[delegate(ModseqSearchKeyExt)]
        ext: Option<ModseqSearchKeyExt<'a>>,
        #[]
        #[primitive(num_u64, number64)]
        modseq: u64,
    }
}

syntax_rule! {
    #[]
    struct ModseqSearchKeyExt<'a> {
        // RFC 7162 curiously doesn't allow general string syntax --- literals
        // aren't allowed. However, as a server, we never need to *generate*
        // this syntax, so just using general strings is safe.
        #[suffix(" ")]
        #[primitive(censored_string, string)]
        name: Cow<'a, str>,
        // This is formally just one of "priv", "shared", or "all", but we
        // don't use it for anything so just parse out the raw value.
        #[]
        #[primitive(verbatim, normal_atom)]
        value: Cow<'a, str>,
    }
}

syntax_rule! {
    #[prefix("CREATE ")]
    struct CreateCommand<'a> {
        #[]
        #[primitive(mailbox, mailbox)]
        mailbox: MailboxName<'a>,
        #[opt surrounded(" USE (", ")") 0*(" ")]
        #[primitive(verbatim, backslash_atom)]
        special_use: Option<Vec<Cow<'a, str>>>,
    }
}

syntax_rule! {
    #[prefix("DELETE ")]
    struct DeleteCommand<'a> {
        #[]
        #[primitive(mailbox, mailbox)]
        mailbox: MailboxName<'a>,
    }
}

syntax_rule! {
    #[prefix("EXAMINE ")]
    struct ExamineCommand<'a> {
        #[]
        #[primitive(mailbox, mailbox)]
        mailbox: MailboxName<'a>,
        #[opt surrounded(" (", ")") 1*(" ")]
        #[delegate(SelectModifier<'a>)]
        modifiers: Option<Vec<SelectModifier<'a>>>,
    }
}

syntax_rule! {
    #[prefix("RENAME ")]
    struct RenameCommand<'a> {
        #[suffix(" ")]
        #[primitive(mailbox, mailbox)]
        src: MailboxName<'a>,
        #[]
        #[primitive(mailbox, mailbox)]
        dst: MailboxName<'a>,
    }
}

syntax_rule! {
    #[prefix("SELECT ")]
    struct SelectCommand<'a> {
        #[]
        #[primitive(mailbox, mailbox)]
        mailbox: MailboxName<'a>,
        #[opt surrounded(" (", ")") 1*(" ")]
        #[delegate(SelectModifier<'a>)]
        modifiers: Option<Vec<SelectModifier<'a>>>,
    }
}

syntax_rule! {
    #[]
    enum SelectModifier<'a> {
        #[]
        #[tag("CONDSTORE")]
        Condstore(()),
        #[]
        #[delegate]
        Qresync(SelectQresyncModifier<'a>),
    }
}

syntax_rule! {
    #[surrounded("QRESYNC (", ")")]
    struct SelectQresyncModifier<'a> {
        #[suffix(" ")]
        #[primitive(num_u32, number)]
        uid_validity: u32,
        #[]
        #[primitive(num_u64, number64)]
        modseq: u64,
        #[opt prefix(" ")]
        #[primitive(verbatim, sequence_set)]
        known_uids: Option<Cow<'a, str>>,
        #[opt surrounded(" (", ")")]
        #[delegate(SeqMatchData)]
        seq_match_data: Option<SeqMatchData<'a>>,
    }
}

syntax_rule! {
    #[]
    struct SeqMatchData<'a> {
        #[suffix(" ")]
        #[primitive(verbatim, sequence_set)]
        seqnums: Cow<'a, str>,
        #[]
        #[primitive(verbatim, sequence_set)]
        uids: Cow<'a, str>,
    }
}

syntax_rule! {
    #[prefix("STATUS ")]
    struct StatusCommand<'a> {
        #[suffix(" ")]
        #[primitive(mailbox, mailbox)]
        mailbox: MailboxName<'a>,
        #[surrounded("(", ")") 1*(" ")]
        #[delegate(StatusAtt)]
        atts: Vec<StatusAtt>,
    }
}

simple_enum! {
    enum StatusAtt {
        // RFC 3501
        Messages("MESSAGES"),
        Recent("RECENT"),
        UidNext("UIDNEXT"),
        UidValidity("UIDVALIDITY"),
        Unseen("UNSEEN"),
        // RFC 7162
        HighestModseq("HIGHESTMODSEQ"),
        // RFC 8474
        MailboxId("MAILBOXID"),
        // RFC 8438
        Size("SIZE"),
        // IMAP4rev2 draft
        Deleted("DELETED"),
    }
}

syntax_rule! {
    #[prefix("SUBSCRIBE ")]
    struct SubscribeCommand<'a> {
        #[]
        #[primitive(mailbox, mailbox)]
        mailbox: MailboxName<'a>,
    }
}

syntax_rule! {
    #[prefix("UNSUBSCRIBE ")]
    struct UnsubscribeCommand<'a> {
        #[]
        #[primitive(mailbox, mailbox)]
        mailbox: MailboxName<'a>,
    }
}

syntax_rule! {
    #[prefix("COPY ")]
    struct CopyCommand<'a> {
        #[suffix(" ")]
        #[primitive(verbatim, sequence_set)]
        messages: Cow<'a, str>,
        #[]
        #[primitive(mailbox, mailbox)]
        dst: MailboxName<'a>,
    }
}

syntax_rule! {
    #[prefix("MOVE ")]
    struct MoveCommand<'a> {
        #[suffix(" ")]
        #[primitive(verbatim, sequence_set)]
        messages: Cow<'a, str>,
        #[]
        #[primitive(mailbox, mailbox)]
        dst: MailboxName<'a>,
    }
}

syntax_rule! {
    #[prefix("STORE ")]
    struct StoreCommand<'a> {
        #[suffix(" ")]
        #[primitive(verbatim, sequence_set)]
        messages: Cow<'a, str>,
        #[opt surrounded("(UNCHANGEDSINCE ", ") ")]
        #[primitive(num_u64, number64)]
        unchanged_since: Option<u64>,
        #[]
        #[delegate]
        typ: StoreCommandType,
        #[suffix(" ")]
        #[cond(".SILENT")]
        silent: bool,
        #[maybe_surrounded("(", ")") 0*(" ")]
        #[primitive(flag, flag)]
        flags: Vec<Flag>,
    }
}

simple_enum! {
    enum StoreCommandType {
        Plus("+FLAGS"),
        Minus("-FLAGS"),
        Eq("FLAGS"),
    }
}

syntax_rule! {
    #[]
    struct AuthenticateCommandStart<'a> {
        #[suffix(" AUTHENTICATE ")]
        #[primitive(verbatim, tag_atom)]
        tag: Cow<'a, str>,
        #[]
        #[primitive(verbatim, normal_atom)]
        auth_type: Cow<'a, str>,
        #[opt prefix(" ")]
        #[primitive(verbatim, normal_atom)]
        initial_response: Option<Cow<'a, str>>,
    }
}

syntax_rule! {
    #[prefix("LOGIN ")]
    struct LogInCommand<'a> {
        #[suffix(" ")]
        #[primitive(unicode_astring, astring)]
        userid: Cow<'a, str>,
        #[]
        #[primitive(unicode_astring, astring)]
        password: Cow<'a, str>,
    }
}

syntax_rule! {
    #[prefix("UID ")]
    enum UidCommand<'a> {
        #[]
        #[delegate]
        Copy(CopyCommand<'a>),
        #[]
        #[delegate]
        Move(MoveCommand<'a>),
        #[]
        #[delegate]
        Fetch(FetchCommand<'a>),
        #[]
        #[delegate]
        Search(SearchCommand<'a>),
        #[]
        #[delegate]
        Store(StoreCommand<'a>),
        #[prefix("EXPUNGE ")]
        #[primitive(verbatim, sequence_set)]
        Expunge(Cow<'a, str>),
    }
}

simple_enum! {
    enum SimpleCommand {
        Capability("CAPABILITY"),
        Check("CHECK"),
        Close("CLOSE"),
        Expunge("EXPUNGE"),
        LogOut("LOGOUT"),
        Noop("NOOP"),
        StartTls("STARTTLS"),
        XCryFlagsOff("XCRY FLAGS OFF"),
        XCryFlagsOn("XCRY FLAGS ON"),
        XCryGetUserConfig("XCRY GET-USER-CONFIG"),
        XCryPurge("XCRY PURGE"),
        XCryZstdTrain("XCRY ZSTD TRAIN"),
        Xyzzy("XYZZY"),
        // RFC 2342
        Namespace("NAMESPACE"),
        // RFC 3691
        Unselect("UNSELECT"),
        // RFC 4978
        Compress("COMPRESS DEFLATE"),
        // RFC 2177
        Idle("IDLE"),
        // Used internally, not expected to match anything
        XAppendFinishedNoop("\nXAppendFinishedNoop"),
    }
}

syntax_rule! {
    #[]
    struct CommandLine<'a> {
        #[suffix(" ")]
        #[primitive(verbatim, tag_atom)]
        tag: Cow<'a, str>,
        #[]
        #[delegate]
        cmd: Command<'a>,
    }
}

syntax_rule! {
    #[]
    enum Command<'a> {
        #[]
        #[delegate]
        Simple(SimpleCommand),
        #[]
        #[delegate]
        Create(CreateCommand<'a>),
        #[]
        #[delegate]
        Delete(DeleteCommand<'a>),
        #[]
        #[delegate]
        Examine(ExamineCommand<'a>),
        #[]
        #[delegate]
        List(ListCommand<'a>),
        #[]
        #[delegate]
        Lsub(LsubCommand<'a>),
        #[]
        #[delegate]
        Xlist(XlistCommand<'a>),
        #[]
        #[delegate]
        Rename(RenameCommand<'a>),
        #[]
        #[delegate]
        Select(SelectCommand<'a>),
        #[]
        #[delegate]
        Status(StatusCommand<'a>),
        #[]
        #[delegate]
        Subscribe(SubscribeCommand<'a>),
        #[]
        #[delegate]
        Unsubscribe(UnsubscribeCommand<'a>),
        #[]
        #[delegate]
        LogIn(LogInCommand<'a>),
        #[]
        #[delegate]
        Copy(CopyCommand<'a>),
        #[]
        #[delegate]
        Move(MoveCommand<'a>),
        #[]
        #[delegate]
        Fetch(FetchCommand<'a>),
        #[]
        #[delegate]
        Store(StoreCommand<'a>),
        #[]
        #[delegate]
        Uid(UidCommand<'a>),
        #[]
        #[delegate]
        Search(SearchCommand<'a>),
        #[prefix("XVANQUISH ")]
        #[primitive(verbatim, sequence_set)]
        XVanquish(Cow<'a, str>),
        // RFC 2971
        #[prefix("ID ") nil_if_empty surrounded("(", ")") 0*(" ")]
        #[primitive(censored_nstring, nstring)]
        Id(Vec<Option<Cow<'a, str>>>),
        // RFC 5161
        #[prefix("ENABLE ") 1*(" ")]
        #[primitive(verbatim, normal_atom)]
        Enable(Vec<Cow<'a, str>>),
        // Crymap extensions
        #[prefix("XCRY SET-USER-CONFIG") 1* prefix(" ")]
        #[delegate(XCryUserConfigOption)]
        XCrySetUserConfig(Vec<XCryUserConfigOption<'a>>),
    }
}

// Command fragment for the start of an APPEND command.
//
// This will parse out all of the APPEND command up to but not including the
// literal. Every time the connection parser encounters a literal, it should
// invoke this on the portion of the line buffered so far (not including the
// literal itself) to see if it is an APPEND.
syntax_rule! {
    #[]
    struct AppendCommandStart<'a> {
        #[suffix(" ")]
        #[primitive(verbatim, tag_atom)]
        tag: Cow<'a, str>,
        #[prefix("APPEND ")]
        #[primitive(mailbox, mailbox)]
        mailbox: MailboxName<'a>,
        #[]
        #[delegate]
        first_fragment: AppendFragment,
    }
}

// Command fragment for additional messages being fed into APPEND (i.e.,
// MULTIAPPEND). After the first APPEND line has been processed, this is used
// to process additional command lines until the final blank line is reached.
//
// Like `AppendCommandStart`, this must be called with the fragment of the line
// before the literal itself.
syntax_rule! {
    #[prefix(" ")]
    struct AppendFragment {
        #[opt surrounded("(", ") ") 0*(" ")]
        #[primitive(flag, flag)]
        flags: Option<Vec<Flag>>,
        #[opt suffix(" ")]
        #[primitive(datetime, datetime)]
        internal_date: Option<DateTime<FixedOffset>>,
        #[]
        #[cond("UTF8 (")]
        utf8: bool,
    }
}

impl Default for AppendFragment {
    fn default() -> Self {
        AppendFragment {
            flags: None,
            internal_date: None,
            utf8: false,
        }
    }
}

syntax_rule! {
    #[]
    struct UnknownCommandFragment<'a> {
        #[suffix(" ")]
        #[primitive(verbatim, tag_atom)]
        tag: Cow<'a, str>,
        #[]
        #[primitive(verbatim, text)]
        garbage: Cow<'a, str>,
    }
}

syntax_rule! {
    #[]
    struct XCryUserConfigData<'a> {
        #[surrounded(" (", ")") 1*(" ")]
        #[primitive(unicode_astring, astring)]
        capabilities: Vec<Cow<'a, str>>,
        #[prefix(" ")]
        #[primitive(unicode_astring, astring)]
        internal_key_pattern: Cow<'a, str>,
        #[prefix(" ")]
        #[primitive(unicode_astring, astring)]
        external_key_pattern: Cow<'a, str>,
        #[prefix(" ") nil]
        #[primitive(datetime, datetime)]
        password_changed: Option<DateTime<FixedOffset>>,
        // Crymap 2.0.0+
        #[0* prefix(" ")]
        #[delegate(XCry2UserConfigData)]
        extended: Vec<XCry2UserConfigData<'a>>,
    }
}

syntax_rule! {
    #[]
    enum XCry2UserConfigData<'a> {
        #[prefix("SMTP-OUT-SAVE ")]
        #[primitive(unicode_nstring, nstring)]
        SmtpOutSave(Option<Cow<'a, str>>),
        #[prefix("SMTP-OUT-SUCCESS-RECEIPTS ")]
        #[primitive(unicode_nstring, nstring)]
        SmtpOutSuccessReceipts(Option<Cow<'a, str>>),
        #[prefix("SMTP-OUT-FAILURE-RECEIPTS ")]
        #[primitive(unicode_nstring, nstring)]
        SmtpOutFailureReceipts(Option<Cow<'a, str>>),
        #[]
        #[delegate]
        Unknown(XCryUnknownUserConfigData<'a>),
    }
}

syntax_rule! {
    #[]
    struct XCryUnknownUserConfigData<'a> {
        #[]
        #[primitive(unicode_astring, astring)]
        key: Cow<'a, str>,
        #[prefix(" ")]
        #[primitive(unicode_astring, astring)]
        value: Cow<'a, str>,
    }
}

syntax_rule! {
    #[]
    enum XCryUserConfigOption<'a> {
        #[prefix("INTERNAL-KEY-PATTERN ")]
        #[primitive(unicode_astring, astring)]
        InternalKeyPattern(Cow<'a, str>),
        #[prefix("EXTERNAL-KEY-PATTERN ")]
        #[primitive(unicode_astring, astring)]
        ExternalKeyPattern(Cow<'a, str>),
        #[prefix("PASSWORD ")]
        #[primitive(unicode_astring, astring)]
        Password(Cow<'a, str>),
        #[prefix("SMTP-OUT-SAVE ")]
        #[primitive(unicode_nstring, nstring)]
        SmtpOutSave(Option<Cow<'a, str>>),
        #[prefix("SMTP-OUT-SUCCESS-RECEIPTS ")]
        #[primitive(unicode_nstring, nstring)]
        SmtpOutSuccessReceipts(Option<Cow<'a, str>>),
        #[prefix("SMTP-OUT-FAILURE-RECEIPTS ")]
        #[primitive(unicode_nstring, nstring)]
        SmtpOutFailureReceipts(Option<Cow<'a, str>>),
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
        // RFC 3501 does not specify a maximum size for tags, but 128 should be
        // more than enough for anyone.
        bytes::complete::take_while_m_n(1, 128, |b| match b {
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

fn number64(i: &[u8]) -> IResult<&[u8], u64> {
    map_opt(character::complete::digit1, |s| {
        str::from_utf8(s).ok().and_then(|s| s.parse::<u64>().ok())
    })(i)
}

fn literal(i: &[u8]) -> IResult<&[u8], &[u8]> {
    let (i, len) = sequence::delimited(
        alt((tag("~{"), tag("{"))),
        number,
        alt((tag("+}\r\n"), tag("+}\n"), tag("}\r\n"), tag("}\n"))),
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
    let (i, len) = sequence::terminated(
        number,
        alt((tag("+}\r\n"), tag("+}\n"), tag("}\r\n"), tag("}\n"))),
    )(i)?;
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
            || Cow::Owned(String::new()),
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
fn list_mailbox(i: &[u8]) -> IResult<&[u8], MailboxName<'_>> {
    map(alt((list_mailbox_atom, string)), MailboxName::of_wire)(i)
}

fn mailbox(i: &[u8]) -> IResult<&[u8], MailboxName<'_>> {
    map(astring, MailboxName::of_wire)(i)
}

fn sequence_set(i: &[u8]) -> IResult<&[u8], Cow<str>> {
    map(
        alt((is_a("0123456789:*,"), tag("$"))),
        String::from_utf8_lossy,
    )(i)
}

fn text(i: &[u8]) -> IResult<&[u8], Cow<str>> {
    map(is_not("\r\n"), String::from_utf8_lossy)(i)
}

fn keyword(i: &[u8]) -> IResult<&[u8], Flag> {
    map_opt(normal_atom, |a| a.parse::<Flag>().ok())(i)
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
    use crate::support::chronox::*;

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

    macro_rules! assert_equivalent {
        ($unicode:expr, $ty:ty, $expected:expr, $($examples:expr),+) => {
            for &example in &[$($examples),+] {
                let (trailing, mut read) =
                    match <$ty>::parse(example.as_bytes()) {
                        Ok(read) => read,
                        Err(e) => panic!("Failed to parse `{}`: {}`",
                                         example, e),
                    };

                if !trailing.is_empty() {
                    panic!(
                        "Didn't parse all of `{}`, `{}` remained",
                        example,
                        String::from_utf8_lossy(trailing)
                    );
                }

                let mut lex = LexWriter::new(Vec::<u8>::new(), $unicode,
                                             false);
                read.write_to(&mut lex).unwrap();
                let text = lex.into_inner();
                let text = str::from_utf8(&text).unwrap();
                if $expected != text {
                    panic!(
                        "Didn't generate correct string\n\
                         Input:    {}\n\
                         Expected: {}\n\
                         Actual:   {}\n\
                         Diff:     {}\n",
                        example,
                        $expected,
                        text,
                        diff($expected, text)
                    );
                }
            }
        }
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

    fn mn(s: &str) -> MailboxName<'static> {
        MailboxName::of_wire(Cow::Owned(s.to_owned()))
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
                select_opts: None,
                reference: mn(""),
                pattern: MboxOrPat::Single(mn("INBOX")),
                return_opts: None,
            }
        );
        assert_reversible!(
            LsubCommand,
            r#"LSUB foo bar"#,
            LsubCommand {
                reference: mn("foo"),
                pattern: mn("bar"),
            }
        );

        assert_reversible!(
            true,
            ListCommand,
            r#"LIST "" "föö""#,
            ListCommand {
                select_opts: None,
                reference: mn(""),
                pattern: MboxOrPat::Single(mn("föö")),
                return_opts: None,
            }
        );

        assert_reversible!(
            true,
            MailboxList,
            r#"() "/" "~peter/mail/台北/日本語""#,
            MailboxList {
                flags: vec![],
                name: mn("~peter/mail/台北/日本語"),
                child_info: None,
            }
        );
        assert_reversible!(
            true,
            MailboxList,
            r#"(\Noinferiors) "/" "~peter/mail/台北/日本語""#,
            MailboxList {
                flags: vec![s("\\Noinferiors")],
                name: mn("~peter/mail/台北/日本語"),
                child_info: None,
            }
        );
        assert_reversible!(
            true,
            MailboxList,
            r#"(\Noinferiors \Marked) "/" "~peter/mail/台北/日本語""#,
            MailboxList {
                flags: vec![s("\\Noinferiors"), s("\\Marked")],
                name: mn("~peter/mail/台北/日本語"),
                child_info: None,
            }
        );
    }

    #[test]
    fn fetch_command_syntax() {
        assert_reversible!(
            FetchCommand,
            "FETCH 1:2,3:* ALL",
            FetchCommand {
                messages: s("1:2,3:*"),
                target: FetchCommandTarget::All(()),
                modifiers: None,
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH $ ALL",
            FetchCommand {
                messages: s("$"),
                target: FetchCommandTarget::All(()),
                modifiers: None,
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1:2,3 FULL",
            FetchCommand {
                messages: s("1:2,3"),
                target: FetchCommandTarget::Full(()),
                modifiers: None,
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1:2,3 FAST",
            FetchCommand {
                messages: s("1:2,3"),
                target: FetchCommandTarget::Fast(()),
                modifiers: None,
            }
        );

        assert_reversible!(
            FetchCommand,
            "FETCH 1 ENVELOPE",
            FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Envelope(())),
                modifiers: None,
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 FLAGS",
            FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Flags(())),
                modifiers: None,
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 INTERNALDATE",
            FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::InternalDate(())),
                modifiers: None,
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 BODY",
            FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Single(
                    FetchAtt::ShortBodyStructure(())
                ),
                modifiers: None,
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 BODYSTRUCTURE",
            FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Single(
                    FetchAtt::ExtendedBodyStructure(())
                ),
                modifiers: None,
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 RFC822",
            FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Rfc822(None)),
                modifiers: None,
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 RFC822.SIZE",
            FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Rfc822(Some(
                    FetchAttRfc822::Size
                ))),
                modifiers: None,
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 RFC822.HEADER",
            FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Rfc822(Some(
                    FetchAttRfc822::Header
                ))),
                modifiers: None,
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 RFC822.TEXT",
            FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Rfc822(Some(
                    FetchAttRfc822::Text
                ))),
                modifiers: None,
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 UID",
            FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Uid(())),
                modifiers: None,
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 EMAILID",
            FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::EmailId(())),
                modifiers: None,
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 THREADID",
            FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::ThreadId(())),
                modifiers: None,
            }
        );

        assert_reversible!(
            FetchCommand,
            "FETCH 1 (FLAGS)",
            FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Multi(vec![FetchAtt::Flags(())]),
                modifiers: None,
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 (FLAGS UID)",
            FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Multi(vec![
                    FetchAtt::Flags(()),
                    FetchAtt::Uid(()),
                ]),
                modifiers: None,
            }
        );

        assert_reversible!(
            FetchCommand,
            "FETCH 1 BODY[]",
            FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Body(
                    FetchAttBody {
                        kind: FetchAttBodyKind::Body,
                        peek: false,
                        size_only: false,
                        section: None,
                        slice: None,
                    }
                )),
                modifiers: None,
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 BODY.PEEK[]",
            FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Body(
                    FetchAttBody {
                        kind: FetchAttBodyKind::Body,
                        peek: true,
                        size_only: false,
                        section: None,
                        slice: None,
                    }
                )),
                modifiers: None,
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 BODY[]<42.56>",
            FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Body(
                    FetchAttBody {
                        kind: FetchAttBodyKind::Body,
                        peek: false,
                        size_only: false,
                        section: None,
                        slice: Some(FetchAttBodySlice {
                            start: 42,
                            length: 56,
                        }),
                    }
                )),
                modifiers: None,
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 BODY[HEADER]",
            FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Body(
                    FetchAttBody {
                        kind: FetchAttBodyKind::Body,
                        peek: false,
                        size_only: false,
                        section: Some(SectionSpec::TopLevel(
                            SectionText::Header(())
                        )),
                        slice: None,
                    }
                )),
                modifiers: None,
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 BODY[TEXT]",
            FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Body(
                    FetchAttBody {
                        kind: FetchAttBodyKind::Body,
                        peek: false,
                        size_only: false,
                        section: Some(SectionSpec::TopLevel(
                            SectionText::Text(())
                        )),
                        slice: None,
                    }
                )),
                modifiers: None,
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 BODY[HEADER.FIELDS (Foo)]",
            FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Body(
                    FetchAttBody {
                        kind: FetchAttBodyKind::Body,
                        peek: false,
                        size_only: false,
                        section: Some(SectionSpec::TopLevel(
                            SectionText::HeaderFields(SectionTextHeaderField {
                                negative: false,
                                headers: vec![s("Foo")],
                            })
                        )),
                        slice: None,
                    }
                )),
                modifiers: None,
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 BODY[HEADER.FIELDS.NOT (Foo)]",
            FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Body(
                    FetchAttBody {
                        kind: FetchAttBodyKind::Body,
                        peek: false,
                        size_only: false,
                        section: Some(SectionSpec::TopLevel(
                            SectionText::HeaderFields(SectionTextHeaderField {
                                negative: true,
                                headers: vec![s("Foo")],
                            })
                        )),
                        slice: None,
                    }
                )),
                modifiers: None,
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 BODY[HEADER.FIELDS (Foo Bar)]",
            FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Body(
                    FetchAttBody {
                        kind: FetchAttBodyKind::Body,
                        peek: false,
                        size_only: false,
                        section: Some(SectionSpec::TopLevel(
                            SectionText::HeaderFields(SectionTextHeaderField {
                                negative: false,
                                headers: vec![s("Foo"), s("Bar")],
                            })
                        )),
                        slice: None,
                    }
                )),
                modifiers: None,
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 BODY[HEADER.FIELDS.NOT (Foo Bar)]",
            FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Body(
                    FetchAttBody {
                        kind: FetchAttBodyKind::Body,
                        peek: false,
                        size_only: false,
                        section: Some(SectionSpec::TopLevel(
                            SectionText::HeaderFields(SectionTextHeaderField {
                                negative: true,
                                headers: vec![s("Foo"), s("Bar")],
                            })
                        )),
                        slice: None,
                    }
                )),
                modifiers: None,
            }
        );

        assert_reversible!(
            FetchCommand,
            "FETCH 1 BODY[1]",
            FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Body(
                    FetchAttBody {
                        kind: FetchAttBodyKind::Body,
                        peek: false,
                        size_only: false,
                        section: Some(SectionSpec::Sub(SubSectionSpec {
                            subscripts: vec![1],
                            text: None,
                        })),
                        slice: None,
                    }
                )),
                modifiers: None,
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 BODY[1.2.3]",
            FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Body(
                    FetchAttBody {
                        kind: FetchAttBodyKind::Body,
                        peek: false,
                        size_only: false,
                        section: Some(SectionSpec::Sub(SubSectionSpec {
                            subscripts: vec![1, 2, 3],
                            text: None,
                        })),
                        slice: None,
                    }
                )),
                modifiers: None,
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 BODY[1.MIME]",
            FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Body(
                    FetchAttBody {
                        kind: FetchAttBodyKind::Body,
                        peek: false,
                        size_only: false,
                        section: Some(SectionSpec::Sub(SubSectionSpec {
                            subscripts: vec![1],
                            text: Some(SectionText::Mime(())),
                        })),
                        slice: None,
                    }
                )),
                modifiers: None,
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 BODY[1.HEADER]",
            FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Body(
                    FetchAttBody {
                        kind: FetchAttBodyKind::Body,
                        peek: false,
                        size_only: false,
                        section: Some(SectionSpec::Sub(SubSectionSpec {
                            subscripts: vec![1],
                            text: Some(SectionText::Header(())),
                        })),
                        slice: None,
                    }
                )),
                modifiers: None,
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 BODY[1.TEXT]",
            FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Body(
                    FetchAttBody {
                        kind: FetchAttBodyKind::Body,
                        peek: false,
                        size_only: false,
                        section: Some(SectionSpec::Sub(SubSectionSpec {
                            subscripts: vec![1],
                            text: Some(SectionText::Text(())),
                        })),
                        slice: None,
                    }
                )),
                modifiers: None,
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 BINARY[1]",
            FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Body(
                    FetchAttBody {
                        kind: FetchAttBodyKind::Binary,
                        peek: false,
                        size_only: false,
                        section: Some(SectionSpec::Sub(SubSectionSpec {
                            subscripts: vec![1],
                            text: None,
                        })),
                        slice: None,
                    }
                )),
                modifiers: None,
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 BINARY.SIZE[1]",
            FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Body(
                    FetchAttBody {
                        kind: FetchAttBodyKind::Binary,
                        peek: false,
                        size_only: true,
                        section: Some(SectionSpec::Sub(SubSectionSpec {
                            subscripts: vec![1],
                            text: None,
                        })),
                        slice: None,
                    }
                )),
                modifiers: None,
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 BINARY.PEEK[1]",
            FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Body(
                    FetchAttBody {
                        kind: FetchAttBodyKind::Binary,
                        peek: true,
                        size_only: false,
                        section: Some(SectionSpec::Sub(SubSectionSpec {
                            subscripts: vec![1],
                            text: None,
                        })),
                        slice: None,
                    }
                )),
                modifiers: None,
            }
        );

        assert_reversible!(
            FetchCommand,
            "FETCH 1 (UID) (VANISHED)",
            FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Multi(vec![FetchAtt::Uid(())]),
                modifiers: Some(vec![FetchModifier::Vanished(())]),
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 UID (VANISHED)",
            FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Single(FetchAtt::Uid(())),
                modifiers: Some(vec![FetchModifier::Vanished(())]),
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 (UID) (CHANGEDSINCE 12345678901234567890)",
            FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Multi(vec![FetchAtt::Uid(())]),
                modifiers: Some(vec![FetchModifier::ChangedSince(
                    12345678901234567890
                ),]),
            }
        );
        assert_reversible!(
            FetchCommand,
            "FETCH 1 (UID) (CHANGEDSINCE 12345678901234567890 VANISHED)",
            FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Multi(vec![FetchAtt::Uid(())]),
                modifiers: Some(vec![
                    FetchModifier::ChangedSince(12345678901234567890),
                    FetchModifier::Vanished(()),
                ]),
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
                FixedOffset::eastx(3600).ymd_hmsx(2020, 7, 4, 16, 31, 0),
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
            "EMAILID (Ethemessageid)",
            MsgAtt::EmailId(s("Ethemessageid"))
        );
        assert_reversible!(MsgAtt, "THREADID NIL", MsgAtt::ThreadIdNil(()));

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
                kind: FetchAttBodyKind::Body,
                section: None,
                slice_origin: None,
                data: LiteralSource::of_data(b"foo", false),
            })
        );
        assert_reversible!(
            MsgAtt,
            "BODY[HEADER] {3}\r\nfoo",
            MsgAtt::Body(MsgAttBody {
                kind: FetchAttBodyKind::Body,
                section: Some(SectionSpec::TopLevel(SectionText::Header(()))),
                slice_origin: None,
                data: LiteralSource::of_data(b"foo", false),
            })
        );
        assert_reversible!(
            MsgAtt,
            "BODY[HEADER.FIELDS (Foo)] {3}\r\nfoo",
            MsgAtt::Body(MsgAttBody {
                kind: FetchAttBodyKind::Body,
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
                kind: FetchAttBodyKind::Body,
                section: Some(SectionSpec::TopLevel(SectionText::Text(()))),
                slice_origin: None,
                data: LiteralSource::of_data(b"foo", false),
            })
        );
        assert_reversible!(
            MsgAtt,
            "BODY[1.2.MIME] {3}\r\nfoo",
            MsgAtt::Body(MsgAttBody {
                kind: FetchAttBodyKind::Body,
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
                kind: FetchAttBodyKind::Body,
                section: None,
                slice_origin: Some(42),
                data: LiteralSource::of_data(b"foo", false),
            })
        );

        assert_reversible!(
            MsgAtt,
            "BINARY[]<42> ~{3}\r\nf\0o",
            MsgAtt::Body(MsgAttBody {
                kind: FetchAttBodyKind::Binary,
                section: None,
                slice_origin: Some(42),
                data: LiteralSource::of_data(b"f\0o", true),
            })
        );

        assert_reversible!(
            MsgAtt,
            "BINARY.SIZE[] 1234",
            MsgAtt::BinarySize(MsgAttBinarySize {
                section: None,
                size: 1234,
            })
        );
        assert_reversible!(
            MsgAtt,
            "BINARY.SIZE[1] 1234",
            MsgAtt::BinarySize(MsgAttBinarySize {
                section: Some(SectionSpec::Sub(SubSectionSpec {
                    subscripts: vec![1],
                    text: None,
                })),
                size: 1234,
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
                date: NaiveDate::from_ymdx(2020, 7, 4),
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
                date: NaiveDate::from_ymdx(2020, 7, 4),
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
                date: NaiveDate::from_ymdx(2020, 7, 4),
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
                date: NaiveDate::from_ymdx(2020, 7, 4),
            })
        );
        assert_reversible!(
            SearchKey,
            "SENTON \"4-Jul-2020\"",
            SearchKey::Date(DateSearchKey {
                typ: DateSearchKeyType::SentOn,
                date: NaiveDate::from_ymdx(2020, 7, 4),
            })
        );
        assert_reversible!(
            SearchKey,
            "SENTSINCE \"4-Jul-2020\"",
            SearchKey::Date(DateSearchKey {
                typ: DateSearchKeyType::SentSince,
                date: NaiveDate::from_ymdx(2020, 7, 4),
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
                return_opts: None,
                charset: None,
                keys: vec![SearchKey::Larger(42)],
            }
        );
        assert_reversible!(
            SearchCommand,
            "SEARCH LARGER 42 SMALLER 56",
            SearchCommand {
                return_opts: None,
                charset: None,
                keys: vec![SearchKey::Larger(42), SearchKey::Smaller(56)],
            }
        );
        assert_reversible!(
            SearchCommand,
            "SEARCH CHARSET utf-8 LARGER 42",
            SearchCommand {
                return_opts: None,
                charset: ns("utf-8"),
                keys: vec![SearchKey::Larger(42)],
            }
        );

        assert_reversible!(
            SearchCommand,
            "SEARCH MODSEQ 12345678901234567890",
            SearchCommand {
                return_opts: None,
                charset: None,
                keys: vec![SearchKey::Modseq(ModseqSearchKey {
                    ext: None,
                    modseq: 12345678901234567890,
                })],
            }
        );
        assert_reversible!(
            SearchCommand,
            r#"SEARCH MODSEQ "/flags/keyword" all 12345678901234567890"#,
            SearchCommand {
                return_opts: None,
                charset: None,
                keys: vec![SearchKey::Modseq(ModseqSearchKey {
                    ext: Some(ModseqSearchKeyExt {
                        name: s("/flags/keyword"),
                        value: s("all"),
                    }),
                    modseq: 12345678901234567890,
                })],
            }
        );
        assert_reversible!(
            SearchCommand,
            "SEARCH EMAILID Efoo",
            SearchCommand {
                return_opts: None,
                charset: None,
                keys: vec![SearchKey::EmailId(s("Efoo"))],
            }
        );
        assert_reversible!(
            SearchCommand,
            "SEARCH THREADID Efoo",
            SearchCommand {
                return_opts: None,
                charset: None,
                keys: vec![SearchKey::ThreadId(s("Efoo"))],
            }
        );
        assert_reversible!(
            SearchCommand,
            "SEARCH RETURN (MIN MAX) ALL",
            SearchCommand {
                return_opts: Some(vec![
                    SearchReturnOpt::Min,
                    SearchReturnOpt::Max,
                ]),
                charset: None,
                keys: vec![SearchKey::Simple(SimpleSearchKey::All)],
            }
        );
        assert_reversible!(
            SearchCommand,
            "SEARCH RETURN () ALL",
            SearchCommand {
                return_opts: Some(vec![]),
                charset: None,
                keys: vec![SearchKey::Simple(SimpleSearchKey::All)],
            }
        );
    }

    #[test]
    fn mailbox_management_commands() {
        assert_reversible!(
            CreateCommand,
            "CREATE mailbox",
            CreateCommand {
                mailbox: mn("mailbox"),
                special_use: None,
            }
        );
        assert_reversible!(
            true,
            CreateCommand,
            "CREATE \"föö\"",
            CreateCommand {
                mailbox: mn("föö"),
                special_use: None,
            }
        );
        assert_reversible!(
            CreateCommand,
            "CREATE mailbox USE (\\Trash)",
            CreateCommand {
                mailbox: mn("mailbox"),
                special_use: Some(vec![s("\\Trash")]),
            }
        );
        assert_reversible!(
            CreateCommand,
            "CREATE mailbox USE (\\Trash \\Sent)",
            CreateCommand {
                mailbox: mn("mailbox"),
                special_use: Some(vec![s("\\Trash"), s("\\Sent")]),
            }
        );

        assert_reversible!(
            DeleteCommand,
            "DELETE mailbox",
            DeleteCommand {
                mailbox: mn("mailbox"),
            }
        );
        assert_reversible!(
            true,
            DeleteCommand,
            "DELETE \"föö\"",
            DeleteCommand {
                mailbox: mn("föö")
            }
        );
        assert_reversible!(
            ExamineCommand,
            "EXAMINE mailbox",
            ExamineCommand {
                mailbox: mn("mailbox"),
                modifiers: None,
            }
        );
        assert_reversible!(
            true,
            ExamineCommand,
            "EXAMINE \"föö\"",
            ExamineCommand {
                mailbox: mn("föö"),
                modifiers: None,
            }
        );
        assert_reversible!(
            ExamineCommand,
            "EXAMINE mailbox (CONDSTORE)",
            ExamineCommand {
                mailbox: mn("mailbox"),
                modifiers: Some(vec![SelectModifier::Condstore(()),]),
            }
        );
        assert_reversible!(
            RenameCommand,
            "RENAME mailbox dst",
            RenameCommand {
                src: mn("mailbox"),
                dst: mn("dst"),
            }
        );
        assert_reversible!(
            true,
            RenameCommand,
            "RENAME \"föö\" dst",
            RenameCommand {
                src: mn("föö"),
                dst: mn("dst"),
            }
        );
        assert_reversible!(
            SelectCommand,
            "SELECT mailbox",
            SelectCommand {
                mailbox: mn("mailbox"),
                modifiers: None,
            }
        );
        assert_reversible!(
            true,
            SelectCommand,
            "SELECT \"föö\"",
            SelectCommand {
                mailbox: mn("föö"),
                modifiers: None,
            }
        );
        assert_reversible!(
            SelectCommand,
            "SELECT mailbox (CONDSTORE)",
            SelectCommand {
                mailbox: mn("mailbox"),
                modifiers: Some(vec![SelectModifier::Condstore(()),]),
            }
        );
        assert_reversible!(
            SelectCommand,
            "SELECT mailbox (QRESYNC (1234 12345678901234567890))",
            SelectCommand {
                mailbox: mn("mailbox"),
                modifiers: Some(vec![SelectModifier::Qresync(
                    SelectQresyncModifier {
                        uid_validity: 1234,
                        modseq: 12345678901234567890,
                        known_uids: None,
                        seq_match_data: None,
                    }
                ),]),
            }
        );
        assert_reversible!(
            SelectCommand,
            "SELECT mailbox (QRESYNC (1234 12345678901234567890 1:4))",
            SelectCommand {
                mailbox: mn("mailbox"),
                modifiers: Some(vec![SelectModifier::Qresync(
                    SelectQresyncModifier {
                        uid_validity: 1234,
                        modseq: 12345678901234567890,
                        known_uids: Some(s("1:4")),
                        seq_match_data: None,
                    }
                ),]),
            }
        );
        assert_reversible!(
            SelectCommand,
            "SELECT mailbox (QRESYNC (1234 12345678901234567890 (1:2 1,4)))",
            SelectCommand {
                mailbox: mn("mailbox"),
                modifiers: Some(vec![SelectModifier::Qresync(
                    SelectQresyncModifier {
                        uid_validity: 1234,
                        modseq: 12345678901234567890,
                        known_uids: None,
                        seq_match_data: Some(SeqMatchData {
                            seqnums: s("1:2"),
                            uids: s("1,4"),
                        }),
                    }
                ),]),
            }
        );
        assert_reversible!(
            SelectCommand,
            "SELECT mailbox (QRESYNC (1234 12345678901234567890 \
             1:4 (1:2 1,4)))",
            SelectCommand {
                mailbox: mn("mailbox"),
                modifiers: Some(vec![SelectModifier::Qresync(
                    SelectQresyncModifier {
                        uid_validity: 1234,
                        modseq: 12345678901234567890,
                        known_uids: Some(s("1:4")),
                        seq_match_data: Some(SeqMatchData {
                            seqnums: s("1:2"),
                            uids: s("1,4"),
                        }),
                    }
                ),]),
            }
        );
        assert_reversible!(
            StatusCommand,
            "STATUS foo (MESSAGES)",
            StatusCommand {
                mailbox: mn("foo"),
                atts: vec![StatusAtt::Messages],
            }
        );
        assert_reversible!(
            StatusCommand,
            "STATUS foo (\
             MESSAGES RECENT UIDNEXT UIDVALIDITY UNSEEN HIGHESTMODSEQ)",
            StatusCommand {
                mailbox: mn("foo"),
                atts: vec![
                    StatusAtt::Messages,
                    StatusAtt::Recent,
                    StatusAtt::UidNext,
                    StatusAtt::UidValidity,
                    StatusAtt::Unseen,
                    StatusAtt::HighestModseq,
                ],
            }
        );
        assert_reversible!(
            SubscribeCommand,
            "SUBSCRIBE mailbox",
            SubscribeCommand {
                mailbox: mn("mailbox"),
            }
        );
        assert_reversible!(
            true,
            SubscribeCommand,
            "SUBSCRIBE \"föö\"",
            SubscribeCommand {
                mailbox: mn("föö")
            }
        );
        assert_reversible!(
            UnsubscribeCommand,
            "UNSUBSCRIBE mailbox",
            UnsubscribeCommand {
                mailbox: mn("mailbox"),
            }
        );
        assert_reversible!(
            true,
            UnsubscribeCommand,
            "UNSUBSCRIBE \"föö\"",
            UnsubscribeCommand {
                mailbox: mn("föö")
            }
        );
    }

    #[test]
    fn message_management_commands() {
        assert_reversible!(
            CopyCommand,
            "COPY 1:2,3:* foo",
            CopyCommand {
                messages: s("1:2,3:*"),
                dst: mn("foo"),
            }
        );

        assert_reversible!(
            StoreCommand,
            "STORE 1:2,3:* FLAGS (\\Seen)",
            StoreCommand {
                messages: s("1:2,3:*"),
                unchanged_since: None,
                typ: StoreCommandType::Eq,
                silent: false,
                flags: vec![Flag::Seen],
            }
        );
        assert_reversible!(
            StoreCommand,
            "STORE 1 +FLAGS (keyword)",
            StoreCommand {
                messages: s("1"),
                unchanged_since: None,
                typ: StoreCommandType::Plus,
                silent: false,
                flags: vec![Flag::Keyword("keyword".to_owned())],
            }
        );
        assert_reversible!(
            StoreCommand,
            "STORE 1 -FLAGS (\\Flagged \\Deleted)",
            StoreCommand {
                messages: s("1"),
                unchanged_since: None,
                typ: StoreCommandType::Minus,
                silent: false,
                flags: vec![Flag::Flagged, Flag::Deleted],
            }
        );
        assert_reversible!(
            StoreCommand,
            "STORE 1 FLAGS.SILENT (\\Flagged)",
            StoreCommand {
                messages: s("1"),
                unchanged_since: None,
                typ: StoreCommandType::Eq,
                silent: true,
                flags: vec![Flag::Flagged],
            }
        );
        assert_reversible!(
            StoreCommand,
            "STORE 1 FLAGS ()",
            StoreCommand {
                messages: s("1"),
                unchanged_since: None,
                typ: StoreCommandType::Eq,
                silent: false,
                flags: vec![],
            }
        );

        assert_reversible!(
            StoreCommand,
            "STORE 1 (UNCHANGEDSINCE 12345678901234567890) +FLAGS (\\Seen)",
            StoreCommand {
                messages: s("1"),
                unchanged_since: Some(12345678901234567890),
                typ: StoreCommandType::Plus,
                silent: false,
                flags: vec![Flag::Seen],
            }
        );

        assert_equivalent!(
            true,
            StoreCommand,
            "STORE 1 FLAGS.SILENT (\\Flagged)",
            "store 1 flags.silent \\flagged"
        );
        assert_equivalent!(
            true,
            StoreCommand,
            "STORE 1 FLAGS (\\Flagged keyword)",
            "STORE 1 FLAGS \\flagged keyword"
        );
    }

    #[test]
    fn authentication_command_syntax() {
        assert_reversible!(
            AuthenticateCommandStart,
            "A1 AUTHENTICATE plain",
            AuthenticateCommandStart {
                tag: s("A1"),
                auth_type: s("plain"),
                initial_response: None,
            }
        );

        assert_reversible!(
            AuthenticateCommandStart,
            "A1 AUTHENTICATE plain AGF6dXJlAGh1bnRlc+/=",
            AuthenticateCommandStart {
                tag: s("A1"),
                auth_type: s("plain"),
                initial_response: Some(s("AGF6dXJlAGh1bnRlc+/=")),
            }
        );

        assert_reversible!(
            LogInCommand,
            "LOGIN AzureDiamond hunter2",
            LogInCommand {
                userid: s("AzureDiamond"),
                password: s("hunter2"),
            }
        );
        assert_reversible!(
            LogInCommand,
            "LOGIN \"User with Spaces\" {17}\r\nComplexPassword\\\"",
            LogInCommand {
                userid: s("User with Spaces"),
                password: s(r#"ComplexPassword\""#),
            }
        );
    }

    #[test]
    fn command_syntax() {
        assert_reversible!(
            Command,
            "CAPABILITY",
            Command::Simple(SimpleCommand::Capability)
        );
        assert_reversible!(
            Command,
            "LOGOUT",
            Command::Simple(SimpleCommand::LogOut)
        );
        assert_reversible!(
            Command,
            "NOOP",
            Command::Simple(SimpleCommand::Noop)
        );
        assert_reversible!(
            Command,
            "STARTTLS",
            Command::Simple(SimpleCommand::StartTls)
        );
        assert_reversible!(
            Command,
            "CHECK",
            Command::Simple(SimpleCommand::Check)
        );
        assert_reversible!(
            Command,
            "CLOSE",
            Command::Simple(SimpleCommand::Close)
        );
        assert_reversible!(
            Command,
            "EXPUNGE",
            Command::Simple(SimpleCommand::Expunge)
        );
        assert_reversible!(
            Command,
            "XYZZY",
            Command::Simple(SimpleCommand::Xyzzy)
        );

        assert_reversible!(
            Command,
            "CREATE foo",
            Command::Create(CreateCommand {
                mailbox: mn("foo"),
                special_use: None,
            })
        );
        assert_reversible!(
            Command,
            "DELETE foo",
            Command::Delete(DeleteCommand { mailbox: mn("foo") })
        );
        assert_reversible!(
            Command,
            "EXAMINE foo",
            Command::Examine(ExamineCommand {
                mailbox: mn("foo"),
                modifiers: None,
            })
        );
        assert_reversible!(
            Command,
            "LIST \"\" foo",
            Command::List(ListCommand {
                select_opts: None,
                reference: mn(""),
                pattern: MboxOrPat::Single(mn("foo")),
                return_opts: None,
            })
        );
        assert_reversible!(
            Command,
            "LSUB \"\" foo",
            Command::Lsub(LsubCommand {
                reference: mn(""),
                pattern: mn("foo"),
            })
        );
        assert_reversible!(
            Command,
            "RENAME foo bar",
            Command::Rename(RenameCommand {
                src: mn("foo"),
                dst: mn("bar"),
            })
        );
        assert_reversible!(
            Command,
            "SELECT foo",
            Command::Select(SelectCommand {
                mailbox: mn("foo"),
                modifiers: None,
            })
        );
        assert_reversible!(
            Command,
            "STATUS foo (RECENT)",
            Command::Status(StatusCommand {
                mailbox: mn("foo"),
                atts: vec![StatusAtt::Recent],
            })
        );
        assert_reversible!(
            Command,
            "SUBSCRIBE foo",
            Command::Subscribe(SubscribeCommand { mailbox: mn("foo") })
        );
        assert_reversible!(
            Command,
            "UNSUBSCRIBE foo",
            Command::Unsubscribe(UnsubscribeCommand { mailbox: mn("foo") })
        );
        assert_reversible!(
            Command,
            "LOGIN AzureDiamond hunter2",
            Command::LogIn(LogInCommand {
                userid: s("AzureDiamond"),
                password: s("hunter2"),
            })
        );
        assert_reversible!(
            Command,
            "COPY 1 dst",
            Command::Copy(CopyCommand {
                messages: s("1"),
                dst: mn("dst"),
            })
        );
        assert_reversible!(
            Command,
            "FETCH 1 FULL",
            Command::Fetch(FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Full(()),
                modifiers: None,
            })
        );
        assert_reversible!(
            Command,
            "STORE 1 FLAGS ()",
            Command::Store(StoreCommand {
                messages: s("1"),
                unchanged_since: None,
                typ: StoreCommandType::Eq,
                silent: false,
                flags: vec![],
            })
        );
        assert_reversible!(
            Command,
            "SEARCH UNSEEN",
            Command::Search(SearchCommand {
                return_opts: None,
                charset: None,
                keys: vec![SearchKey::Simple(SimpleSearchKey::Unseen)],
            })
        );

        assert_reversible!(
            Command,
            "XVANQUISH 1:*",
            Command::XVanquish(s("1:*"))
        );

        assert_reversible!(
            Command,
            "UID COPY 1 dst",
            Command::Uid(UidCommand::Copy(CopyCommand {
                messages: s("1"),
                dst: mn("dst"),
            }))
        );
        assert_reversible!(
            Command,
            "UID FETCH 1 FULL",
            Command::Uid(UidCommand::Fetch(FetchCommand {
                messages: s("1"),
                target: FetchCommandTarget::Full(()),
                modifiers: None,
            }))
        );
        assert_reversible!(
            Command,
            "UID SEARCH UNSEEN",
            Command::Uid(UidCommand::Search(SearchCommand {
                return_opts: None,
                charset: None,
                keys: vec![SearchKey::Simple(SimpleSearchKey::Unseen)],
            }))
        );
        assert_reversible!(
            Command,
            "UID STORE 1 FLAGS ()",
            Command::Uid(UidCommand::Store(StoreCommand {
                messages: s("1"),
                unchanged_since: None,
                typ: StoreCommandType::Eq,
                silent: false,
                flags: vec![],
            }))
        );
        assert_reversible!(
            Command,
            "UID EXPUNGE 1:*",
            Command::Uid(UidCommand::Expunge(s("1:*")))
        );
    }

    #[test]
    fn command_line_syntax() {
        assert_reversible!(
            CommandLine,
            "A0001 NOOP",
            CommandLine {
                tag: s("A0001"),
                cmd: Command::Simple(SimpleCommand::Noop),
            }
        );
        assert_reversible!(
            CommandLine,
            "UID COPY 1 dst",
            CommandLine {
                tag: s("UID"),
                cmd: Command::Copy(CopyCommand {
                    messages: s("1"),
                    dst: mn("dst"),
                }),
            }
        );
    }

    #[test]
    fn response_line_syntax() {
        assert_reversible!(
            ResponseLine,
            "* OK Hello World",
            ResponseLine {
                tag: None,
                response: Response::Cond(CondResponse {
                    cond: RespCondType::Ok,
                    code: None,
                    quip: ns("Hello World"),
                }),
            }
        );
        assert_reversible!(
            ResponseLine,
            "42 BAD command or file name",
            ResponseLine {
                tag: ns("42"),
                response: Response::Cond(CondResponse {
                    cond: RespCondType::Bad,
                    code: None,
                    quip: ns("command or file name"),
                }),
            }
        );
        assert_reversible!(
            ResponseLine,
            "* BYE BYE",
            ResponseLine {
                tag: None,
                response: Response::Cond(CondResponse {
                    cond: RespCondType::Bye,
                    code: None,
                    quip: ns("BYE"),
                }),
            }
        );
        assert_reversible!(
            ResponseLine,
            "* NO !@$#",
            ResponseLine {
                tag: None,
                response: Response::Cond(CondResponse {
                    cond: RespCondType::No,
                    code: None,
                    quip: ns("!@$#"),
                }),
            }
        );

        assert_reversible!(
            ResponseLine,
            "* OK [ALERT] Show message to user",
            ResponseLine {
                tag: None,
                response: Response::Cond(CondResponse {
                    cond: RespCondType::Ok,
                    code: Some(RespTextCode::Alert(())),
                    quip: ns("Show message to user"),
                }),
            }
        );
        assert_reversible!(
            ResponseLine,
            "* NO [BADCHARSET (us-ascii utf-8)] K",
            ResponseLine {
                tag: None,
                response: Response::Cond(CondResponse {
                    cond: RespCondType::No,
                    code: Some(RespTextCode::BadCharset(vec![
                        s("us-ascii"),
                        s("utf-8")
                    ])),
                    quip: None,
                }),
            }
        );
        assert_reversible!(
            ResponseLine,
            "* OK [CAPABILITY IMAP4rev1 XYZZY] K",
            ResponseLine {
                tag: None,
                response: Response::Cond(CondResponse {
                    cond: RespCondType::Ok,
                    code: Some(RespTextCode::Capability(CapabilityData {
                        capabilities: vec![s("IMAP4rev1"), s("XYZZY")],
                    })),
                    quip: None,
                }),
            }
        );
        assert_reversible!(
            ResponseLine,
            "* BAD [PARSE] K",
            ResponseLine {
                tag: None,
                response: Response::Cond(CondResponse {
                    cond: RespCondType::Bad,
                    code: Some(RespTextCode::Parse(())),
                    quip: None,
                }),
            }
        );
        assert_reversible!(
            ResponseLine,
            "* OK [PERMANENTFLAGS (\\Flagged keyword \\*)] K",
            ResponseLine {
                tag: None,
                response: Response::Cond(CondResponse {
                    cond: RespCondType::Ok,
                    code: Some(RespTextCode::PermanentFlags(vec![
                        Flag::Flagged,
                        Flag::Keyword("keyword".to_owned())
                    ])),
                    quip: None,
                }),
            }
        );
        assert_reversible!(
            ResponseLine,
            "* OK [READ-ONLY] K",
            ResponseLine {
                tag: None,
                response: Response::Cond(CondResponse {
                    cond: RespCondType::Ok,
                    code: Some(RespTextCode::ReadOnly(())),
                    quip: None,
                }),
            }
        );
        assert_reversible!(
            ResponseLine,
            "* OK [READ-WRITE] K",
            ResponseLine {
                tag: None,
                response: Response::Cond(CondResponse {
                    cond: RespCondType::Ok,
                    code: Some(RespTextCode::ReadWrite(())),
                    quip: None,
                }),
            }
        );
        assert_reversible!(
            ResponseLine,
            "* NO [TRYCREATE] K",
            ResponseLine {
                tag: None,
                response: Response::Cond(CondResponse {
                    cond: RespCondType::No,
                    code: Some(RespTextCode::TryCreate(())),
                    quip: None,
                }),
            }
        );
        assert_reversible!(
            ResponseLine,
            "* OK [UIDNEXT 1234] K",
            ResponseLine {
                tag: None,
                response: Response::Cond(CondResponse {
                    cond: RespCondType::Ok,
                    code: Some(RespTextCode::UidNext(1234)),
                    quip: None,
                })
            }
        );
        assert_reversible!(
            ResponseLine,
            "* OK [UIDVALIDITY 1234] K",
            ResponseLine {
                tag: None,
                response: Response::Cond(CondResponse {
                    cond: RespCondType::Ok,
                    code: Some(RespTextCode::UidValidity(1234)),
                    quip: None,
                }),
            }
        );
        assert_reversible!(
            ResponseLine,
            "* OK [UNSEEN 42] K",
            ResponseLine {
                tag: None,
                response: Response::Cond(CondResponse {
                    cond: RespCondType::Ok,
                    code: Some(RespTextCode::Unseen(42)),
                    quip: None,
                }),
            }
        );
        assert_reversible!(
            ResponseLine,
            "* OK [MAILBOXID (MINBOX)] K",
            ResponseLine {
                tag: None,
                response: Response::Cond(CondResponse {
                    cond: RespCondType::Ok,
                    code: Some(RespTextCode::MailboxId(s("MINBOX"))),
                    quip: None,
                }),
            }
        );

        assert_reversible!(
            ResponseLine,
            "* FLAGS (\\Flagged keyword)",
            ResponseLine {
                tag: None,
                response: Response::Flags(vec![
                    Flag::Flagged,
                    Flag::Keyword("keyword".to_owned())
                ]),
            }
        );
        assert_reversible!(
            ResponseLine,
            "* LIST () \"/\" INBOX",
            ResponseLine {
                tag: None,
                response: Response::List(MailboxList {
                    flags: vec![],
                    name: mn("INBOX"),
                    child_info: None,
                }),
            }
        );
        assert_reversible!(
            ResponseLine,
            "* LIST (\\Marked \\Subscribed) \"/\" INBOX",
            ResponseLine {
                tag: None,
                response: Response::List(MailboxList {
                    flags: vec![s("\\Marked"), s("\\Subscribed")],
                    name: mn("INBOX"),
                    child_info: None,
                }),
            }
        );
        assert_reversible!(
            ResponseLine,
            "* LSUB (\\Noselect) \"/\" \"foo bar\"",
            ResponseLine {
                tag: None,
                response: Response::Lsub(MailboxList {
                    flags: vec![s("\\Noselect")],
                    name: mn("foo bar"),
                    child_info: None,
                }),
            }
        );
        assert_reversible!(
            ResponseLine,
            "* SEARCH",
            ResponseLine {
                tag: None,
                response: Response::Search(SearchResponse {
                    hits: vec![],
                    max_modseq: None,
                }),
            }
        );
        assert_reversible!(
            ResponseLine,
            "* SEARCH 42",
            ResponseLine {
                tag: None,
                response: Response::Search(SearchResponse {
                    hits: vec![42],
                    max_modseq: None,
                }),
            }
        );
        assert_reversible!(
            ResponseLine,
            "* SEARCH 42 56",
            ResponseLine {
                tag: None,
                response: Response::Search(SearchResponse {
                    hits: vec![42, 56],
                    max_modseq: None,
                }),
            }
        );
        assert_reversible!(
            ResponseLine,
            "* SEARCH 42 (MODSEQ 12345678901234567890)",
            ResponseLine {
                tag: None,
                response: Response::Search(SearchResponse {
                    hits: vec![42],
                    max_modseq: Some(12345678901234567890),
                }),
            }
        );
        assert_reversible!(
            ResponseLine,
            r#"* ESEARCH (TAG "42") MIN 1 MAX 42 MODSEQ 12345678901234567890"#,
            ResponseLine {
                tag: None,
                response: Response::Esearch(EsearchResponse {
                    tag: s("42"),
                    uid: false,
                    min: Some(1),
                    max: Some(42),
                    all: None,
                    count: None,
                    modseq: Some(12345678901234567890),
                }),
            }
        );
        assert_reversible!(
            ResponseLine,
            r#"* ESEARCH (TAG "42") UID ALL 2:4 COUNT 42"#,
            ResponseLine {
                tag: None,
                response: Response::Esearch(EsearchResponse {
                    tag: s("42"),
                    uid: true,
                    min: None,
                    max: None,
                    all: ns("2:4"),
                    count: Some(42),
                    modseq: None,
                }),
            }
        );
        assert_reversible!(
            ResponseLine,
            "* 42 EXISTS",
            ResponseLine {
                tag: None,
                response: Response::Exists(42),
            }
        );
        assert_reversible!(
            ResponseLine,
            "* 42 RECENT",
            ResponseLine {
                tag: None,
                response: Response::Recent(42),
            }
        );
        assert_reversible!(
            ResponseLine,
            "* 42 EXPUNGE",
            ResponseLine {
                tag: None,
                response: Response::Expunge(42),
            }
        );
        assert_reversible!(
            ResponseLine,
            "* 4 FETCH (UID 1)",
            ResponseLine {
                tag: None,
                response: Response::Fetch(FetchResponse {
                    seqnum: 4,
                    atts: MsgAtts {
                        atts: vec![MsgAtt::Uid(1)],
                    },
                }),
            }
        );
        assert_reversible!(
            ResponseLine,
            "* STATUS foo (RECENT 1)",
            ResponseLine {
                tag: None,
                response: Response::Status(StatusResponse {
                    mailbox: mn("foo"),
                    atts: vec![StatusResponseAtt::Recent(1)]
                }),
            }
        );
        assert_reversible!(
            ResponseLine,
            "* STATUS foo (MESSAGES 1 RECENT 2 UIDNEXT 3 UIDVALIDITY 4 \
             UNSEEN 5 HIGHESTMODSEQ 12345678901234567890 \
             MAILBOXID (MINBOX))",
            ResponseLine {
                tag: None,
                response: Response::Status(StatusResponse {
                    mailbox: mn("foo"),
                    atts: vec![
                        StatusResponseAtt::Messages(1),
                        StatusResponseAtt::Recent(2),
                        StatusResponseAtt::UidNext(3),
                        StatusResponseAtt::UidValidity(4),
                        StatusResponseAtt::Unseen(5),
                        StatusResponseAtt::HighestModseq(12345678901234567890),
                        StatusResponseAtt::MailboxId(s("MINBOX")),
                    ],
                }),
            }
        );
        assert_reversible!(
            ResponseLine,
            "* CAPABILITY IMAP4rev1 XYZZY",
            ResponseLine {
                tag: None,
                response: Response::Capability(CapabilityData {
                    capabilities: vec![s("IMAP4rev1"), s("XYZZY")],
                }),
            }
        );

        assert_reversible!(
            ResponseLine,
            "* VANISHED 1:4",
            ResponseLine {
                tag: None,
                response: Response::Vanished(VanishedResponse {
                    earlier: false,
                    uids: s("1:4"),
                }),
            }
        );
        assert_reversible!(
            ResponseLine,
            "* VANISHED (EARLIER) 1:4",
            ResponseLine {
                tag: None,
                response: Response::Vanished(VanishedResponse {
                    earlier: true,
                    uids: s("1:4"),
                }),
            }
        );
    }

    #[test]
    fn append_fragment_syntax() {
        assert_reversible!(
            AppendCommandStart,
            "1 APPEND dst ",
            AppendCommandStart {
                tag: s("1"),
                mailbox: mn("dst"),
                first_fragment: AppendFragment {
                    flags: None,
                    internal_date: None,
                    utf8: false,
                },
            }
        );
        assert_reversible!(
            AppendCommandStart,
            "1 APPEND dst UTF8 (",
            AppendCommandStart {
                tag: s("1"),
                mailbox: mn("dst"),
                first_fragment: AppendFragment {
                    flags: None,
                    internal_date: None,
                    utf8: true,
                },
            }
        );
        assert_reversible!(
            AppendCommandStart,
            "1 APPEND \"foo bar\" () ",
            AppendCommandStart {
                tag: s("1"),
                mailbox: mn("foo bar"),
                first_fragment: AppendFragment {
                    flags: Some(vec![]),
                    internal_date: None,
                    utf8: false,
                },
            }
        );
        assert_reversible!(
            AppendCommandStart,
            "1 APPEND dst (\\Deleted) ",
            AppendCommandStart {
                tag: s("1"),
                mailbox: mn("dst"),
                first_fragment: AppendFragment {
                    flags: Some(vec![Flag::Deleted]),
                    internal_date: None,
                    utf8: false,
                },
            }
        );
        assert_reversible!(
            AppendCommandStart,
            "1 APPEND dst (\\Deleted keyword) ",
            AppendCommandStart {
                tag: s("1"),
                mailbox: mn("dst"),
                first_fragment: AppendFragment {
                    flags: Some(vec![
                        Flag::Deleted,
                        Flag::Keyword("keyword".to_owned())
                    ]),
                    internal_date: None,
                    utf8: false,
                },
            }
        );
        assert_reversible!(
            AppendCommandStart,
            "1 APPEND dst \" 4-Jul-2020 16:31:00 +0100\" ",
            AppendCommandStart {
                tag: s("1"),
                mailbox: mn("dst"),
                first_fragment: AppendFragment {
                    flags: None,
                    internal_date: Some(
                        FixedOffset::eastx(3600)
                            .ymd_hmsx(2020, 7, 4, 16, 31, 0),
                    ),
                    utf8: false,
                }
            }
        );
        assert_reversible!(
            AppendCommandStart,
            "1 APPEND dst (\\Deleted) \" 4-Jul-2020 16:31:00 +0100\" ",
            AppendCommandStart {
                tag: s("1"),
                mailbox: mn("dst"),
                first_fragment: AppendFragment {
                    flags: Some(vec![Flag::Deleted]),
                    internal_date: Some(
                        FixedOffset::eastx(3600)
                            .ymd_hmsx(2020, 7, 4, 16, 31, 0)
                    ),
                    utf8: false,
                }
            }
        );

        assert_equivalent!(
            false,
            AppendCommandStart,
            r#"483.10 APPEND INBOX " 2-Feb-2003 18:06:48 +0000" "#,
            r#"483.10 APPEND "INBOX" "02-Feb-2003 18:06:48 +0000" "#
        );
    }

    #[test]
    fn misc_equivalencies() {
        // Strings -- backslash escapes are handled properly, empty literals
        // are understood, LITERAL+ syntax is understood.
        assert_equivalent!(
            true,
            LsubCommand,
            "LSUB \"\" {8}\r\nfoo\"\\bar",
            "lsub {0}\r\n \"foo\\\"\\\\bar\"",
            "lsub \"\" {8+}\r\nfoo\"\\bar"
        );
        // Dates --- months are case-insensitive, string and atom syntax
        // understood, 0-padding allowed.
        assert_equivalent!(
            true,
            DateSearchKey,
            "ON \"9-Jul-2020\"",
            "on 9-jul-2020",
            "on 09-jUl-2020",
            "on \"09-Jul-2020\""
        );
        // Datetimes --- months are case-insensitive, 0 padding allowed instead
        // of space padding.
        assert_equivalent!(
            true,
            MsgAtt,
            "INTERNALDATE \" 9-Jul-2020 01:09:00 +0100\"",
            "internaldate \"09-jUL-2020 01:09:00 +0100\""
        );
    }
}
