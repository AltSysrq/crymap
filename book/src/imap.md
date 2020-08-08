# IMAP Characteristics

This section is targeted at client developers or those with an interest in the
lower-level IMAP details.

## Conformance

Crymap fully conforms to the IMAP4rev1 (RFC 3501) standard and has provisional
conformance to the upcoming IMAP4rev2 standard (as of the 2020-07-29 draft). It
also conforms to a number of extensions detailed in later sections.

Crymap passes the full [Dovecot imaptest compliance
suite](https://imapwiki.org/ImapTest) excepting tests for extensions that
Crymap does not implement.

Crymap was developed with the following priorities:

1. Don't corrupt the user's mail. (The "prime directive".)
2. Be secure.
3. Conform to standards.
4. Be reasonably performant and light-weight.

In spite of the earlier paragraphs, there are cases where (1) and (3) come into
conflict. Usually this is a result of a specification assuming all email
messages are well-formed or pre-dating another specification change that makes
compliance impossible without violating the prime directive, but there are also
some issues with self-contradiction. These will all be discussed in individual
sections where relevant.

Notwithstanding the few exceptions discussed, Crymap's IMAP implementation
conforms to the following standards:

- RFC 2045 MIME Extensions: Format of Internet Message Bodies
- RFC 2046 MIME Extensions: Media types
- RFC 2047 MIME Extensions: Message Header Extensions for Non-ASCII Text
- RFC 2157 UTF-7
- RFC 2177 (IDLE)
- RFC 2183 The Content-Disposition Header Field
- RFC 2231 MIME Parameter Value and Encoded Word Extensions: Character Sets, Languages, and Continuations
- RFC 2342 (NAMESPACE)
- RFC 2557 (Content-Location header field)
- RFC 2595 (PLAIN authentication)
- RFC 2971 (ID)
- RFC 3066 Tags for the Identification of Languages
- RFC 3282 Content Language Headers
- RFC 3348 (CHILDREN)
- RFC 3501 (IMAP4rev1)
- RFC 3502 (MULTIAPPEND)
- RFC 3516 (BINARY)
- RFC 3691 (UNSELECT)
- RFC 4315 (UIDPLUS)
- RFC 4731 (ESEARCH)
- RFC 4959 (SASL-IR)
- RFC 4978 (COMPRESS=DEFLATE)
- RFC 5161 (ENABLE)
- RFC 5182 (SEARCHRES)
- RFC 5253 (LIST-EXTENDED)
- RFC 5322 (Internet Message Format)
- RFC 5530 IMAP Response Codes
- RFC 5819 (LIST-STATUS)
- RFC 5918 Unicode Format for Network Interchange
- RFC 6154 (CREATE-SPECIAL-USE and SPECIAL-USE)
- RFC 6532 Internationalized Email Headers
- RFC 6851 (MOVE)
- RFC 6855 (UTF8=ACCEPT)
- RFC 7162 (CONDSTORE and QRESYNC)
- RFC 7888 (LITERAL+)
- RFC 8438 (STATUS=SIZE)
- RFC 8457 IMAP "$Important" Keyword and "\Important" Special-Use Attribute
- RFC 8474 (OBJECTID)

## Unicode support

Crymap is inherently a Unicode-aware, UTF-8-based application. All data which
is returned to the client in a structured way (i.e., not as a raw byte stream)
is internally managed as UTF-8.

If non-ASCII strings would be sent to a client that has not enabled UTF-8
support, one of two approaches is taken right before the data is put onto the
wire, depending on the field:

- The whole field may be put into RFC 2047 "encoded word" form, using
  base64-encoded UTF-8. Note that this means that returned "encoded words" are
  rarely in exactly the same form as they are in the original message, though
  the content remains the same.

- Non-ASCII characters may be replaced by 'X'. This is only done for fields
  that do not allow the previous strategy.

RFC 2184 is not implemented because it is impossible to implement its IMAP4
requirement at the same time as conforming to IMAP4rev1. Specifically, RFC 2184
would have the server decode encoded non-ASCII text in certain header
parameters, but IMAP4rev1 does not allow these fields to contain non-ASCII
content and the fields also may not contain encoded words. Instead, Crymap
assumes the client will be able to deal with the parameters itself. This is
likely to be a safe assumption, since this has always been an optional feature
of IMAP servers, so clients need to be prepared to do it themselves either way.

Search uses Unicode "simple" case folding.

## Limits

The maximum message size for `APPEND` is hard-wired to 64MB.

Batch insertions (through `COPY`, `MOVE`, or `APPEND`) are limited to 65536
messages.

Any operation that involves parsing message content will not process more than
20 levels of multipart or `message/rfc822` nesting, nor will it process more
than 1000 different body parts.

Message header lines in excess of 64kB are not processed.

Search operations will consider up to 128kB of text. Non-text body parts are
ignored for search.

A mailbox can have up to 2'305'843'008 message IDs allocated. Note however that
inserting multiple messages into a mailbox at once can use up to 128 times as
many IDs as the number of messages actually inserted. Up to 3'999'999'999
change transactions can be performed on a mailbox. If either of these limits
are reached, the mailbox will be "full" and further operations will fail. (Note
that Crymap has not actually been tested in this condition.)

## Mailboxes

All mailboxes other than `INBOX` may have children. Nesting depth is dependent
on the host operating system's maximum path length.

Mailbox names may not contain `%`, `*`, `\`, `/`, control characters or one of
a few Unicode control characters, and may not begin with `.` or `#`.

Mailbox names other than `INBOX` are case-sensitive. `INBOX` is always
upper-case.

The path delimiter is `/`. Making a mailbox path "absolute" by prefixing it
with a `/` has no effect. Duplicate `/` characters in a name are ignored.

Non-normalised MUTF7 is accepted in mailbox names. Mailbox names are always
returned in normalised MUTF7. MUTF7 is not returned on output nor transformed
on input when the client has enabled UTF-8 support.

The `\Marked` and `\Unmarked` attributes are not used.

If a mailbox is deleted or renamed while a session has it open, the session
will be terminated as soon as this occurrence is discovered.

When an account is created, the following mailboxes are made, with the shown
special-use attributes.

| Mailbox | Special-Use |
|---------|-------------|
| `INBOX` |             |
| Archive | `\Archive`  |
| Drafts  | `\Drafts`   |
| Sent    | `\Sent`     |
| Spam    | `\Junk`     |
| Trash   | `\Trash`    |

## Messages

Crymap tolerates and preserves messages with arbitrary binary content.

Clients in sessions that have not yet observed the expungement of a message can
continue to access it for 24hr after the expungement.

If a message contains 8-bit content in the headers and the client requests the
raw headers, Crymap will return that 8-bit content verbatim even if the client
has not enabled UTF-8 support. If a message contains binary content and the
client requests that binary content, even without using the `BINARY` extension,
Crymap will return the binary content as-is because the IMAP specification
gives no other way to return the data without corrupting it. Both of these
issues are described in more detail in the descriptions of the `UTF8=ACCEPT`
and `BINARY` extensions.

If messages contain non-DOS line endings, the line endings are returned as-is,
so as not to corrupt anything. Crymap understands both UNIX and DOS line
endings in messages. This is expected to be a non-issue, given that GMail
actually served messages exclusively with UNIX line endings before anyone
noticed. (Note though that when acting as a UNIX MDA, Crymap _does_ convert
line endings as they come in. This paragraph applies to messages that come in
through IMAP or LMTP.)

Unsolicited `FETCH` responses always include `UID` and `FLAGS`. If `CONDSTORE`
has been enabled, they include `MODSEQ` as well.

## Flags

All "system flags" are supported and permanent. `\Recent` is fully implemented
and fully atomic. Arbitrary keywords can be created without limit.

## Authentication

`LOGIN` and `AUTHENTICATE PLAIN` are both supported and have the same effect.
`AUTHENTICATE` does not allow the authorisation and authentication usernames to
differ.

## Extensions

### RFC 8457

Crymap supports the `$Important` keyword and the `\Important` special-use
attribute.

### RFC 5530

Extended status codes are used everywhere they make sense.

### APPENDLIMIT

Crymap uses a fixed `APPENDLIMIT` value which is reported in the capabilities
list.

### BINARY

Binary literals are understood, but are not handled any differently than
non-binary literals. (That is, Crymap accepts and properly handles binary
content in all contexts.)

If a client requests a `BINARY` body section, binary literal syntax is used iff
the response payload contains a NUL byte.

The `BINARY` fetch feature is treated as orthogonal to the rest of the fetch
options, and Crymap currently allows combinations not allowed by the standard.

The `BINARY` extension presents an odd conundrum: An IMAP4rev1 server is
required to report the actual content transfer encoding of a binary part
(`binary`), and is required to return body parts in their original transfer
encoding when queried without `BINARY`, but at the same time is forbidden from
returning binary data. In these cases, Crymap returns the binary data anyway,
since doing so is a lesser evil than corrupting the data itself.

Crymap does not perform any encoding changes of messages appended using binary
literals.

The standard insinuates that if the client requests content transfer decoding
of a body part, and the server finds that the body part does not use DOS
newlines, it should convert the newlines to DOS newlines. Crymap does not do
this, since that constitutes data corruption.

### CHILDREN

If a client makes a non-extended `LIST` command, `\HasChildren` and
`\HasNoChildren` mailbox attributes are returned implicitly.

### COMPRESS=DEFLATE

Deflate-based compression may be enabled at any time.

Crymap is not aware of whether TLS itself is using compression and so will not
reject enabling compression even if TLS compression is active.

### CONDSTORE

This extension is fully implemented.

Atomic updates are performed with respect to all flags on a message and not
just the flags being modified, since this is both simpler and more useful. (And
seems like what clients expect — there has been some talk of using conditional
store to maintain tri-state flags like Junk/NonJunk/(nothing) properly.)

Modseqs are 63-bit integers as required by the later QRESYNC extension.

Internally, Modseqs are a 2-element vector clock pairing the maximum known UID
with a monotonic "Change ID" (CID) with additional bookkeeping to maintain the
extension's strict ordering requirements. This can be seen in returned Modseq
values as the UID multiplied by 4 billion plus the CID.

If multiple messages are changed at once, they all receive the same Modseq.

Expunging a message increments the highest Modseq value.

Crymap does not return `HIGHESTMODSEQ` response codes until `CONDSTORE` is
enabled.

### CREATE-SPECIAL-USE

The following special-use attributes are allowed: `\Archive`, `\Drafts`,
`\Flagged`, `\Junk`, `\Sent`, `\Trash`, `\Important`. `\All` is not allowed
since Crymap does not support an "all mail" view.

At most one special-use can be given to a mailbox. Crymap does not take action
on special-use attributes except to return them, and does not prevent creating
multiple mailboxes with the same special use.

### ENABLE

This extension is fully implemented.

### ESEARCH

This extension is fully implemented.

Crymap does not attempt to optimise searches for `MIN` or `MAX` alone.

### ID

This extension is fully implemented.

The client-submitted identifying information is written into the server logs.

The `[identification]` section of the server configuration can provide
additional attributes to be returned here. By default, Crymap returns `name`
and `version`.

### IDLE

This extension is fully implemented.

Notifications about changes are typically delivered within a millisecond of
when they occurred (modulo client-server latency of course). Message creation
and expungement and flag operations are all monitored.

Crymap does not strictly validate that the idle is terminated with "DONE".

### LIST-EXTENDED

This extension is fully implemented.

### LIST-STATUS

This extension is fully implemented, but only because IMAP4rev2 requires it. No
optimisations are made over simply making separate `STATUS` calls.

### LITERAL+

This extension is fully implemented.

### MOVE

This extension is fully implemented.

Moves occur as three separate atomic steps:

- Messages are added to the destination.
- Flags are set on the destination messages.
- Messages are removed from the source.

### MULTIAPPEND

This extension is fully implemented.

Setting flags on the messages occurs in a separate step message insertion.
(This is allowed by the spec since even setting the flags at all is only a
SHOULD.)

### NAMESPACE

Crymap does not have namespaces. The extension is implemented in that it
returns a canned "no namespaces" response.

### OBJECTID

This extension is fully implemented except for the optional `THREADID`
attribute, since Crymap does not support message threads.

Mailbox IDs always begin with `M`, except for `INBOX`s mailbox ID, which always
begins with `I`. Email IDs always begin with `E`.

All mailboxes support these attributes.

### QRESYNC

This extension is fully implemented.

Crymap remembers the most recent 1024 expunge events.

### SASL-IR

This extension is fully implemented.

### SEARCHRES

This extension is fully implemented.

### SPECIAL-USE

This extension is fully implemented.

See [CREATE-SPECIAL-USE](#create-special-use) for a reference on what
attributes are supported.

### STATUS=SIZE

This extension is fully implemented to the letter of the standard and not at
all to the spirit. It is only implemented because IMAP4rev2 requires it.

Returning the size of a mailbox sounds like a useful operation. However, the
standard does not permit returning the _actual_ size. Instead, it requires the
returned size to be greater than or equal to the sum of the sizes of the
messages as they would be fetched in full.

Since determining the size of a message requires decrypting it, Crymap has no
way to do this in a way that even resembles efficiency. Instead, it takes
advantage of the fact that the returned size need only be an _upper bound_ and
determines the "size" by simply multiplying the message count by 4GB.

### UIDPLUS

This extension is fully supported.

No mailboxes have the `UIDNOTSTICKY` attribute.

### UNSELECT

This extension is fully implemented.

### UTF8=ACCEPT

The useful part of this extension is implemented. Clients using the extension
cannot observe aspects (arguably) unimplemented. To clients not using the
extension, Crymap is the same as any IMAP implementation that does not support
this extension.

Once a client enables this extension, mailbox names are returned and accepted
in UTF-8, and MUTF7 interpretation no longer occurs. Envelope and body
structure data is returned in UTF-8, with all encoded words decoded.

The "UTF-8 literals" added by this extension are handled no differently than
normal literals. The standard suggests that the server should do something to
"downgrade" UTF-8 messages for the sake of clients not using this extension.
Crymap does not do this, since it would violate the prime directive, and is
also not useful since nearly all clients are already prepared to encounter
8-bit characters where they are not formally allowed by the older 7-bit
standard.

The standard requires that non-UTF8 literals containing 8-bit characters in the
message headers are rejected. Crymap also does not do this, since it is
actively harmful, leaving users without the ability to copy their existing
messages into Crymap, and as mentioned in the previous paragraph, clients are
able to deal with such messages anyway.

### XCRY

Crymap-specific extension. This entails several commands:

#### XCRY PURGE

No arguments.

All expunged messages in the selected mailbox are removed from the host
filesystem immediately, making them inaccessible to concurrent sessions that
have not yet observed the expungement.

This is mainly used as part of Crymap's internal test suite.

#### XCRY GET-USER-CONFIG

No arguments.

Retrieves the current user configuration.

Response:

```text
* XCRY USER-CONFIG (capabilities...)
  internal-key-pattern
  external-key-pattern
  password-changed-datetime
  [astring astring...]
```

`capabilities` provides a list of valid tokens that can be passed to `XCRY
SET-USER-CONFIG`.

#### XCRY SET-USER-CONFIG

Arguments: `key value [key value [...]]`

Updates the given key-value pairs in the configuration. Using this to
"configure" `PASSWORD` is also how password changes are done.

Response:

```text
* XCRY BACKUP-FILE "filename"
```

The returned filename should be shown to the user to let them know what file to
use to undo the change.

### XLIST

Implements the `XLIST` command, which was developed for GMail before
`LIST-EXTENDED` was standardised. Some clients may still use this instead of
the extended `LIST` command.

### XVANQUISH

Crymap-specific extension.

Adds the `XVANQUISH` command. This command takes one argument, a UID sequence
set. The given messages are immediately expunged without having to go through
the `\Deleted` dance first.

This is not under the `XCRY` umbrella since it could be useful to others.

### XYZZY

This is obviously a very important extension for GMail compatibility.

## Miscellaneous

Crymap always returns `CAPABILITY` response codes to the `OK` used as a
greeting upon connection and after successful authentication.

Crymap accepts UNIX line endings in IMAP, but always outputs DOS line endings.

## Extensions not implemented

Extensions in this list were deliberately excluded because they were not
useful or harmful.

### ACL, LIST-MYRIGHTS, RIGHTS=

Since users are strictly bound to their own mailboxes, permissions don't make
much sense for Crymap.

### CATENATE, URL-PARTIAL, URLAUTH, URLAUTH=BINARY

Not implemented due to higher complexity with low benefit.

URLAUTH is feasible to implement, as it would work by encoding the session key
of the message in question in the auth string. This would probably be
sufficient to make it work with BURL. However, it's not a feature that the
author would get use of any time soon.

### CONVERT

Insanity.

It also looks like, quite possibly, literally nobody has ever implemented this
for server _or_ client.

### I18NLEVEL=

Requires use of an out-dated, non-standard algorithm for Unicode collation and
folding.

### SORT, ESORT, THREAD

These concerns are much better handled by the client. Now that QRESYNC exists,
clients can cheaply keep envelope data synchronised and not only do these
operations themselves, but do them using up-to-date, standardised collation
algorithms which take into account the user's locale.

Secondarily, these add a decent amount of memory overhead and aren't something
the author would ever get use of.

### UNAUTHENTICATE

Incompatible with the way Crymap chroots into the user data directory in
traditional UNIX-style deployments.

### SAVEDATE

Incompatible with the way Crymap stores message data.

### WITHIN

Should Crymap ever implement the CONTEXT extensions, this extension has a
pathological interaction with them, and itself offers very little benefit.

### QUOTA

Besides being useless to the author, it's also unclear how this should really
work, since mail delivery does not have access to the information it would need
to maintain the quota.

