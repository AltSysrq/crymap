# IMAP Characteristics

This section is targeted at client developers or those with an interest in the
lower-level IMAP details.

## Conformance

Crymap fully conforms to the IMAP4rev1 (RFC 3501) and IMAP4rev2 (RFC 9051)
standards. It also conforms to a number of extensions detailed in later
sections.

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

- [RFC 2045](https://datatracker.ietf.org/doc/html/rfc2045.html) MIME Extensions: Format of Internet Message Bodies
- [RFC 2046](https://datatracker.ietf.org/doc/html/rfc2046.html) MIME Extensions: Media types
- [RFC 2047](https://datatracker.ietf.org/doc/html/rfc2047.html) MIME Extensions: Message Header Extensions for Non-ASCII Text
- [RFC 2157](https://datatracker.ietf.org/doc/html/rfc2157.html) UTF-7
- [RFC 2177](https://datatracker.ietf.org/doc/html/rfc2177.html) (IDLE)
- [RFC 2183](https://datatracker.ietf.org/doc/html/rfc2183.html) The Content-Disposition Header Field
- [RFC 2231](https://datatracker.ietf.org/doc/html/rfc2231.html) MIME Parameter Value and Encoded Word Extensions: Character Sets, Languages, and Continuations
- [RFC 2342](https://datatracker.ietf.org/doc/html/rfc2342.html) (NAMESPACE)
- [RFC 2557](https://datatracker.ietf.org/doc/html/rfc2557.html) (Content-Location header field)
- [RFC 2595](https://datatracker.ietf.org/doc/html/rfc2595.html) (PLAIN authentication)
- [RFC 2971](https://datatracker.ietf.org/doc/html/rfc2971.html) (ID)
- [RFC 3066](https://datatracker.ietf.org/doc/html/rfc3066.html) Tags for the Identification of Languages
- [RFC 3282](https://datatracker.ietf.org/doc/html/rfc3282.html) Content Language Headers
- [RFC 3348](https://datatracker.ietf.org/doc/html/rfc3348.html) (CHILDREN)
- [RFC 3501](https://datatracker.ietf.org/doc/html/rfc3501.html) (IMAP4rev1)
- [RFC 3502](https://datatracker.ietf.org/doc/html/rfc3502.html) (MULTIAPPEND)
- [RFC 3516](https://datatracker.ietf.org/doc/html/rfc3516.html) (BINARY)
- [RFC 3691](https://datatracker.ietf.org/doc/html/rfc3691.html) (UNSELECT)
- [RFC 4315](https://datatracker.ietf.org/doc/html/rfc4315.html) (UIDPLUS)
- [RFC 4731](https://datatracker.ietf.org/doc/html/rfc4731.html) (ESEARCH)
- [RFC 4959](https://datatracker.ietf.org/doc/html/rfc4959.html) (SASL-IR)
- [RFC 4978](https://datatracker.ietf.org/doc/html/rfc4978.html) (COMPRESS=DEFLATE)
- [RFC 5161](https://datatracker.ietf.org/doc/html/rfc5161.html) (ENABLE)
- [RFC 5182](https://datatracker.ietf.org/doc/html/rfc5182.html) (SEARCHRES)
- [RFC 5253](https://datatracker.ietf.org/doc/html/rfc5253.html) (LIST-EXTENDED)
- [RFC 5322](https://datatracker.ietf.org/doc/html/rfc5322.html) (Internet Message Format)
- [RFC 5530](https://datatracker.ietf.org/doc/html/rfc5530.html) IMAP Response Codes
- [RFC 5819](https://datatracker.ietf.org/doc/html/rfc5819.html) (LIST-STATUS)
- [RFC 5918](https://datatracker.ietf.org/doc/html/rfc5918.html) Unicode Format for Network Interchange
- [RFC 6154](https://datatracker.ietf.org/doc/html/rfc6154.html) (CREATE-SPECIAL-USE and SPECIAL-USE)
- [RFC 6532](https://datatracker.ietf.org/doc/html/rfc6532.html) Internationalized Email Headers
- [RFC 6851](https://datatracker.ietf.org/doc/html/rfc6851.html) (MOVE)
- [RFC 6855](https://datatracker.ietf.org/doc/html/rfc6855.html) (UTF8=ACCEPT)
- [RFC 7162](https://datatracker.ietf.org/doc/html/rfc7162.html) (CONDSTORE and QRESYNC)
- [RFC 7888](https://datatracker.ietf.org/doc/html/rfc7888.html) (LITERAL+)
- [RFC 8438](https://datatracker.ietf.org/doc/html/rfc8438.html) (STATUS=SIZE)
- [RFC 8457](https://datatracker.ietf.org/doc/html/rfc8457.html) IMAP "$Important" Keyword and "\Important" Special-Use Attribute
- [RFC 8474](https://datatracker.ietf.org/doc/html/rfc8474.html) (OBJECTID)
- [RFC 8514](https://datatracker.ietf.org/doc/html/rfc8514.html) (SAVEDATE)
  since Crymap 2.0.0.
- [RFC 9051](https://datatracker.ietf.org/doc/html/rfc9051.html) (IMAP4rev2)
  since Crymap 1.0.1.

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

The maximum IMAP command line length is 65536 bytes, including the line ending.
For `APPEND` commands, the message literals are not included in this, and each
line fragment between a message literal is treated as a separate line.

The maximum message size for `APPEND` is hard-wired to 64MB.

Any operation that involves parsing message content will not process more than
20 levels of multipart or `message/rfc822` nesting, nor will it process more
than 1000 different body parts.

Message header lines in excess of 64kB are not processed.

Search operations will consider up to 128kB of text. Non-text body parts are
ignored for search.

A mailbox can have up to 4'294'967'294 message IDs allocated. Message IDs are
allocated sequentially.

## Mailboxes

All mailboxes other than `INBOX` may have children. Nesting depth is limited
only by the maximum IMAP command line length.

Mailbox names may not contain `%`, `*`, `\`, `/`, control characters or one of
a few Unicode control characters, and may not begin with `.` or `#`.

Mailbox names other than `INBOX` are case-sensitive. `INBOX` is always
upper-case.

The path delimiter is `/`. Making a mailbox path "absolute" by prefixing it
with a `/` has no effect. Duplicate `/` characters in a name are ignored.

Non-normalised MUTF7 is accepted in mailbox names. Mailbox names are always
returned in normalised MUTF7. MUTF7 is not returned on output nor transformed
on input when the client has enabled UTF-8 support.

When UTF-8 support is enabled, including by way of IMAP4rev2, no normalisation
of mailbox names occurs other than removal of extraneous path delimiters and
the special case of `INBOX` being case-insensitive. IMAP4rev2 has a
recommendation to send unsolicited `LIST` responses when a client uses a
denormalised mailbox name. Due to the extremely limited utility of this feature
in the context of Crymap's implementation, Crymap does not implement this
recommendation.

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
actually served messages exclusively with UNIX line endings for years before
anyone noticed. (Note though that when acting as a UNIX MDA, Crymap _does_
convert line endings as they come in. This paragraph applies to messages that
come in through IMAP or LMTP.)

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

Crymap remembers all expunge events.

### SASL-IR

This extension is fully implemented.

### SAVEDATE

This extension is fully implemented as of Crymap 2.0.0.

When migrating from the Crymap 1.x message store, the `SAVEDATE` of each
message is initialised to the modified time of the file storing the message.

### SEARCHRES

This extension is fully implemented.

### SPECIAL-USE

This extension is fully implemented.

See [CREATE-SPECIAL-USE](#create-special-use) for a reference on what
attributes are supported.

### STATUS=SIZE

This extension is fully implemented.

In versions of Crymap prior to 2.0.0, this was only implemented to the letter
of the standard and not the spirit due to efficiency concerns: Each message was
assumed to be 4GB in size and this size was simply multiplied by the message
count. Crymap 2.0.0 is able to track message sizes efficiently, so this
limitation no longer applies.

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
  key value key value [...]
```

The `GET-USER-CONFIG` subcommand was poorly designed in Crymap 1.x.

The Crymap 1.x capabilities are `INTERNAL-KEY-PATTERN`, `EXTERNAL-KEY-PATTERN`,
and `PASSWORD`, which correspond to the ability to pass each of those settings
to `SET-USER-CONFIG`. The values of those three settings are guaranteed to be
present, in that order, immediately after the capabilities in the `USER-CONFIG`
response. Each is an `nstring`.

Beyond the Crymap 1.x settings are other settings. Each `key` is an `atom`
naming the setting, and the `value` is an `nstring` giving the current value of
that setting. The presence of a setting in this list implies that it can be
passed to `XRY SET-USER-CONFIG`.

Crymap 2.0.0 adds the `SMTP-OUT` capability. This indicates the presence of the
`XCRY SMTP-OUT` subcommand and the following new settings:
- `SMTP-OUT-SAVE`, mailbox into which sent messages are implicitly saved
  (default `NIL`, meaning no implicit saving happens)
- `SMTP-OUT-SUCCESS-RECEIPTS`, mailbox into which receipts for
  successfully-delivered messages are saved (default `NIL`, meaning no delivery
  of success receipts)
- `SMTP-OUT-FAILURE-RECEIPTS`, mailbox into which receipts for
  unsuccessfully-delivered messages are saved (default `NIL`, which is the same
  as `"INBOX"`)

#### XCRY SET-USER-CONFIG

Arguments: `key value [key value [...]]`

Updates the given key-value pairs in the configuration. Each `key` is an
`atom`; each `value` is an `nstring`. Using this to "configure" `PASSWORD` is
also how password changes are done.

Response:

```text
* XCRY BACKUP-FILE "filename"
```

The returned filename should be shown to the user to let them know what file to
use to undo the change.

#### XCRY SMTP-OUT FOREIGN-TLS LIST

No arguments.

Produces a list of the TLS requirements imposed on outbound SMTP domains.

Example responses:

```text
* XCRY SMTP-OUT FOREIGN-TLS secure.example.com STARTTLS VALID-CERTIFICATE "TLS 1.3"
* XCRY SMTP-OUT FOREIGN-TLS insecure.example.com NIL
```

#### XCRY SMTP-OUT FOREIGN-TLS DELETE

Arguments: `domain [domain ...]`

Each `domain` is an `astring` naming a domain whose TLS requirements are to be
forgotten. The next attempt to send mail to that domain will not require any
particular TLS features to be present.

#### XCRY SMTP-OUT SPOOL EXECUTE

Arguments: `message-id`

`message-id` is an `astring` naming a spooled message ID which should be
retried.

Currently, spooled message IDs can only be found by the user in message failure
receipts.

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

### WITHIN

Should Crymap ever implement the CONTEXT extensions, this extension has a
pathological interaction with them, and itself offers very little benefit.

### QUOTA

Besides being useless to the author, it's also unclear how this should really
work, since mail delivery does not have access to the information it would need
to maintain the quota.
