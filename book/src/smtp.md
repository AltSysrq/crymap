# SMTP/LMTP Characteristics

## Conformance

Crymap's SMTP/LMTP implementation is believed to conform to:

- [RFC 1652](https://datatracker.ietf.org/doc/html/rfc1652.html) (8BITMIME)
- [RFC 1830](https://datatracker.ietf.org/doc/html/rfc1830.html) (BINARY)
- [RFC 1854](https://datatracker.ietf.org/doc/html/rfc1854.html) (PIPELINING)
- [RFC 1870](https://datatracker.ietf.org/doc/html/rfc1870.html) (SIZE)
- [RFC 1893](https://datatracker.ietf.org/doc/html/rfc1893.html) and
  [RFC 2034](https://datatracker.ietf.org/doc/html/rfc2034.html) (ENHANCEDSTATUSCODES)
- [RFC 2033](https://datatracker.ietf.org/doc/html/rfc2033.html) (LMTP)
- [RFC 3207](https://datatracker.ietf.org/doc/html/rfc3207.html) (STARTTLS)
- [RFC 4954](https://datatracker.ietf.org/doc/html/rfc4954.html) (AUTH PLAIN)
- [RFC 5321](https://datatracker.ietf.org/doc/html/rfc5321.html) (SMTP)
- [RFC 6531](https://datatracker.ietf.org/doc/html/rfc6531.html) (SMTPUTF8)

## Inbound variants

### SMTP delivery

STARTTLS is fully supported, but not required.

Crymap will always evaluate DMARC/DKIM/SPF, but will not reject messages on
that basis unless enabled in the configuration. If enabled, it rejects it in
the SMTP transaction.

Crymap does not generate any DMARC reports.

Attempts to authenticate on the inbound SMTP port will always be rejected.

Message delivery will always be rejected for any recipient domain which is not
explicitly defined in the server configuration, even if the server is otherwise
configured to not consider the domain during delivery, so that the Crymap
server does not appear to be an open relay.

### SMTP submission

STARTTLS is fully supported for connections that start in cleartext and is
required before any attempt to authenticate will be allowed.

The `BINARYMIME` capability is not reported to the client in SMTP submission as
Crymap is not able to downgrade binary messages for transmission to servers
that do not support them.

Messages cannot be submitted until the user has successfully authenticated.
Crymap validates that the return path and the `From` header all reference the
authenticated user and correspond to a domain which is explicitly defined in
the server configuration.

### LMTP

STARTTLS is fully supported, but not required.

DMARC/DKIM/SPF are not evaluated; that should be handled by whatever is
fronting LMTP. If Crymap is configured to ignore the email domain when
identifying users, delivery will be accepted for any domain.

Attempts to authenticate over LMTP will always be rejected.

### General notes

DOS-style line endings are not required.

The `DATA` command will perform line-ending conversion from UNIX to DOS
newlines in two conditions:

- The client is using UNIX newlines at the SMTP level.
- The first line ending in the data is a UNIX newline.

If neither of these conditions are met, binary data can be correctly sent even
through a plain `DATA` command, as long as the other end uses the same very
strict interpretation of dot-stuffing.

Line ending conversion is never performed on messages sent through the
`CHUNKING` extension.

Maximum line length is 65534 bytes.

For SMTP delivery and SMTP submission, which must inspect the header block, the
message header block may not exceed 256kB or the message will be rejected. LMTP
does not inspect the header block and so has no such limit.

`VRFY` and `EXPN` are not supported and return constant hardwired responses.

The `BODY=` argument to `MAIL FROM` is entirely ignored. For SMTP submission,
Crymap identifies the appropriate transfer type by inspecting the message
itself.

The same limit used for IMAP APPEND is enforced for SMTP and LMTP.

## Outbound SMTP

The outbound SMTP implementation is simplistic and only suitable for low-volume
sites.

A given SMTP session will only be used to send one message (but possibly to
multiple recipients).

Crymap remembers the best TLS characteristics it has seen for an email domain
(not a particular SMTP server), and will abort the transaction if the
connection it obtains cannot meet those same characteristics:

- Whether or not the server supports TLS at all;
- Whether the server provides a valid certificate;
- The TLS version.

Crymap will include the exact size of the message in the `MAIL FROM` command if
the server supports the `SIZE` extension. If the server supports the `SIZE`
extension and indicates a definite size limit which is smaller than the size of
the message, Crymap will fail the transaction without attempting it.

Crymap is not capabable of performing any kind of "downgrading" of a message
before sending it. In general, the assertion is that servers which do not
support transport of 8-bit content simply _do not exist_.

- If a binary message is to be sent (which can only occur if the user agent
  which submitted the message ignored the lack of the `BINARYMIME` capability),
  Crymap will report `BODY=BINARYMIME` if the remote server advertises
  `BINARYMIME`, `BODY=8BITMIME` if the remote server does not advertise
  `BINARYMIME` but does advertise `8BITMIME`, and no `BODY=` argument if the
  server supports neither extension.

- If an 8-bit message is to be sent, Crymap will report `BODY=8BITMIME` if the
  remote server advertises `8BITMIME`, and no `BODY=` argument otherwise.

The presence of the `SMTPUTF8` capability has no effect. For a message that
nominally requires that capability, Crymap will attempt to send it anyway and
allow the server to decide whether or not it understands the SMTP commands and
the message itself.

Crymap will always transfer the message with `BDAT` if the server supports the
`CHUNKING` extension.

Crymap never takes advantage of pipelining or enhanced status codes.
