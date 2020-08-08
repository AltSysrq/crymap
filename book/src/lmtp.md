# LMTP Characteristics

## Conformance

Crymap's LMTP implementation is believed to conform to:

- RFC 1652 (8BITMIME)
- RFC 1830 (BINARY)
- RFC 1854 (PIPELINING)
- RFC 1870 (SIZE)
- RFC 1893 and RFC 2034 (ENHANCEDSTATUSCODES)
- RFC 2033 (LMTP)
- RFC 3207 (STARTTLS)
- RFC 5321 (SMTP)
- RFC 6531 (SMTPUTF8)

## Security

Crymap does not implement any authentication mechanism and does not require use
of TLS. LMTP is not expected to be used with untrusted sources, as OS-level
controls should be sufficient to prevent foreign access to LMTP.

For similar reasons, Crymap LMTP makes no attempt to verify the host name
presented to it in `LHLO` and simply records it as-is.

## Implementation notes

DOS-style line endings are strictly enforced.

Binary data is correctly processed even if sent through a `DATA` command.

Maximum line length is 65534 bytes.

`VRFY` and `EXPN` are not supported and return constant hardwired responses.

The same limit used for IMAP APPEND is enforced for LMTP.
