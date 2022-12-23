# Crymap IMAP Server

[![](http://meritbadge.herokuapp.com/crymap)](https://crates.io/crates/crymap)

# Introduction

Crymap is an IMAP server implementation for FreeBSD and Linux with a strong
focus on security and simplicity of administration. Its spotlight feature is
transparent encryption of data at rest — it is not possible to read any user's
mail without knowing their password, while a regular IMAP experience is
provided and mail can be received while the user is offline.

Crymap supports both traditional UNIX-style deployments, where each user
corresponds to a UNIX account and owns their own mail, and "black box"
deployments, where users do not have shell access and all mail is owned by a
single system UNIX account.

Crymap does not provide an SMTP server; i.e., it does not provide a solution
for sending or receiving mail from the outside world, and a third party
application such as OpenSMTPD must be used for this. Crymap can act as a UNIX
MDA or as an LMTP server to transfer incoming mail from your SMTP server to the
Crymap mail store.

## Features

- Fully compliant with the IMAP4rev1 specification.
- Secure by default. IMAPS only.
- Minimal configuration.
- Messages and metadata transparently encrypted at rest.
- Automatic key rotation.
- Transparent file and over-the-wire compression.
- All normal mailboxes are "dual-use" (allow both messages and sub-mailboxes).
- Instant mail delivery notifications.
- QRESYNC support.
- "Special-use" mailbox support.
- A decent number of additional IMAP extensions.
- Supports messages with 8-bit and binary content.
- Mail delivery as an MDA.
- Mail delivery via LMTP.
- Interoperates properly with filesystem-based backup systems.

## Status and Support

The author uses Crymap for all personal email. It is known to work well in
this use case. But this is naturally a fairly small amount of experience; in
particular, Crymap has only seen day-to-day use in conjunction with OpenSMTPD
and Thunderbird.

Crymap is currently maintained by its author alone. I am motivated to address
bugs, but feature requests are unlikely to be accepted unless they offer
substantial benefits to security or very common use cases. I will try to answer
questions but cannot make commitments.

## Caveats

- If a password is forgotten, all data owned by that user is lost forever.
  There is no way for an administrator to reset a user's password, as that
  would defeat Crymap's purpose.

- Crymap has no ability to integrate into the host authentication system. I.e.,
  Crymap user accounts are fully independent of host user accounts in terms of
  password, enabled/disabled status, etc. This is because Crymap needs full
  control of the password change process for password changes to happen without
  destroying the user's data. It would be technologically feasible to make,
  e.g., a PAM module that delegates to Crymap, but this is not implemented nor
  are there any plans to ever do so.
## Documentation

Refer to the [Crymap mdbook](https://altsysrq.github.io/crymap/index.html) for
full documentation.

## License

Crymap is licensed under the [GPL version 3 or later](COPYING).
