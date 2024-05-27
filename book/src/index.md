# Introduction

Crymap is an IMAP and SMTP server implementation for FreeBSD and Linux with a
strong focus on security and simplicity of administration. Its spotlight
feature is transparent encryption of data at rest — it is not possible to read
any user's mail without knowing their password, while a regular IMAP experience
is provided and mail can be received while the user is offline.

If using the Crymap SMTP server, none of any user's mail will ever be stored on
disk in the clear (on your server, anyway), though note that Crymap SMTP has
serious caveats.

Crymap supports both traditional UNIX-style deployments, where each user
corresponds to a UNIX account and owns their own mail, and "black box"
deployments, where users do not have shell access and all mail is owned by a
single system UNIX account.

## Features

- Fully compliant with the IMAP4rev1 and IMAP4rev2 specifications.
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
- Mail delivery via SMTP or LMTP.
- Simple but secure sending of mail via SMTP with built-in DKIM support.
- Interoperates well with filesystem-based backup systems.

## Status and Support

The author uses Crymap for all personal email. It is known to work well in this
use case. But this is naturally a fairly small amount of experience; in
particular, Crymap has only seen day-to-day use in conjunction with Thunderbird
and Fairmail.

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

- The maximum size of an email is currently hard-coded to 64MB.

- Crymap's outbound SMTP experience is unusual and somewhat cumbersome. If
  sending an email experiences a temporary failure, it cannot be automatically
  retried since all access to messages is cryptographically locked behind user
  authentication. Retrying must be done manually via an IMAP extension, which
  is currently only implemented by the Crymap CLI utility. For a more
  conventional experience, you can use something like OpenSMTPD to handle
  outbound messages instead.
