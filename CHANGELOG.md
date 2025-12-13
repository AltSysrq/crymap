# Unreleased

- Fix the SMTP receiver being unable to receive mail from MailGun.

# 2.0.0

- Major overhaul.
- Entirely new data model for accounts, giving better performance and
  reliability.
- The SAVEDATE IMAP extension is now supported.
- Crymap can now take inbound SMTP directly.
- Crymap can now perform outbound SMTP (albeit the workflow is a bit
  unconventional).
- Various bugfixes.

## Breaking changes

- `--create` is no longer an option to `crymap deliver`.

# 1.0.1

- Rust 1.66.0 is now the earliest officially supported Rust version.
- IMAP4rev2 is now officially supported.
- Update OpenSSL bindings and other crate versions to support latest Rust
  version.
- Added option to redirect standard error to a file so that fatal errors do not
  get sent over the wire to the client.
- The literal string "NIL" is no longer sent on the wire as an atom to prevent
  issues with bad parsers that would interpret it as the sentinel `NIL`.
