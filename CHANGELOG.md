# Unreleased

- Rust 1.66.0 is now the earliest officially supported Rust version.
- IMAP4rev2 is now officially supported.
- Update OpenSSL bindings and other crate versions to support latest Rust
  version.
- Added option to redirect standard error to a file so that fatal errors do not
  get sent over the wire to the client.
- The literal string "NIL" is no longer sent on the wire as an atom to prevent
  issues with bad parsers that would interpret it as the sentinel `NIL`.
