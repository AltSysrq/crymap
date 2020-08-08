# Understanding the Filesystem

This section only covers what is useful to know when inspecting a Crymap
installation with regular shell tools. For the nitty-gritty details, you'll
need to look at the Crymap source code's internal documentation.

## Crymap root

There are three files of significance at the _Crymap root_:

- `crymap.toml`. This is the "system configuration" and provides all of
  Crymap's configuration other than logging and that which is represented by
  the filesystem.

- `logging.toml`. If present, replaces syslog-based logging with something
  else.

- `users`. Either a directory or a symlink to a directory which contains one
  entry for each Crymap user.

Refer to the [configuration reference](config.md) for the two configuration
files, and [user management](users.md) for the `users` directory.

## User data directory

The user data directory contains the following files:

- `garbage`. This is used internally for deleting directories. It is safe to
  fully delete all its contents at any time. Crymap itself aggressively cleans
  it.

- `keys`. A directory containing the user's RSA keys. It is a critical part the
  user data needed for accessing the user's mail.

- `mail`. The root of the user's mailbox hierarchy. All the user's mail is
  stored inside this directory. Each directory inside is a single mailbox.

- `maintenance-run`. This is a marker file used to track the last time that a
  full maintenance pass was run on the account. This can be deleted safely,
  which will cause the next login to trigger a full maintenance pass.

- `shadow`. This is a "shadow" of the `mail` hierarchy used to track mailbox
  attributes that operate independently of the mailboxes themselves. Currently,
  this is only for IMAP subscriptions.

- `tmp`. Used for temporary files and temporary markers. Crymap will
  automatically clean stale files out of this directory. It is not too
  important to back up (though it is also the destination for config backups
  which allow undoing password changes) but should not be cleaned manually
  unless there is some clear need to do so.

- `user.toml`. This contains the user's preferences and the data needed to
  derive their master key from their password. This file can be overwritten
  with an earlier backup version (either a backup created under `tmp` or by
  some external backup system) to revert a password change.

## Mailboxes

A mailbox is a directory named after the IMAP mailbox of the same name. The
`INBOX` mailbox is quite special (and must be all upper case); other mailboxes
can be named freely.

Inside a mailbox, all subdirectories not prefixed with `%` are child mailboxes.

Normally, each mailbox will have a directory named `%$hexcode` and a symlink
pointing to it named `%`. If neither exists, it means the user at some point
attempted to delete the mailbox while it had child mailboxes. This manifests as
a "non selectable" mailbox in IMAP. The `%$hexcode` directory contains the
actual mailbox data.

A mailbox data directory may contain the following:

- `c0`, `c1`, `c2`, `c3`. These contain metadata transactions for the mailbox,
  such as changing flags on messages.

- `c-guess`. Used in the metadata transaction process. Safe to delete or
  corrupt.

- `mailbox.toml`. Contains immutable metadata about the mailbox.

- `recent`. Contains a marker file used to track the "recent" IMAP flag. Safe
  to delete.

- `rollups`. Contains rollups of the mailbox state.

- `socks`. Contains marker symlinks used to locate sockets used to notify
  idling Crymap processes of changes. Safe to delete.

- `u0`, `u1`, `u2`, `u3`. These contain the actual messages in the mailbox.

- `u-guess`. Used to accelerate working with the `u*` directories. Safe to
  delete or corrupt.

It is normal for the `c*` and `u*` directory trees to contain broken or cyclic
symlinks. These symlinks play an important role in how Crymap manages its data.

If you think a mailbox has been corrupted somehow, it is a reasonable
last-resort step to remove the `c*` and `rollups` directories. **This will
destroy all the user's message metadata** and may undelete some messages. The
next time the mailbox is opened, it may take a very long time. However, Crymap
should be able to recover the messages themselves.
