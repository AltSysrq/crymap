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

- `backups`. This contains routine database backups produced atomically by
  Crymap.

- `crymap-v1-files`. This contains the file trees that were present when the
  user was migrated from Crymap 1.x to Crymap 2.x. It will not be present for
  users that were created on Crymap 2.x, nor will it be recreated if removed.
  It is safe to remove entirely once you are sure you don't need to roll back
  to Crymap 1.x.

- `delivery.sqlite` and `delivery.sqlite-journal`. This is a cleartext SQLite
  database used for message delivery. Message delivery occurs without the user
  being logged in, and information about how such messages are to be added to
  the user's account are written here. When the user is logged in, the database
  is processed and the messages are deposited into their final positions. If
  this database is removed, and pending messages will eventually show up in the
  inbox once Crymap determines that they have been orphaned.

- `garbage`. This is a holdover from Crymap 1.x, and was used internally for
  deleting directories. It is safe to fully delete all its contents at any
  time. Crymap itself aggressively cleans it.

- `keys`. A directory containing the user's RSA keys. It is a critical part the
  user data needed for accessing the user's mail.

- `maintenance-run`. This is a marker file used to track the last time that a
  full maintenance pass was run on the account. This can be deleted safely,
  which will cause the next login to trigger a full maintenance pass.

- `messages`. This contains the user's actual email, one file per message.

- `meta.sqlite.xex` and `meta.sqlite.xex-journal`. This is an encrypted SQLite
  database containing all information about the user's messages and mailboxes.
  Atomic backups of `meta.sqlite.xex` are routinely created under `backups`. If
  you restore `meta.sqlite.xex` from backup, you **MUST** also remove
  `meta.sqlite.xex-journal` at the same time.

- `tmp`. Used for temporary files and temporary markers. Crymap will
  automatically clean stale files out of this directory. It is not too
  important to back up (though it is also the destination for config backups
  which allow undoing password changes) but should not be cleaned manually
  unless there is some clear need to do so.

- `user.toml`. This contains the user's preferences and the data needed to
  derive their master key from their password. This file can be overwritten
  with an earlier backup version (either a backup created under `tmp` or by
  some external backup system) to revert a password change.

## OpenSSL mirrors

If Crymap is set up in a way that causes it to chroot, it will maintain a copy
of the system OpenSSL certificate store within each chroot. This will usually
manifest as an `etc` or `usr` directory within the `users` directory or within
each user directory. This is needed so that certificates of external servers
can be validated when using outbound SMTP, as they must access these files
after Crymap has moved into the chroot and rendered the normal location of
these files inaccessible.

If possible, Crymap will create hard links, but will copy the files if the
destination directory is on a different file system.
