# Backups and Recovery

## Backups

Crymap uses a "filesystem as a database" model for its storage. This means that
no exotic tooling is required to back the Crymap data up. Even simple tools
such as `rsync` are sufficient.

A proper backup system should be able to handle the following:

- Binary file content
- Unicode file names
- Symlinks must be backed up as symlinks, not copies of what they point to, and
  must retain their exact target
- Cyclic and dangling symlinks must be tolerated

Exact file modes and owners do not need to be preserved, but it is better if
they are. While Crymap creates hard links, it does not require them to be
preserved, and a backup will function properly if the hard-linked files are
reconstructed as separate files. Crymap does not use file timestamps or
extended attributes for anything important.

Crymap is designed to be tolerant of anomalies resulting from the backup
process not capturing an atomic snapshot of the user data directory. There is
one requirement: the backup system must be able to process the a user's whole
data directory in less than 24 hours. If this requirement is met, no data which
existed before the backup started will be lost, with one corner case.

The corner case is has to do with mailbox renaming, since Crymap uses
filesystem directories to model the mailbox hierarchy. Consider a user with the
below mailbox hierarchy.

```text
|-+ INBOX
|
|-+ In Progress
| |
| \-+ TPS Reports
|
\-+ Archive
```

It might happen that the backup system happens to process these directories in
this order: `Archive`, `INBOX`, `In Progress`. When it goes through `Archive`,
it makes a backup in which `Archive` has no child mailboxes. Now, suppose that
when it is working on `INBOX`, the user moves `TPS Reports` into `Archive`:

```text
|-+ INBOX
|
|-+ In Progress
|
\-+ Archive
  |
  \-+ TPS Reports
```

Now, when the backup system finishes `INBOX` and moves on to `In Progress`, it
makes a backup of `In Progress` which has no child mailboxes. Now we have a
backup which does not contain `TPS Reports` anywhere, even though that mailbox
always existed somewhere!

This is a problem inherent in any filesystem-based backup system, and means it
is important to have multiple backups available in case one backup runs at just
the wrong time.

This corner case does not affect moving individual messages between mailboxes
because Crymap is able to retain the messages in their old location for the
24hr grace period.

## Restoring from Backup

Due to the "filesystem as a database" model, restoring from backup is usually
just a matter of recovering the files and putting them back in the correct
place, possibly after fixing permissions if the backup system does not preserve
them.

If the backup is not a fully consistent state, mail applications may have
difficulty resynchronising. It may be necessary to do a "repair" or fully
reconfigure the application.

It is also possible to retrieve parts of a user's account (i.e. mailboxes) and
insert them into the current account by placing the directories in an
appropriate place under the `mail` directory within the user data directory. If
there are missing RSA keys, they can also be retrieved from the `keys`
directory in the backup and added to the current filesystem. No special
configuration or notification to Crymap is needed for these operations; simply
putting the files/directories into place is sufficient.

Objects from a user account are readable from only that user account. For
example, in case of a system failure, you cannot set up a new system, create
user accounts in it, and then expect to be able to drop data from the backups
into those new user accounts. The user accounts themselves must be restored
from backup.
