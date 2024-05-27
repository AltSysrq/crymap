# Backups and Recovery

## Backups

Starting with Crymap 2.0.0, each message and private key is stored in its own
file, with all other data tracked in a couple SQLite databases.

Backup tooling does not need to support any exotic filesystem features, and
even Windows filesystems will be able to carry the backup in tact.

## Restoring from Backup

In most cases, simply restoring from backup should do the trick.

There are a few cases where a backup could be torn across an update:

1. Messages on the filesystem but not in the database. At least once a day,
   Crymap automatically checks for such messages. They will automatically
   appear in the user's inbox.

2. Messages in the database but not in the filesystem. These will appear to the
   user as stub messages indicating the problem. The user must delete the
   entries themselves.

3. Corrupt SQLite database. You can remove `delivery.sqlite*` and
   `meta.sqlite.xex*` (**important**: ensure you remove the `-journal` file
   too!), then copy one of the `meta.sqlite.xex.*` backups from the user's
   `backup` directory to `meta.sqlite.xex` in the user's directory. In the
   worst case, if you can't get anything to work, you can remove
   `meta.sqlite.xex*` entirely, which will result in all the user's messages
   being in unread, in `INBOX`, and in no particular order, but at least their
   mail will be there.

Objects from a user account are readable from only that user account. For
example, in case of a system failure, you cannot set up a new system, create
user accounts in it, and then expect to be able to drop data from the backups
into those new user accounts. The user accounts themselves must be restored
from backup.
