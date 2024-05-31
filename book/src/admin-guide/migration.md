# Migration from Crymap 1.x

## System

To upgrade from Crymap 1.x to 2.x, no configuration changes or user action is
required. The recommended upgrade procedure is as follows:

1. Disable all ways for Crymap server processes to be created.
2. Terminate any remaining Crymap server processes.
3. Upgrade the Crymap binary to 2.x.
4. Reenable Crymap.

## User

Crymap 2.x uses an entirely different data model than 1.x. When a user next
logs in, they will automatically be migrated from the 1.x data model to the 2.x
data model. This can take a few seconds to a few minutes, depending on the size
of the account and the speed of the server.

The data migration process preserves all messages, message flags, and the
mailbox hierarchy. It does not preserve message IDs of any kind or
synchronisation states. The user's email client will thus effectively start
from a blank slate once migration completes and will need to
resynchronise/redownload everything it wants to keep local.

There is no way to migrate users in advance, as the migration process requires
the user's credentials to proceed.

A user whose account is still on the 1.x data model can still receive mail from
Crymap 2.x, though this mail will be added to the account under the 2.x data
model.

## Rollback

If you decide you need to roll back, the recommended procedure is as follows:

1. Disable all ways for Crymap server processes to be created.
2. Terminate any remaining Crymap server processes.
3. Manually roll back any user accounts that had been upgraded.
4. Downgrade the Crymap binary to 1.x.
5. Reenable Crymap.

A user account that was migrated from the 1.x data model to the 2.x data model
can be identified by the presence of a `crymap-v1-files` directory under the
user directory. A user can be rolled back to the 1.x model by running the
following commands in the user directory:

```sh
mv crymap-v1-files/* .
rmdir crymap-v1-files
rm -rf messages delivery.sqlite* meta.sqlite.xex*
```

This will reset the account to the state it was in before the migration, except
for changes to the `user.toml` file (which would include password changes). If
the `user.toml` file now has an `[smtp_out]` section, you will need to remove
that manually with a text editor, or restore the `user.toml` file from a backup
in `tmp` if there is one or from another backup you had made.

## Finishing touches

Once you are sure you won't need to roll back, you can entirely remove the
`crymap-v1-files` within each user directory.
