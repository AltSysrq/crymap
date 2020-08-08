# Managing Users

## Crymap's notion of a user

A "user" in Crymap simply refers to an entry within the `users` directory. Each
entry may either be a directory, or be a symlink to a directory. Whichever it
is, that directory is the _user data directory_.

In traditional UNIX-style deployments, Crymap uses the owner of the user data
directory to determine which UNIX account to assume for operations on that
user. In black box deployments, the exact ownership of the user data directory
is less important, but it is still necessarily something that the Crymap user
has access to and which doesn't let unauthorised users access it.

## Creating users

Creation of a user is (internally) a non-trivial operation since it needs to
generate a master key for the user and make it derivable from the user's
initial password. The process also must set up the user's basic directory
structure and mailboxes, most importantly INBOX.

User creation is done through the `crymap user add` command. This command
should be run as `root` for traditional UNIX-style deployments and as the
Crymap user for black box deployments.

The first argument of the command is the name of the user to create, e.g.,
`jsmith`. If the command is run as `root`, Crymap will by default assume that
that name also refers to the name of the UNIX account that will own the mail
data, and will fail if no such account exists. The `--uid` option can be passed
to provide the UID that should own the user data directory.

The optional second argument of the command gives the path to the user data
directory. If this argument is not given, the user data directory is simply a
directory within `users`. The command will fail if this would cause the user
data to be stored inside `/etc` or `/usr/local/etc`; in this case, you need to
explicitly give a path for the user data.

By default, a password for the user is randomly generated. You can pass
`--prompt-password` to input your own.

## Renaming, aliasing, and deleting users

Crymap does not currently have special commands for these operations. Once
created, users can be treated as regular file system objects. In particular:

- A user can be renamed by simply renaming the entry under `users`.

- User aliases can be created by symlinking the additional alias to the user
  data directory.

- Users can be deleted by removing their entry from `users`.

- Users can be disabled by renaming them to an illegal user name. The simplest
  way is to just prefix their name with `%`.

- A user can be imported from another Crymap installation by simply moving the
  user data directory (or a symlink thereto) into `users`.

## Password Resets

When a user changes their password, a backup of the user configuration is
created in the `tmp` directory within the user data directory, with a name of
the format `config-backup-DATETIME.toml`. If necessary (for example, because
the user mistyped their new password), the password change can be undone by
replacing the `user.toml` file at the top of the user data directory with the
backup file. Note that these backup files are automatically deleted after a
successful login 24 hours after the change was made.

If a user forgets their password, there is no recourse. Their data is gone
forever. The best thing to do is to move their user data directory to somewhere
else in case they remember the password later and create a new account for
them.
