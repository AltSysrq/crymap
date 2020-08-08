# Installation Guide

## System Requirements

Crymap is designed to run on FreeBSD and Linux. It probably works on the other
BSDs, but is not tested on them. Windows is not supported and most likely never
will be since its filesystem is incompatible with Crymap's requirements on many
fronts.

The host file system must support symlinks and hard links, be case-sensitive,
and either be non-normalising or use NFC normalisation. There must not be mount
points inside any user directory. Remote file systems like NFS are supported if
they provide sufficient consistency guarantees, but Crymap is not specifically
designed to work with them, and IDLE notifications will only work properly if
all Crymap instances for a given user are run on the same host.

When run on a single-CPU host or with appropriate tuning on a multi-CPU host,
each Crymap instance typically only consumes a few MB of RAM. However, do be
aware that Crymap is a one-process-per-connection system.

Crymap generally only holds at most a few dozen file handles open at any given
time.

## Installation

Crymap requires having the OpenSSL libraries installed. On Debian/Ubuntu, you
can get them with `apt install openssl`. FreeBSD has the required libraries in
the base distribution. (There is a way to cause OpenSSL to be built along with
Crymap and statically linked, but this is not recommended since you won't be
able to get OpenSSL updates with your OS and this process is not described in
this manual.)

Each release of Crymap has pre-built binaries for AMD64 Debian and FreeBSD.
TODO Link once URL exists. Simply download the appropriate one of these and
save it in a place you consider appropriate; for example (`#` means "as root"):

```text
# cp crymap-$version-$os-amd64 /usr/local/bin/crymap
# chmod a=rx /usr/local/bin/crymap
```

If you do not want to use the pre-built binary or need to run on a different OS
or architecture, you need to build Crymap from source. This requires having
Rust installed, which you can get through
[rustup](https://github.com/rust-lang/rustup/#other-installation-methods).

The easiest way to build Crymap is to get it with `cargo`:
```text
$ cargo install crymap
# cp ~yourusername/.cargo/bin/crymap /usr/local/bin/crymap
```

You can also clone the repository directly:
```text
$ git clone git@github.com:altsysrq/crymap
$ cd crymap
$ cargo build --release
# cp target/release/crymap /usr/local/bin/crymap
```

## Initial System Setup

First, make sure you have valid SSL certificates for your domain. A full
explanation of how to do this is beyond the scope of this document, but
[Let's Encrypt](https://letsencrypt.org/) is a good place to start if you are
new to this.

All files used by Crymap are reachable from (though not necessarily "in") a
directory referred to as the "Crymap root". By default, this is either
`/etc/crymap` or `/usr/local/etc/crymap` (whichever exists); you can use
something else, but if you do so, you must pass `--root` to all `crymap server`
commands to tell Crymap where its data is. For this tutorial, we'll use
`/usr/local/etc/crymap` as the root.

Start by creating the Crymap root directory. The files we're setting up below
shouldn't be modified in normal operation, so they should be owned by `root`.

```text
# mkdir /usr/local/etc/crymap
```

Next, we create Crymap's system configuration file, which is a file named
`crymap.toml` under the Crymap root. A minimal configuration example is shown
below.

```toml
# /usr/local/etc/crymap/crymap.toml
[tls]
# The path to your X509 private key. The example here would be correct for
# a FreeBSD system at `example.org` using Let's Encrypt with the default
# configuration.
private_key = "/usr/local/etc/letsencrypt/live/example.org/privkey.pem"
# The path to the full X509 certificate chain.
certificate_chain = "/usr/local/etc/letsencrypt/live/example.org/fullchain.pem"
```

(Yes, that's all there is to the required configuration.)

Before we go further, we need to decide what style of deployment we're going to
do. Crymap supports three general patterns:

- UNIX-style deployment, in which each Crymap user corresponds to a UNIX user
  on the host system and owns their Crymap files.

- Simple black box deployment, where Crymap users are unrelated to UNIX users,
  and all Crymap data is owned by a dedicated UNIX account. Crymap is always
  run under that UNIX account.

- Two-step black box deployment. As above, but Crymap is run as `root` and then
  allowed to drop privileges once it no longer needs them. This requires more
  work to set up but means that the dedicated Crymap user doesn't need
  permission to read SSL certificates and the like. This chapter won't talk
  about this approach; simply go through the setup for the simple black box
  deployment, then refer to [the configuration
  reference](admin-guide/config.md) to see what to change.

If doing a black box deployment, set up the dedicated Crymap user now. Below,
we'll assume the user has name `crymap` and group `mail`, but of course that
will vary with your system.

The next step is to create the `users` directory.

If doing a UNIX-style deployment, the user's mail will typically be stored in
their home directory. This means that `users` will not actually contain the
data and we can just make it a normal directory.

```text
# mkdir /usr/local/etc/crymap/users
```

On a black-box deployment, the user data will end up under whatever directory
we create, and we don't really want to be storing data under `/etc`. Thus, we
will create the `users` directory elsewhere and symlink it from the nominal
location. In this example, we store users under `/srv/crymap-users`.

```text
# mkdir -m 750 /srv/crymap-users
# chown crymap:mail /srv/crymap-users
# ln -s /srv/crymap-users /usr/local/etc/crymap/users
```

To see if your configuration so far is good, try running `crymap serve
serve-imaps` under the same UNIX account you intend using in the real
deployment. If you get the message `stdin and stdout must not be a terminal`,
it means the configuration is valid and Crymap was ready to serve network
traffic.

We won't create any users just yet.

## Running Crymap in IMAPS mode

Crymap does not run as a daemon. Instead, it uses a one-process-per-connection
model in which some other process listens for connections and spawns Crymap
processes as connections arrive. There are a number of options here, including
xinetd and systemd. Here, we will use traditional inetd, available as the
package `openbsd-inetd` on Debian and part of the base FreeBSD installation.

Arranging for Crymap to be run by inetd is just a matter of adding two lines to
`/etc/inetd.conf` and then restarting inetd:

```text
imaps   stream  tcp     nowait  root    /usr/local/bin/crymap   crymap server serve-imaps
imaps	stream  tcp6    nowait  root    /usr/local/bin/crymap   crymap server serve-imaps
```

If setting up a simple black box deployment, replace `root` with whatever user
you want to run Crymap as.

Note the second occurrence of `crymap` in the command line is because inetd
requires the configuration to specify the usually implicit `argv[0]`
explicitly.

Do not add entries for the `imap4` service. Crymap does not support the
[obsolete](https://tools.ietf.org/html/rfc8314) cleartext+`STARTTLS` mechanism
on the IMAP4 port 143.

To test whether this setup works, run `crymap remote test --trace
--host=localhost`. (You can of course run from another system, in which case
pass the server's host name to `--host`.) If successful, you should see some
IMAP protocol traces and receive a prompt for a password. Of course, since no
users have been created yet, it is not possible to log in, so simply cancel
once it gets that far.

## Creating a User

User creation is done with the `crymap server user add` command. By default, it
generates a random password for the new user; `--prompt-password` can be given
to input a password on the terminal instead. Refer to the [user
guide](user-guide.md) to see how to change the password after the account has
been created.

On a UNIX-style setup, this command should be run as `root`, and you'll usually
want to give the path to the user data explicitly.

```text
# crymap server user add jsmith ~jsmith/crymap-mail
```

On a black box setup, this command should be run as the Crymap user, and if
your `users` directory is symlinked to a location outside of `/etc`, you can
leave the user directory off to simply store the user data inside `users`.

```text
$ crymap server user add jsmith
```

With that done, you should be able to test logging in as the new user:

```text
$ crymap remote test --host=localhost --user=jsmith
```

It is also possible at this point to connect your favourite email application
to Crymap, though you can't receive email just yet.

## Configuring Mail Delivery

Since Crymap does not provide an SMTP solution, it must be integrated with a
third party application to accept incoming mail. Crymap currently offers two
ways to do this integration:

- LMTP. LMTP is a variant of SMTP which is suitable for the final step in the
  mail delivery process. LMTP is robust, can correctly handle binary payloads,
  and can be more efficient, but is inflexible in that all messages are
  delivered to INBOX and without flags.

- UNIX MDA. This is more flexible than LMTP as it can be made to deliver to
  arbitrary mailboxes in a user's account and to set flags on new messages. In
  traditional UNIX setups, users can also invoke Crymap in as an MDA from their
  `.forward` file. Its main disadvantages are that it is less robust against
  errors, and because UNIX MDAs are typically passed the message with all line
  endings converted to UNIX line endings, Crymap must convert the line endings
  back, which will destroy binary content.

The instructions here are for LMTP. Refer to `crymap server deliver --help` for
more information on using Crymap as an MDA. This section also contains concrete
examples of using OpenSMTPD; if you are using a different SMTP daemon, you will
need to refer to its documentation.

First, we need to set something up to run Crymap in LMTP mode. This works
essentially the same as how we set up IMAPS, except here we *don't* want the
server to be accessible to anyone in the world. There's two ways to do that:

- Configure inetd, etc, to only listen on localhost.

- Use a UNIX socket. This is what we do in this example, since it is possible
  to set finer-grained permissions.

Here is an example inetd configuration for a UNIX-style deployment:

```text
:root:wheel:666:/var/run/lmtp.sock stream tcp nowait root /usr/local/bin/crymap crymap server serve-lmtp
```

Notes:

- Notice this uses `serve-lmtp` instead of `serve-imaps` at the end.

- `root:wheel` would be written `root:root` on typical Linux installations.

- As with IMAPS, for a simple black box deployment, you would configure it to
  run under the Crymap user and not `root`.

- This example allows anyone with shell access to open the LMTP socket and
  deliver mail (due to the `666` permission). To prevent that, you can give the
  socket a different owner and less permissive permissions. But to start with,
  it is probably best to keep it simple so there are fewer things to debug.

Crymap has a number of configurable options for LMTP. The defaults are fine for
simple installations, but you may want to have a look at the [configuration
reference](config-reference.md).

You can use `socat` to see if LMTP is working:

```text
$ socat STDIO UNIX:/var/run/lmtp.sock
220 yourhostname crymap 1.0.0 LMTP ready
^C
```

Finally, you need to configure your SMTP server to deliver mail through LMTP.
For OpenSMTPD, your `smtpd.conf` file might contain something like this:

```text
action "local_mail" lmtp "/var/run/lmtp.sock"
match from any for domain "lin.gl" action "local_mail"
match for local action "local_mail"
```

After that, all that's left to test is to send the user an email and see if it
shows up!

## Troubleshooting

By default, Crymap logs to syslog under the "mail" utility. When Crymap is not
run from a terminal, this means its logs should end up someplace like
`/var/log/maillog` or `/var/log/mail.log`.

In certain cases of severe misconfiguration (for example, by passing invalid
parameters in `inetd.conf`), Crymap may instead print an error on standard
error and exit. Where these messages end up depends on what you are using to
run Crymap. The output might be in a system log like `/var/log/messages`, or it
could be getting sent over the socket. To check for the latter case, you can
run a command like `socat STDIO TCP:localhost:993` to see if anything shows up.
