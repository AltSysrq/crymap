# Installation Guide

## System Requirements

Crymap is designed to run on FreeBSD and Linux. It probably works on the other
BSDs, but is not tested on them. Windows is not supported and most likely never
will be since its filesystem is incompatible with Crymap's requirements on many
fronts.

The host file system must support symlinks and hard links. There must not be
mount points inside any user directory. Remote file systems like NFS are
supported if they provide sufficient consistency guarantees, but Crymap is not
specifically designed to work with them, and IDLE notifications will only work
properly if all Crymap instances for a given user are run on the same host.

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

Each [release of Crymap](https://github.com/AltSysrq/crymap/releases/) has
pre-built binaries for AMD64 Debian and FreeBSD. Simply download the
appropriate one of these and save it in a place you consider appropriate; for
example (`#` means "as root"):

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

## Configuring Inbound Mail Delivery

There are three ways to set up inbound mail delivery.

- SMTP. In this setup, Crymap receives messages directly from external servers.
  Having Crymap handle SMTP directly is the simplest setup and ensures no
  message data is written to disk in the clear, but is also the least flexible
  option, as Crymap won't do anything with inbound messages but deliver them to
  the INBOX without flags.

- LMTP. LMTP is a variant of SMTP which is suitable for the final step in the
  mail delivery process. Compared to having Crymap serve SMTP directly, LMTP is
  more complicated to set up as you need a third-party SMTP solution and may be
  less secure since most SMTP servers spool messages to disk in cleartext, but
  will give you whatever flexibility the SMTP solution offers. Compared to the
  UNIX MDA option below, LMTP is robust, can correctly handle binary payloads,
  and can be more efficient, but is inflexible in that all messages are
  delivered to INBOX and without flags.

- UNIX MDA. This is more flexible than SMTP LMTP as it can be made to deliver
  to arbitrary mailboxes in a user's account and to set flags on new messages.
  In traditional UNIX setups, users can also invoke Crymap in as an MDA from
  their `.forward` file. Its main disadvantages are that it is less robust
  against errors, and because UNIX MDAs are typically passed the message with
  all line endings converted to UNIX line endings, Crymap must convert the line
  endings back, which will destroy binary content. Like LMTP, this also comes
  with the disadvantages of needing an external SMTP solution.

### SMTP

First, inbound SMTP requires a bit of extra configuration in `crymap.toml`.
You'll need to tell Crymap what its fully-qualified domain name is and what
domains it is expecting to serve.

The below example shows what you might add to a server that will be receiving
email from `example.com` and `example.net`.

```toml
[smtp]
# A DNS lookup for this name should return the IP address of the Crymap server.
host_name = "mx.example.net"

[smtp.domains."example.com"]
# No configuration here for now, we just need to make sure the section for
# "example.com" exists.

[smtp.domains."example.net"]
# No configuration here for now, we just need to make sure the section for
# "example.com" exists.
```

Next, you just need to arrange for Crymap to handle inbound SMTP connections.
Here is an example inetd configuration for a UNIX-style deployment:

```text
smtp    stream  tcp     nowait  root    /usr/local/bin/crymap   crymap server serve-smtpin
smtp	stream  tcp6    nowait  root    /usr/local/bin/crymap   crymap server serve-smtpin
```

Notes:

- Notice this uses `serve-smtpin` instead of `serve-imaps` at the end.

- As with IMAPS, for a simple black box deployment, you would configure it to
  run under the Crymap user and not `root`.

You can use `socat` to see if SMTP is working:

```text
$ socat STDIO TCP:localhost:25
220 mx.example.net crymap 2.0.0 ESMTP ready
^C
```

At this point, you should also be able to send email from external email
providers to your server.

### LMTP

Besides setting up crymap, this section also contains concrete examples of
using OpenSMTPD; if you are using a different SMTP daemon, you will need to
refer to its documentation.

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
220 yourhostname crymap 2.0.0 LMTP ready
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

### Unix MDA

There isn't anything Crymap-specific to set up for this use case. You will need
to find out how to get your SMTP solution to run a UNIX MDA command line, which
in most cases would simply be `crymap server deliver`. Refer to
`crymap server deliver --help` for additional options.

## Outbound SMTP

If you want to use a third-party solution for outbound mail, there is nothing
to configure which is Crymap-specific. Third-party solutions are generally more
user-friendly, more battle-tested, and more flexible, but are less secure since
they need to spool messages onto disk in cleartext or another way that allows
passive recovery of the message content.

Crymap does have outbound SMTP support. Its advantages are simple
configuration, built-in DKIM support, unification of the authentication system
with IMAP, and that messages do not get spooled to disk in the clear. However,
it has a major downside: Retrying failed messages is **manual**, and currently
can only be done with the Crymap **command-line application**.

If you want to use Crymap's outbound SMTP support, you will first need to add
the SMTP configuration to `crymap.toml` if you haven't done this already. Refer
to the [SMTP](#SMTP) section for an example.

If you have existing DKIM keys you wish to continue using, you can add these to
the domain-specific sections in `crymap.toml`. Search for "DKIM" in the
[Configuration Guide](admin-guide/config.md) for details on what to add there.
You can use the `openssl` and `base64` command-line utilities to convert the
private keys you already have into the required format.

If you do not have existing DKIM keys, the next step will help you generate
some.

You can use `crymap server smtp-out-sanity-check` on your server to check your
configuration, including external DNS. This tool will generate DKIM keys for
you if you have none, and will provide additional suggestions to make it more
likely that major email providers will accept your email.

Finally, you need to arrange for Crymap to run SMTP submission to receive
outbound mail from your users. There are two supported options here:

- SMTP+TLS on port 465, called variously `submissions`, `smtps`, or `ssmtp` in
  `/etc/services`, is preferred. Use only this one if you can. This is the
  `serve-smtpssub` subcommand (note the double "s").

- SMTP submission on port 587, usually called `submission` in `/etc/services`.
  This variant relies on the client performing `STARTTLS` and may be vulnerable
  to the "strip TLS" attack depending on the client. This is the
  `serve-smtpsub` (note no double "s").

Here is an example inetd configuration for a UNIX-style deployment with both protocols:

```text
# The preferred "implicit TLS" variant
submissions stream  tcp     nowait  root    /usr/local/bin/crymap   crymap server serve-smtpssub
submissions stream  tcp6    nowait  root    /usr/local/bin/crymap   crymap server serve-smtpssub
# The legacy STARTTLS variant
submission  stream  tcp     nowait  root    /usr/local/bin/crymap   crymap server serve-smtpsub
submission  stream  tcp6    nowait  root    /usr/local/bin/crymap   crymap server serve-smtpsub
```

Notes:

- Sotice this uses `serve-smtpssub` and `serve-smtpsub` instead of
  `serve-imaps` at the end.

- As with IMAPS, for a simple black box deployment, you would configure it to
  run under the Crymap user and not `root`.

You can use `socat` to see if it is working:

```text
# Implicit TLS protocol
# You could also use your server's fully-qualified domain name instead of
# "localhost" and then exclude ",verify=0" instead.
$ socat STDIO SSL:localhost:465,verify=0
220 mx.example.net crymap 2.0.0 ESMTPS ready
^C
# Legacy STARTTLS protocol
$ socat STDIO TCP:localhost:587
220 mx.example.net crymap 2.0.0 ESMTP ready
^C
```

You are now ready to test sending mail. You should start by emailing yourself
so that bad configuration does not impact your reputation on the big providers,
then move on to various third parties.

If sending a message fails at the SMTP level, the failure receipt will be
delivered to your account's inbox, which you can use to debug why the remote
server rejected your message.

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
