# Configuration Reference

## crymap.toml

Below is an example `crymap.toml` with every option explicitly set to the
default and comments explaining what each one does.

```toml
[tls]
# The path to your X509 private key.
private_key = "<no default>"
# The path to the full X509 certificate chain.
certificate_chain = "<no default>"

# Additional identification information to send to clients.
# This is a free-form map. Refer to RFC 2971 § 3.3 to see what standard
# identification names exist. You do not need to set all the values.
# `support_url` is probably the most important one since some mail clients
# can use it to help the user get assistance.
# Underscores in key names are replaced with hyphens.
[identification]
vendor = "Example Company"
support_url = "mailto:it@example.com"
address = "1313 Dead End Dr"

# The [security] section applies any time any of the `crymap server ...`
# commands is run.
[security]
# If this is set to true and Crymap is run as `root`, it will chroot into the
# `users` path under the Crymap root once it has accessed all system files it needs
# which are outside that directory.
#
# This can be set for any style of deployment where Crymap is started as
# `root`, but note that if this is set, user directories inside `users` may not
# be absolute symlinks or symlinks to anywhere outside `users`.
chroot_system = false

# If this is set to a non-empty value and Crymap is run as `root`, it will drop
# privileges to this UNIX user once it has accessed all system files it needs
# which are outside the Crymap root. This occurs before any interaction with the
# incoming connection occurs. This makes it possible to run Crymap in a
# configuration where it does not normally have access to SSL certificates, for
# example.
#
# This setting is the main difference between a "simple" black box deployment,
# where Crymap is started as the desired non-root user, and a "two-step" black
# box deployment, where Crymap is started as root and then drops to the user
# given here.
system_user = ""

# The [lmtp] section applies when Crymap is run with `crymap server serve-lmtp`.
[lmtp]
# If non-empty, Crymap will report this value as its hostname.
# By default, Crymap reports the system host name.
host_name = ""

# By default, Crymap will strip everything after the `@` in destination
# addresses to determine the name of the Crymap user (so an email addressed
# to "foo@bar.com" gets delivered to Crymap user "foo"). Setting this to true
# suppresses this behaviour. Note that your SMTP daemon may also do this
# stripping, in which case you must configure both Crymap and the SMTP daemon
# to retain the domain.
#
# Set to true if your users log in as `user@domain.com` instead of `user`.
keep_recipient_domain = false

# By default, Crymap will make the recipient user name lower case, remove all
# periods, and strip everything including and after the first `+`. (If
# `keep_recipient_domain` is `true`, the `@` and domain part are not affected
# by these rules, but the local part is.) Setting this to true prevents all
# these normalisations, which may be useful if you want something different to
# happen. Note that this means that your SMTP daemon must make the
# normalisations you want. Most importantly, enabling this option will make
# Crymap mail delivery CASE SENSITIVE TO USER NAMES.
verbatim_user_names = false

[diagnostic]
# If set, redirect standard error to this file on startup.
#
# This is applied before any part of the security configuration is
# applied and before any communication with the remote host.
#
# This is useful if `inetd` (or equivalent) or your MTA runs Crymap such
# that standard error goes to a less useful place, such as to the remote
# host. If anything actually ends up in this file, it represents a bug in
# Crymap, as actual errors should go through the logging system.
stderr = null
```

## Logging

By default, Crymap logs to syslog under the "mail" facility.

If you want to do something else, you can create a file named `logging.toml`
next to `crymap.toml`. This file is a [log4rs](https://docs.rs/log4rs)
configuration file. The exact format of this file is not extensively
documented, so if you want to do this, you're unfortunately on your own for
now. Note that there is not currently a way to log to syslog *and* a separate
logging system simultaneously at this time.

Here is a basic example of a `logging.toml` file:

```toml
[appenders.file]
kind = "rolling_file"
path = "/var/log/crymap/crymap.log"
append = true

[appenders.file.policy.trigger]
kind = "size"
limit = "10 MB"

[appenders.file.policy.roller]
kind = "delete"

[appenders.file.encoder]
kind = "pattern"
pattern = "{d(%Y-%m-%dT%H:%M:%S)} [{l}][{t}] {m}{n}"

[root]
level = "info"
appenders = ["file"]
```
