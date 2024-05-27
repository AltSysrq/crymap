# Configuration Reference

## crymap.toml

Below is an example `crymap.toml` with every option explicitly set to the
default (or an example value if there is no default) and comments explaining
what each one does.

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
# The contents of this section is examples and not defaults, as the default
# configuration is empty.
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

# The [smtp] section applies when Crymap is run with `crymap server serve-lmtp`,
# `crymap server serve-smtpin`, `crymap server serve-smtpsub`, and
# `crymap server serve-smtpssub`.
#
# In Crymap 1.x, this section was called `[lmtp]`, and that name is still
# supported for backwards-compatibility.
[smtp]
# If non-empty, Crymap will report this value as its hostname.
# By default, Crymap reports the system host name.
# Explicit configuration of this value is required for outbound SMTP support
# as a fully-qualified domain is required in that case.
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
#
# You probably shouldn't set this to true if Crymap is fronting SMTP itself.
verbatim_user_names = false

# By default, Crymap evaluates DMARC for inbound SMTP but does not take any
# action on DMARC failures.
# If set to true, Crymap will reject inbound SMTP transactions if the DMARC
# evaluation fails and the DMARC record requests to reject such failures.
#
# This has no effect on LMTP or SMTP submission.
reject_dmarc_failures = false

# Each entry under `smtp.domains` describes an SMTP domain the Crymap server
# will support. You only need to configure this if Crymap is handling SMTP
# itself.
# Simply defining a table, even if empty, is sufficient to make Crymap consider
# the domain usable.
[smtp.domains."example.com"]
# Each value under `dkim` defines a DKIM key which will be used to sign
# messages originating from this domain. They have no effect on inbound
# messages.
#
# The part after `dkim.` is the DKIM selector. The value is either `rsa:DATA`,
# where DATA is a base64-encoded RSA private key in DER format, or
# `ed25519:DATA`, where DATA is a base64-encoded ED25519 private key in raw
# format.
#
# If there are multiple keys for one domain, they will all be used to sign the
# message, in lexicographical order. Note that Microsoft Exchange only examines
# the first DKIM header on a message, and fails the message if it does not know
# about the signature algorithm. As of 2024-05, it does not understand ED25519,
# so you should ensure that the first key (in lexicographical order, not
# necessarily the written in the configuration) is a reasonably-sized RSA key
# if you care about talking to people on Exchange/Outlook.com/Hotmail/etc.
dkim.selector1 = "rsa:MIQU2whmZwg<VERY LONG STRING...>"
dkim.selector2 = "ed25519:13SSM<LONG STRING...>"

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
