# User Guide

## Mail server settings

Assuming your administrator has not indicated otherwise:

- Protocol: IMAPS or IMAP (POP not supported)
- Host/domain: Provided by administrator
- Port: 993
- Connection security: "SSL/TLS", "Secure connection"; *not* "STARTTLS"
- Password/Authentication: "Normal", "plain"

Do not proceed if you receive certificate or security warnings.

Mail submission settings must be provided by your administrator.

## Changing your password or settings

To change your Crymap password or Crymap settings, you currently need the
`crymap` program. Your administrator should provide this; if not, refer to the
[installation subsection](installation-guide.md#installation) for ways to get
`crymap`. (This is the same program used to run Crymap on the mail server.)

### Changing your password

To change your IMAP password, run the below command, where `USER` is the
username you use to log in to IMAP, and `HOST` is the host or domain you use to
connect to IMAP:

```text
crymap remote chpw --user=USER --host=HOST
```

The password change takes effect immediately, but does not terminate existing
IMAP sessions.

**Note that your Crymap password is independent of your other email
password(s).** You need to change both. (It is possible to use different
passwords for the separate systems too, if you prefer, though not all mail
clients can work with such a configuration.)

If you find you need to undo the password change, the administrator can help
you with that.

### Changing key rotation settings

By default, Crymap rotates your mail encryption keys once per month. Rotation
is controlled by _key name templates_, which are filled in with the current
time. Changing these templates to include more or less of the date will have
the effect of changing the key rotation frequency.

Below are some examples of setting the key rotation.

```sh
# Rotate once per day
crymap remote config --external-key-pattern "external-%Y-m-%d" \
    --internal-key-pattern "internal-%Y-%m-%d" --user=USER --host=HOST
# Rotate once per year
crymap remote config --external-key-pattern "external-%Y" \
    --internal-key-pattern "internal-%Y" --user=USER --host=HOST
# Rotate once per week
crymap remote config --external-key-pattern "external-%Y-%W" \
    --internal-key-pattern "internal-%Y-%W" --user=USER --host=HOST
```

### Viewing the current configuration

To view the current configuration, simply run

```sh
crymap remote config --user=USER --host=HOST
```
