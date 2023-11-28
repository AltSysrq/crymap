//-
// Copyright (c) 2020, Jason Lingle
//
// This file is part of Crymap.
//
// Crymap is free software: you can  redistribute it and/or modify it under the
// terms of  the GNU General Public  License as published by  the Free Software
// Foundation, either version  3 of the License, or (at  your option) any later
// version.
//
// Crymap is distributed  in the hope that  it will be useful,  but WITHOUT ANY
// WARRANTY; without  even the implied  warranty of MERCHANTABILITY  or FITNESS
// FOR  A PARTICULAR  PURPOSE.  See the  GNU General  Public  License for  more
// details.
//
// You should have received a copy of the GNU General Public License along with
// Crymap. If not, see <http://www.gnu.org/licenses/>.

use std::fs;
use std::io::{self, BufRead, Read};
use std::mem;
use std::path::{Path, PathBuf};

use chrono::prelude::*;
use log::error;

use super::main::ServerDeliverSubcommand;
use crate::account::model::*;
use crate::account::v1::account::Account;
use crate::account::v1::mailbox::StatelessMailbox;
use crate::support::{
    chronox::*, error::Error, safe_name::is_safe_name, sysexits::*,
    system_config::SystemConfig, unix_privileges,
};

pub(super) fn deliver(
    system_config: SystemConfig,
    mut cmd: ServerDeliverSubcommand,
    mut users_root: PathBuf,
) {
    if let Err(exit) =
        unix_privileges::assume_system(&system_config.security, &mut users_root)
    {
        exit.exit();
    }

    let user_name = match cmd.user {
        Some(ref un) => un.clone(),
        None => match nix::unistd::User::from_uid(nix::unistd::getuid()) {
            Ok(Some(user)) => user.name,
            Ok(None) => die!(
                EX_NOUSER,
                "No entry found for UID {}",
                nix::unistd::getuid()
            ),
            Err(e) => die!(
                EX_OSERR,
                "Failed to look up passwd entry for UID {}: {}",
                nix::unistd::getuid(),
                e
            ),
        },
    };

    if !is_safe_name(&user_name) {
        die!(EX_NOUSER, "Bad user name: {}", user_name);
    }

    let mut user_root = users_root.join(&user_name);
    let log_prefix = format!("delivery:~{}", user_name);

    if !user_root.is_dir() {
        die!(EX_NOUSER, "{} is not a Crymap user.", user_name);
    }

    if let Err(exit) = unix_privileges::assume_user_privileges(
        &log_prefix,
        system_config.security.chroot_system,
        &mut user_root,
        false,
    ) {
        exit.exit();
    }

    let account = Account::new(log_prefix, user_root, None);

    if cmd.create {
        match account.create(CreateRequest {
            name: cmd.mailbox.clone(),
            special_use: vec![],
        }) {
            Ok(_) => (),
            Err(Error::MailboxExists) => (),
            Err(Error::UnsafeName) | Err(Error::BadOperationOnInbox) => {
                die!(EX_CANTCREAT, "{}: Bad mailbox name", cmd.mailbox);
            },
            Err(e) => {
                die!(EX_CANTCREAT, "Failed to create {}: {}", cmd.mailbox, e);
            },
        }
    }

    let mailbox = match account.mailbox(&cmd.mailbox, false) {
        Ok(mb) => mb,
        Err(Error::NxMailbox) | Err(Error::UnsafeName) => {
            die!(EX_CANTCREAT, "{}: Non-existent mailbox", cmd.mailbox)
        },
        Err(e) => die!(EX_SOFTWARE, "Failed to open {}: {}", cmd.mailbox, e),
    };

    let items = mem::take(&mut cmd.inputs);

    if let Err(e) =
        run_delivery(cmd, items.into_iter(), io::stdin().lock(), mailbox)
    {
        e.exit();
    }
}

trait DeliveryTarget {
    fn deliver<R: Read>(
        &mut self,
        flags: Vec<Flag>,
        data: R,
    ) -> Result<(), Error>;
}

impl DeliveryTarget for StatelessMailbox {
    fn deliver<R: Read>(
        &mut self,
        flags: Vec<Flag>,
        data: R,
    ) -> Result<(), Error> {
        let internal_date =
            FixedOffset::zero().from_utc_datetime(&Utc::now().naive_local());
        self.append(internal_date, flags, data)?;
        Ok(())
    }
}

fn run_delivery(
    cmd: ServerDeliverSubcommand,
    items: impl Iterator<Item = PathBuf>,
    mut stdin: impl Read,
    mut target: impl DeliveryTarget,
) -> Result<(), Sysexit> {
    for item in items {
        match deliver_single(&cmd, &item, &mut stdin, &mut target) {
            Ok(()) => (),
            Err(e) => {
                error!("Unable to process {}: {}", item.display(), e);
                return Err(match e {
                    Error::Io(e) if io::ErrorKind::NotFound == e.kind() => {
                        EX_NOINPUT
                    },
                    Error::Io(_) | Error::GaveUpInsertion => EX_UNAVAILABLE,
                    _ => EX_SOFTWARE,
                });
            },
        }
    }

    Ok(())
}

fn deliver_single(
    cmd: &ServerDeliverSubcommand,
    item: &Path,
    stdin: &mut impl Read,
    target: &mut impl DeliveryTarget,
) -> Result<(), Error> {
    let item_reader: Box<dyn BufRead> = if Path::new("-") == item {
        Box::new(io::BufReader::new(stdin))
    } else {
        Box::new(io::BufReader::new(fs::File::open(item)?))
    };

    let mut flags = cmd.flag.clone();
    if cmd.maildir_flags {
        flags.extend(extract_maildir_flags(item));
    }

    target.deliver(flags, NormaliseLineEnding::new(item_reader))?;
    Ok(())
}

fn extract_maildir_flags(path: &Path) -> impl Iterator<Item = Flag> + '_ {
    path.extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .chars()
        .filter_map(|ch| match ch {
            'D' => Some(Flag::Draft),
            'F' => Some(Flag::Flagged),
            'R' => Some(Flag::Answered),
            'S' => Some(Flag::Seen),
            'T' => Some(Flag::Deleted),
            _ => None,
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineEndingDisposition {
    Unknown,
    Unix,
    Dos,
}

#[derive(Debug, Clone)]
struct NormaliseLineEnding<R> {
    inner: R,
    disposition: LineEndingDisposition,
    has_trailing_cr: bool,
    has_queued_lf: bool,
}

impl<R> NormaliseLineEnding<R> {
    fn new(inner: R) -> Self {
        NormaliseLineEnding {
            inner,
            disposition: LineEndingDisposition::Unknown,
            has_trailing_cr: false,
            has_queued_lf: false,
        }
    }
}

impl<R: Read> Read for NormaliseLineEnding<R> {
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        if LineEndingDisposition::Dos == self.disposition {
            return self.inner.read(dst);
        }

        if dst.is_empty() {
            return Ok(0);
        }

        if self.has_queued_lf {
            self.has_queued_lf = false;
            dst[0] = b'\n';
            return Ok(1);
        }

        if 1 == dst.len() {
            // This is awkward; if we get a UNIX line ending, we need two bytes
            // of space.
            let nread = self.inner.read(dst)?;
            if 0 == nread {
                return Ok(0);
            }

            let ch = dst[0];
            if b'\n' == ch && LineEndingDisposition::Unknown == self.disposition
            {
                if self.has_trailing_cr {
                    self.disposition = LineEndingDisposition::Dos;
                } else {
                    self.disposition = LineEndingDisposition::Unix;
                }
            }

            let had_trailing_cr = self.has_trailing_cr;
            self.has_trailing_cr = b'\r' == ch;

            if LineEndingDisposition::Dos == self.disposition
                || b'\n' != ch
                || had_trailing_cr
            {
                return Ok(1);
            } else {
                // Need to convert \n to \r\n but we only have space for one
                // byte
                self.has_queued_lf = true;
                dst[0] = b'\r';
                return Ok(1);
            }
        }

        // Only read half the buffer, rounded down, since each byte we get
        // could be expanded into two.
        let dst_len = dst.len();
        let nread = self.inner.read(&mut dst[..dst_len / 2])?;
        if 0 == nread {
            return Ok(0);
        }

        // Look for UNIX line endings. On the first line ending found, we
        // decide whether this is overall a UNIX or canonical format.
        let mut unix_line_count = 0usize;
        for ix in memchr::memchr_iter(b'\n', &dst[..nread]) {
            let is_dos = (0 != ix && b'\r' == dst[ix - 1])
                || (0 == ix && self.has_trailing_cr);

            if LineEndingDisposition::Unknown == self.disposition {
                if is_dos {
                    self.disposition = LineEndingDisposition::Dos;
                    break;
                } else {
                    self.disposition = LineEndingDisposition::Unix;
                }
            }

            if !is_dos {
                unix_line_count += 1;
            }
        }

        let had_trailing_cr = self.has_trailing_cr;
        self.has_trailing_cr = b'\r' == dst[nread - 1];

        // If there are no line endings, or we decided the input is using DOS
        // line endings, no transform is needed.
        if LineEndingDisposition::Unix != self.disposition {
            return Ok(nread);
        }

        let mut src_ix = nread;
        let mut dst_ix = nread + unix_line_count;
        while src_ix > 0 {
            src_ix -= 1;
            dst_ix -= 1;

            let ch = dst[src_ix];
            dst[dst_ix] = ch;

            if b'\n' == ch {
                let is_dos = (0 != src_ix && b'\r' == dst[src_ix - 1])
                    || (0 == src_ix && had_trailing_cr);
                if !is_dos {
                    dst_ix -= 1;
                    dst[dst_ix] = b'\r';
                }
            }
        }

        Ok(nread + unix_line_count)
    }
}

#[cfg(test)]
mod test {
    use std::io::Write;
    use std::iter;

    use proptest::prelude::*;

    use super::*;

    #[test]
    fn test_extract_maildir_flags() {
        fn extract(s: &str) -> Vec<Flag> {
            extract_maildir_flags(Path::new(s)).collect()
        }

        assert_eq!(Vec::<Flag>::new(), extract("foo/bar"));
        assert_eq!(Vec::<Flag>::new(), extract(""));
        assert_eq!(Vec::<Flag>::new(), extract("-"));

        assert_eq!(vec![Flag::Answered], extract("foo.2R"));
        assert_eq!(vec![Flag::Flagged], extract("foo.2F"));
        assert_eq!(vec![Flag::Seen], extract("foo.2S"));
        assert_eq!(vec![Flag::Deleted], extract("foo.2T"));
        assert_eq!(vec![Flag::Draft], extract("foo.2D"));
        assert_eq!(
            vec![
                Flag::Answered,
                Flag::Flagged,
                Flag::Seen,
                Flag::Deleted,
                Flag::Draft
            ],
            extract("foo/bar.2RFSxTDy")
        );
    }

    fn assert_read_like(expected: &str, src: &mut impl Read, buf_size: usize) {
        // Initialise to \n since that is most likely to cause problems if the
        // Read implementation reads past the end of the used portion of the
        // buffer.
        let mut buf = vec![b'\n'; buf_size];
        let nread = src.read(&mut buf).unwrap();

        assert_eq!(expected, String::from_utf8_lossy(&buf[..nread]));
    }

    #[test]
    fn dos_line_non_conversion() {
        let mut r = NormaliseLineEnding::new(
            b"line 1\r\nline 2\r\nline 3\r\n" as &[u8],
        );
        assert_read_like("line 1\r\n", &mut r, 16);
        assert_read_like("line 2\r\nline 3\r\n", &mut r, 16);
        assert_read_like("", &mut r, 16);
    }

    #[test]
    fn dos_line_conversion_one_byte_at_a_time() {
        let mut r = NormaliseLineEnding::new(b"a\r\nb\nc\r\n" as &[u8]);
        assert_read_like("a", &mut r, 1);
        assert_read_like("\r", &mut r, 1);
        assert_read_like("\n", &mut r, 1);
        assert_read_like("b", &mut r, 1);
        assert_read_like("\n", &mut r, 1);
        assert_read_like("c", &mut r, 1);
        assert_read_like("\r", &mut r, 1);
        assert_read_like("\n", &mut r, 1);
        assert_read_like("", &mut r, 1);
    }

    #[test]
    fn unix_line_conversion() {
        let mut r =
            NormaliseLineEnding::new(b"line 1\nline 2\nline 3\n" as &[u8]);
        assert_read_like("line 1\r\n", &mut r, 14);
        assert_read_like("line 2\r\nline 3\r\n", &mut r, 28);
        assert_read_like("", &mut r, 28);
    }

    #[test]
    fn unix_line_conversion_one_byte_at_a_time() {
        let mut r = NormaliseLineEnding::new(b"a\nb\r\nc\n" as &[u8]);
        assert_read_like("a", &mut r, 1);
        assert_read_like("\r", &mut r, 1);
        assert_read_like("\n", &mut r, 1);
        assert_read_like("b", &mut r, 1);
        assert_read_like("\r", &mut r, 1);
        assert_read_like("\n", &mut r, 1);
        assert_read_like("c", &mut r, 1);
        assert_read_like("\r", &mut r, 1);
        assert_read_like("\n", &mut r, 1);
        assert_read_like("", &mut r, 1);
    }

    #[test]
    fn binary_content_not_converted_in_dos_input() {
        let mut r = NormaliseLineEnding::new(
            b"Header\r\n\r\nbinary\ncontent\nhere" as &[u8],
        );
        assert_read_like("Header\r\n\r\n", &mut r, 20);
        assert_read_like("binary\ncontent\nhere", &mut r, 100);
    }

    #[test]
    fn dos_line_endings_not_converted_in_unix_input() {
        let mut r = NormaliseLineEnding::new(b"Header\nmore\r\ntext" as &[u8]);
        assert_read_like("Header\r\n", &mut r, 14);
        assert_read_like("more\r\ntext", &mut r, 100);
    }

    #[test]
    fn dos_line_detected_from_split_read() {
        let mut r = NormaliseLineEnding::new(
            b"Header\r\n\r\nbinary\ncontent\nhere" as &[u8],
        );
        assert_read_like("Header\r", &mut r, 14);
        assert_read_like("\n\r\nbinary\ncontent\nhere", &mut r, 100);
    }

    #[test]
    fn unix_line_conversion_doesnt_convert_split_crlf() {
        let mut r = NormaliseLineEnding::new(b"Header\nmore\r\ntext" as &[u8]);
        assert_read_like("Header\r\n", &mut r, 14);
        assert_read_like("more\r", &mut r, 10);
        assert_read_like("\ntext", &mut r, 100);
    }

    proptest! {
        #[test]
        fn dos_conversion_is_always_verbatim(
            prelude in "[a-z]{0,32}",
            content in "[a-f\r\n\t]{0,100}",
            buffer_size in (1usize..=48usize)
        ) {
            let mut input = prelude.as_bytes().to_vec();
            input.extend_from_slice(b"\r\n");
            input.extend_from_slice(content.as_bytes());

            let mut r = NormaliseLineEnding::new(&input as &[u8]);
            let mut buffer = vec![0u8; buffer_size];
            let mut output = Vec::new();
            loop {
                let nread = r.read(&mut buffer).unwrap();
                if 0 == nread {
                    break;
                }

                output.extend_from_slice(&buffer[..nread]);
            }

            assert_eq!(
                String::from_utf8_lossy(&input),
                String::from_utf8_lossy(&output)
            );
        }

        #[test]
        fn unix_conversion_always_preserves_content(
            prelude in "[a-z]{0,32}",
            content in "[a-f\r\n\t]{0,100}",
            buffer_size in (2usize..=48usize)
        ) {
            let mut input = prelude.as_bytes().to_vec();
            input.extend_from_slice(b"\n");
            input.extend_from_slice(content.as_bytes());

            let mut r = NormaliseLineEnding::new(&input as &[u8]);
            let mut buffer = vec![0u8; buffer_size];
            let mut output = Vec::new();
            loop {
                let nread = r.read(&mut buffer).unwrap();
                if 0 == nread {
                    break;
                }

                output.extend_from_slice(&buffer[..nread]);
            }

            assert_eq!(
                String::from_utf8_lossy(&input).replace('\r', ""),
                String::from_utf8_lossy(&output).replace('\r', "")
            );
        }
    }

    #[derive(Debug, Default)]
    struct MockTarget {
        delivered: Vec<(Vec<Flag>, String)>,
    }

    impl<'a> DeliveryTarget for &'a mut MockTarget {
        fn deliver<R: Read>(
            &mut self,
            flags: Vec<Flag>,
            mut data: R,
        ) -> Result<(), Error> {
            let mut buf = Vec::new();
            data.read_to_end(&mut buf).unwrap();
            self.delivered
                .push((flags, String::from_utf8_lossy(&buf).into_owned()));
            Ok(())
        }
    }

    #[test]
    fn deliver_unix_from_stdin() {
        let flags = vec![Flag::Answered, Flag::Keyword("plugh".to_owned())];
        let cmd = ServerDeliverSubcommand {
            common: Default::default(),
            user: None,
            mailbox: "INBOX".to_owned(),
            create: false,
            flag: flags.clone(),
            maildir_flags: false,
            inputs: vec![],
        };
        let mut target = MockTarget::default();

        run_delivery(
            cmd,
            iter::once(Path::new("-").to_owned()),
            b"This is a message.\nFoo bar baz.\n" as &[u8],
            &mut target,
        )
        .unwrap();

        assert_eq!(
            vec![(
                flags.clone(),
                "This is a message.\r\nFoo bar baz.\r\n".to_owned()
            )],
            target.delivered
        );
    }

    #[test]
    fn deliver_dos_from_stdin() {
        let flags = vec![Flag::Answered, Flag::Keyword("plugh".to_owned())];
        let cmd = ServerDeliverSubcommand {
            common: Default::default(),
            user: None,
            mailbox: "INBOX".to_owned(),
            create: false,
            flag: flags.clone(),
            maildir_flags: false,
            inputs: vec![],
        };
        let mut target = MockTarget::default();

        run_delivery(
            cmd,
            iter::once(Path::new("-").to_owned()),
            b"This is a message.\r\nFoo bar baz.\r\n" as &[u8],
            &mut target,
        )
        .unwrap();

        assert_eq!(
            vec![(
                flags.clone(),
                "This is a message.\r\nFoo bar baz.\r\n".to_owned()
            )],
            target.delivered
        );
    }

    #[test]
    fn deliver_multiple_from_maildir() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let path_a = tmpdir.path().join("a.2D");
        let path_b = tmpdir.path().join("b.2RT");

        fs::File::create(&path_a)
            .unwrap()
            .write_all(b"DOS\r\nContent")
            .unwrap();
        fs::File::create(&path_b)
            .unwrap()
            .write_all(b"UNIX\nContent")
            .unwrap();

        let flags = vec![Flag::Flagged];

        let cmd = ServerDeliverSubcommand {
            common: Default::default(),
            user: None,
            mailbox: "INBOX".to_owned(),
            create: false,
            flag: flags.clone(),
            maildir_flags: true,
            inputs: vec![],
        };

        let mut target = MockTarget::default();
        run_delivery(
            cmd,
            vec![path_a, path_b].into_iter(),
            b"" as &[u8],
            &mut target,
        )
        .unwrap();

        assert_eq!(
            vec![
                (
                    vec![Flag::Flagged, Flag::Draft],
                    "DOS\r\nContent".to_owned()
                ),
                (
                    vec![Flag::Flagged, Flag::Answered, Flag::Deleted],
                    "UNIX\r\nContent".to_owned()
                ),
            ],
            target.delivered
        );
    }
}
