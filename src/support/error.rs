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

use std::io;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Unsafe key or mailbox name")]
    UnsafeName,
    #[error("Master key unavailable")]
    MasterKeyUnavailable,
    #[error("Named key not found")]
    NamedKeyNotFound,
    #[error("Encrypted key malformed")]
    BadEncryptedKey,
    #[error("Mailbox full")]
    MailboxFull,
    #[error("Mailbox read-only")]
    MailboxReadOnly,
    #[error("Mailbox already exists")]
    MailboxExists,
    #[error("Mailbox has inferiors")]
    MailboxHasInferiors,
    #[error("Mailbox is not selectable")]
    MailboxUnselectable,
    #[error("Operation not allowed for INBOX")]
    BadOperationOnInbox,
    #[error("No such mailbox")]
    NxMailbox,
    #[error("Message expunged")]
    ExpungedMessage,
    #[error("Message not addressable by sequence number")]
    UnaddressableMessage,
    #[error("Non-existent message")]
    NxMessage,
    #[error("Unsupported/unknown flag")]
    NxFlag,
    #[error("Corrupted flag bitmap")]
    CorruptFlag,
    #[error("Gave up atomic insertion after too many retries")]
    GaveUpInsertion,
    #[error("File/directory layout is corrupt")]
    CorruptFileLayout,
    #[error("Unsupported special-use for CREATE")]
    UnsupportedSpecialUse,
    #[error("Rename source and destination are the same")]
    RenameToSelf,
    #[error("Rename destination is child of self")]
    RenameIntoSelf,
    #[error("Too many items in batch operation")]
    BatchTooBig,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Nix(#[from] nix::Error),
    #[error(transparent)]
    Ssl(#[from] openssl::error::ErrorStack),
    #[error(transparent)]
    Cbor(#[from] serde_cbor::error::Error),
    #[error(transparent)]
    Toml(#[from] toml::de::Error),
}
