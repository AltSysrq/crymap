//-
// Copyright (c) 2023, 2024, Jason Lingle
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

//! The in-memory state for the V2 state and storage system. This is the API
//! used by the IMAP protocol layer and the delivery systems.
//!
//! This module tree should be thought of as one large module, as it is very
//! tightly cross-coupled; the main types are `Account` and `ExternAccount`,
//! whose very large implementation is split across multiple files for
//! manageability.

mod defs;
mod delivery;
mod expunge;
mod fetch;
mod flags;
mod idle;
mod init;
mod mailboxes;
mod maintenance;
mod messages;
mod migration;
mod poll;
mod search;
mod select;
mod spool;
mod user_config;

#[cfg(feature = "dev-tools")]
mod zstd_train;

pub use defs::{Account, Mailbox};
pub use delivery::DeliveryAccount;
pub use fetch::FetchReceiver;
#[allow(unused_imports)] // TODO Remove
pub use spool::{SpooledMessage, SpooledMessageId};
