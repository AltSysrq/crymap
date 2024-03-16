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

//! The V2 storage and state system was introduced with Crymap 2.0.0.

mod state;
mod storage;

pub use super::v1::account::account_config_file;
#[allow(unused_imports)] // TODO Remove
pub use state::{
    Account, DeliveryAccount, FetchReceiver, LogInError, Mailbox,
    SpooledMessage, SpooledMessageId,
};
