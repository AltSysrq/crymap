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

//! This module contains everything to do with a single user's data: their
//! mailboxes, their settings, their keys.

pub(crate) mod account;
mod hier_id_scheme;
pub(crate) mod key_store;
pub(crate) mod mailbox;
pub(crate) mod mailbox_path;
mod mailbox_state;
pub(crate) mod model;
mod recency_token;
