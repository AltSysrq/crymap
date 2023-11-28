//-
// Copyright (c) 2023, Jason Lingle
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

//! The storage system that was used in Crymap before version 2.0.
//!
//! V1 storage uses a complex and delicate "filesystem as a database" model,
//! described in more detail in each module.
//!
//! The code here is the entire storage layer from Crymap 1.x. In the binary
//! build, it is used in a read-only manner to migrate to the V2 model. Tests
//! do use the write support to generate scenarios to test the migration path.
#![allow(dead_code)]

pub mod account;
mod hier_id_scheme;
pub mod mailbox;
pub mod mailbox_path;
mod mailbox_state;
mod recency_token;
