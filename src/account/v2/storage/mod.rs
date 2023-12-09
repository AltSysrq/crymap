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

//! The storage layer for the V2 system.
//!
//! The storage layer is stateless (aside from SQLite connections themselves
//! and the key cache) and provides the fundamental building blocks used to
//! implement the state layer. The general guidelines are:
//!
//! 1. Every operation is atomic unless otherwise noted.
//! 2. The concept of a database transaction does not escape the storage layer.

mod db_migrations;
mod deliverydb;
mod metadb;
mod sqlite_xex_vfs;
mod types;
