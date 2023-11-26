//-
// Copyright (c) 2020, 2022, 2023, Jason Lingle
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

pub mod buffer;
pub mod chronox;
pub mod compression;
pub mod diagnostic;
pub mod error;
pub mod file_ops;
pub mod rcio;
pub mod safe_name;
pub mod small_bitset;
pub mod sysexits;
pub mod system_config;
pub mod threading;
pub mod un64;
pub mod unix_privileges;
pub mod user_config;
#[macro_use]
pub mod append_limit;
