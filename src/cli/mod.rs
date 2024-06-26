//-
// Copyright (c) 2020, 2024 Jason Lingle
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

macro_rules! die {
    ($ex:ident, $($stuff:tt)*) => {{
        eprintln!($($stuff)*);
        crate::support::sysexits::$ex.exit()
    }}
}

pub mod main;

#[cfg(feature = "dev-tools")]
mod imap_test;

mod deliver;
mod remote;
mod sanity;
mod serve;
mod user;
