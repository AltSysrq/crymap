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

//! Constants from `sysexits.h`
//!
//! Relevant for things that use the sendmail/procmail/etc conventions for MTA
//! exit codes.
#![allow(dead_code)]

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Sysexit(pub i32);

pub const EX_USAGE: Sysexit = Sysexit(64);
pub const EX_DATAERR: Sysexit = Sysexit(65);
pub const EX_NOINPUT: Sysexit = Sysexit(66);
pub const EX_NOUSER: Sysexit = Sysexit(67);
pub const EX_NOHOST: Sysexit = Sysexit(68);
pub const EX_UNAVAILABLE: Sysexit = Sysexit(69);
pub const EX_SOFTWARE: Sysexit = Sysexit(70);
pub const EX_OSERR: Sysexit = Sysexit(71);
pub const EX_OSFILE: Sysexit = Sysexit(72);
pub const EX_CANTCREAT: Sysexit = Sysexit(73);
pub const EX_IOERR: Sysexit = Sysexit(74);
pub const EX_TEMPFAIL: Sysexit = Sysexit(75);
pub const EX_PROTOCOL: Sysexit = Sysexit(76);
pub const EX_NOPERM: Sysexit = Sysexit(77);
pub const EX_CONFIG: Sysexit = Sysexit(78);

impl Sysexit {
    pub fn exit(self) -> ! {
        std::process::exit(self.0)
    }
}
