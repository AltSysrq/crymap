//-
// Copyright (c) 2020, 2023, 2024, Jason Lingle
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

mod bridge;
mod delivery;
mod lmtp;
mod server;
mod smtpin;
mod smtpsub;

#[cfg(test)]
mod integration_test_common;
#[cfg(test)]
mod lmtp_integration_tests;
#[cfg(test)]
mod smtpin_integration_tests;
#[cfg(test)]
mod smtpsub_integration_tests;

pub use lmtp::serve_lmtp;
pub use smtpin::serve_smtpin;
pub use smtpsub::serve_smtpsub;
