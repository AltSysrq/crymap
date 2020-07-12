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

//! The integration tests are near "full-stack" tests which run the actual
//! client and server code, without test-specific modifications and with as
//! little "reaching under the covers" as possible.
//!
//! Since initialising an account, particularly with the default RSA settings,
//! is a somewhat slow process, the tests will share a single system directory
//! and account as long as they are run concurrently. (The system directory is
//! removed as soon as no test using it is running to ensure that it does in
//! fact get cleaned up in all cases.)
//!
//! Each "connection" spawns a dedicated server thread. The client communicates
//! to the server over a pair of UNIX pipes (as in `pipe(2)`), which presents a
//! reasonable approximation of a real network connection without the tests
//! needing to worry about port numbers and such.
//!
//! Since the tests run within one account, they typically create their own
//! mailbox or mailbox hierarchy, each named after the test in question.

mod defs;

mod rfc3501;
