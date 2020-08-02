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

use std::cell::RefCell;
use std::io::{self, Read, Write};
use std::rc::Rc;

/// Wraps a type in a `Rc<RefCell<T>>` and provides the `std::io` traits for it
/// through simple delegation.
///
/// This is used to take a single bidirectional stream and split it into
/// separate read and write parts (since, e.g., the read side often needs to be
/// wrapped in a `BufReader`).
#[derive(Debug)]
pub struct RcIo<T>(Rc<RefCell<T>>);

impl<T> RcIo<T> {
    pub fn wrap(inner: T) -> Self {
        RcIo(Rc::new(RefCell::new(inner)))
    }
}

impl<T> Clone for RcIo<T> {
    fn clone(&self) -> Self {
        RcIo(Rc::clone(&self.0))
    }
}

impl<T: Read> Read for RcIo<T> {
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        self.0.borrow_mut().read(dst)
    }
}

impl<T: Write> Write for RcIo<T> {
    fn write(&mut self, src: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().write(src)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.borrow_mut().flush()
    }
}
