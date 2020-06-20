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

use std::borrow::Cow;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddrSpec<'a> {
    pub local: Vec<Cow<'a, [u8]>>,
    pub domain: Vec<Cow<'a, [u8]>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MailboxSpec<'a> {
    pub addr: AddrSpec<'a>,
    pub name: Vec<Cow<'a, [u8]>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupSpec<'a> {
    pub name: Vec<Cow<'a, [u8]>>,
    pub boxes: Vec<MailboxSpec<'a>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Address<'a> {
    Mailbox(MailboxSpec<'a>),
    Group(GroupSpec<'a>),
}
