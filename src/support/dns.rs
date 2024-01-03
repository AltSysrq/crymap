//-
// Copyright (c) 2023, 2024, Jason Lingle
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
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::rc::Rc;

pub use hickory_resolver::Name;

pub type Resolver = hickory_resolver::AsyncResolver<
    hickory_resolver::name_server::GenericConnector<
        hickory_resolver::name_server::TokioRuntimeProvider,
    >,
>;

/// A cache of DNS records used by SPF evaluation and other validators.
///
/// The evaluator creates entries with status `New` as it discovers them. The
/// driver is responsible for actually fetching them and updating their status
/// as they become available.
#[derive(Default)]
pub struct Cache {
    pub name_intern: HashMap<String, Rc<Name>>,
    pub a: CacheMap<Vec<Ipv4Addr>>,
    pub aaaa: CacheMap<Vec<Ipv6Addr>>,
    pub txt: CacheMap<Vec<Rc<str>>>,
    pub mx: CacheMap<Vec<Rc<Name>>>,
    pub ptr: HashMap<IpAddr, Entry<Vec<Rc<Name>>>>,
}

// These are association lists instead of hash maps because <Name as Hash>
// allocates like there's no tomorrow, and ultimately these won't be very big.
pub type CacheMap<T> = Vec<(Rc<Name>, Entry<T>)>;

/// An entry in the DNS cache passed to the SPF evaluator.
pub enum Entry<T> {
    /// The query succeeded, and these are its results.
    Ok(T),
    /// The query succeeded and returned no results.
    NotFound,
    /// The query failed.
    Error,
    /// The query is in-flight.
    Pending,
    /// The evaluator newly discovered the need for this query.
    New,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheError {
    NotFound,
    Error,
    NotReady,
}

pub trait MaybeBorrowedName {
    fn as_dns_name_ref(&self) -> &Name;
    fn into_rc_dns_name(self) -> Rc<Name>;
}

impl MaybeBorrowedName for Name {
    fn as_dns_name_ref(&self) -> &Name {
        self
    }

    fn into_rc_dns_name(self) -> Rc<Name> {
        Rc::new(self)
    }
}

impl MaybeBorrowedName for &Name {
    fn as_dns_name_ref(&self) -> &Name {
        self
    }

    fn into_rc_dns_name(self) -> Rc<Name> {
        Rc::new(self.clone())
    }
}

impl MaybeBorrowedName for Rc<Name> {
    fn as_dns_name_ref(&self) -> &Name {
        self
    }

    fn into_rc_dns_name(self) -> Rc<Name> {
        self
    }
}

impl MaybeBorrowedName for &Rc<Name> {
    fn as_dns_name_ref(&self) -> &Name {
        self
    }

    fn into_rc_dns_name(self) -> Rc<Name> {
        Rc::clone(self)
    }
}

/// Look `name` up in `cache`.
///
/// If `name` is not in the cache, put it into the `New` status and return
/// `NotReady`.
pub fn look_up<T>(
    cache: &mut CacheMap<T>,
    name: impl MaybeBorrowedName,
) -> Result<&T, CacheError> {
    // Work around https://github.com/rust-lang/rust/issues/54663
    let position = cache.iter().position(|e| &*e.0 == name.as_dns_name_ref());
    if let Some(position) = position {
        match cache[position].1 {
            Entry::Ok(ref v) => Ok(v),
            Entry::NotFound => Err(CacheError::NotFound),
            Entry::Error => Err(CacheError::Error),
            Entry::Pending | Entry::New => Err(CacheError::NotReady),
        }
    } else {
        cache.push((name.into_rc_dns_name(), Entry::New));
        Err(CacheError::NotReady)
    }
}

pub fn ptr(
    cache: &mut HashMap<IpAddr, Entry<Vec<Rc<Name>>>>,
    ip: IpAddr,
) -> Result<&'_ [Rc<Name>], CacheError> {
    match *cache.entry(ip).or_insert(Entry::New) {
        Entry::Ok(ref v) => Ok(v),
        Entry::NotFound => Err(CacheError::NotFound),
        Entry::Error => Err(CacheError::Error),
        Entry::Pending | Entry::New => Err(CacheError::NotReady),
    }
}

pub fn intern_domain(
    cache: &mut HashMap<String, Rc<Name>>,
    s: Cow<'_, str>,
) -> Result<Rc<Name>, ()> {
    // Work around https://github.com/rust-lang/rust/issues/54663
    if cache.contains_key(&*s) {
        return Ok(Rc::clone(cache.get(&*s).unwrap()));
    }

    let name = Name::from_ascii(&s)
        .map(Rc::new)
        .map_err(|_| ())?;
    cache.insert(s.into_owned(), Rc::clone(&name));
    Ok(name)
}

impl Cache {
    pub fn intern_domain(
        &mut self,
        s: Cow<'_, str>,
    ) -> Result<Rc<Name>, ()> {
        intern_domain(&mut self.name_intern, s)
    }
}
