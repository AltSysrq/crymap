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
use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::rc::{Rc, Weak};

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
///
/// The cache maintains an internal list of tasks which have not yet completed.
/// When the `Cache` is dropped, all tasks are cancelled. The tasks themselves
/// do not keep the `Rc` alive.
#[derive(Debug)]
pub struct Cache {
    pub name_intern: HashMap<String, Rc<Name>>,
    pub a: CacheMap<Vec<Ipv4Addr>>,
    pub aaaa: CacheMap<Vec<Ipv6Addr>>,
    pub txt: CacheMap<Vec<Rc<str>>>,
    pub mx: CacheMap<Vec<Rc<Name>>>,
    pub ptr: HashMap<IpAddr, Entry<Vec<Rc<Name>>>>,

    notify: Rc<tokio::sync::Notify>,
    in_flight_tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Default for Cache {
    fn default() -> Self {
        Self {
            name_intern: Default::default(),
            a: Default::default(),
            aaaa: Default::default(),
            txt: Default::default(),
            mx: Default::default(),
            ptr: Default::default(),

            notify: Rc::new(tokio::sync::Notify::new()),
            in_flight_tasks: Default::default(),
        }
    }
}

impl Drop for Cache {
    fn drop(&mut self) {
        for task in &self.in_flight_tasks {
            task.abort();
        }
    }
}

// These are association lists instead of hash maps because <Name as Hash>
// allocates like there's no tomorrow, and ultimately these won't be very big.
pub type CacheMap<T> = Vec<(Rc<Name>, Entry<T>)>;

/// An entry in the DNS cache passed to the SPF evaluator.
#[derive(Debug)]
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

pub async fn wait_for<T, F: FnMut(&mut Cache) -> Result<T, CacheError>>(
    cache: &Rc<RefCell<Cache>>,
    resolver: Option<&Rc<Resolver>>,
    mut look_up: F,
) -> Result<T, CacheError> {
    loop {
        let result = look_up(&mut cache.borrow_mut());
        if !matches!(result, Err(CacheError::NotReady)) {
            return result;
        }

        if resolver.is_none() {
            return Err(CacheError::Error);
        }

        spawn_lookups(cache, resolver);
        wait_for_progress(cache).await;
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

    let name = Name::from_ascii(&s).map(Rc::new).map_err(|_| ())?;
    cache.insert(s.into_owned(), Rc::clone(&name));
    Ok(name)
}

impl Cache {
    pub fn intern_domain(&mut self, s: Cow<'_, str>) -> Result<Rc<Name>, ()> {
        intern_domain(&mut self.name_intern, s)
    }
}

/// Wait for any lookup in the DNS cache to complete.
///
/// There must have been no await points between the check which found the
/// required name to be `NotReady` and this call.
pub async fn wait_for_progress(cache: &RefCell<Cache>) {
    let notify = Rc::clone(&cache.borrow().notify);
    notify.notified().await
}

/// Start any DNS lookups for `New` entries in the given task.
///
/// Entries are spawned in the contextual `LocalSet`.
///
/// If `resolver` is `None`, all new entries are immediately resolved to
/// `Error`.
pub fn spawn_lookups(
    cache: &Rc<RefCell<Cache>>,
    resolver: Option<&Rc<Resolver>>,
) {
    let mut cache_mut = cache.borrow_mut();
    let cache_mut = &mut *cache_mut;

    cache_mut.in_flight_tasks.retain(|t| !t.is_finished());

    spawn_name_lookups(
        &mut cache_mut.a,
        &mut cache_mut.in_flight_tasks,
        cache,
        resolver,
        |resolver, name| async move {
            resolver
                .ipv4_lookup(name)
                .await
                .map(|r| r.iter().map(|a| a.0).collect::<Vec<_>>())
        },
        |d| &mut d.a,
    );
    spawn_name_lookups(
        &mut cache_mut.aaaa,
        &mut cache_mut.in_flight_tasks,
        cache,
        resolver,
        |resolver, name| async move {
            resolver
                .ipv6_lookup(name)
                .await
                .map(|r| r.iter().map(|a| a.0).collect::<Vec<_>>())
        },
        |d| &mut d.aaaa,
    );
    spawn_name_lookups(
        &mut cache_mut.mx,
        &mut cache_mut.in_flight_tasks,
        cache,
        resolver,
        |resolver, name| async move {
            resolver.mx_lookup(name).await.map(|r| {
                r.iter()
                    .map(|n| Rc::new(n.exchange().clone()))
                    .collect::<Vec<_>>()
            })
        },
        |d| &mut d.mx,
    );
    spawn_name_lookups(
        &mut cache_mut.txt,
        &mut cache_mut.in_flight_tasks,
        cache,
        resolver,
        |resolver, name| async move {
            resolver.txt_lookup(name).await.map(|r| {
                r.iter()
                    .map(|parts| {
                        let len = parts.iter().map(|p| p.len()).sum();
                        let mut combined = Vec::with_capacity(len);
                        for part in parts.iter() {
                            combined.extend_from_slice(part);
                        }

                        match String::from_utf8(combined) {
                            Ok(s) => s,
                            Err(e) => String::from_utf8_lossy(e.as_bytes())
                                .into_owned(),
                        }
                        .into()
                    })
                    .collect::<Vec<_>>()
            })
        },
        |d| &mut d.txt,
    );

    for (&ip, entry) in &mut cache_mut.ptr {
        if !matches!(*entry, Entry::New) {
            continue;
        }

        let Some(resolver) = resolver else {
            *entry = Entry::Error;
            continue;
        };

        *entry = Entry::Pending;

        let cache = Rc::downgrade(cache);
        let resolver = Rc::clone(resolver);
        cache_mut
            .in_flight_tasks
            .push(tokio::task::spawn_local(async move {
                let new_entry =
                    to_entry(resolver.reverse_lookup(ip).await.map(|rev| {
                        rev.iter()
                            .map(|n| Rc::new(n.0.clone()))
                            .collect::<Vec<_>>()
                    }));

                let Some(cache) = Weak::upgrade(&cache) else {
                    return;
                };

                let mut cache = cache.borrow_mut();
                cache.ptr.insert(ip, new_entry);
                cache.notify.notify_waiters();
            }));
    }
}

fn spawn_name_lookups<T, R, F, A>(
    map: &mut CacheMap<T>,
    tasks: &mut Vec<tokio::task::JoinHandle<()>>,
    cache: &Rc<RefCell<Cache>>,
    resolver: Option<&Rc<Resolver>>,
    run: F,
    access: A,
) where
    R: Future<Output = Result<T, hickory_resolver::error::ResolveError>>
        + 'static,
    F: FnOnce(Rc<Resolver>, Name) -> R + Clone + 'static,
    A: FnOnce(&mut Cache) -> &mut CacheMap<T> + Clone + 'static,
{
    for entry in map {
        if !matches!(entry.1, Entry::New) {
            continue;
        }

        let Some(resolver) = resolver else {
            entry.1 = Entry::Error;
            continue;
        };

        entry.1 = Entry::Pending;

        let run = run.clone();
        let access = access.clone();
        let cache = Rc::downgrade(cache);
        let resolver = Rc::clone(resolver);
        let name = Rc::clone(&entry.0);
        tasks.push(tokio::task::spawn_local(async move {
            let mut name_clone = (*name).clone();
            name_clone.set_fqdn(true);
            let new_entry = to_entry(run(resolver, name_clone).await);

            let Some(cache) = Weak::upgrade(&cache) else {
                return;
            };
            let mut cache = cache.borrow_mut();
            for entry in access(&mut cache) {
                if name == entry.0 {
                    entry.1 = new_entry;
                    break;
                }
            }
            cache.notify.notify_waiters();
        }));
    }
}

fn to_entry<T>(
    r: Result<T, hickory_resolver::error::ResolveError>,
) -> Entry<T> {
    use hickory_resolver::error::ResolveErrorKind as Rek;

    match r {
        Ok(v) => Entry::Ok(v),
        Err(e) => match *e.kind() {
            Rek::NoRecordsFound { .. } => Entry::NotFound,
            _ => Entry::Error,
        },
    }
}
