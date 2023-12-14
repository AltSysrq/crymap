//-
// Copyright (c) 2020, 2023, Jason Lingle
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

use std::fmt;
use std::iter;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A bitset strongly memory-optimised for the case where no bits over 63 are
/// required, with no unsafe code.
///
/// This is internally just an inline `u64` and an `Option<Box<Vec<u64>>>`, so
/// that the inline overhead (relative to the `u64` alone) is only one pointer.
/// Unsafe code could make it more compact by representing it as a union
/// between a `usize` and a `Box<Vec<u64>>`, using bit 0 of the `usize` to
/// distinguish cases, but that's not worth it.
///
/// An `enum { Inline(u64), OutOfLine(Box<Vec<u64>>) }` is as large as this
/// structure but with inferior characteristics.
///
/// Serialises as a `[u64]`, with the "near" element *last*.
#[derive(Clone, Default)]
pub struct SmallBitset {
    near: u64,
    #[allow(clippy::box_collection)]
    far: Option<Box<Vec<u64>>>,
}

impl fmt::Debug for SmallBitset {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SmallBitset")?;
        f.debug_list().entries(self.iter()).finish()
    }
}

impl SmallBitset {
    /// Initialise a new, empty bitset.
    pub fn new() -> Self {
        Self::default()
    }

    /// Initialise a new bitset with the given near bits and no far bits.
    pub fn new_with_near(near: u64) -> Self {
        Self { near, far: None }
    }

    /// Insert `val` into the bitset.
    ///
    /// Returns true if the element was not already present.
    pub fn insert(&mut self, val: usize) -> bool {
        let (word, mask) = self.addr_mut(val);
        let ret = 0 == (*word & mask);
        *word |= mask;
        ret
    }

    /// Remove `val` from the bitset.
    ///
    /// Returns true if the element was present.
    pub fn remove(&mut self, val: usize) -> bool {
        let (word, mask) = self.addr_mut(val);
        let ret = 0 != (*word & mask);
        *word &= !mask;
        ret
    }

    /// Return whether the given element is currently in the bitset.
    pub fn contains(&self, val: usize) -> bool {
        let (word, mask) = self.addr(val);
        0 != (word & mask)
    }

    /// Iterate over all the values in the bitset.
    pub fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        static EMPTY: Vec<u64> = Vec::new();
        iter::once(self.near)
            .chain(self.far.as_deref().unwrap_or(&EMPTY).iter().copied())
            .enumerate()
            .flat_map(move |(ix, word)| {
                (0..64)
                    .filter(move |&bit| 0 != (word & (1 << bit)))
                    .map(move |bit| bit + ix * 64)
            })
    }

    /// Iterates over the far values in the bitset.
    pub fn iter_far(&self) -> impl Iterator<Item = usize> + '_ {
        self.iter().filter(|&i| i >= 64)
    }

    // TODO Add tests around these set functions

    /// Add all flags from `rhs` to `self`.
    pub fn add_all(&mut self, rhs: &Self) {
        self.near |= rhs.near;
        for i in rhs.iter_far() {
            self.insert(i);
        }
    }

    /// Remove all flags from `rhs` in `self`.
    pub fn remove_all(&mut self, rhs: &Self) {
        self.near &= !rhs.near;
        for i in rhs.iter_far() {
            self.remove(i);
        }
    }

    /// Remove all flags from `self` not set in `rhs`.
    pub fn remove_complement(&mut self, rhs: &Self) {
        self.near &= rhs.near;
        for i in self.clone().iter_far() {
            if !rhs.contains(i) {
                self.remove(i);
            }
        }
    }

    /// Returns the bitset of the "near" 64 values.
    pub fn near_bits(&self) -> u64 {
        self.near
    }

    /// Returns whether the bitset has any "far" (>=64) values.
    pub fn has_far(&self) -> bool {
        self.far.is_some()
    }

    fn addr_mut(&mut self, val: usize) -> (&mut u64, u64) {
        if val < 64 {
            (&mut self.near, 1 << val)
        } else {
            let ix = val / 64 - 1;
            let far = self.far.get_or_insert_with(Box::default);
            if far.len() <= ix {
                far.resize(ix + 1, 0);
            }

            (&mut far[ix], 1 << (val % 64))
        }
    }

    fn addr(&self, val: usize) -> (u64, u64) {
        if val < 64 {
            (self.near, 1 << val)
        } else if let Some(far) = self.far.as_ref() {
            let ix = val / 64 - 1;
            (far.get(ix).copied().unwrap_or(0), 1 << (val % 64))
        } else {
            (0, 1 << (val % 64))
        }
    }
}

impl Serialize for SmallBitset {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match self.far {
            None => {
                let near_array = [self.near];
                if self.near == 0 {
                    &[] as &[u64]
                } else {
                    &near_array as &[u64]
                }
                .serialize(serializer)
            },
            Some(ref far) => {
                let mut elements = Vec::clone(far);
                elements.push(self.near);
                elements.serialize(serializer)
            },
        }
    }
}

impl<'de> Deserialize<'de> for SmallBitset {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        let mut elements: Vec<u64> = Vec::deserialize(deserializer)?;
        let near = elements.pop().unwrap_or(0);
        Ok(SmallBitset {
            near,
            far: if elements.is_empty() {
                None
            } else {
                Some(Box::new(elements))
            },
        })
    }
}

impl std::iter::FromIterator<usize> for SmallBitset {
    fn from_iter<T: IntoIterator<Item = usize>>(iter: T) -> Self {
        let mut this = Self::new();
        for bit in iter {
            this.insert(bit);
        }
        this
    }
}

#[cfg(test)]
impl From<Vec<usize>> for SmallBitset {
    fn from(v: Vec<usize>) -> Self {
        v.into_iter().collect()
    }
}

// TODO Add unit test
impl std::cmp::PartialEq for SmallBitset {
    fn eq(&self, rhs: &Self) -> bool {
        if self.near != rhs.near {
            return false;
        }

        match (&self.far, &rhs.far) {
            (&None, &None) => true,
            (&Some(ref v), &None) | (&None, &Some(ref v)) => {
                v.iter().all(|&w| 0 == w)
            },
            (&Some(ref lhs), &Some(ref rhs)) => {
                let len = lhs.len().max(rhs.len());
                lhs.iter()
                    .copied()
                    .chain(std::iter::repeat(0))
                    .zip(rhs.iter().copied().chain(std::iter::repeat(0)))
                    .take(len)
                    .all(|(lhs, rhs)| lhs == rhs)
            },
        }
    }
}

impl std::cmp::Eq for SmallBitset {}

#[cfg(test)]
mod test {
    use serde_cbor;

    use super::*;

    #[test]
    fn basic_operations() {
        let mut bs = SmallBitset::new();

        assert!(!bs.contains(0));
        assert!(!bs.contains(100));
        assert!(!bs.contains(usize::MAX));

        assert!(bs.insert(0));
        assert!(bs.insert(42));
        assert!(!bs.insert(42));

        assert!(bs.contains(0));
        assert!(!bs.contains(1));
        assert!(bs.contains(42));

        assert_eq!(vec![0, 42], bs.iter().collect::<Vec<_>>());

        assert!(bs.remove(0));
        assert!(!bs.remove(0));
        assert!(!bs.contains(0));
        assert!(bs.contains(42));

        assert_eq!(vec![42], bs.iter().collect::<Vec<_>>());

        assert!(bs.insert(100));
        assert!(bs.contains(100));
        assert_eq!(vec![42, 100], bs.iter().collect::<Vec<_>>());

        assert!(bs.insert(1000));
        assert!(bs.contains(1000));
        assert_eq!(vec![42, 100, 1000], bs.iter().collect::<Vec<_>>());

        assert!(bs.remove(100));
        assert!(!bs.contains(100));
        assert_eq!(vec![42, 1000], bs.iter().collect::<Vec<_>>());
    }

    fn serde_flip(bs: &SmallBitset) {
        let as_bytes = serde_cbor::to_vec(bs).unwrap();
        let reread: SmallBitset =
            serde_cbor::from_reader(&as_bytes[..]).unwrap();

        assert_eq!(
            bs.iter().collect::<Vec<_>>(),
            reread.iter().collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_serde() {
        let mut bs = SmallBitset::new();
        serde_flip(&bs);

        bs.insert(0);
        serde_flip(&bs);

        bs.insert(42);
        serde_flip(&bs);

        bs.remove(0);
        serde_flip(&bs);

        bs.insert(100);
        serde_flip(&bs);

        bs.insert(1000);
        serde_flip(&bs);

        bs.remove(42);
        serde_flip(&bs);

        bs.remove(1000);
        serde_flip(&bs);
    }
}
