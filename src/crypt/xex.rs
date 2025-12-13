//-
// Copyright (c) 2023, Jason Lingle
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

//! An implementation of XEX (Xor-Encrypt-Xor) mode on AES-128, which supports
//! random-access read/write of the underlying data. It is used as the backing
//! for the main SQLite database.
//!
//! This is implemented using OpenSSL to perform ECB-mode AES-128 with manual
//! pre- and post-processing to implement the XOR steps. OpenSSL actually has
//! built-in support for XTS mode (a superset of XEX), but it's not clear how
//! to actually use it, or if it is even usable through the current Rust
//! bindings. XEX is very simple, however.
//!
//! XEX is described here:
//! <https://www.cs.ucdavis.edu/~rogaway/papers/offsets.pdf>
//!
//! The core idea of XEX is that, for each block, we generate some "tweak"
//! based solely on the block's position and some global permutation:
//!
//! ```text
//!   ciphertext = tweak(nonce, offset) ^ encrypt_ecb(
//!     key, tweak(nonce, offset) ^ cleartext)
//! ```
//!
//! The XEX paper suggests generating the tweak as follows:
//!
//! ```text
//!   tweak(nonce, 0) = encrypt_ecb(key, nonce)
//!   tweak(nonce, n) = {
//!     let pred = tweak(nonce, n - 1);
//!     // 2 * pred   in GF(2**128)
//!     if 0 == pred & 1 << 127 {
//!       pred << 1
//!     } else {
//!       (pred << 1) ^ 0b10000111
//!     }
//!   }
//!   // In general,
//!   tweak(nonce, n) = 2**n * nonce   in GF(2**128)
//! ```
//!
//! The stated goal of this approach is that generating each successive tweak
//! is extremely fast, at the cost of making it expensive to generate a tweak
//! in the middle of the stream.
//!
//! The particular choice of this approach appears to be a desire to support
//! multi-dimensional indices at the level of the cryptographic primitive (as
//! opposed to folding multiple dimensions into one dimension outside of the
//! primitive), as the paper also presents an option based on powers of 2 and 3
//! for two-dimensional indexing, and even powers of 2, 3, and 11 for
//! three-dimensional indexing.
//!
//! The issue for us is that computing a power of 2 in a Galois Field is more
//! expensive than the encryption itself if we don't have access to carry-less
//! multiplication primitives (which are present on most modern processors, but
//! OpenSSL doesn't expose functionality to do this multiplication, and Crymap
//! is not the place for novel assembly-coded algorithms).
//!
//! The proofs rely solely on the fact that these power-of-prime schemes
//! generate distinct values within the field for all input indices. This would
//! also be true of a simple increment function, something the paper does not
//! mention.
//!
//! The paper notably entirely fails to define serif-N (not to be confused with
//! sans-serif-N).
//!
//! Wikipedia gives some more details on the practical implementation of XEX:
//! <https://en.wikipedia.org/wiki/XTS_mode#Xor–encrypt–xor_(XEX)>
//! (Fascinatingly, the dedicated page on XEX does not have these details.)
//!
//! Wikipedia effectively defines
//! ```text
//! tweak(n) = encrypt_ecb(key, n / sector_size) * 2**(n%sector_size)  in GF(2**128)
//! ```
//!
//! For this implementation, we define a "sector" to be 64 blocks (1KB).
//! GF(2**128) multiplication can be done by powers of 2 up to 120 by a handful
//! of bitshifts and masks. We additionally XOR a constant nonce into the input
//! of `encrypt_ecb` to avoid revealing the encryption of the zero block.
//!
//! SQLite will try to create files that are not a whole multiple of the block
//! size. This implementation pads such writes to a full block size so that we
//! do not need any special handling of this case. In general, SQLite tolerates
//! arbitrary garbage at the end of its files.

use std::mem;

use super::{master_key::MasterKey, AES_BLOCK, AES_BLOCK64};

/// The backing store on which XEX operates.
///
/// In the real database, this delegates to the `sqlite_file` which we get from
/// SQLite's default VFS implementation.
pub trait Backing {
    type Error;

    /// Fill `dst` by reading bytes starting at `offset`.
    ///
    /// Returns an error if `dst` cannot be filled.
    fn read(&mut self, dst: &mut [u8], offset: u64) -> Result<(), Self::Error>;
    /// Write the full contents of `src` at `offset`.
    fn write(&mut self, src: &[u8], offset: u64) -> Result<(), Self::Error>;
    /// Returns the length of the backing store.
    fn len(&mut self) -> Result<u64, Self::Error>;
    /// Returns an appropriate error representing an encryption error.
    fn encryption_error() -> Self::Error;
}

/// We process this many blocks at once in order to spend more time in
/// OpenSSL's optimised AES code.
const GROUP_STRIDE: usize = 16;

/// The contextual state for XEX mode.
///
/// This does not actually contain the `Backing` to simplify lifetime
/// management.
pub struct Xex {
    nonce: [u8; AES_BLOCK],

    enc: openssl::symm::Crypter,
    dec: openssl::symm::Crypter,
    tweaker: Tweaker,

    // Reusable buffers to avoid having large memsets in leaf functions for
    // stack buffers or unsafe code for uninitialised buffers.
    tmp_tweaks: [[u8; AES_BLOCK]; GROUP_STRIDE],
    tmp_enc: [u8; AES_BLOCK * GROUP_STRIDE + AES_BLOCK],
    tmp_write: Vec<u8>,
}

impl Xex {
    /// Creates a new XEX context from the given master key which will be used
    /// with the given file.
    pub fn new(
        master: &MasterKey,
        filename: &str,
    ) -> Result<Self, crate::support::error::Error> {
        let key = master.xex_key(filename);
        let nonce = master.xex_nonce(filename);
        let mut enc = openssl::symm::Crypter::new(
            openssl::symm::Cipher::aes_128_ecb(),
            openssl::symm::Mode::Encrypt,
            &key,
            None,
        )?;
        enc.pad(false);
        let mut dec = openssl::symm::Crypter::new(
            openssl::symm::Cipher::aes_128_ecb(),
            openssl::symm::Mode::Decrypt,
            &key,
            None,
        )?;
        dec.pad(false);

        Ok(Self {
            nonce,
            enc,
            dec,

            tweaker: Tweaker::new(),
            tmp_tweaks: Default::default(),
            tmp_enc: [0u8; AES_BLOCK * GROUP_STRIDE + AES_BLOCK],
            tmp_write: Default::default(),
        })
    }

    /// Fills `dst` from `backing` starting at `offset`.
    ///
    /// For a non-empty `dst`, this will perform between 1 and 3 discrete read
    /// operations depending on the size and alignment of the request.
    pub fn read<B: Backing>(
        &mut self,
        backing: &mut B,
        mut dst: &mut [u8],
        mut offset: u64,
    ) -> Result<(), B::Error> {
        if dst.is_empty() {
            return Ok(());
        }

        let end = offset + dst.len() as u64;

        if !end.is_multiple_of(AES_BLOCK64) {
            // dst ends with an incomplete block.
            let final_block_start = end / AES_BLOCK64 * AES_BLOCK64;
            let final_block_len = end - final_block_start;
            if final_block_len as usize >= dst.len() {
                // dst is entirely contained by the final block. Read the block
                // from the beginning and then get the relevant portion into
                // dst.
                let mut block = [0u8; AES_BLOCK];
                let block = &mut block[..final_block_len as usize];
                self.read_incomplete_aligned_block(
                    backing,
                    block,
                    final_block_start,
                )?;
                let inner_off = (offset - final_block_start) as usize;
                dst.copy_from_slice(&block[inner_off..][..dst.len()]);
                return Ok(());
            }

            let dst_block_start = dst.len() - final_block_len as usize;
            self.read_incomplete_aligned_block(
                backing,
                &mut dst[dst_block_start..],
                final_block_start,
            )?;
            dst = &mut dst[..dst_block_start];
        }

        // We now know that `dst` ends on a block boundary.

        if !offset.is_multiple_of(AES_BLOCK64) {
            // dst begins with a misaligned block.
            let first_block_start = offset / AES_BLOCK64 * AES_BLOCK64;
            let first_block_len = AES_BLOCK64 - (offset - first_block_start);
            let mut block = [0u8; AES_BLOCK];
            self.read_aligned_blocks(backing, &mut block, first_block_start)?;
            dst[..first_block_len as usize]
                .copy_from_slice(&block[(offset % AES_BLOCK64) as usize..]);
            dst = &mut dst[first_block_len as usize..];
            offset += first_block_len;
        }

        // The remainder of dst is entirely aligned with block boundaries.

        self.read_aligned_blocks(backing, dst, offset)
    }

    /// Reads a single block into `dst` starting at `offset`, which must be
    /// aligned to a multiple of `AES_BLOCK64`.
    ///
    /// `dst.len()` shall be less than `AES_BLOCK`.
    fn read_incomplete_aligned_block<B: Backing>(
        &mut self,
        backing: &mut B,
        dst: &mut [u8],
        offset: u64,
    ) -> Result<(), B::Error> {
        debug_assert_eq!(0, offset % AES_BLOCK64);
        debug_assert!(dst.len() < AES_BLOCK);

        // We always have a whole block to read since we pad end-of-file writes
        // to the next block boundary.
        let mut whole = [0u8; AES_BLOCK];
        self.read_aligned_blocks(backing, &mut whole, offset)?;
        dst.copy_from_slice(&whole[..dst.len()]);

        Ok(())
    }

    /// Read some number of whole, aligned encryption blocks into `dst`
    /// starting at `offset`.
    fn read_aligned_blocks<B: Backing>(
        &mut self,
        backing: &mut B,
        dst: &mut [u8],
        offset: u64,
    ) -> Result<(), B::Error> {
        debug_assert_eq!(0, offset % AES_BLOCK64);
        debug_assert_eq!(0, dst.len() % AES_BLOCK);

        if dst.is_empty() {
            return Ok(());
        }

        // Read all the data we'll need in one go.
        backing.read(dst, offset)?;
        self.crypt::<B>(dst, offset, false)?;
        Ok(())
    }

    pub fn write<B: Backing>(
        &mut self,
        backing: &mut B,
        mut src: &[u8],
        mut offset: u64,
    ) -> Result<(), B::Error> {
        let end = offset + src.len() as u64;
        let tail_block_start = end / AES_BLOCK64 * AES_BLOCK64;
        let tail_block_len = end - tail_block_start;

        if tail_block_len as usize >= src.len() {
            // src is entirely contained within the block and might not be
            // aligned with it at the start, and is definitely not aligned with
            // it at the end.
            return self
                .write_incomplete_misaligned_block(backing, src, offset);
        }

        // For other cases where there's an incomplete block tail, we handle it
        // at the end.

        if !offset.is_multiple_of(AES_BLOCK64) {
            // The start of the write is not aligned to a block boundary, so do
            // the read-modify-write for that block separately.
            let new_offset = offset.next_multiple_of(AES_BLOCK64);
            let advance = (new_offset - offset) as usize;
            self.write_misaligned_block(backing, &src[..advance], offset)?;

            src = &src[advance..];
            offset = new_offset;
        }

        // Write all the aligned blocks covered by `src` in one go.
        self.write_aligned_blocks(
            backing,
            &src[..(tail_block_start - offset) as usize],
            offset,
        )?;

        if tail_block_len > 0 {
            // src extends into a block but does not completely cover it. Do
            // the read-modify-write cycle separately.
            self.write_incomplete_misaligned_block(
                backing,
                &src[(tail_block_start - offset) as usize..],
                tail_block_start,
            )?;
        }

        Ok(())
    }

    /// Writes a block whose `src` data does not extend to the end of the block
    /// and which may also not start at the beginning of the block.
    ///
    /// This handles the special case of padding to make the file a multiple of
    /// 16 bytes in size.
    fn write_incomplete_misaligned_block<B: Backing>(
        &mut self,
        backing: &mut B,
        src: &[u8],
        offset: u64,
    ) -> Result<(), B::Error> {
        debug_assert!(src.len() < AES_BLOCK);

        let mut block = [0u8; AES_BLOCK];
        let block_start = offset / AES_BLOCK64 * AES_BLOCK64;

        let end = offset + src.len() as u64;
        if backing.len()? >= end {
            self.read_aligned_blocks(backing, &mut block, block_start)?;
        }

        block[(offset % AES_BLOCK64) as usize..][..src.len()]
            .copy_from_slice(src);
        self.write_aligned_blocks(backing, &block, block_start)
    }

    /// Writes a block whose `src` data does not begin at the start of a
    /// block, but which does run to the end of a block.
    fn write_misaligned_block<B: Backing>(
        &mut self,
        backing: &mut B,
        src: &[u8],
        offset: u64,
    ) -> Result<(), B::Error> {
        debug_assert!(src.len() < AES_BLOCK);
        debug_assert_eq!(0, (offset + src.len() as u64) % AES_BLOCK64);

        let mut block = [0u8; AES_BLOCK];
        let block_start = offset / AES_BLOCK64 * AES_BLOCK64;
        self.read_aligned_blocks(backing, &mut block, block_start)?;
        block[AES_BLOCK - src.len()..].copy_from_slice(src);
        self.write_aligned_blocks(backing, &block, block_start)
    }

    /// Writes some number of whole blocks starting at the given offset.
    fn write_aligned_blocks<B: Backing>(
        &mut self,
        backing: &mut B,
        src: &[u8],
        offset: u64,
    ) -> Result<(), B::Error> {
        assert_eq!(0, offset % AES_BLOCK64);
        assert_eq!(0, src.len() % AES_BLOCK);

        // src is immutable because SQLite's xWrite method passes a `const
        // void*`, so we can't use `src` as scratch space, unfortunately.
        // Instead, we grab a reusable vec, so that we can still do the entire
        // write in one call to the backing store.
        let mut tmp = mem::take(&mut self.tmp_write);
        tmp.clear();
        tmp.extend_from_slice(src);
        let result = self.crypt::<B>(&mut tmp, offset, true);
        // Put the vec back before possibly returning early.
        self.tmp_write = tmp;
        result?;
        backing.write(&self.tmp_write, offset)
    }

    /// Apply encryption or decryption on `dst`, which must be buffer
    /// block-aligned on both ends representing file contents starting at
    /// `offset`.
    fn crypt<B: Backing>(
        &mut self,
        dst: &mut [u8],
        offset: u64,
        encrypt: bool,
    ) -> Result<(), B::Error> {
        let tmp = &mut self.tmp_enc;
        let tweaks = &mut self.tmp_tweaks;

        // Process `dst` in chunks of `GROUP_STRIDE` blocks.
        for (block_group, offset) in dst
            .chunks_mut(tmp.len() - AES_BLOCK)
            .zip((offset..).step_by(AES_BLOCK * GROUP_STRIDE))
        {
            // Compute the tweaks we need for this group and apply them
            // in-place to dst.
            for ((block, tweak), offset) in block_group
                .chunks_exact_mut(AES_BLOCK)
                .zip(tweaks.iter_mut())
                .zip((offset..).step_by(AES_BLOCK))
            {
                *tweak =
                    self.tweaker.gen_tweak(&mut self.enc, &self.nonce, offset);
                for (b, t) in block.iter_mut().zip(tweak.iter().copied()) {
                    *b ^= t;
                }
            }

            // Encrypt/decrypt from dst to tmp.
            let crypt = if encrypt {
                &mut self.enc
            } else {
                &mut self.dec
            };
            match crypt.update(
                block_group,
                // OpenSSL demands an extra block worth of scratch space.
                &mut tmp[..block_group.len() + AES_BLOCK],
            ) {
                Ok(len) => {
                    debug_assert_eq!(block_group.len(), len);
                },
                Err(_) => return Err(B::encryption_error()),
            }

            // Apply the post-crypt tweaks and transfer from tmp back to dst.
            for ((block, tmp), tweak) in block_group
                .chunks_exact_mut(AES_BLOCK)
                .zip(tmp.chunks_exact(AES_BLOCK))
                .zip(&*tweaks)
            {
                for ((dst, src), tw) in block
                    .iter_mut()
                    .zip(tmp.iter().copied())
                    .zip(tweak.iter().copied())
                {
                    *dst = src ^ tw;
                }
            }
        }

        Ok(())
    }
}

const TWEAK_SECTOR_SIZE_BLOCKS: u64 = 64;
struct Tweaker {
    sector: u64,
    base: u128,
}

impl Tweaker {
    fn new() -> Self {
        Self {
            sector: u64::MAX,
            base: 0,
        }
    }

    fn gen_tweak(
        &mut self,
        enc: &mut openssl::symm::Crypter,
        nonce: &[u8; AES_BLOCK],
        file_offset: u64,
    ) -> [u8; AES_BLOCK] {
        debug_assert_eq!(0, file_offset % AES_BLOCK64);
        let block = file_offset / AES_BLOCK64;
        let sector = block / TWEAK_SECTOR_SIZE_BLOCKS;
        let block_in_sector = (block % TWEAK_SECTOR_SIZE_BLOCKS) as u32;

        if sector != self.sector {
            let mut enc_in = *nonce;
            for (b, e) in sector.to_le_bytes().into_iter().zip(&mut enc_in) {
                *e ^= b;
            }

            let mut enc_out = [0u8; AES_BLOCK * 2];
            let n = enc.update(&enc_in, &mut enc_out).unwrap();
            assert_eq!(AES_BLOCK, n);

            self.sector = sector;
            self.base =
                u128::from_le_bytes(enc_out[..AES_BLOCK].try_into().unwrap());
        }

        gf128_mul_exp2(self.base, block_in_sector).to_le_bytes()
    }
}

/// Compute `n * 2**exp2` in GF(2**128) for small values of `exp2`.
fn gf128_mul_exp2(n: u128, exp2: u32) -> u128 {
    debug_assert!(exp2 <= 120);

    if 0 == exp2 {
        return n;
    }

    let lo_half = n << exp2;
    let hi_half = n >> 128 - exp2;

    lo_half ^ (hi_half << 7) ^ (hi_half << 2) ^ (hi_half << 1) ^ hi_half
}

#[cfg(test)]
mod test {
    use std::convert::TryFrom;

    use super::*;

    impl Backing for Vec<u8> {
        type Error = &'static str;

        fn read(
            &mut self,
            dst: &mut [u8],
            offset: u64,
        ) -> Result<(), &'static str> {
            let offset =
                usize::try_from(offset).map_err(|_| "offset too large")?;
            let end = offset
                .checked_add(dst.len())
                .ok_or("end beyond usize::MAX")?;
            if end > Vec::len(self) {
                return Err("read short");
            }

            dst.copy_from_slice(&self[offset..end]);
            Ok(())
        }

        fn write(
            &mut self,
            src: &[u8],
            offset: u64,
        ) -> Result<(), &'static str> {
            let offset =
                usize::try_from(offset).map_err(|_| "offset too large")?;
            let end = offset
                .checked_add(src.len())
                .ok_or("end beyond usize::MAX")?;

            if end > Vec::len(self) {
                self.resize(offset, 0);
                self.extend_from_slice(src);
            } else {
                self[offset..end].copy_from_slice(src);
            }

            Ok(())
        }

        fn len(&mut self) -> Result<u64, &'static str> {
            Ok(Vec::len(self) as u64)
        }

        fn encryption_error() -> &'static str {
            "encryption error"
        }
    }

    #[test]
    fn basic() {
        let mut backing = Vec::<u8>::new();
        let master = MasterKey::new();
        let mut xex = Xex::new(&master, "some-db").unwrap();

        xex.write(&mut backing, b"hello world", 0).unwrap();

        let mut read = [0u8; 11];
        xex.read(&mut backing, &mut read, 0).unwrap();
        assert_eq!(b"hello world", &read);
    }

    #[test]
    fn random_write() {
        let mut backing = Vec::<u8>::new();
        let master = MasterKey::new();
        let mut xex = Xex::new(&master, "some-db").unwrap();

        let mut read = [0u8; 48];

        xex.write(
            &mut backing,
            //                16              32
            b"The quick brown fox jumps over the lazy dog.",
            0,
        )
        .unwrap();

        xex.read(&mut backing, &mut read, 0).unwrap();
        assert_eq!(
            b"The quick brown fox jumps over the lazy dog.\x00\x00\x00\x00",
            &read,
        );

        // Overwrite whole block
        xex.write(&mut backing, b"FOX JUMPS OVER T", 16).unwrap();

        xex.read(&mut backing, &mut read, 0).unwrap();
        assert_eq!(
            b"The quick brown FOX JUMPS OVER The lazy dog.\x00\x00\x00\x00",
            &read,
        );

        // Non-aligned write which doesn't straddle any boundaries
        xex.write(&mut backing, b"HE", 1).unwrap();

        xex.read(&mut backing, &mut read, 0).unwrap();
        assert_eq!(
            b"THE quick brown FOX JUMPS OVER The lazy dog.\x00\x00\x00\x00",
            &read,
        );

        // Non-aligned write which straddles one boundary
        xex.write(&mut backing, b"another doge", 31).unwrap();

        xex.read(&mut backing, &mut read, 0).unwrap();
        assert_eq!(
            b"THE quick brown FOX JUMPS OVER another doge.\x00\x00\x00\x00",
            &read,
        );

        // Non-aligned write which straddles two boundaries
        xex.write(&mut backing, b"lazy dog jumps over the quick brown fox", 4)
            .unwrap();

        xex.read(&mut backing, &mut read, 0).unwrap();
        assert_eq!(
            b"THE lazy dog jumps over the quick brown fox.\x00\x00\x00\x00",
            &read,
        );
    }

    #[test]
    fn random_read() {
        let mut backing = Vec::<u8>::new();
        let master = MasterKey::new();
        let mut xex = Xex::new(&master, "some-db").unwrap();

        let mut read = [0u8; 48];

        xex.write(
            &mut backing,
            //                16              32
            b"The quick brown fox jumps over the lazy dog.",
            0,
        )
        .unwrap();

        // Aligned start, misaligned end, no straddling
        xex.read(&mut backing, &mut read[..8], 16).unwrap();
        assert_eq!(b"fox jump", &read[..8]);

        // Misaligned start, aligned end, no straddling
        xex.read(&mut backing, &mut read[..8], 24).unwrap();
        assert_eq!(b"s over t", &read[..8]);

        // Misaligned start and end in one block
        xex.read(&mut backing, &mut read[..5], 4).unwrap();
        assert_eq!(b"quick", &read[..5]);

        // Misaligned start and end, straddling one boundary
        xex.read(&mut backing, &mut read[..9], 10).unwrap();
        assert_eq!(b"brown fox", &read[..9]);

        // Misaligned start and end, straddling two boundaries
        xex.read(&mut backing, &mut read[..34], 10).unwrap();
        assert_eq!(b"brown fox jumps over the lazy dog.", &read[..34]);
    }

    #[test]
    fn test_gf128_mul_exp2() {
        fn gf128_mul_exp2_slow(mut n: u128, exp2: u32) -> u128 {
            // The simple one-at-a-time algorithm described in the XEX paper.
            for _ in 0..exp2 {
                let high_bit = 0 != n >> 127;
                n <<= 1;
                if high_bit {
                    n ^= 0b10000111;
                }
            }

            n
        }

        for n in [
            1u128,
            2,
            3,
            4,
            0x2ee4108684a71b2f89d0c73a9ef65217,
            0xb596d9bfada34102f38f7a24fa107bd7,
            0xacf0daba883f2031ccba47bf3947abfa,
            0xbfc3ed42a15e8c4afc13c344692ae1e3,
            0xd03cfd5db6e15417e9d3144450f4f5f1,
            0xc2b8bd6e23b61e678140bafd3bb15307,
            0x828197e375f4979e39c138ca9e4e8657,
            0x2c7a7ad6a2709581124e17791209dc60,
        ] {
            for exp2 in 0..=64 {
                let slow = gf128_mul_exp2_slow(n, exp2);
                let fast = gf128_mul_exp2(n, exp2);
                assert_eq!(slow, fast, "for {n} * 2**{exp2}");
            }
        }
    }
}
