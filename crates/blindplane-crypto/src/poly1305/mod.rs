//! Poly1305 one-time authenticator (RFC 8439).
//!
//! The accumulator is two 64-bit limbs plus a small overflow word, the base
//! 2^64 layout OpenSSL's portable implementation uses: one block is four
//! 64x64->128 products plus two short products, against nine wide products
//! for the classic 44-bit-limb layout. The reduction leans on the clamp
//! guaranteeing `r1` is a multiple of four, so `r1 + (r1 >> 2)` is exactly
//! `r1 * 5 / 4` and folds the modulus without a branch. The final comparison
//! against `2^130 - 5` is done with a mask rather than a conditional jump.

#[cfg(test)]
mod tests;

use crate::util::{Choice, ct_eq_bytes};

/// Poly1305 over a one-time 256-bit key.
///
/// A key must never authenticate two different messages: doing so reveals `r`
/// and lets anyone forge tags. In the AEAD constructions here, the key is
/// derived from the cipher's first keystream block, which makes reuse
/// impossible as long as nonces are unique.
pub struct Poly1305 {
    r: [u64; 2],
    /// `r[1] * 5 / 4`, the folded high limb used by the reduction.
    s1: u64,
    /// `h[2]` never exceeds 4 between blocks; the bounds are in `absorb`.
    h: [u64; 3],
    pad: [u8; 16],
    buffer: [u8; 16],
    buffered: usize,
}

impl Poly1305 {
    /// Tag length in bytes.
    pub const TAG_LEN: usize = 16;

    /// Start an authenticator under a one-time key.
    pub fn new(key: &[u8; 32]) -> Self {
        let t0 = u64::from_le_bytes(key[0..8].try_into().expect("8 bytes"));
        let t1 = u64::from_le_bytes(key[8..16].try_into().expect("8 bytes"));

        // Clamping: the specified bits of r are forced to zero, which also
        // bounds both limbs below 2^60 and makes r[1] a multiple of four.
        let r = [t0 & 0x0ffffffc0fffffff, t1 & 0x0ffffffc0ffffffc];
        let s1 = r[1] + (r[1] >> 2);

        let mut pad = [0_u8; 16];
        pad.copy_from_slice(&key[16..32]);

        Self {
            r,
            s1,
            h: [0; 3],
            pad,
            buffer: [0; 16],
            buffered: 0,
        }
    }

    /// Absorb more message bytes.
    pub fn update(&mut self, mut data: &[u8]) {
        if self.buffered > 0 {
            let take = core::cmp::min(16 - self.buffered, data.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered == 16 {
                let block = self.buffer;
                self.absorb(&block, 1);
                self.buffered = 0;
            }
        }

        while data.len() >= 16 {
            let mut block = [0_u8; 16];
            block.copy_from_slice(&data[..16]);
            self.absorb(&block, 1);
            data = &data[16..];
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffered = data.len();
        }
    }

    /// Absorb zero bytes until the message length is a multiple of 16.
    ///
    /// The AEAD constructions use this between the associated data and the
    /// ciphertext so the two cannot be shifted into each other.
    pub fn pad_to_block(&mut self) {
        if self.buffered > 0 {
            let padding = 16 - self.buffered;
            self.update(&[0_u8; 16][..padding]);
        }
    }

    /// Finish and return the 16-byte tag.
    pub fn finalize(mut self) -> [u8; 16] {
        if self.buffered > 0 {
            let mut block = [0_u8; 16];
            block[..self.buffered].copy_from_slice(&self.buffer[..self.buffered]);
            block[self.buffered] = 1;
            self.buffered = 0;
            self.absorb(&block, 0);
        }

        let [h0, h1, h2] = self.h;

        // Compute h + 5 and keep it only if h >= 2^130 - 5. Between blocks
        // h2 <= 4, so h < 2^130 + 2^128 < 2p and one subtraction settles it.
        let t = u128::from(h0) + 5;
        let g0 = t as u64;
        let t = u128::from(h1) + (t >> 64);
        let g1 = t as u64;
        let g2 = h2.wrapping_add((t >> 64) as u64);

        // Bit 130 of h + 5 set means h >= p; select g in that case.
        let mask = 0_u64.wrapping_sub(g2 >> 2);
        let h0 = (h0 & !mask) | (g0 & mask);
        let h1 = (h1 & !mask) | (g1 & mask);

        // Add the key's second half modulo 2^128.
        let t0 = u64::from_le_bytes(self.pad[0..8].try_into().expect("8 bytes"));
        let t1 = u64::from_le_bytes(self.pad[8..16].try_into().expect("8 bytes"));
        let t = u128::from(h0) + u128::from(t0);
        let h0 = t as u64;
        let h1 = h1.wrapping_add(t1).wrapping_add((t >> 64) as u64);

        let mut tag = [0_u8; 16];
        tag[..8].copy_from_slice(&h0.to_le_bytes());
        tag[8..].copy_from_slice(&h1.to_le_bytes());
        self.s1 = 0;
        tag
    }

    /// Finish and compare against an expected tag in constant time.
    pub fn verify(self, expected: &[u8]) -> Choice {
        let tag = self.finalize();
        ct_eq_bytes(&tag, expected)
    }

    /// One block of `h = (h + m) * r mod (2^130 - 5)`, partially reduced.
    ///
    /// Bounds, so every step visibly fits: `h2 <= 4` on entry, so after the
    /// message add `h2 <= 6`. With both `r` limbs below 2^60, `h2 * s1` and
    /// `h2 * r0` stay below 2^63 and the wide sums below 2^126. The fold
    /// returns `h2` to at most 3 plus one carry, restoring the invariant.
    #[inline(always)]
    fn absorb(&mut self, block: &[u8; 16], padbit: u64) {
        let m0 = u64::from_le_bytes(block[0..8].try_into().expect("8 bytes"));
        let m1 = u64::from_le_bytes(block[8..16].try_into().expect("8 bytes"));

        let (r0, r1) = (self.r[0], self.r[1]);
        let s1 = self.s1;

        // h += m, with the padbit as bit 128.
        let t = u128::from(self.h[0]) + u128::from(m0);
        let h0 = t as u64;
        let t = u128::from(self.h[1]) + (t >> 64) + u128::from(m1);
        let h1 = t as u64;
        let h2 = self.h[2]
            .wrapping_add((t >> 64) as u64)
            .wrapping_add(padbit);

        // h *= r, folding 2^128 * x to (5/4) * r1 * x as it appears.
        let d0 = u128::from(h0) * u128::from(r0) + u128::from(h1) * u128::from(s1);
        let d1 = u128::from(h0) * u128::from(r1)
            + u128::from(h1) * u128::from(r0)
            + u128::from(h2.wrapping_mul(s1));
        let h2r = h2.wrapping_mul(r0);

        let h0 = d0 as u64;
        let d1 = d1 + (d0 >> 64);
        let h1 = d1 as u64;
        let h2 = h2r.wrapping_add((d1 >> 64) as u64);

        // Fold the bits at and above 2^130 back in: h += 5 * (h >> 130).
        let c = (h2 >> 2).wrapping_add(h2 & !3);
        let h2 = h2 & 3;
        let t = u128::from(h0) + u128::from(c);
        let h0 = t as u64;
        let t = u128::from(h1) + (t >> 64);
        let h1 = t as u64;
        let h2 = h2.wrapping_add((t >> 64) as u64);

        self.h = [h0, h1, h2];
    }
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        self.r = [0; 2];
        self.s1 = 0;
        self.h = [0; 3];
        crate::util::secure_erase(&mut self.pad);
        crate::util::secure_erase(&mut self.buffer);
    }
}
