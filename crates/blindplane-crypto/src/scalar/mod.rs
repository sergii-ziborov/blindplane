//! Arithmetic modulo the Ed25519 group order
//! `L = 2^252 + 27742317777372353535851937790883648493`.
//!
//! Reduction uses Barrett's method with a precomputed `mu = floor(2^512 / L)`.
//! Every step is straight-line limb arithmetic, and the two possible final
//! subtractions are always performed, selected by a mask.

mod reduce;
#[cfg(test)]
mod tests;

use crate::util::Choice;

use reduce::{add_mod_l, barrett_reduce, is_less_than, mul_wide};

/// `L` in four 64-bit little-endian limbs.
const L: [u64; 4] = [
    0x5812631a5cf5d3ed,
    0x14def9dea2f79cd6,
    0x0000000000000000,
    0x1000000000000000,
];

/// `mu = floor(2^512 / L)` in five 64-bit little-endian limbs.
const MU: [u64; 5] = [
    0xed9ce5a30a2c131b,
    0x2106215d086329a7,
    0xffffffffffffffeb,
    0xffffffffffffffff,
    0x000000000000000f,
];

/// An integer modulo `L`.
#[derive(Clone, Copy, Debug, Default)]
pub struct Scalar(pub [u64; 4]);

impl Scalar {
    /// Zero.
    pub const ZERO: Self = Self([0, 0, 0, 0]);

    /// Reduce a 64-byte little-endian integer, as produced by SHA-512.
    pub fn from_wide_bytes(bytes: &[u8; 64]) -> Self {
        let mut wide = [0_u64; 8];
        for (i, limb) in wide.iter_mut().enumerate() {
            let mut buf = [0_u8; 8];
            buf.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
            *limb = u64::from_le_bytes(buf);
        }
        Self(barrett_reduce(&wide))
    }

    /// Reduce a 32-byte little-endian integer.
    pub fn from_bytes_mod_order(bytes: &[u8; 32]) -> Self {
        let mut wide = [0_u64; 8];
        for i in 0..4 {
            let mut buf = [0_u8; 8];
            buf.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
            wide[i] = u64::from_le_bytes(buf);
        }
        Self(barrett_reduce(&wide))
    }

    /// Accept a 32-byte little-endian integer only when it is already reduced.
    ///
    /// Signature verification rejects non-canonical scalars rather than
    /// silently reducing them, which is what makes signatures non-malleable.
    pub fn from_canonical_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let mut limbs = [0_u64; 4];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let mut buf = [0_u8; 8];
            buf.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
            *limb = u64::from_le_bytes(buf);
        }
        if is_less_than(&limbs, &L).is_set() {
            Some(Self(limbs))
        } else {
            None
        }
    }

    /// Serialize to 32 little-endian bytes.
    pub fn to_bytes(self) -> [u8; 32] {
        let mut out = [0_u8; 32];
        for (i, limb) in self.0.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
        }
        out
    }

    /// `self * rhs + addend` reduced modulo `L`.
    pub fn mul_add(&self, rhs: &Self, addend: &Self) -> Self {
        let product = mul_wide(&self.0, &rhs.0);
        let reduced = barrett_reduce(&product);
        Self(add_mod_l(&reduced, &addend.0))
    }

    /// Whether the scalar is zero.
    pub fn is_zero(&self) -> Choice {
        let mut acc = 0_u64;
        for limb in self.0 {
            acc |= limb;
        }
        Choice::from_bit(((acc | acc.wrapping_neg()) >> 63) ^ 1)
    }

    /// The i-th bit, counting from the least significant.
    #[inline(always)]
    pub const fn bit(&self, i: usize) -> u64 {
        (self.0[i >> 6] >> (i & 63)) & 1
    }

    /// Split into 64 signed radix-16 digits in `[-8, 8]`.
    ///
    /// Used by the fixed-base multiplier: signed digits halve the size of the
    /// precomputed table because a point's negation is free.
    pub fn radix16(&self) -> [i8; 64] {
        let bytes = self.to_bytes();
        let mut digits = [0_i8; 64];
        for i in 0..32 {
            digits[2 * i] = (bytes[i] & 0x0f) as i8;
            digits[2 * i + 1] = ((bytes[i] >> 4) & 0x0f) as i8;
        }
        // Rewrite each digit into [-8, 8] by borrowing from the next one. The
        // top digit cannot overflow because a reduced scalar is below 2^253.
        let mut carry = 0_i8;
        for digit in digits.iter_mut().take(63) {
            *digit += carry;
            carry = (*digit + 8) >> 4;
            *digit -= carry << 4;
        }
        digits[63] += carry;
        digits
    }

    /// Split into a width-5 non-adjacent form for variable-time verification.
    ///
    /// Only public values are ever passed through this, so the data-dependent
    /// length of the NAF is not a leak.
    pub fn non_adjacent_form(&self, width: u32) -> [i8; 256] {
        debug_assert!((2..=8).contains(&width), "digits must fit an i8");
        let radix: u64 = 1 << width;
        let window_mask: u64 = radix - 1;

        let mut naf = [0_i8; 256];
        let mut x = [0_u64; 5];
        x[..4].copy_from_slice(&self.0);

        let mut pos = 0_usize;
        let mut carry = 0_u64;
        while pos < 256 {
            let limb = pos / 64;
            let bit = pos % 64;
            // Read a window, crossing a limb boundary when necessary. The
            // fifth limb exists only so this read is always in bounds.
            let window_bits = if bit < 64 - width as usize {
                x[limb] >> bit
            } else {
                (x[limb] >> bit) | (x[limb + 1] << (64 - bit))
            };

            let window = carry + (window_bits & window_mask);
            if window & 1 == 0 {
                // Digits are odd by construction; skip an even position.
                pos += 1;
                continue;
            }

            if window < radix / 2 {
                carry = 0;
                naf[pos] = window as i8;
            } else {
                // Emit a negative digit and carry one into the next window.
                // Computed in i16: at width 8 the radix itself does not fit
                // an i8, though every emitted digit does.
                carry = 1;
                naf[pos] = (window as i16 - radix as i16) as i8;
            }
            pos += width as usize;
        }
        naf
    }
}
