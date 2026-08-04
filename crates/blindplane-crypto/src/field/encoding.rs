//! Byte encoding, constant-time selection, and square roots.

use crate::util::Choice;

use super::{Fe, MASK51, load_le64};

impl Fe {
    /// Load a field element from 32 little-endian bytes, ignoring bit 255.
    pub const fn from_bytes(bytes: &[u8; 32]) -> Self {
        let w0 = load_le64(bytes, 0);
        let w1 = load_le64(bytes, 8);
        let w2 = load_le64(bytes, 16);
        let w3 = load_le64(bytes, 24);
        Self([
            w0 & MASK51,
            ((w0 >> 51) | (w1 << 13)) & MASK51,
            ((w1 >> 38) | (w2 << 26)) & MASK51,
            ((w2 >> 25) | (w3 << 39)) & MASK51,
            (w3 >> 12) & MASK51,
        ])
    }

    /// Fully reduce modulo `p` and serialize to 32 little-endian bytes.
    pub const fn to_bytes(&self) -> [u8; 32] {
        let mut limbs = self.weak_reduce().0;

        // Compute `self + 19` and look at the top limb to learn whether the
        // value is at least `p`; then subtract `p` under that condition without
        // branching.
        let mut q = (limbs[0] + 19) >> 51;
        q = (limbs[1] + q) >> 51;
        q = (limbs[2] + q) >> 51;
        q = (limbs[3] + q) >> 51;
        q = (limbs[4] + q) >> 51;

        limbs[0] += 19 * q;
        let mut i = 0;
        while i < 4 {
            limbs[i + 1] += limbs[i] >> 51;
            limbs[i] &= MASK51;
            i += 1;
        }
        limbs[4] &= MASK51;

        let w0 = limbs[0] | (limbs[1] << 51);
        let w1 = (limbs[1] >> 13) | (limbs[2] << 38);
        let w2 = (limbs[2] >> 26) | (limbs[3] << 25);
        let w3 = (limbs[3] >> 39) | (limbs[4] << 12);

        let mut out = [0_u8; 32];
        let mut j = 0;
        while j < 8 {
            out[j] = (w0 >> (8 * j)) as u8;
            out[8 + j] = (w1 >> (8 * j)) as u8;
            out[16 + j] = (w2 >> (8 * j)) as u8;
            out[24 + j] = (w3 >> (8 * j)) as u8;
            j += 1;
        }
        out
    }

    /// Return `b` when `choice` is set and `a` otherwise, without branching.
    #[inline(always)]
    pub fn select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mask = choice.mask();
        let mut out = [0_u64; 5];
        for i in 0..5 {
            out[i] = a.0[i] ^ (mask & (a.0[i] ^ b.0[i]));
        }
        Self(out)
    }

    /// Exchange `a` and `b` when `choice` is set, without branching.
    #[inline(always)]
    pub fn conditional_swap(a: &mut Self, b: &mut Self, choice: Choice) {
        let mask = choice.mask();
        for i in 0..5 {
            let t = mask & (a.0[i] ^ b.0[i]);
            a.0[i] ^= t;
            b.0[i] ^= t;
        }
    }

    /// Replace `self` with its negation when `choice` is set.
    #[inline(always)]
    pub fn conditional_negate(&mut self, choice: Choice) {
        *self = Self::select(self, &self.neg(), choice);
    }

    /// Whether the canonical encoding has its low bit set.
    pub fn is_negative(&self) -> Choice {
        Choice::from_bit(u64::from(self.to_bytes()[0] & 1))
    }

    /// Whether this element is zero.
    pub fn is_zero(&self) -> Choice {
        crate::util::ct_eq_bytes(&self.to_bytes(), &[0_u8; 32])
    }

    /// Whether two elements are equal modulo `p`.
    pub fn ct_eq(&self, other: &Self) -> Choice {
        crate::util::ct_eq_bytes(&self.to_bytes(), &other.to_bytes())
    }

    /// Square root of `u/v`, if one exists.
    ///
    /// Returns the candidate root together with a flag saying whether it really
    /// squares to `u/v`. Callers must check the flag; the value is returned
    /// unconditionally so the caller's control flow stays data independent.
    pub fn sqrt_ratio(u: &Self, v: &Self) -> (Self, Choice) {
        let v3 = v.square().mul(v);
        let v7 = v3.square().mul(v);
        let mut root = u.mul(&v3).mul(&u.mul(&v7).pow_p58());

        let check = v.mul(&root.square());
        let correct = check.ct_eq(u);
        let flipped = check.ct_eq(&u.neg());

        let root_times_i = root.mul(&Self::SQRT_M1);
        root = Self::select(&root, &root_times_i, flipped);
        root.conditional_negate(root.is_negative());
        (root, correct | flipped)
    }
}
