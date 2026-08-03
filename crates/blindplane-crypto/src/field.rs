//! Arithmetic in GF(2^255 - 19) using five 51-bit limbs.
//!
//! Every operation here runs in time independent of its operands: there are no
//! secret-dependent branches, no secret-dependent memory indices, and no
//! variable-latency instructions. Conditional behaviour is expressed as a mask
//! built from a `Choice`.

use crate::util::Choice;

const MASK51: u64 = (1 << 51) - 1;

/// Read eight little-endian bytes starting at `offset`.
#[inline(always)]
const fn load_le64(bytes: &[u8; 32], offset: usize) -> u64 {
    (bytes[offset] as u64)
        | ((bytes[offset + 1] as u64) << 8)
        | ((bytes[offset + 2] as u64) << 16)
        | ((bytes[offset + 3] as u64) << 24)
        | ((bytes[offset + 4] as u64) << 32)
        | ((bytes[offset + 5] as u64) << 40)
        | ((bytes[offset + 6] as u64) << 48)
        | ((bytes[offset + 7] as u64) << 56)
}

/// A field element held as `f0 + f1*2^51 + f2*2^102 + f3*2^153 + f4*2^204`.
///
/// Limbs are kept below `2^52` after every public operation, which leaves room
/// for the lazy reduction the multiplication routines depend on.
#[derive(Clone, Copy, Debug)]
pub struct Fe(pub [u64; 5]);

impl Fe {
    /// The additive identity.
    pub const ZERO: Self = Self([0, 0, 0, 0, 0]);
    /// The multiplicative identity.
    pub const ONE: Self = Self([1, 0, 0, 0, 0]);

    /// `sqrt(-1) mod p`, used to take square roots and to decompress points.
    pub const SQRT_M1: Self = Self([
        0x00061b274a0ea0b0,
        0x0000d5a5fc8f189d,
        0x0007ef5e9cbd0c60,
        0x00078595a6804c9e,
        0x0002b8324804fc1d,
    ]);

    /// Sum of two field elements.
    #[inline(always)]
    pub const fn add(&self, rhs: &Self) -> Self {
        let mut out = [0_u64; 5];
        let mut i = 0;
        while i < 5 {
            out[i] = self.0[i] + rhs.0[i];
            i += 1;
        }
        Self(out).weak_reduce()
    }

    /// Difference of two field elements.
    ///
    /// `2 * p` is added limb-wise first so the subtraction never borrows.
    #[inline(always)]
    pub const fn sub(&self, rhs: &Self) -> Self {
        let mut out = [0_u64; 5];
        // 2*p written in 51-bit limbs.
        const P2: [u64; 5] = [
            0x000fffffffffffda,
            0x000ffffffffffffe,
            0x000ffffffffffffe,
            0x000ffffffffffffe,
            0x000ffffffffffffe,
        ];
        let mut i = 0;
        while i < 5 {
            out[i] = self.0[i] + P2[i] - rhs.0[i];
            i += 1;
        }
        Self(out).weak_reduce()
    }

    /// Additive inverse.
    #[inline(always)]
    pub const fn neg(&self) -> Self {
        Self::ZERO.sub(self)
    }

    /// Product of two field elements.
    #[inline(always)]
    pub const fn mul(&self, rhs: &Self) -> Self {
        let [a0, a1, a2, a3, a4] = self.0;
        let [b0, b1, b2, b3, b4] = rhs.0;

        // Limbs above the top one fold back in multiplied by 19, because
        // 2^255 = 19 (mod p).
        let b1_19 = (b1 as u128) * 19;
        let b2_19 = (b2 as u128) * 19;
        let b3_19 = (b3 as u128) * 19;
        let b4_19 = (b4 as u128) * 19;

        let (a0, a1, a2, a3, a4) = (a0 as u128, a1 as u128, a2 as u128, a3 as u128, a4 as u128);
        let (b0, b1, b2, b3, b4) = (b0 as u128, b1 as u128, b2 as u128, b3 as u128, b4 as u128);

        let r0 = a0 * b0 + a1 * b4_19 + a2 * b3_19 + a3 * b2_19 + a4 * b1_19;
        let r1 = a0 * b1 + a1 * b0 + a2 * b4_19 + a3 * b3_19 + a4 * b2_19;
        let r2 = a0 * b2 + a1 * b1 + a2 * b0 + a3 * b4_19 + a4 * b3_19;
        let r3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + a4 * b4_19;
        let r4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;

        Self::carry([r0, r1, r2, r3, r4])
    }

    /// Square of a field element.
    ///
    /// The cross terms are shared, which makes this roughly a third cheaper
    /// than the equivalent `mul`.
    #[inline(always)]
    pub const fn square(&self) -> Self {
        let [a0, a1, a2, a3, a4] = self.0;
        let a0_2 = 2 * a0;
        let a1_2 = 2 * a1;
        let a3_19 = 19 * a3;
        let a4_19 = 19 * a4;

        let (a0, a1, a2, a3, a4) = (a0 as u128, a1 as u128, a2 as u128, a3 as u128, a4 as u128);
        let (a0_2, a1_2) = (a0_2 as u128, a1_2 as u128);
        let (a3_19, a4_19) = (a3_19 as u128, a4_19 as u128);

        let r0 = a0 * a0 + a1_2 * a4_19 + 2 * a2 * a3_19;
        let r1 = a0_2 * a1 + 2 * a2 * a4_19 + a3 * a3_19;
        let r2 = a0_2 * a2 + a1 * a1 + 2 * a3 * a4_19;
        let r3 = a0_2 * a3 + a1_2 * a2 + a4 * a4_19;
        let r4 = a0_2 * a4 + a1_2 * a3 + a2 * a2;

        Self::carry([r0, r1, r2, r3, r4])
    }

    /// `self` squared `n` times.
    #[inline(always)]
    pub const fn square_n(&self, n: u32) -> Self {
        let mut out = *self;
        let mut i = 0;
        while i < n {
            out = out.square();
            i += 1;
        }
        out
    }

    /// Multiplication by the Montgomery-ladder constant `a24 = 121666`.
    #[inline(always)]
    pub const fn mul121666(&self) -> Self {
        let mut r = [0_u128; 5];
        let mut i = 0;
        while i < 5 {
            r[i] = (self.0[i] as u128) * 121_666;
            i += 1;
        }
        Self::carry(r)
    }

    /// Reduce five wide accumulators into 51-bit limbs.
    #[inline(always)]
    const fn carry(mut r: [u128; 5]) -> Self {
        let mut out = [0_u64; 5];
        let mut carry = (r[0] >> 51) as u64;
        out[0] = (r[0] as u64) & MASK51;
        r[1] += carry as u128;
        carry = (r[1] >> 51) as u64;
        out[1] = (r[1] as u64) & MASK51;
        r[2] += carry as u128;
        carry = (r[2] >> 51) as u64;
        out[2] = (r[2] as u64) & MASK51;
        r[3] += carry as u128;
        carry = (r[3] >> 51) as u64;
        out[3] = (r[3] as u64) & MASK51;
        r[4] += carry as u128;
        carry = (r[4] >> 51) as u64;
        out[4] = (r[4] as u64) & MASK51;

        // The overflow out of the top limb re-enters at the bottom times 19.
        out[0] += carry * 19;
        out[1] += out[0] >> 51;
        out[0] &= MASK51;
        Self(out)
    }

    /// Propagate carries without a full reduction.
    #[inline(always)]
    const fn weak_reduce(self) -> Self {
        let mut out = self.0;
        let carry = out[4] >> 51;
        out[4] &= MASK51;
        out[0] += carry * 19;
        let mut i = 0;
        while i < 4 {
            out[i + 1] += out[i] >> 51;
            out[i] &= MASK51;
            i += 1;
        }
        Self(out)
    }

    /// Multiplicative inverse, computed as `self^(p-2)`.
    ///
    /// The addition chain is the standard 254-step ladder: 11 multiplications
    /// and 254 squarings, all unconditional.
    pub const fn invert(&self) -> Self {
        let z1 = *self;
        let z2 = z1.square();
        let z8 = z2.square_n(2);
        let z9 = z1.mul(&z8);
        let z11 = z2.mul(&z9);
        let z22 = z11.square();
        let z_5_0 = z9.mul(&z22);
        let z_10_5 = z_5_0.square_n(5);
        let z_10_0 = z_10_5.mul(&z_5_0);
        let z_20_10 = z_10_0.square_n(10);
        let z_20_0 = z_20_10.mul(&z_10_0);
        let z_40_20 = z_20_0.square_n(20);
        let z_40_0 = z_40_20.mul(&z_20_0);
        let z_50_10 = z_40_0.square_n(10);
        let z_50_0 = z_50_10.mul(&z_10_0);
        let z_100_50 = z_50_0.square_n(50);
        let z_100_0 = z_100_50.mul(&z_50_0);
        let z_200_100 = z_100_0.square_n(100);
        let z_200_0 = z_200_100.mul(&z_100_0);
        let z_250_50 = z_200_0.square_n(50);
        let z_250_0 = z_250_50.mul(&z_50_0);
        let z_255_5 = z_250_0.square_n(5);
        z_255_5.mul(&z11)
    }

    /// `self^((p-5)/8)`, the exponent used when taking square roots.
    pub const fn pow_p58(&self) -> Self {
        let z1 = *self;
        let z2 = z1.square();
        let z8 = z2.square_n(2);
        let z9 = z1.mul(&z8);
        let z11 = z2.mul(&z9);
        let z22 = z11.square();
        let z_5_0 = z9.mul(&z22);
        let z_10_5 = z_5_0.square_n(5);
        let z_10_0 = z_10_5.mul(&z_5_0);
        let z_20_10 = z_10_0.square_n(10);
        let z_20_0 = z_20_10.mul(&z_10_0);
        let z_40_20 = z_20_0.square_n(20);
        let z_40_0 = z_40_20.mul(&z_20_0);
        let z_50_10 = z_40_0.square_n(10);
        let z_50_0 = z_50_10.mul(&z_10_0);
        let z_100_50 = z_50_0.square_n(50);
        let z_100_0 = z_100_50.mul(&z_50_0);
        let z_200_100 = z_100_0.square_n(100);
        let z_200_0 = z_200_100.mul(&z_100_0);
        let z_250_50 = z_200_0.square_n(50);
        let z_250_0 = z_250_50.mul(&z_50_0);
        let z_252_2 = z_250_0.square_n(2);
        z_252_2.mul(&z1)
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    fn from_u64(v: u64) -> Fe {
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&v.to_le_bytes());
        Fe::from_bytes(&bytes)
    }

    #[test]
    fn add_sub_round_trip() {
        let a = from_u64(0x1234_5678_9abc_def0);
        let b = from_u64(0x0fed_cba9_8765_4321);
        assert_eq!(a.add(&b).sub(&b).to_bytes(), a.to_bytes());
    }

    #[test]
    fn multiplication_matches_square() {
        let a = from_u64(0xdead_beef_cafe_1234);
        assert_eq!(a.mul(&a).to_bytes(), a.square().to_bytes());
    }

    #[test]
    fn inverse_is_an_inverse() {
        let a = from_u64(9);
        assert_eq!(a.mul(&a.invert()).to_bytes(), Fe::ONE.to_bytes());
    }

    #[test]
    fn canonical_encoding_reduces_p_to_zero() {
        // p itself must encode as zero.
        let mut p_bytes = [0xff_u8; 32];
        p_bytes[0] = 0xed;
        p_bytes[31] = 0x7f;
        assert_eq!(Fe::from_bytes(&p_bytes).to_bytes(), [0_u8; 32]);
    }

    #[test]
    fn sqrt_m1_squares_to_minus_one() {
        assert_eq!(
            Fe::SQRT_M1.square().to_bytes(),
            Fe::ONE.neg().to_bytes(),
            "sqrt(-1)^2 must be -1"
        );
    }

    #[test]
    fn selection_is_value_correct() {
        let a = from_u64(7);
        let b = from_u64(9);
        assert_eq!(
            Fe::select(&a, &b, Choice::from_bit(0)).to_bytes(),
            a.to_bytes()
        );
        assert_eq!(
            Fe::select(&a, &b, Choice::from_bit(1)).to_bytes(),
            b.to_bytes()
        );
    }
}
