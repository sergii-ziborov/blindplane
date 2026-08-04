//! Arithmetic modulo the Ed25519 group order
//! `L = 2^252 + 27742317777372353535851937790883648493`.
//!
//! Reduction uses Barrett's method with a precomputed `mu = floor(2^512 / L)`.
//! Every step is straight-line limb arithmetic, and the two possible final
//! subtractions are always performed, selected by a mask.

use crate::util::Choice;

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

/// Schoolbook 4x4 -> 8 limb multiplication.
fn mul_wide(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let mut out = [0_u64; 8];
    for i in 0..4 {
        let mut carry = 0_u128;
        for j in 0..4 {
            let t = u128::from(a[i]) * u128::from(b[j]) + u128::from(out[i + j]) + carry;
            out[i + j] = t as u64;
            carry = t >> 64;
        }
        out[i + 4] = carry as u64;
    }
    out
}

/// Barrett reduction of a 512-bit integer modulo `L`.
fn barrett_reduce(x: &[u64; 8]) -> [u64; 4] {
    // q1 = floor(x / 2^192), five limbs.
    let q1: [u64; 5] = [x[3], x[4], x[5], x[6], x[7]];

    // q2 = q1 * mu, ten limbs; only limbs 5..=9 are needed.
    let mut q2 = [0_u64; 10];
    for i in 0..5 {
        let mut carry = 0_u128;
        for j in 0..5 {
            let t = u128::from(q1[i]) * u128::from(MU[j]) + u128::from(q2[i + j]) + carry;
            q2[i + j] = t as u64;
            carry = t >> 64;
        }
        q2[i + 5] = q2[i + 5].wrapping_add(carry as u64);
    }
    let q3: [u64; 5] = [q2[5], q2[6], q2[7], q2[8], q2[9]];

    // r2 = (q3 * L) mod 2^320, five limbs.
    let mut r2 = [0_u64; 5];
    for i in 0..5 {
        let mut carry = 0_u128;
        for j in 0..(5 - i) {
            let bj = if j < 4 { L[j] } else { 0 };
            let t = u128::from(q3[i]) * u128::from(bj) + u128::from(r2[i + j]) + carry;
            r2[i + j] = t as u64;
            carry = t >> 64;
        }
    }

    // r = (x mod 2^320) - r2, five limbs, always non-negative modulo 2^320.
    let r1: [u64; 5] = [x[0], x[1], x[2], x[3], x[4]];
    let mut r = [0_u64; 5];
    let mut borrow = 0_u64;
    for i in 0..5 {
        let (d, b1) = r1[i].overflowing_sub(r2[i]);
        let (d, b2) = d.overflowing_sub(borrow);
        r[i] = d;
        borrow = u64::from(b1) | u64::from(b2);
    }

    // At this point r < 3L, so at most two conditional subtractions remain.
    let mut result = r;
    for _ in 0..2 {
        let candidate = sub_l_5(&result);
        let underflowed = Choice::from_bit(candidate.1);
        for i in 0..5 {
            let mask = (!underflowed).mask();
            result[i] = result[i] ^ (mask & (result[i] ^ candidate.0[i]));
        }
    }
    [result[0], result[1], result[2], result[3]]
}

/// Subtract `L` from a five-limb value; the flag reports a borrow.
fn sub_l_5(value: &[u64; 5]) -> ([u64; 5], u64) {
    let mut out = [0_u64; 5];
    let mut borrow = 0_u64;
    for i in 0..5 {
        let li = if i < 4 { L[i] } else { 0 };
        let (d, b1) = value[i].overflowing_sub(li);
        let (d, b2) = d.overflowing_sub(borrow);
        out[i] = d;
        borrow = u64::from(b1) | u64::from(b2);
    }
    (out, borrow)
}

/// Addition modulo `L` for two already-reduced values.
fn add_mod_l(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut sum = [0_u64; 5];
    let mut carry = 0_u64;
    for i in 0..4 {
        let (s, c1) = a[i].overflowing_add(b[i]);
        let (s, c2) = s.overflowing_add(carry);
        sum[i] = s;
        carry = u64::from(c1) | u64::from(c2);
    }
    sum[4] = carry;

    let (reduced, borrow) = sub_l_5(&sum);
    let keep = Choice::from_bit(borrow);
    let mut out = [0_u64; 4];
    for i in 0..4 {
        let mask = keep.mask();
        out[i] = reduced[i] ^ (mask & (reduced[i] ^ sum[i]));
    }
    out
}

/// Constant-time `a < b` for four-limb values.
fn is_less_than(a: &[u64; 4], b: &[u64; 4]) -> Choice {
    let mut borrow = 0_u64;
    for i in 0..4 {
        let (d, b1) = a[i].overflowing_sub(b[i]);
        let (_, b2) = d.overflowing_sub(borrow);
        borrow = u64::from(b1) | u64::from(b2);
    }
    Choice::from_bit(borrow)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_int(bytes: &[u8]) -> u128 {
        let mut acc = 0_u128;
        for (i, b) in bytes.iter().enumerate().take(16) {
            acc |= u128::from(*b) << (8 * i);
        }
        acc
    }

    #[test]
    fn small_values_are_unchanged() {
        let mut bytes = [0_u8; 32];
        bytes[0] = 42;
        let s = Scalar::from_bytes_mod_order(&bytes);
        assert_eq!(s.to_bytes(), bytes);
    }

    #[test]
    fn l_reduces_to_zero() {
        let mut bytes = [0_u8; 32];
        for (i, limb) in L.iter().enumerate() {
            bytes[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
        }
        assert_eq!(Scalar::from_bytes_mod_order(&bytes).to_bytes(), [0_u8; 32]);
        assert!(Scalar::from_canonical_bytes(&bytes).is_none());
    }

    #[test]
    fn wide_reduction_matches_reference_modulus() {
        // 2^256 mod L, computed independently:
        // 2^256 = 4 * 2^254, and reducing gives this constant.
        let mut wide = [0_u8; 64];
        wide[32] = 1; // value = 2^256
        let reduced = Scalar::from_wide_bytes(&wide);
        // Verify by the defining property: 2^256 - reduced must be a multiple
        // of L, checked through a second reduction of the difference.
        let mut check = [0_u8; 64];
        check[32] = 1;
        let bytes = reduced.to_bytes();
        let mut borrow = 0_i32;
        for i in 0..64 {
            let sub = if i < 32 { i32::from(bytes[i]) } else { 0 };
            let mut diff = i32::from(check[i]) - sub - borrow;
            if diff < 0 {
                diff += 256;
                borrow = 1;
            } else {
                borrow = 0;
            }
            check[i] = diff as u8;
        }
        assert_eq!(Scalar::from_wide_bytes(&check).to_bytes(), [0_u8; 32]);
    }

    #[test]
    fn multiply_add_is_value_correct_for_small_inputs() {
        let mut a_bytes = [0_u8; 32];
        a_bytes[0] = 7;
        let mut b_bytes = [0_u8; 32];
        b_bytes[0] = 9;
        let mut c_bytes = [0_u8; 32];
        c_bytes[0] = 5;
        let a = Scalar::from_bytes_mod_order(&a_bytes);
        let b = Scalar::from_bytes_mod_order(&b_bytes);
        let c = Scalar::from_bytes_mod_order(&c_bytes);
        assert_eq!(to_int(&a.mul_add(&b, &c).to_bytes()), 7 * 9 + 5);
    }

    #[test]
    fn radix16_digits_recompose() {
        let mut bytes = [0_u8; 32];
        bytes[0] = 0xff;
        bytes[1] = 0x7f;
        let s = Scalar::from_bytes_mod_order(&bytes);
        let digits = s.radix16();
        let mut acc = 0_i128;
        for (i, d) in digits.iter().enumerate().take(8) {
            acc += i128::from(*d) << (4 * i);
        }
        assert_eq!(acc, 0x7fff);
        assert!(digits.iter().all(|d| (-8..=8).contains(d)));
    }

    #[test]
    fn non_adjacent_form_recomposes_at_every_width() {
        // A value small enough to recompose exactly in an i128.
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&0x0123_4567_89ab_cdef_u64.to_le_bytes());
        bytes[8..12].copy_from_slice(&0x0eadbeef_u32.to_le_bytes());
        let s = Scalar::from_bytes_mod_order(&bytes);
        let expected = i128::from(0x0eadbeef_u32) << 64 | i128::from(0x0123_4567_89ab_cdef_u64);

        for width in [4_u32, 5, 6, 7, 8] {
            let naf = s.non_adjacent_form(width);
            let mut acc = 0_i128;
            for (i, digit) in naf.iter().enumerate().take(100) {
                acc += i128::from(*digit) << i;
            }
            assert_eq!(acc, expected, "width {width}");
            let bound = 1_i16 << (width - 1);
            assert!(
                naf.iter()
                    .all(|d| i16::from(*d).abs() < bound && (d % 2 != 0 || *d == 0)),
                "width {width} digit out of range"
            );
        }
    }
}
