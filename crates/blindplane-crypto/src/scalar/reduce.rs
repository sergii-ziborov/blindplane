//! Wide multiplication and Barrett reduction modulo `L`.

use crate::util::Choice;

use super::{L, MU};

/// Schoolbook 4x4 -> 8 limb multiplication.
pub(super) fn mul_wide(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
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
pub(super) fn barrett_reduce(x: &[u64; 8]) -> [u64; 4] {
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
pub(super) fn add_mod_l(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
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
pub(super) fn is_less_than(a: &[u64; 4], b: &[u64; 4]) -> Choice {
    let mut borrow = 0_u64;
    for i in 0..4 {
        let (d, b1) = a[i].overflowing_sub(b[i]);
        let (_, b2) = d.overflowing_sub(borrow);
        borrow = u64::from(b1) | u64::from(b2);
    }
    Choice::from_bit(borrow)
}
