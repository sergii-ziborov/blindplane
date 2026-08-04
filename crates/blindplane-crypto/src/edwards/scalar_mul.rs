//! Constant-time, table-based scalar multiplication.

use crate::field::Fe;
use crate::scalar::Scalar;
use crate::util::Choice;

#[cfg(not(feature = "std"))]
use super::point::BASEPOINT;
use super::point::EdwardsPoint;
#[cfg(feature = "std")]
use super::tables::basepoint_table;

impl EdwardsPoint {
    /// Constant-time multiplication by a secret scalar.
    pub fn mul(&self, scalar: &Scalar) -> Self {
        // Signed radix-16 digits, so the table holds only [1..8]P.
        let mut table = [Self::IDENTITY; 8];
        table[0] = *self;
        for i in 1..8 {
            table[i] = table[i - 1].add(self);
        }

        let digits = scalar.radix16();
        let mut acc = Self::IDENTITY;
        for i in (0..64).rev() {
            acc = acc.double().double().double().double();
            acc = acc.add(&select_signed(&table, digits[i]));
        }
        acc
    }

    /// Constant-time multiplication of the base point by a secret scalar.
    pub fn mul_base(scalar: &Scalar) -> Self {
        #[cfg(feature = "std")]
        {
            let table = basepoint_table();
            let digits = scalar.radix16();
            let mut acc = Self::IDENTITY;
            for (i, digit) in digits.iter().enumerate() {
                acc = acc.add(&select_signed(&table[i], *digit));
            }
            acc
        }
        #[cfg(not(feature = "std"))]
        {
            BASEPOINT.mul(scalar)
        }
    }
}

/// Select `|digit| * P` from a table and negate it when the digit is negative,
/// touching every table entry so the access pattern is digit independent.
fn select_signed(table: &[EdwardsPoint; 8], digit: i8) -> EdwardsPoint {
    let negative = Choice::from_bit(u64::from((digit as u8) >> 7));
    let magnitude =
        ((digit as i16) ^ (-i16::from(negative.is_set()))) + i16::from(negative.is_set());
    let magnitude = magnitude as u64;

    let mut selected = EdwardsPoint::IDENTITY;
    for (i, point) in table.iter().enumerate() {
        let hit = ct_eq_u64(magnitude, (i + 1) as u64);
        selected = EdwardsPoint {
            x: Fe::select(&selected.x, &point.x, hit),
            y: Fe::select(&selected.y, &point.y, hit),
            z: Fe::select(&selected.z, &point.z, hit),
            t: Fe::select(&selected.t, &point.t, hit),
        };
    }
    let negated = selected.negate();
    EdwardsPoint {
        x: Fe::select(&selected.x, &negated.x, negative),
        y: selected.y,
        z: selected.z,
        t: Fe::select(&selected.t, &negated.t, negative),
    }
}

#[inline(always)]
fn ct_eq_u64(a: u64, b: u64) -> Choice {
    let diff = a ^ b;
    Choice::from_bit(((diff | diff.wrapping_neg()) >> 63) ^ 1)
}
