//! Precomputed multiples of the basepoint and of arbitrary points.

use crate::field::Fe;

use super::niels::AffineNiels;
use super::point::{BASEPOINT, D2, EdwardsPoint};

/// `[1..8] * 16^i * B` for every one of the 64 radix-16 positions.
///
/// Built once on first use, which costs one scalar multiplication and removes
/// all doublings from every later signature.
#[cfg(feature = "std")]
pub(super) fn basepoint_table() -> &'static [[EdwardsPoint; 8]; 64] {
    use std::sync::OnceLock;
    static TABLE: OnceLock<Box<[[EdwardsPoint; 8]; 64]>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = Box::new([[EdwardsPoint::IDENTITY; 8]; 64]);
        let mut base = BASEPOINT;
        for row in table.iter_mut() {
            row[0] = base;
            for j in 1..8 {
                row[j] = row[j - 1].add(&base);
            }
            // Advance to 16 * base for the next radix-16 position.
            base = base.double().double().double().double();
        }
        table
    })
}

/// Odd multiples `1B, 3B, .., 127B` in affine-Niels form for variable-time
/// verification. The basepoint is constant, so this table is built once and its
/// entries have `Z = 1`, which is what makes the loop's basepoint additions the
/// cheapest addition there is.
#[cfg(feature = "std")]
pub(super) fn basepoint_affine_odd_multiples() -> &'static [AffineNiels; 64] {
    use std::sync::OnceLock;
    static ODD: OnceLock<[AffineNiels; 64]> = OnceLock::new();
    ODD.get_or_init(build_basepoint_affine_odd_multiples)
}

pub(super) fn build_basepoint_affine_odd_multiples() -> [AffineNiels; 64] {
    affine_odd_multiples(&BASEPOINT)
}

/// Odd multiples `1P, 3P, .., 127P` of a point in affine-Niels form.
pub(super) fn affine_odd_multiples(point: &EdwardsPoint) -> [AffineNiels; 64] {
    let mut odd = [EdwardsPoint::IDENTITY; 64];
    odd[0] = *point;
    let double_p = point.double();
    for i in 1..64 {
        odd[i] = odd[i - 1].add(&double_p);
    }

    // Normalize all 64 points to Z = 1 with one shared inversion
    // (Montgomery's trick): prefix products forward, unwind backward.
    let mut prefix = [Fe::ONE; 64];
    let mut running = Fe::ONE;
    for (slot, point) in prefix.iter_mut().zip(odd.iter()) {
        *slot = running;
        running = running.mul(&point.z);
    }
    let mut suffix_inverse = running.invert();
    let mut z_inverse = [Fe::ONE; 64];
    for i in (0..64).rev() {
        z_inverse[i] = suffix_inverse.mul(&prefix[i]);
        suffix_inverse = suffix_inverse.mul(&odd[i].z);
    }

    core::array::from_fn(|i| {
        let x = odd[i].x.mul(&z_inverse[i]);
        let y = odd[i].y.mul(&z_inverse[i]);
        AffineNiels {
            y_plus_x: y.add(&x),
            y_minus_x: y.sub(&x),
            xy2d: x.mul(&y).mul(&D2),
        }
    })
}
