//! Variable-time double-scalar multiplication for signature verification.

use crate::scalar::Scalar;

use super::niels::{AffineNiels, CompletedPoint, ProjectiveNiels, ProjectivePoint};
use super::point::EdwardsPoint;
#[cfg(feature = "std")]
use super::tables::basepoint_affine_odd_multiples;
#[cfg(not(feature = "std"))]
use super::tables::build_basepoint_affine_odd_multiples;

/// A table of odd multiples the verification loop adds from.
///
/// The two callers differ only in the cached form their `A`-side entries take
/// — projective-Niels when the key was decompressed for this one signature,
/// affine-Niels when a [`PreparedVerifier`](super::PreparedVerifier)
/// normalised them once — and in the window width that form pays for. Both
/// facts live here so the loop below exists exactly once: it is the inner
/// loop of signature verification, and a second copy is a second place for
/// the two to drift apart.
trait OddMultiples {
    /// NAF window width matching this table's size.
    const WIDTH: u32;

    /// Add the multiple named by a non-zero signed NAF digit.
    fn add_signed(&self, point: &EdwardsPoint, digit: i8) -> CompletedPoint;
}

/// Odd multiples `1A, 3A, .., 15A` of a point decompressed for one signature.
impl OddMultiples for [ProjectiveNiels; 8] {
    const WIDTH: u32 = 5;

    fn add_signed(&self, point: &EdwardsPoint, digit: i8) -> CompletedPoint {
        if digit > 0 {
            point.add_projective_niels(&self[(digit as usize) / 2])
        } else {
            point.add_projective_niels(&self[((-digit) as usize) / 2].negate())
        }
    }
}

/// Odd multiples `1P, 3P, .., 127P` normalised to `Z = 1` ahead of time: the
/// constant basepoint table, and a prepared verifier's key table.
impl OddMultiples for [AffineNiels; 64] {
    const WIDTH: u32 = 8;

    fn add_signed(&self, point: &EdwardsPoint, digit: i8) -> CompletedPoint {
        if digit > 0 {
            point.add_affine_niels(&self[(digit as usize) / 2])
        } else {
            point.add_affine_niels(&self[((-digit) as usize) / 2].negate())
        }
    }
}

/// Variable-time `[a]A + [b]B`, with `A`'s odd multiples supplied by the
/// caller in whichever cached form it has them.
///
/// Both inputs are public: `A` comes from the signature's public key and `b`
/// from the signature itself, so a data-dependent execution path here reveals
/// nothing secret.
///
/// The accumulator lives in projective coordinates and every stretch of pure
/// doublings runs T-free at four squarings each; the extended `T` coordinate
/// is materialised only at the positions where a non-zero NAF digit makes an
/// addition happen.
fn double_scalar_mul<T: OddMultiples>(a: &Scalar, odd_a: &T, b: &Scalar) -> EdwardsPoint {
    // The basepoint's odd multiples are constant, affine and shared across
    // every verification, so the B side always gets the widest window.
    #[cfg(feature = "std")]
    let odd_b = basepoint_affine_odd_multiples();
    // Without a place to cache the table, rebuild it per call. `no_std`
    // verification is not the performance-critical path.
    #[cfg(not(feature = "std"))]
    let odd_b = &build_basepoint_affine_odd_multiples();

    let a_naf = a.non_adjacent_form(T::WIDTH);
    let b_naf = b.non_adjacent_form(<[AffineNiels; 64] as OddMultiples>::WIDTH);
    let mut i = 255;
    while i > 0 && a_naf[i] == 0 && b_naf[i] == 0 {
        i -= 1;
    }

    let mut acc = ProjectivePoint::IDENTITY;
    loop {
        let mut completed = acc.double();
        if a_naf[i] != 0 || b_naf[i] != 0 {
            let mut extended = completed.to_extended();
            if a_naf[i] != 0 {
                completed = odd_a.add_signed(&extended, a_naf[i]);
            }
            if b_naf[i] != 0 {
                if a_naf[i] != 0 {
                    extended = completed.to_extended();
                }
                completed = odd_b.add_signed(&extended, b_naf[i]);
            }
        }
        if i == 0 {
            break completed.to_extended();
        }
        acc = completed.to_projective();
        i -= 1;
    }
}

impl EdwardsPoint {
    /// Variable-time `[a]A + [b]B` for a key decompressed for this signature.
    ///
    /// The odd multiples of `A` are cached in projective-Niels form, so each
    /// reuse inside the loop is a mixed addition rather than a generic one
    /// that recomputes the same subterms.
    pub fn vartime_double_scalar_mul_basepoint(a: &Scalar, big_a: &Self, b: &Scalar) -> Self {
        let double_a = big_a.double();
        let mut multiple = *big_a;
        let mut odd_a = [ProjectiveNiels::IDENTITY; 8];
        odd_a[0] = multiple.to_projective_niels();
        for slot in odd_a.iter_mut().skip(1) {
            multiple = multiple.add(&double_a);
            *slot = multiple.to_projective_niels();
        }
        double_scalar_mul(a, &odd_a, b)
    }

    /// Variable-time `[a]A + [b]B` where the odd multiples of `A` arrive
    /// already prepared in affine-Niels form, as
    /// [`PreparedVerifier`](super::PreparedVerifier) holds them. With both
    /// tables affine and width 8, every addition in the loop is the cheapest
    /// kind and the per-call table build disappears.
    pub(super) fn vartime_double_scalar_mul_prepared(
        a: &Scalar,
        odd_a: &[AffineNiels; 64],
        b: &Scalar,
    ) -> Self {
        double_scalar_mul(a, odd_a, b)
    }
}
