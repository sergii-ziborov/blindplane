//! Variable-time double-scalar multiplication for signature verification.

use crate::scalar::Scalar;

use super::niels::{AffineNiels, ProjectiveNiels, ProjectivePoint};
use super::point::EdwardsPoint;
#[cfg(feature = "std")]
use super::tables::basepoint_affine_odd_multiples;
#[cfg(not(feature = "std"))]
use super::tables::build_basepoint_affine_odd_multiples;

impl EdwardsPoint {
    /// Variable-time `[a]A + [b]B` for signature verification.
    ///
    /// Both inputs are public: `A` comes from the signature's public key and
    /// `b` from the signature itself, so a data-dependent execution path here
    /// reveals nothing secret.
    ///
    /// The accumulator lives in projective coordinates and every stretch of
    /// pure doublings runs T-free at four squarings each; the extended `T`
    /// coordinate is materialised only at the positions where a non-zero NAF
    /// digit makes an addition happen.
    pub fn vartime_double_scalar_mul_basepoint(a: &Scalar, big_a: &Self, b: &Scalar) -> Self {
        // Odd multiples 1A, 3A, .., 15A, cached once in projective-Niels form
        // so each reuse inside the loop is a mixed addition rather than a
        // generic one that recomputes the same subterms.
        let double_a = big_a.double();
        let mut multiple = *big_a;
        let mut odd_a = [ProjectiveNiels::IDENTITY; 8];
        odd_a[0] = multiple.to_projective_niels();
        for slot in odd_a.iter_mut().skip(1) {
            multiple = multiple.add(&double_a);
            *slot = multiple.to_projective_niels();
        }

        // The basepoint's odd multiples are constant; they are built once, in
        // affine-Niels form (Z = 1), and shared across every verification.
        // Width 8 against the by-key table's width 5: a wider window pays a
        // bigger table, which for the fixed basepoint costs nothing per call.
        #[cfg(feature = "std")]
        let odd_b = basepoint_affine_odd_multiples();
        // Without a place to cache the table, rebuild it per call. `no_std`
        // verification is not the performance-critical path.
        #[cfg(not(feature = "std"))]
        let odd_b = &build_basepoint_affine_odd_multiples();

        let a_naf = a.non_adjacent_form(5);
        let b_naf = b.non_adjacent_form(8);
        let mut i = 255;
        while i > 0 && a_naf[i] == 0 && b_naf[i] == 0 {
            i -= 1;
        }

        let mut acc = ProjectivePoint::IDENTITY;
        loop {
            let mut completed = acc.double();
            if a_naf[i] != 0 || b_naf[i] != 0 {
                let mut extended = completed.to_extended();
                if a_naf[i] > 0 {
                    completed = extended.add_projective_niels(&odd_a[(a_naf[i] as usize) / 2]);
                } else if a_naf[i] < 0 {
                    completed =
                        extended.add_projective_niels(&odd_a[((-a_naf[i]) as usize) / 2].negate());
                }
                if b_naf[i] != 0 {
                    if a_naf[i] != 0 {
                        extended = completed.to_extended();
                    }
                    if b_naf[i] > 0 {
                        completed = extended.add_affine_niels(&odd_b[(b_naf[i] as usize) / 2]);
                    } else {
                        completed =
                            extended.add_affine_niels(&odd_b[((-b_naf[i]) as usize) / 2].negate());
                    }
                }
            }
            if i == 0 {
                break completed.to_extended();
            }
            acc = completed.to_projective();
            i -= 1;
        }
    }

    /// Variable-time `[a]A + [b]B` where the odd multiples of `A` arrive
    /// already prepared in affine-Niels form, as
    /// [`PreparedVerifier`](crate::edwards::PreparedVerifier) holds them.
    /// With both tables affine and width 8, every addition in the loop is the
    /// cheapest kind and the per-call table build disappears.
    pub(super) fn vartime_double_scalar_mul_prepared(
        a: &Scalar,
        odd_a: &[AffineNiels; 64],
        b: &Scalar,
    ) -> Self {
        #[cfg(feature = "std")]
        let odd_b = basepoint_affine_odd_multiples();
        // Without a place to cache the table, rebuild it per call. `no_std`
        // verification is not the performance-critical path.
        #[cfg(not(feature = "std"))]
        let odd_b = &build_basepoint_affine_odd_multiples();

        let a_naf = a.non_adjacent_form(8);
        let b_naf = b.non_adjacent_form(8);
        let mut i = 255;
        while i > 0 && a_naf[i] == 0 && b_naf[i] == 0 {
            i -= 1;
        }

        let mut acc = ProjectivePoint::IDENTITY;
        loop {
            let mut completed = acc.double();
            if a_naf[i] != 0 || b_naf[i] != 0 {
                let mut extended = completed.to_extended();
                if a_naf[i] > 0 {
                    completed = extended.add_affine_niels(&odd_a[(a_naf[i] as usize) / 2]);
                } else if a_naf[i] < 0 {
                    completed =
                        extended.add_affine_niels(&odd_a[((-a_naf[i]) as usize) / 2].negate());
                }
                if b_naf[i] != 0 {
                    if a_naf[i] != 0 {
                        extended = completed.to_extended();
                    }
                    if b_naf[i] > 0 {
                        completed = extended.add_affine_niels(&odd_b[(b_naf[i] as usize) / 2]);
                    } else {
                        completed =
                            extended.add_affine_niels(&odd_b[((-b_naf[i]) as usize) / 2].negate());
                    }
                }
            }
            if i == 0 {
                break completed.to_extended();
            }
            acc = completed.to_projective();
            i -= 1;
        }
    }
}
