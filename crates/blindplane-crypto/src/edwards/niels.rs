//! Cached point representations shared by the scalar-multiplication passes.

use crate::field::Fe;

use super::point::EdwardsPoint;

/// A point in projective coordinates `(X:Y:Z)`, the shape the doubling-heavy
/// stretches of the vartime loop run in: a doubling here needs no `T` and no
/// multiplies at all, only four squarings.
#[derive(Clone, Copy)]
pub(super) struct ProjectivePoint {
    x: Fe,
    y: Fe,
    z: Fe,
}

impl ProjectivePoint {
    pub(super) const IDENTITY: Self = Self {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
    };

    /// `dbl-2008-hwcd` up to the completed coordinates, `T` never formed.
    pub(super) fn double(&self) -> CompletedPoint {
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square();
        let c = c.add(&c);
        let h = a.add(&b);
        let e = h.sub(&self.x.add(&self.y).square());
        let g = a.sub(&b);
        let f = c.add(&g);
        CompletedPoint { e, h, f, g }
    }
}

/// An addition or doubling result before multiplying back into a concrete
/// representation: `x = E/G`, `y = H/F`. Which conversion the caller picks
/// decides whether the extended `T` is ever computed.
#[derive(Clone, Copy)]
pub(super) struct CompletedPoint {
    pub(super) e: Fe,
    pub(super) h: Fe,
    pub(super) f: Fe,
    pub(super) g: Fe,
}

impl CompletedPoint {
    /// Three multiplies; enough when the next operation is a doubling.
    pub(super) fn to_projective(self) -> ProjectivePoint {
        ProjectivePoint {
            x: self.e.mul(&self.f),
            y: self.g.mul(&self.h),
            z: self.f.mul(&self.g),
        }
    }

    /// Four multiplies; needed when the next operation is an addition.
    pub(super) fn to_extended(self) -> EdwardsPoint {
        EdwardsPoint {
            x: self.e.mul(&self.f),
            y: self.g.mul(&self.h),
            z: self.f.mul(&self.g),
            t: self.e.mul(&self.h),
        }
    }
}

/// A point cached for repeated addition: `Y+X`, `Y-X`, `Z`, `2d*T`.
#[derive(Clone, Copy)]
pub(super) struct ProjectiveNiels {
    pub(super) y_plus_x: Fe,
    pub(super) y_minus_x: Fe,
    pub(super) z: Fe,
    pub(super) t2d: Fe,
}

impl ProjectiveNiels {
    pub(super) const IDENTITY: Self = Self {
        y_plus_x: Fe::ONE,
        y_minus_x: Fe::ONE,
        z: Fe::ONE,
        t2d: Fe::ZERO,
    };

    /// Negation swaps the `Y±X` terms and negates `2d*T`.
    pub(super) fn negate(&self) -> Self {
        Self {
            y_plus_x: self.y_minus_x,
            y_minus_x: self.y_plus_x,
            z: self.z,
            t2d: self.t2d.neg(),
        }
    }
}

/// A point with `Z = 1`, cached as `Y+X`, `Y-X`, `2d*X*Y`.
#[derive(Clone, Copy)]
pub(super) struct AffineNiels {
    pub(super) y_plus_x: Fe,
    pub(super) y_minus_x: Fe,
    pub(super) xy2d: Fe,
}

impl AffineNiels {
    pub(super) fn negate(&self) -> Self {
        Self {
            y_plus_x: self.y_minus_x,
            y_minus_x: self.y_plus_x,
            xy2d: self.xy2d.neg(),
        }
    }
}
