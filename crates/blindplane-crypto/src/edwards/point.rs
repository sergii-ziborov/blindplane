//! The `EdwardsPoint` type and its core group operations.

use crate::field::Fe;
use crate::util::{Choice, ct_eq_bytes};

use super::niels::{AffineNiels, CompletedPoint, ProjectiveNiels};

/// The curve constant `d = -121665/121666`.
const D: Fe = Fe([
    0x00034dca135978a3,
    0x0001a8283b156ebd,
    0x0005e7a26001c029,
    0x000739c663a03cbb,
    0x00052036cee2b6ff,
]);

/// `2*d`, the constant the extended addition law needs.
pub(super) const D2: Fe = Fe([
    0x00069b9426b2f159,
    0x00035050762add7a,
    0x0003cf44c0038052,
    0x0006738cc7407977,
    0x0002406d9dc56dff,
]);

/// The Ed25519 base point.
pub(super) const BASEPOINT: EdwardsPoint = EdwardsPoint {
    x: Fe([
        0x00062d608f25d51a,
        0x000412a4b4f6592a,
        0x00075b7171a4b31d,
        0x0001ff60527118fe,
        0x000216936d3cd6e5,
    ]),
    y: Fe([
        0x0006666666666658,
        0x0004cccccccccccc,
        0x0001999999999999,
        0x0003333333333333,
        0x0006666666666666,
    ]),
    z: Fe::ONE,
    t: Fe([
        0x00068ab3a5b7dda3,
        0x00000eea2a5eadbb,
        0x0002af8df483c27e,
        0x000332b375274732,
        0x00067875f0fd78b7,
    ]),
};

/// A point on the Edwards form of Curve25519.
#[derive(Clone, Copy, Debug)]
pub struct EdwardsPoint {
    pub(super) x: Fe,
    pub(super) y: Fe,
    pub(super) z: Fe,
    pub(super) t: Fe,
}

impl EdwardsPoint {
    /// The group identity.
    pub const IDENTITY: Self = Self {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
        t: Fe::ZERO,
    };

    /// The standard base point.
    pub const fn basepoint() -> Self {
        BASEPOINT
    }

    /// Point addition (`add-2008-hwcd-3`).
    pub fn add(&self, rhs: &Self) -> Self {
        let a = self.y.sub(&self.x).mul(&rhs.y.sub(&rhs.x));
        let b = self.y.add(&self.x).mul(&rhs.y.add(&rhs.x));
        let c = self.t.mul(&D2).mul(&rhs.t);
        let d = self.z.mul(&rhs.z);
        let d = d.add(&d);
        let e = b.sub(&a);
        let f = d.sub(&c);
        let g = d.add(&c);
        let h = b.add(&a);
        Self {
            x: e.mul(&f),
            y: g.mul(&h),
            t: e.mul(&h),
            z: f.mul(&g),
        }
    }

    /// Point subtraction.
    pub fn sub(&self, rhs: &Self) -> Self {
        self.add(&rhs.negate())
    }

    /// Cache the three subterms that an addition would otherwise recompute
    /// every time this point is used as an addend.
    ///
    /// A table entry is added into the accumulator many times across a scalar
    /// multiplication; precomputing `Y+X`, `Y-X` and `2d*T` once turns the
    /// 9-multiply generic addition into an 8-multiply mixed addition and stops
    /// the per-use recomputation entirely.
    pub(super) fn to_projective_niels(self) -> ProjectiveNiels {
        ProjectiveNiels {
            y_plus_x: self.y.add(&self.x),
            y_minus_x: self.y.sub(&self.x),
            z: self.z,
            t2d: self.t.mul(&D2),
        }
    }

    /// Add a cached point in projective-Niels form: four multiplications to a
    /// completed point, whose caller pays only for the coordinates it needs.
    pub(super) fn add_projective_niels(&self, rhs: &ProjectiveNiels) -> CompletedPoint {
        let pp = self.y.add(&self.x).mul(&rhs.y_plus_x);
        let mm = self.y.sub(&self.x).mul(&rhs.y_minus_x);
        let tt2d = self.t.mul(&rhs.t2d);
        let zz = self.z.mul(&rhs.z);
        let zz2 = zz.add(&zz);

        CompletedPoint {
            e: pp.sub(&mm),
            h: pp.add(&mm),
            g: zz2.add(&tt2d),
            f: zz2.sub(&tt2d),
        }
    }

    /// Add a cached point in affine-Niels form (its `Z` is one): three
    /// multiplications to a completed point, for the constant basepoint table.
    pub(super) fn add_affine_niels(&self, rhs: &AffineNiels) -> CompletedPoint {
        let pp = self.y.add(&self.x).mul(&rhs.y_plus_x);
        let mm = self.y.sub(&self.x).mul(&rhs.y_minus_x);
        let txy2d = self.t.mul(&rhs.xy2d);
        let z2 = self.z.add(&self.z);

        CompletedPoint {
            e: pp.sub(&mm),
            h: pp.add(&mm),
            g: z2.add(&txy2d),
            f: z2.sub(&txy2d),
        }
    }

    /// Point negation.
    pub fn negate(&self) -> Self {
        Self {
            x: self.x.neg(),
            y: self.y,
            z: self.z,
            t: self.t.neg(),
        }
    }

    /// Point doubling (`dbl-2008-hwcd`), which does not need `d`.
    pub fn double(&self) -> Self {
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square();
        let c = c.add(&c);
        let h = a.add(&b);
        let xy = self.x.add(&self.y);
        let e = h.sub(&xy.square());
        let g = a.sub(&b);
        let f = c.add(&g);
        Self {
            x: e.mul(&f),
            y: g.mul(&h),
            t: e.mul(&h),
            z: f.mul(&g),
        }
    }

    /// Multiply by the cofactor 8.
    pub fn mul_by_cofactor(&self) -> Self {
        self.double().double().double()
    }

    /// Whether this is the identity element.
    pub fn is_identity(&self) -> Choice {
        // x/z == 0 and y/z == 1, tested without inverting z.
        self.x.is_zero() & self.y.ct_eq(&self.z)
    }

    /// Whether the point has order dividing 8, which makes it useless as a
    /// public key and is rejected by strict verification.
    pub fn is_small_order(&self) -> Choice {
        self.mul_by_cofactor().is_identity()
    }

    /// Compress to the 32-byte RFC 8032 encoding.
    pub fn compress(&self) -> [u8; 32] {
        let z_inv = self.z.invert();
        let x = self.x.mul(&z_inv);
        let y = self.y.mul(&z_inv);
        let mut out = y.to_bytes();
        out[31] ^= (x.is_negative().mask() as u8) & 0x80;
        out
    }

    /// Decompress from the 32-byte RFC 8032 encoding.
    ///
    /// Returns `None` for any encoding that does not name a curve point,
    /// including a `y` coordinate that is not canonically reduced.
    pub fn decompress(bytes: &[u8; 32]) -> Option<Self> {
        let mut y_bytes = *bytes;
        let sign = Choice::from_bit(u64::from(y_bytes[31] >> 7));
        y_bytes[31] &= 0x7f;

        let y = Fe::from_bytes(&y_bytes);
        // Reject a non-canonical y, which would give two encodings per point.
        if !ct_eq_bytes(&y.to_bytes(), &y_bytes).is_set() {
            return None;
        }

        let y2 = y.square();
        let u = y2.sub(&Fe::ONE);
        let v = y2.mul(&D).add(&Fe::ONE);
        let (mut x, is_square) = Fe::sqrt_ratio(&u, &v);
        if !is_square.is_set() {
            return None;
        }
        // x == 0 has only one root, so a set sign bit is a second encoding of
        // the same point and must be rejected.
        if x.is_zero().is_set() && sign.is_set() {
            return None;
        }
        x.conditional_negate(x.is_negative() ^ sign);

        Some(Self {
            x,
            y,
            z: Fe::ONE,
            t: x.mul(&y),
        })
    }
}
