//! The Ed25519 group and RFC 8032 signatures.
//!
//! Points are held in extended twisted Edwards coordinates `(X:Y:Z:T)` with
//! `x = X/Z`, `y = Y/Z` and `x*y = T/Z`. Secret-scalar multiplication uses a
//! signed radix-16 fixed-base table with constant-time selection; signature
//! verification, which only touches public data, uses a variable-time
//! non-adjacent form.

use crate::field::Fe;
use crate::scalar::Scalar;
use crate::sha2::Sha512;
use crate::util::{Choice, Secret, ct_eq_bytes};

/// The curve constant `d = -121665/121666`.
const D: Fe = Fe([
    0x00034dca135978a3,
    0x0001a8283b156ebd,
    0x0005e7a26001c029,
    0x000739c663a03cbb,
    0x00052036cee2b6ff,
]);

/// `2*d`, the constant the extended addition law needs.
const D2: Fe = Fe([
    0x00069b9426b2f159,
    0x00035050762add7a,
    0x0003cf44c0038052,
    0x0006738cc7407977,
    0x0002406d9dc56dff,
]);

/// The Ed25519 base point.
const BASEPOINT: EdwardsPoint = EdwardsPoint {
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
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
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
    fn to_projective_niels(self) -> ProjectiveNiels {
        ProjectiveNiels {
            y_plus_x: self.y.add(&self.x),
            y_minus_x: self.y.sub(&self.x),
            z: self.z,
            t2d: self.t.mul(&D2),
        }
    }

    /// Add a cached point in projective-Niels form. Eight multiplications.
    fn add_projective_niels(&self, rhs: &ProjectiveNiels) -> Self {
        let pp = self.y.add(&self.x).mul(&rhs.y_plus_x);
        let mm = self.y.sub(&self.x).mul(&rhs.y_minus_x);
        let tt2d = self.t.mul(&rhs.t2d);
        let zz = self.z.mul(&rhs.z);
        let zz2 = zz.add(&zz);

        // Completed coordinates, then back to extended.
        let cx = pp.sub(&mm);
        let cy = pp.add(&mm);
        let cz = zz2.add(&tt2d);
        let ct = zz2.sub(&tt2d);
        Self {
            x: cx.mul(&ct),
            y: cy.mul(&cz),
            z: cz.mul(&ct),
            t: cx.mul(&cy),
        }
    }

    /// Add a cached point in affine-Niels form (its `Z` is one). Seven
    /// multiplications, used for the constant basepoint table.
    fn add_affine_niels(&self, rhs: &AffineNiels) -> Self {
        let pp = self.y.add(&self.x).mul(&rhs.y_plus_x);
        let mm = self.y.sub(&self.x).mul(&rhs.y_minus_x);
        let txy2d = self.t.mul(&rhs.xy2d);
        let z2 = self.z.add(&self.z);

        let cx = pp.sub(&mm);
        let cy = pp.add(&mm);
        let cz = z2.add(&txy2d);
        let ct = z2.sub(&txy2d);
        Self {
            x: cx.mul(&ct),
            y: cy.mul(&cz),
            z: cz.mul(&ct),
            t: cx.mul(&cy),
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

    /// Variable-time `[a]A + [b]B` for signature verification.
    ///
    /// Both inputs are public: `A` comes from the signature's public key and
    /// `b` from the signature itself, so a data-dependent execution path here
    /// reveals nothing secret.
    pub fn vartime_double_scalar_mul_basepoint(a: &Scalar, big_a: &Self, b: &Scalar) -> Self {
        // Odd multiples 1A, 3A, .., 15A, cached once in projective-Niels form so
        // each reuse inside the loop is an 8-multiply mixed addition rather than
        // a 9-multiply generic one that recomputes the same subterms.
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
        let odd_b = basepoint_affine_odd_multiples();

        let a_naf = a.non_adjacent_form();
        let b_naf = b.non_adjacent_form();
        let mut i = 255;
        while i > 0 && a_naf[i] == 0 && b_naf[i] == 0 {
            i -= 1;
        }

        let mut acc = Self::IDENTITY;
        loop {
            acc = acc.double();
            if a_naf[i] > 0 {
                acc = acc.add_projective_niels(&odd_a[(a_naf[i] as usize) / 2]);
            } else if a_naf[i] < 0 {
                acc = acc.add_projective_niels(&odd_a[((-a_naf[i]) as usize) / 2].negate());
            }
            if b_naf[i] > 0 {
                acc = acc.add_affine_niels(&odd_b[(b_naf[i] as usize) / 2]);
            } else if b_naf[i] < 0 {
                acc = acc.add_affine_niels(&odd_b[((-b_naf[i]) as usize) / 2].negate());
            }
            if i == 0 {
                break;
            }
            i -= 1;
        }
        acc
    }
}

/// A point cached for repeated addition: `Y+X`, `Y-X`, `Z`, `2d*T`.
#[derive(Clone, Copy)]
struct ProjectiveNiels {
    y_plus_x: Fe,
    y_minus_x: Fe,
    z: Fe,
    t2d: Fe,
}

impl ProjectiveNiels {
    const IDENTITY: Self = Self {
        y_plus_x: Fe::ONE,
        y_minus_x: Fe::ONE,
        z: Fe::ONE,
        t2d: Fe::ZERO,
    };

    /// Negation swaps the `Y±X` terms and negates `2d*T`.
    fn negate(&self) -> Self {
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
struct AffineNiels {
    y_plus_x: Fe,
    y_minus_x: Fe,
    xy2d: Fe,
}

impl AffineNiels {
    fn negate(&self) -> Self {
        Self {
            y_plus_x: self.y_minus_x,
            y_minus_x: self.y_plus_x,
            xy2d: self.xy2d.neg(),
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

/// `[1..8] * 16^i * B` for every one of the 64 radix-16 positions.
///
/// Built once on first use, which costs one scalar multiplication and removes
/// all doublings from every later signature.
#[cfg(feature = "std")]
fn basepoint_table() -> &'static [[EdwardsPoint; 8]; 64] {
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

/// Odd multiples `1B, 3B, .., 15B` in affine-Niels form for variable-time
/// verification. The basepoint is constant, so this table is built once and its
/// entries have `Z = 1`, which is what makes the loop's basepoint additions cost
/// seven multiplications instead of nine.
fn basepoint_affine_odd_multiples() -> &'static [AffineNiels; 8] {
    #[cfg(feature = "std")]
    {
        use std::sync::OnceLock;
        static ODD: OnceLock<[AffineNiels; 8]> = OnceLock::new();
        ODD.get_or_init(build_basepoint_affine_odd_multiples)
    }
    #[cfg(not(feature = "std"))]
    {
        // Without a place to cache it, rebuild per call. `no_std` verification
        // is not the performance-critical path.
        use std::boxed::Box;
        Box::leak(Box::new(build_basepoint_affine_odd_multiples()))
    }
}

fn build_basepoint_affine_odd_multiples() -> [AffineNiels; 8] {
    let mut odd = [EdwardsPoint::IDENTITY; 8];
    odd[0] = BASEPOINT;
    let double_b = BASEPOINT.double();
    for i in 1..8 {
        odd[i] = odd[i - 1].add(&double_b);
    }
    // Normalize each to Z = 1 (one shared batchable inversion would be nicer,
    // but this runs once per process) and cache the Niels subterms.
    core::array::from_fn(|i| {
        let z_inv = odd[i].z.invert();
        let x = odd[i].x.mul(&z_inv);
        let y = odd[i].y.mul(&z_inv);
        AffineNiels {
            y_plus_x: y.add(&x),
            y_minus_x: y.sub(&x),
            xy2d: x.mul(&y).mul(&D2),
        }
    })
}

/// An Ed25519 signing key.
pub struct SigningKey {
    seed: Secret<32>,
    scalar: Scalar,
    prefix: Secret<32>,
    public: [u8; 32],
}

impl SigningKey {
    /// Derive a signing key from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let expanded = Sha512::digest(seed);
        let mut scalar_bytes = [0_u8; 32];
        scalar_bytes.copy_from_slice(&expanded[..32]);
        // RFC 8032 clamping: clear the low three bits, clear bit 255, set 254.
        scalar_bytes[0] &= 0b1111_1000;
        scalar_bytes[31] &= 127;
        scalar_bytes[31] |= 64;

        let mut prefix = [0_u8; 32];
        prefix.copy_from_slice(&expanded[32..]);

        let scalar = Scalar::from_bytes_mod_order(&scalar_bytes);
        let public = EdwardsPoint::mul_base(&scalar).compress();

        Self {
            seed: Secret::new(*seed),
            scalar,
            prefix: Secret::new(prefix),
            public,
        }
    }

    /// Generate a signing key from operating-system entropy.
    #[cfg(feature = "std")]
    pub fn generate() -> Result<Self, crate::rand::RandomError> {
        let mut seed = Secret::zeroed();
        crate::rand::fill(seed.as_mut())?;
        Ok(Self::from_seed(seed.as_bytes()))
    }

    /// The 32-byte seed, for storage inside an encrypted vault.
    pub fn to_seed(&self) -> [u8; 32] {
        self.seed.expose()
    }

    /// The 32-byte public verifying key.
    pub const fn verifying_key(&self) -> [u8; 32] {
        self.public
    }

    /// Sign a message, producing a 64-byte signature.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let mut hasher = Sha512::new();
        hasher.update(self.prefix.as_bytes());
        hasher.update(message);
        let r = Scalar::from_wide_bytes(&hasher.finalize());
        let big_r = EdwardsPoint::mul_base(&r).compress();

        let mut hasher = Sha512::new();
        hasher.update(&big_r);
        hasher.update(&self.public);
        hasher.update(message);
        let k = Scalar::from_wide_bytes(&hasher.finalize());

        let s = k.mul_add(&self.scalar, &r);

        let mut signature = [0_u8; 64];
        signature[..32].copy_from_slice(&big_r);
        signature[32..].copy_from_slice(&s.to_bytes());
        signature
    }
}

impl core::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SigningKey({:?}, secret redacted)", self.public)
    }
}

/// Signature verification failure. The variants are informational only; every
/// one of them means the same thing to a caller: reject the message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureError {
    /// The public key is not a canonical curve point.
    InvalidPublicKey,
    /// The public key has small order and cannot authenticate anything.
    SmallOrderPublicKey,
    /// The signature's `R` component is not a canonical curve point.
    InvalidSignatureR,
    /// The signature's `S` component is not a canonically reduced scalar.
    NonCanonicalSignatureS,
    /// The verification equation did not hold.
    VerificationFailed,
}

/// Verify a signature under RFC 8032 with the strict checks that make
/// signatures non-malleable and unforgeable in the multi-key setting.
///
/// This is the "strict" variant: `S` must be canonically reduced, and small
/// order public keys are refused outright.
pub fn verify_strict(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), SignatureError> {
    let big_a = EdwardsPoint::decompress(public_key).ok_or(SignatureError::InvalidPublicKey)?;
    if big_a.is_small_order().is_set() {
        return Err(SignatureError::SmallOrderPublicKey);
    }

    let mut r_bytes = [0_u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    let mut s_bytes = [0_u8; 32];
    s_bytes.copy_from_slice(&signature[32..]);

    // A canonical S is what stops an attacker from producing a second valid
    // signature for a message that was already signed.
    let s = Scalar::from_canonical_bytes(&s_bytes).ok_or(SignatureError::NonCanonicalSignatureS)?;
    if EdwardsPoint::decompress(&r_bytes).is_none() {
        return Err(SignatureError::InvalidSignatureR);
    }

    let mut hasher = Sha512::new();
    hasher.update(&r_bytes);
    hasher.update(public_key);
    hasher.update(message);
    let k = Scalar::from_wide_bytes(&hasher.finalize());

    // R = [s]B - [k]A, compared in compressed form.
    let recomputed = EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &big_a.negate(), &s);
    if ct_eq_bytes(&recomputed.compress(), &r_bytes).is_set() {
        Ok(())
    } else {
        Err(SignatureError::VerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basepoint_has_prime_order() {
        // [L]B must be the identity; L is reduced to zero, so use L-1 and add B.
        let mut l_minus_one = [0_u8; 32];
        l_minus_one[..8].copy_from_slice(&0x5812631a5cf5d3ec_u64.to_le_bytes());
        l_minus_one[8..16].copy_from_slice(&0x14def9dea2f79cd6_u64.to_le_bytes());
        l_minus_one[24..32].copy_from_slice(&0x1000000000000000_u64.to_le_bytes());
        let scalar = Scalar::from_canonical_bytes(&l_minus_one).unwrap();
        let point = EdwardsPoint::mul_base(&scalar).add(&BASEPOINT);
        assert!(point.is_identity().is_set(), "[L]B must be the identity");
    }

    #[test]
    fn compress_decompress_round_trip() {
        let mut seed = [0_u8; 32];
        seed[0] = 3;
        let scalar = Scalar::from_bytes_mod_order(&seed);
        let point = EdwardsPoint::mul_base(&scalar);
        let bytes = point.compress();
        let restored = EdwardsPoint::decompress(&bytes).unwrap();
        assert_eq!(restored.compress(), bytes);
    }

    #[test]
    fn fixed_base_agrees_with_variable_base() {
        let mut bytes = [0_u8; 32];
        bytes[0] = 0x9d;
        bytes[5] = 0x11;
        bytes[31] = 0x0f;
        let scalar = Scalar::from_bytes_mod_order(&bytes);
        assert_eq!(
            EdwardsPoint::mul_base(&scalar).compress(),
            BASEPOINT.mul(&scalar).compress()
        );
    }

    #[test]
    fn rfc8032_test_vector_1() {
        // RFC 8032, section 7.1, the empty message.
        let seed = hex32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let key = SigningKey::from_seed(&seed);
        assert_eq!(
            key.verifying_key(),
            hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        );
        let signature = key.sign(b"");
        let expected = hex64(concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ));
        assert_eq!(signature, expected);
        assert!(verify_strict(&key.verifying_key(), b"", &signature).is_ok());
    }

    #[test]
    fn rfc8032_test_vector_2() {
        let seed = hex32("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
        let key = SigningKey::from_seed(&seed);
        assert_eq!(
            key.verifying_key(),
            hex32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
        );
        let signature = key.sign(&[0x72]);
        let expected = hex64(concat!(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da",
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        ));
        assert_eq!(signature, expected);
        assert!(verify_strict(&key.verifying_key(), &[0x72], &signature).is_ok());
    }

    #[test]
    fn rfc8032_test_vector_3() {
        let seed = hex32("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
        let key = SigningKey::from_seed(&seed);
        let message = [0xaf, 0x82];
        let signature = key.sign(&message);
        let expected = hex64(concat!(
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac",
            "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
        ));
        assert_eq!(signature, expected);
        assert!(verify_strict(&key.verifying_key(), &message, &signature).is_ok());
    }

    #[test]
    fn tampered_message_is_rejected() {
        let key = SigningKey::from_seed(&[7_u8; 32]);
        let signature = key.sign(b"authentic");
        assert_eq!(
            verify_strict(&key.verifying_key(), b"forged", &signature),
            Err(SignatureError::VerificationFailed)
        );
    }

    #[test]
    fn non_canonical_s_is_rejected() {
        let key = SigningKey::from_seed(&[9_u8; 32]);
        let mut signature = key.sign(b"message");
        // Set S to L, which is not canonically reduced.
        signature[32..].copy_from_slice(&[
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ]);
        assert_eq!(
            verify_strict(&key.verifying_key(), b"message", &signature),
            Err(SignatureError::NonCanonicalSignatureS)
        );
    }

    #[test]
    fn small_order_public_key_is_rejected() {
        // The order-4 point with y = 0.
        let mut public = [0_u8; 32];
        public[0] = 0;
        let key = SigningKey::from_seed(&[1_u8; 32]);
        let signature = key.sign(b"m");
        let result = verify_strict(&public, b"m", &signature);
        assert!(matches!(
            result,
            Err(SignatureError::SmallOrderPublicKey | SignatureError::InvalidPublicKey)
        ));
    }

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0_u8; 32];
        decode_hex(s, &mut out);
        out
    }

    fn hex64(s: &str) -> [u8; 64] {
        let mut out = [0_u8; 64];
        decode_hex(s, &mut out);
        out
    }

    fn decode_hex(s: &str, out: &mut [u8]) {
        let bytes = s.as_bytes();
        for (i, slot) in out.iter_mut().enumerate() {
            let hi = (bytes[2 * i] as char).to_digit(16).unwrap() as u8;
            let lo = (bytes[2 * i + 1] as char).to_digit(16).unwrap() as u8;
            *slot = (hi << 4) | lo;
        }
    }
}
