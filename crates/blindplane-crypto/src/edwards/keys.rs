//! Ed25519 signing keys, strict verification, and the prepared verifier.

use crate::scalar::Scalar;
use crate::sha2::Sha512;
use crate::util::{Secret, ct_eq_bytes};

use super::niels::AffineNiels;
use super::point::EdwardsPoint;
use super::tables::affine_odd_multiples;

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

    verify_tail(public_key, message, signature, |k, s| {
        EdwardsPoint::vartime_double_scalar_mul_basepoint(k, &big_a.negate(), s)
    })
}

/// The tail every strict verification shares once the key itself is settled:
/// parse and canonicity-check `S`, derive `k`, recompute the equation's right
/// side, compare in compressed form.
fn verify_tail(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
    recompute: impl FnOnce(&Scalar, &Scalar) -> EdwardsPoint,
) -> Result<(), SignatureError> {
    let mut r_bytes = [0_u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    let mut s_bytes = [0_u8; 32];
    s_bytes.copy_from_slice(&signature[32..]);

    // A canonical S is what stops an attacker from producing a second valid
    // signature for a message that was already signed.
    let s = Scalar::from_canonical_bytes(&s_bytes).ok_or(SignatureError::NonCanonicalSignatureS)?;

    let mut hasher = Sha512::new();
    hasher.update(&r_bytes);
    hasher.update(public_key);
    hasher.update(message);
    let k = Scalar::from_wide_bytes(&hasher.finalize());

    // R = [s]B - [k]A, compared in compressed form. The comparison subsumes
    // decompressing R: the recomputed side always compresses to a canonical
    // encoding of a curve point, so bytes that are not one can never match.
    // R is decompressed only on the failure path, to classify the error the
    // same way as before.
    let recomputed = recompute(&k, &s);
    if ct_eq_bytes(&recomputed.compress(), &r_bytes).is_set() {
        Ok(())
    } else if EdwardsPoint::decompress(&r_bytes).is_none() {
        Err(SignatureError::InvalidSignatureR)
    } else {
        Err(SignatureError::VerificationFailed)
    }
}

/// A public key prepared for repeated strict verification.
///
/// Records are verified far more often than authors change: one sync opens
/// many records from the same pinned key. Preparation pays the key's
/// decompression, its small-order rejection and its odd-multiples table once;
/// every verification against the prepared key skips all three, and its
/// `A`-side additions run from an affine table — the cheapest kind, the same
/// shape the constant basepoint enjoys.
///
/// [`PreparedVerifier::verify_strict`] accepts and rejects exactly what the
/// free [`verify_strict`] accepts and rejects, error for error; the
/// key-shaped failures simply surface at construction instead of per call.
#[derive(Clone)]
pub struct PreparedVerifier {
    public: [u8; 32],
    /// Odd multiples of the *negated* key point: the equation adds `[k](-A)`.
    negated_odd: [AffineNiels; 64],
}

impl core::fmt::Debug for PreparedVerifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PreparedVerifier({:?})", self.public)
    }
}

impl PreparedVerifier {
    /// Decompress the key, reject small-order points, build the table.
    pub fn new(public_key: &[u8; 32]) -> Result<Self, SignatureError> {
        let big_a = EdwardsPoint::decompress(public_key).ok_or(SignatureError::InvalidPublicKey)?;
        if big_a.is_small_order().is_set() {
            return Err(SignatureError::SmallOrderPublicKey);
        }
        Ok(Self {
            public: *public_key,
            negated_odd: affine_odd_multiples(&big_a.negate()),
        })
    }

    /// The 32-byte key this verifier was prepared from.
    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public
    }

    /// Strict verification against the prepared key.
    pub fn verify_strict(
        &self,
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), SignatureError> {
        verify_tail(&self.public, message, signature, |k, s| {
            EdwardsPoint::vartime_double_scalar_mul_prepared(k, &self.negated_odd, s)
        })
    }
}
