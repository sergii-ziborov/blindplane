//! X25519 Diffie-Hellman (RFC 7748).

use crate::field::Fe;
use crate::util::{Choice, Secret};

/// Multiply a u-coordinate by a scalar with the Montgomery ladder.
///
/// The ladder performs the same operations for every scalar bit and swaps its
/// two working points with a mask, so timing and memory access reveal nothing
/// about the secret.
pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let mut clamped = *scalar;
    clamped[0] &= 0b1111_1000;
    clamped[31] &= 127;
    clamped[31] |= 64;

    let x1 = Fe::from_bytes(point);
    let mut x2 = Fe::ONE;
    let mut z2 = Fe::ZERO;
    let mut x3 = x1;
    let mut z3 = Fe::ONE;
    let mut swap = Choice::FALSE;

    for i in (0..255).rev() {
        let bit = Choice::from_bit(u64::from((clamped[i >> 3] >> (i & 7)) & 1));
        swap = swap ^ bit;
        Fe::conditional_swap(&mut x2, &mut x3, swap);
        Fe::conditional_swap(&mut z2, &mut z3, swap);
        swap = bit;

        let a = x2.add(&z2);
        let b = x2.sub(&z2);
        let c = x3.add(&z3);
        let d = x3.sub(&z3);
        let da = d.mul(&a);
        let cb = c.mul(&b);
        let aa = a.square();
        let bb = b.square();

        x3 = da.add(&cb).square();
        z3 = x1.mul(&da.sub(&cb).square());
        x2 = aa.mul(&bb);
        let e = aa.sub(&bb);
        z2 = e.mul(&bb.add(&e.mul121666()));
    }

    Fe::conditional_swap(&mut x2, &mut x3, swap);
    Fe::conditional_swap(&mut z2, &mut z3, swap);

    x2.mul(&z2.invert()).to_bytes()
}

/// The X25519 base point, u = 9.
pub const BASEPOINT: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Derive the public key for a secret key.
pub fn public_key(secret: &[u8; 32]) -> [u8; 32] {
    x25519(secret, &BASEPOINT)
}

/// An X25519 key pair.
pub struct StaticSecret {
    secret: Secret<32>,
    public: [u8; 32],
}

impl StaticSecret {
    /// Adopt an existing 32-byte secret.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        let public = public_key(&bytes);
        Self {
            secret: Secret::new(bytes),
            public,
        }
    }

    /// Generate a key pair from operating-system entropy.
    #[cfg(feature = "std")]
    pub fn generate() -> Result<Self, crate::rand::RandomError> {
        let mut bytes = [0_u8; 32];
        crate::rand::fill(&mut bytes)?;
        Ok(Self::from_bytes(bytes))
    }

    /// The public key.
    pub const fn public_key(&self) -> [u8; 32] {
        self.public
    }

    /// The secret bytes, for storage inside an encrypted vault.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.secret.expose()
    }

    /// Compute the shared secret with a peer's public key.
    ///
    /// Returns `None` when the result is all zeroes, which is what a
    /// small-order peer key produces and which must never be used as key
    /// material.
    pub fn diffie_hellman(&self, peer: &[u8; 32]) -> Option<Secret<32>> {
        let shared = x25519(self.secret.as_bytes(), peer);
        if crate::util::ct_eq_bytes(&shared, &[0_u8; 32]).is_set() {
            return None;
        }
        Some(Secret::new(shared))
    }
}

impl core::fmt::Debug for StaticSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "StaticSecret({:?}, secret redacted)", self.public)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::testutil::unhex_array as hex32;

    #[test]
    fn rfc7748_vector_1() {
        let scalar = hex32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let point = hex32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        assert_eq!(
            x25519(&scalar, &point),
            hex32("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        );
    }

    #[test]
    fn rfc7748_vector_2() {
        let scalar = hex32("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        let point = hex32("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        assert_eq!(
            x25519(&scalar, &point),
            hex32("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")
        );
    }

    #[test]
    fn rfc7748_diffie_hellman() {
        let alice_secret =
            hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let bob_secret = hex32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");

        let alice_public = public_key(&alice_secret);
        let bob_public = public_key(&bob_secret);
        assert_eq!(
            alice_public,
            hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        assert_eq!(
            bob_public,
            hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        );

        let expected = hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(x25519(&alice_secret, &bob_public), expected);
        assert_eq!(x25519(&bob_secret, &alice_public), expected);
    }

    #[test]
    fn small_order_peer_key_is_rejected() {
        let secret = StaticSecret::from_bytes([1_u8; 32]);
        // The all-zero u-coordinate has order 1.
        assert!(secret.diffie_hellman(&[0_u8; 32]).is_none());
    }

    #[test]
    fn iterated_vector() {
        // RFC 7748, section 5.2: one iteration of the recurrence.
        let mut k = hex32("0900000000000000000000000000000000000000000000000000000000000000");
        let mut u = k;
        for _ in 0..1 {
            let result = x25519(&k, &u);
            u = k;
            k = result;
        }
        assert_eq!(
            k,
            hex32("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
        );
    }
}
