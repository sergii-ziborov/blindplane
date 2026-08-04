//! Blindplane's cryptographic core, implemented from the specifications with
//! no third-party runtime dependencies.
//!
//! # Why this crate exists
//!
//! Blindplane's whole claim is that a server cannot read what it stores. That
//! claim is only as good as the code under it, so the code under it is here,
//! in one auditable crate, rather than spread across a dependency tree nobody
//! reads. The shipped dependency graph is empty: `cargo tree` on any crate in
//! this workspace lists only workspace members.
//!
//! Third-party implementations do appear in `[dev-dependencies]`. They are
//! used to cross-check this crate's output byte for byte in tests and to
//! provide the competitor numbers in the benchmarks. None of them can reach a
//! shipped binary.
//!
//! # What is implemented
//!
//! | Primitive | Specification | Notes |
//! |---|---|---|
//! | SHA-256, SHA-512 | FIPS 180-4 | SHA-256 uses ARMv8 SHA-2 instructions when present |
//! | HMAC, HKDF | RFC 2104, RFC 5869 | over SHA-256 and SHA-512 |
//! | ChaCha20, HChaCha20 | RFC 8439, XChaCha draft | four blocks per pass in 32-bit lanes |
//! | Poly1305 | RFC 8439 | base-2^64 limbs, four wide products per block |
//! | ChaCha20-Poly1305, XChaCha20-Poly1305 | RFC 8439 | constant time on every target |
//! | AES-256-GCM | NIST SP 800-38D | CPU instructions only, by design |
//! | X25519 | RFC 7748 | Montgomery ladder, 51-bit limbs |
//! | Ed25519 | RFC 8032 | strict verification, signed radix-16 fixed-base table |
//! | HPKE | RFC 9180 | DHKEM(X25519, HKDF-SHA256), modes base and auth |
//! | Argon2id | RFC 9106 | single-lane, for password-derived vault keys |
//!
//! # Security posture
//!
//! Secret-dependent branches and secret-dependent memory addresses are treated
//! as bugs. Comparisons on secret data go through [`util::Choice`], key
//! material lives in [`util::Secret`], and AEAD decryption authenticates
//! before it releases any plaintext.
//!
//! This code has not been independently audited. It is a prototype
//! implementation of standard algorithms, verified against published test
//! vectors and cross-checked against established implementations, which is not
//! the same thing as an audit. Treat it accordingly.
//!
//! # Feature flags
//!
//! * `std` (default) — operating-system entropy (`rand`, the `generate`
//!   constructors) and everything that returns a heap buffer: `hpke`,
//!   `simple`, `argon2`, and the `Vec`-based [`aead::Suite`] conveniences.
//! * `accel` (default, implies `std`) — the CPU instruction paths, selected
//!   by runtime detection.
//!
//! With `--no-default-features` the crate is `no_std` and allocation-free:
//! SHA-2, HMAC, HKDF, the in-place AEAD calls, X25519 and Ed25519 signing
//! and verification all remain available, with keys supplied by the caller.
//!
//! # Example
//!
//! ```
//! use blindplane_crypto::{aead::Suite, hpke, montgomery::StaticSecret};
//!
//! let recipient = StaticSecret::generate()?;
//! let (encapsulated, ciphertext) = hpke::seal(
//!     Suite::ChaCha20Poly1305,
//!     &recipient.public_key(),
//!     b"application context",
//!     b"associated data",
//!     b"the server never sees this",
//! )?;
//!
//! let opened = hpke::open(
//!     Suite::ChaCha20Poly1305,
//!     &recipient,
//!     &encapsulated,
//!     b"application context",
//!     b"associated data",
//!     &ciphertext,
//! )?;
//! assert_eq!(opened, b"the server never sees this");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_op_in_unsafe_fn)]

pub mod aead;
pub mod aes;
#[cfg(feature = "std")]
pub mod argon2;
pub mod chacha;
pub mod edwards;
pub mod field;
#[cfg(feature = "std")]
pub mod hpke;
pub mod kdf;
pub mod montgomery;
pub mod poly1305;
#[cfg(feature = "std")]
pub mod rand;
pub mod scalar;
pub mod sha2;
#[cfg(feature = "std")]
pub mod simple;
pub mod util;

pub use aead::{AeadError, Suite};
pub use edwards::{PreparedVerifier, SignatureError, SigningKey, verify_strict};
pub use kdf::{HmacSha256, HmacSha512, hkdf, hkdf_expand, hkdf_extract};
pub use montgomery::StaticSecret;
pub use sha2::{Sha256, Sha512};
#[cfg(feature = "std")]
pub use simple::{Key, hash_password, verify_password};
pub use util::{Choice, Secret, ct_eq_bytes, secure_erase};

/// Which accelerated code paths this build will actually use on this CPU.
///
/// Reported by the benchmark harness and by `blindplane-cli` so a performance
/// number always says which implementation produced it.
#[allow(
    clippy::struct_excessive_bools,
    reason = "a flat capability report, not state"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Acceleration {
    /// SHA-256 runs on CPU cryptographic instructions.
    pub sha256_hardware: bool,
    /// SHA-512 runs on the FEAT_SHA512 instructions.
    pub sha512_hardware: bool,
    /// AES-256-GCM is available at all, which requires those instructions.
    pub aes_hardware: bool,
    /// The build was compiled with the `accel` feature.
    pub accel_feature: bool,
}

impl Acceleration {
    /// Detect at runtime.
    pub fn detect() -> Self {
        Self {
            sha256_hardware: sha256_hardware(),
            sha512_hardware: sha2::sha512_is_hardware(),
            aes_hardware: aes::available(),
            accel_feature: cfg!(feature = "accel"),
        }
    }
}

fn sha256_hardware() -> bool {
    #[cfg(all(feature = "accel", target_arch = "aarch64"))]
    {
        std::arch::is_aarch64_feature_detected!("sha2")
    }
    #[cfg(not(all(feature = "accel", target_arch = "aarch64")))]
    {
        false
    }
}

impl core::fmt::Display for Acceleration {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "accel={} sha256={} sha512={} aes-gcm={}",
            if self.accel_feature { "on" } else { "off" },
            if self.sha256_hardware {
                "hardware"
            } else {
                "portable"
            },
            if self.sha512_hardware {
                "hardware"
            } else {
                "portable"
            },
            if self.aes_hardware {
                "hardware"
            } else {
                "unavailable"
            }
        )
    }
}
