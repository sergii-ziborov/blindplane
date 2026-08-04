//! SHA-256 and SHA-512.
//!
//! SHA-256 has two interchangeable implementations: a portable one and one
//! built on the ARMv8 SHA-2 instructions, chosen once per process by runtime
//! feature detection. Both produce identical digests; the tests assert that on
//! every input they are given.

mod sha256;
mod sha512;
#[cfg(test)]
mod tests;

pub use sha256::Sha256;
pub use sha512::{Sha512, sha512_is_hardware};
