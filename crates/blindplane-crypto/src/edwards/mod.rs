//! The Ed25519 group and RFC 8032 signatures.
//!
//! Points are held in extended twisted Edwards coordinates `(X:Y:Z:T)` with
//! `x = X/Z`, `y = Y/Z` and `x*y = T/Z`. Secret-scalar multiplication uses a
//! signed radix-16 fixed-base table with constant-time selection; signature
//! verification, which only touches public data, uses a variable-time
//! non-adjacent form.

mod keys;
mod niels;
mod point;
mod scalar_mul;
mod tables;
#[cfg(test)]
mod tests;
mod vartime;

pub use keys::{PreparedVerifier, SignatureError, SigningKey, verify_strict};
pub use point::EdwardsPoint;
