//! Hybrid Public Key Encryption (RFC 9180).
//!
//! The suite is fixed: `DHKEM(X25519, HKDF-SHA256)`, `HKDF-SHA256`, and either
//! ChaCha20-Poly1305 or AES-256-GCM. Both `mode_base` and `mode_auth` are
//! implemented; `mode_auth` binds the sender's static key into the key
//! schedule, which gives the receiver a sender guarantee without a separate
//! signature and without revealing the sender to anyone else.

mod open;
mod primitives;
mod seal;
#[cfg(test)]
mod tests;

pub use open::{auth_open, open};
pub use primitives::{
    ENCAPSULATED_KEY_LEN, HpkeError, KEY_LEN, NONCE_LEN, derive_key_pair, diffie_hellman,
    public_key_from_secret,
};
pub use seal::{auth_seal, seal};
