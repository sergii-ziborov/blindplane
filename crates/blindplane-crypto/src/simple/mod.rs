//! The short path: encrypt data, decrypt it, and store passwords.
//!
//! The rest of this crate is a toolkit. This module is the three things most
//! applications actually need, with the decisions already made — cipher suite,
//! nonce handling, key-derivation cost — so there is nothing to get wrong.
//!
//! ```
//! use blindplane_crypto::simple::{Key, hash_password, verify_password};
//!
//! // Encrypting a message or a blob of user data.
//! let key = Key::generate()?;
//! let sealed = key.encrypt(b"a private message", b"message:42")?;
//! let opened = key.decrypt(&sealed, b"message:42")?;
//! assert_eq!(opened, b"a private message");
//!
//! // Storing a password. Note this is hashing, not encryption.
//! let stored = hash_password("correct horse battery staple")?;
//! assert!(verify_password("correct horse battery staple", &stored));
//! assert!(!verify_password("wrong guess", &stored));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Passwords are hashed, never encrypted
//!
//! [`hash_password`] does not encrypt. Encryption is reversible, so a system
//! that encrypts passwords hands every one of them to whoever gets the key.
//! Passwords go through Argon2id, which is one-way and deliberately slow, and
//! [`verify_password`] re-derives to compare. If you find yourself wanting to
//! decrypt a password, the answer is always that you do not need to.
//!
//! # What the associated data is for
//!
//! [`Key::encrypt`] takes a `context` argument that is authenticated but not
//! encrypted. Put in it whatever identifies where this ciphertext belongs —
//! a record id, a field name, a user id. Decryption fails unless the same
//! context is supplied, so an attacker who can move ciphertexts around your
//! database cannot silently swap one user's field into another's record.
//! Passing `b""` is allowed and gives up that protection.

mod key;
mod password;
#[cfg(test)]
mod tests;

use crate::aead::AeadError;
use crate::argon2::InvalidParams;

pub use key::Key;
pub use password::{hash_password, verify_password};

/// Length of the random salt stored alongside a password hash.
const SALT_LEN: usize = 16;
/// Length of the derived password hash.
const HASH_LEN: usize = 32;

/// What can go wrong.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoError {
    /// The operating system would not provide randomness.
    Randomness,
    /// Wrong key, wrong context, or the data was altered — deliberately not
    /// distinguished.
    Unauthenticated,
    /// The requested cipher suite is unavailable on this CPU.
    Unsupported,
    /// Password-hashing parameters were out of range.
    InvalidParameters,
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Randomness => f.write_str("operating system randomness failed"),
            Self::Unauthenticated => {
                f.write_str("could not decrypt: wrong key, wrong context, or altered data")
            }
            Self::Unsupported => f.write_str("cipher suite unsupported on this CPU"),
            Self::InvalidParameters => f.write_str("invalid password-hashing parameters"),
        }
    }
}

impl core::error::Error for CryptoError {}

impl From<AeadError> for CryptoError {
    fn from(error: AeadError) -> Self {
        match error {
            AeadError::Unsupported => Self::Unsupported,
            AeadError::Unauthenticated | AeadError::MessageTooLong => Self::Unauthenticated,
        }
    }
}

impl From<InvalidParams> for CryptoError {
    fn from(_: InvalidParams) -> Self {
        Self::InvalidParameters
    }
}
