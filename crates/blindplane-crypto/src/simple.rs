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

use crate::aead::{AeadError, Suite};
use crate::argon2::{Argon2Params, InvalidParams, argon2id};
use crate::rand;
use crate::util::{Secret, ct_eq_bytes};

/// Length of the random salt stored alongside a password hash.
const SALT_LEN: usize = 16;
/// Length of the derived password hash.
const HASH_LEN: usize = 32;

/// A 256-bit symmetric key.
///
/// Generate one with [`Key::generate`] and store it somewhere your application
/// code cannot leak — a key manager, an OS keychain, an environment secret. The
/// bytes erase themselves when the key is dropped.
pub struct Key(Secret<32>);

impl Key {
    /// Generate a key from the operating system's randomness.
    pub fn generate() -> Result<Self, CryptoError> {
        rand::secret_32()
            .map(Self)
            .map_err(|_| CryptoError::Randomness)
    }

    /// Adopt an existing 32-byte key.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Secret::new(bytes))
    }

    /// Derive a key from a password.
    ///
    /// Use this only when a human password really is the key, as with a
    /// client-side vault. `salt` must be stored alongside the ciphertext and
    /// must be unique per key; 16 random bytes is the usual choice. This is
    /// deliberately slow — around a tenth of a second — because that cost is
    /// what stands between a stolen ciphertext and a dictionary attack.
    pub fn from_password(password: &str, salt: &[u8]) -> Result<Self, CryptoError> {
        let derived = argon2id(password.as_bytes(), salt, Argon2Params::default())?;
        let mut key = Secret::zeroed();
        key.as_mut().copy_from_slice(&derived);
        Ok(Self(key))
    }

    /// Export the raw key bytes, for storage in a key manager.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.expose()
    }

    /// Encrypt `plaintext`, binding it to `context`.
    ///
    /// The result carries its own nonce and authentication tag, so it is the
    /// only thing you need to store. It is 28 bytes longer than the input.
    pub fn encrypt(&self, plaintext: &[u8], context: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // A fresh random nonce per message. The suite is chosen once per
        // process: hardware AES-GCM where the CPU has AES instructions,
        // ChaCha20-Poly1305 everywhere else, which is fast and constant time
        // in software.
        let suite = Suite::fastest_available();
        let mut out = vec![0_u8; suite.nonce_len()];
        rand::fill(&mut out).map_err(|_| CryptoError::Randomness)?;

        let sealed = suite.seal(self.0.as_bytes(), &out, context, plaintext)?;
        out.push(suite.code());
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Decrypt something produced by [`Key::encrypt`].
    ///
    /// Fails if the key is wrong, the context differs, or a single bit was
    /// changed. The failure is deliberately indistinguishable between those
    /// cases: telling them apart would hand an attacker an oracle.
    pub fn decrypt(&self, sealed: &[u8], context: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Read the suite code first; it sits after the nonce, whose length the
        // suite itself determines, so try each known nonce length.
        for suite in [
            Suite::Aes256Gcm,
            Suite::XChaCha20Poly1305,
            Suite::ChaCha20Poly1305,
        ] {
            let header = suite.nonce_len() + 1;
            if sealed.len() > header && sealed[suite.nonce_len()] == suite.code() {
                let plaintext = suite.open(
                    self.0.as_bytes(),
                    &sealed[..suite.nonce_len()],
                    context,
                    &sealed[header..],
                )?;
                return Ok(plaintext);
            }
        }
        Err(CryptoError::Unauthenticated)
    }
}

impl core::fmt::Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Key(redacted)")
    }
}

/// Hash a password for storage.
///
/// The returned string carries the salt and the parameters, so it is the only
/// thing to store. Hand it back to [`verify_password`] at login. This is not
/// encryption and cannot be reversed, which is the point.
pub fn hash_password(password: &str) -> Result<String, CryptoError> {
    let mut salt = [0_u8; SALT_LEN];
    rand::fill(&mut salt).map_err(|_| CryptoError::Randomness)?;

    let params = Argon2Params::default();
    let hash = argon2id(password.as_bytes(), &salt, params)?;

    // Self-describing, so the cost parameters can be raised later without
    // invalidating hashes already stored.
    Ok(format!(
        "argon2id$v=19$m={},t={},p=1${}${}",
        params.memory_kib,
        params.passes,
        hex(&salt),
        hex(&hash)
    ))
}

/// Check a password against a stored hash from [`hash_password`].
///
/// Returns `false` for a wrong password and for a malformed stored value; it
/// never panics on bad input, because that input often comes from a database
/// somebody else can write to.
#[must_use]
pub fn verify_password(password: &str, stored: &str) -> bool {
    let Some((salt, expected, params)) = parse_stored(stored) else {
        return false;
    };
    let Ok(derived) = argon2id(password.as_bytes(), &salt, params) else {
        return false;
    };
    ct_eq_bytes(&derived, &expected).is_set()
}

fn parse_stored(stored: &str) -> Option<(Vec<u8>, Vec<u8>, Argon2Params)> {
    let mut parts = stored.split('$');
    if parts.next()? != "argon2id" || parts.next()? != "v=19" {
        return None;
    }

    let mut memory_kib = 0_u32;
    let mut passes = 0_u32;
    for setting in parts.next()?.split(',') {
        let (name, value) = setting.split_once('=')?;
        match name {
            "m" => memory_kib = value.parse().ok()?,
            "t" => passes = value.parse().ok()?,
            "p" => {
                if value != "1" {
                    return None;
                }
            }
            _ => return None,
        }
    }

    let salt = unhex(parts.next()?)?;
    let expected = unhex(parts.next()?)?;
    if parts.next().is_some() || salt.len() < 8 || expected.is_empty() {
        return None;
    }

    Some((
        salt,
        expected,
        Argon2Params {
            memory_kib,
            passes,
            output_len: HASH_LEN,
        },
    ))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 15)] as char);
    }
    out
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 || text.is_empty() {
        return None;
    }
    let bytes = text.as_bytes();
    (0..bytes.len() / 2)
        .map(|i| {
            let hi = (bytes[i * 2] as char).to_digit(16)?;
            let lo = (bytes[i * 2 + 1] as char).to_digit(16)?;
            Some(((hi << 4) | lo) as u8)
        })
        .collect()
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_at_many_sizes() {
        let key = Key::generate().unwrap();
        for len in [0_usize, 1, 15, 16, 17, 1024, 100_000] {
            let message: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
            let sealed = key.encrypt(&message, b"ctx").unwrap();
            assert_eq!(key.decrypt(&sealed, b"ctx").unwrap(), message);
        }
    }

    #[test]
    fn the_same_message_encrypts_differently_every_time() {
        // A fresh nonce per message, so identical plaintexts must not produce
        // identical ciphertexts; otherwise an observer learns which records match.
        let key = Key::generate().unwrap();
        let first = key.encrypt(b"same", b"ctx").unwrap();
        let second = key.encrypt(b"same", b"ctx").unwrap();
        assert_ne!(first, second);
        assert_eq!(key.decrypt(&first, b"ctx").unwrap(), b"same");
        assert_eq!(key.decrypt(&second, b"ctx").unwrap(), b"same");
    }

    #[test]
    fn wrong_key_context_or_bit_all_fail() {
        let key = Key::generate().unwrap();
        let other = Key::generate().unwrap();
        let sealed = key.encrypt(b"secret", b"record:1").unwrap();

        assert_eq!(
            other.decrypt(&sealed, b"record:1"),
            Err(CryptoError::Unauthenticated)
        );
        assert_eq!(
            key.decrypt(&sealed, b"record:2"),
            Err(CryptoError::Unauthenticated)
        );

        for index in 0..sealed.len() {
            let mut tampered = sealed.clone();
            tampered[index] ^= 1;
            assert!(
                key.decrypt(&tampered, b"record:1").is_err(),
                "a flipped bit at {index} was accepted"
            );
        }
    }

    #[test]
    fn truncated_input_is_rejected_without_panicking() {
        let key = Key::generate().unwrap();
        let sealed = key.encrypt(b"secret", b"ctx").unwrap();
        for len in 0..sealed.len() {
            assert!(key.decrypt(&sealed[..len], b"ctx").is_err());
        }
    }

    #[test]
    fn password_hash_verifies_and_rejects() {
        let stored = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password("correct horse battery staple", &stored));
        assert!(!verify_password("Correct horse battery staple", &stored));
        assert!(!verify_password("", &stored));
    }

    #[test]
    fn password_hashes_are_salted() {
        // Two users with the same password must not share a stored value, or
        // one cracked hash breaks every account that reused that password.
        let first = hash_password("same password").unwrap();
        let second = hash_password("same password").unwrap();
        assert_ne!(first, second);
        assert!(verify_password("same password", &first));
        assert!(verify_password("same password", &second));
    }

    #[test]
    fn malformed_stored_hashes_are_rejected_quietly() {
        for stored in [
            "",
            "not-a-hash",
            "argon2id$v=19$m=64,t=1,p=1$",
            "argon2id$v=19$m=64,t=1,p=2$aabbccdd$eeff",
            "bcrypt$v=19$m=64,t=1,p=1$aabbccddaabbccdd$eeff",
            "argon2id$v=19$m=64,t=1,p=1$zz$eeff",
        ] {
            assert!(!verify_password("anything", stored), "accepted {stored:?}");
        }
    }

    #[test]
    fn a_password_derived_key_round_trips() {
        let salt = [7_u8; SALT_LEN];
        let key = Key::from_password("vault password", &salt).unwrap();
        let sealed = key.encrypt(b"vault contents", b"vault").unwrap();

        let reopened = Key::from_password("vault password", &salt).unwrap();
        assert_eq!(
            reopened.decrypt(&sealed, b"vault").unwrap(),
            b"vault contents"
        );

        let wrong = Key::from_password("wrong password", &salt).unwrap();
        assert!(wrong.decrypt(&sealed, b"vault").is_err());
    }
}
