//! The symmetric key type: generate, derive, encrypt, decrypt.

use crate::aead::Suite;
use crate::argon2::{Argon2Params, argon2id};
use crate::rand;
use crate::util::Secret;

use super::CryptoError;

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
