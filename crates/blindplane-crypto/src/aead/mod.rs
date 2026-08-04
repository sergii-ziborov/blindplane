//! Authenticated encryption with associated data.
//!
//! Three constructions share one interface: ChaCha20-Poly1305 (RFC 8439),
//! XChaCha20-Poly1305 with a 192-bit nonce, and AES-256-GCM on CPU
//! instructions. All of them authenticate before decrypting and never hand a
//! caller unverified plaintext.

mod chacha20poly1305;
#[cfg(test)]
mod tests;

use crate::util::secure_erase;

use chacha20poly1305::{chacha20poly1305_open, chacha20poly1305_seal, xchacha_split};

/// Tag length shared by every suite here.
pub const TAG_LEN: usize = 16;

/// An AEAD failure. Decryption failures are a single opaque variant so a
/// caller cannot build an oracle distinguishing "wrong key" from "tampered".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AeadError {
    /// The message could not be authenticated.
    Unauthenticated,
    /// The selected suite needs CPU instructions this machine does not have.
    Unsupported,
    /// The input exceeds what the construction can safely encrypt.
    MessageTooLong,
}

impl core::fmt::Display for AeadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unauthenticated => f.write_str("message could not be authenticated"),
            Self::Unsupported => f.write_str("cipher suite unsupported on this CPU"),
            Self::MessageTooLong => f.write_str("message exceeds the maximum length"),
        }
    }
}

impl core::error::Error for AeadError {}

/// The AEAD suites the wire format can name.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub enum Suite {
    /// AES-256-GCM, the fastest option wherever the CPU has AES instructions.
    #[default]
    Aes256Gcm,
    /// XChaCha20-Poly1305, constant time in software with a 192-bit nonce.
    XChaCha20Poly1305,
    /// ChaCha20-Poly1305 exactly as specified in RFC 8439.
    ChaCha20Poly1305,
}

impl Suite {
    /// Nonce length in bytes.
    pub const fn nonce_len(self) -> usize {
        match self {
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 12,
            Self::XChaCha20Poly1305 => 24,
        }
    }

    /// Stable one-byte code used in signed transcripts.
    pub const fn code(self) -> u8 {
        match self {
            Self::Aes256Gcm => 1,
            Self::XChaCha20Poly1305 => 2,
            Self::ChaCha20Poly1305 => 3,
        }
    }

    /// Whether this CPU can run the suite.
    pub fn is_available(self) -> bool {
        match self {
            Self::Aes256Gcm => crate::aes::available(),
            Self::XChaCha20Poly1305 | Self::ChaCha20Poly1305 => true,
        }
    }

    /// The fastest suite this CPU supports.
    ///
    /// Hardware AES-GCM beats software ChaCha by a wide margin on Apple
    /// Silicon and on any x86-64 with AES-NI; everywhere else ChaCha wins,
    /// and is also the only one that stays constant time.
    pub fn fastest_available() -> Self {
        if crate::aes::available() {
            Self::Aes256Gcm
        } else {
            Self::XChaCha20Poly1305
        }
    }

    /// Encrypt `buffer` in place and return the authentication tag.
    pub fn seal_in_place(
        self,
        key: &[u8; 32],
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; TAG_LEN], AeadError> {
        if nonce.len() != self.nonce_len() {
            return Err(AeadError::Unsupported);
        }
        match self {
            Self::Aes256Gcm => {
                let mut fixed = [0_u8; 12];
                fixed.copy_from_slice(nonce);
                crate::aes::seal_in_place(key, &fixed, associated_data, buffer)
                    .ok_or(AeadError::Unsupported)
            }
            Self::ChaCha20Poly1305 => {
                let mut fixed = [0_u8; 12];
                fixed.copy_from_slice(nonce);
                Ok(chacha20poly1305_seal(key, &fixed, associated_data, buffer))
            }
            Self::XChaCha20Poly1305 => {
                let (subkey, fixed) = xchacha_split(key, nonce);
                Ok(chacha20poly1305_seal(
                    subkey.as_bytes(),
                    &fixed,
                    associated_data,
                    buffer,
                ))
            }
        }
    }

    /// Verify the tag and decrypt `buffer` in place.
    ///
    /// On failure the buffer is zeroed rather than left holding a partially
    /// decrypted message.
    pub fn open_in_place(
        self,
        key: &[u8; 32],
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), AeadError> {
        if nonce.len() != self.nonce_len() {
            return Err(AeadError::Unauthenticated);
        }
        let opened = match self {
            Self::Aes256Gcm => {
                let mut fixed = [0_u8; 12];
                fixed.copy_from_slice(nonce);
                match crate::aes::open_in_place(key, &fixed, associated_data, buffer, tag) {
                    Some(result) => result,
                    None => return Err(AeadError::Unsupported),
                }
            }
            Self::ChaCha20Poly1305 => {
                let mut fixed = [0_u8; 12];
                fixed.copy_from_slice(nonce);
                chacha20poly1305_open(key, &fixed, associated_data, buffer, tag)
            }
            Self::XChaCha20Poly1305 => {
                let (subkey, fixed) = xchacha_split(key, nonce);
                chacha20poly1305_open(subkey.as_bytes(), &fixed, associated_data, buffer, tag)
            }
        };

        if opened {
            Ok(())
        } else {
            secure_erase(buffer);
            Err(AeadError::Unauthenticated)
        }
    }

    /// Encrypt into a fresh buffer holding ciphertext followed by the tag.
    #[cfg(feature = "std")]
    pub fn seal(
        self,
        key: &[u8; 32],
        nonce: &[u8],
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        let mut out = Vec::with_capacity(plaintext.len() + TAG_LEN);
        out.extend_from_slice(plaintext);
        let tag = self.seal_in_place(key, nonce, associated_data, &mut out)?;
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// Decrypt a buffer holding ciphertext followed by the tag.
    #[cfg(feature = "std")]
    pub fn open(
        self,
        key: &[u8; 32],
        nonce: &[u8],
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        if ciphertext.len() < TAG_LEN {
            return Err(AeadError::Unauthenticated);
        }
        let split = ciphertext.len() - TAG_LEN;
        let mut tag = [0_u8; TAG_LEN];
        tag.copy_from_slice(&ciphertext[split..]);
        let mut out = ciphertext[..split].to_vec();
        self.open_in_place(key, nonce, associated_data, &mut out, &tag)?;
        Ok(out)
    }
}
