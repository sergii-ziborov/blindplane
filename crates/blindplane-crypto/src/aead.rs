//! Authenticated encryption with associated data.
//!
//! Three constructions share one interface: ChaCha20-Poly1305 (RFC 8439),
//! XChaCha20-Poly1305 with a 192-bit nonce, and AES-256-GCM on CPU
//! instructions. All of them authenticate before decrypting and never hand a
//! caller unverified plaintext.

use crate::chacha::{ChaCha20, hchacha20};
use crate::poly1305::Poly1305;
use crate::util::{Secret, secure_erase};

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

/// Derive the XChaCha subkey and the 96-bit nonce it is used with.
fn xchacha_split(key: &[u8; 32], nonce: &[u8]) -> (Secret<32>, [u8; 12]) {
    let mut hchacha_nonce = [0_u8; 16];
    hchacha_nonce.copy_from_slice(&nonce[..16]);
    let subkey = hchacha20(key, &hchacha_nonce);

    let mut inner = [0_u8; 12];
    inner[4..].copy_from_slice(&nonce[16..24]);
    (Secret::new(subkey), inner)
}

fn chacha20poly1305_seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    associated_data: &[u8],
    buffer: &mut [u8],
) -> [u8; TAG_LEN] {
    let mut mac = Poly1305::new(&poly_key(key, nonce));
    ChaCha20::new(key, nonce, 1).apply_keystream(buffer);

    mac.update(associated_data);
    mac.pad_to_block();
    mac.update(buffer);
    mac.pad_to_block();
    mac.update(&(associated_data.len() as u64).to_le_bytes());
    mac.update(&(buffer.len() as u64).to_le_bytes());
    mac.finalize()
}

fn chacha20poly1305_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    associated_data: &[u8],
    buffer: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> bool {
    let mut mac = Poly1305::new(&poly_key(key, nonce));
    mac.update(associated_data);
    mac.pad_to_block();
    mac.update(buffer);
    mac.pad_to_block();
    mac.update(&(associated_data.len() as u64).to_le_bytes());
    mac.update(&(buffer.len() as u64).to_le_bytes());

    if !mac.verify(tag).is_set() {
        return false;
    }
    ChaCha20::new(key, nonce, 1).apply_keystream(buffer);
    true
}

/// The one-time Poly1305 key is the cipher's block zero.
fn poly_key(key: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let mut block = [0_u8; 64];
    ChaCha20::new(key, nonce, 0).apply_keystream(&mut block);
    let mut poly_key = [0_u8; 32];
    poly_key.copy_from_slice(&block[..32]);
    secure_erase(&mut block);
    poly_key
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc8439_aead_vector() {
        // RFC 8439, section 2.8.2.
        let key: [u8; 32] = core::array::from_fn(|i| (0x80 + i) as u8);
        let nonce = hex("070000004041424344454647");
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you \
only one tip for the future, sunscreen would be it.";

        let sealed = Suite::ChaCha20Poly1305
            .seal(&key, &nonce, &aad, plaintext)
            .unwrap();

        let expected_ciphertext = hex(concat!(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6",
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36",
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc",
            "3ff4def08e4b7a9de576d26586cec64b6116"
        ));
        assert_eq!(&sealed[..sealed.len() - 16], &expected_ciphertext[..]);
        assert_eq!(
            &sealed[sealed.len() - 16..],
            &hex("1ae10b594f09e26a7e902ecbd0600691")[..]
        );

        let opened = Suite::ChaCha20Poly1305
            .open(&key, &nonce, &aad, &sealed)
            .unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn xchacha20poly1305_round_trip() {
        let key = [3_u8; 32];
        let nonce = [7_u8; 24];
        let sealed = Suite::XChaCha20Poly1305
            .seal(&key, &nonce, b"context", b"secret message")
            .unwrap();
        let opened = Suite::XChaCha20Poly1305
            .open(&key, &nonce, b"context", &sealed)
            .unwrap();
        assert_eq!(opened, b"secret message");
    }

    #[test]
    fn every_available_suite_round_trips_at_many_lengths() {
        for suite in [
            Suite::Aes256Gcm,
            Suite::XChaCha20Poly1305,
            Suite::ChaCha20Poly1305,
        ] {
            if !suite.is_available() {
                continue;
            }
            let key = [11_u8; 32];
            let nonce = vec![2_u8; suite.nonce_len()];
            for len in [0_usize, 1, 15, 16, 17, 63, 64, 65, 1024, 4096, 10_000] {
                let plaintext: Vec<u8> = (0..len).map(|i| (i * 37) as u8).collect();
                let sealed = suite.seal(&key, &nonce, b"aad", &plaintext).unwrap();
                assert_eq!(sealed.len(), len + TAG_LEN);
                let opened = suite.open(&key, &nonce, b"aad", &sealed).unwrap();
                assert_eq!(opened, plaintext, "suite {suite:?} length {len}");
            }
        }
    }

    #[test]
    fn tampering_is_rejected_by_every_suite() {
        for suite in [
            Suite::Aes256Gcm,
            Suite::XChaCha20Poly1305,
            Suite::ChaCha20Poly1305,
        ] {
            if !suite.is_available() {
                continue;
            }
            let key = [13_u8; 32];
            let nonce = vec![5_u8; suite.nonce_len()];
            let sealed = suite.seal(&key, &nonce, b"aad", b"payload").unwrap();

            for index in 0..sealed.len() {
                let mut tampered = sealed.clone();
                tampered[index] ^= 0x01;
                assert_eq!(
                    suite.open(&key, &nonce, b"aad", &tampered),
                    Err(AeadError::Unauthenticated),
                    "suite {suite:?} accepted a flipped bit at {index}"
                );
            }

            assert_eq!(
                suite.open(&key, &nonce, b"different", &sealed),
                Err(AeadError::Unauthenticated)
            );
        }
    }
}
