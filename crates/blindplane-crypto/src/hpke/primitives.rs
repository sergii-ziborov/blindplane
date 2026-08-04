//! Suite identifiers, the labeled KDF, the DHKEM, and the key schedule.

use crate::aead::{AeadError, Suite};
use crate::kdf::{hkdf_expand, hkdf_extract};
use crate::montgomery::{StaticSecret, public_key, x25519};
use crate::util::{Secret, secure_erase};

const VERSION_LABEL: &[u8] = b"HPKE-v1";
const KEM_ID: u16 = 0x0020; // DHKEM(X25519, HKDF-SHA256)
const KDF_ID: u16 = 0x0001; // HKDF-SHA256

pub(super) const MODE_BASE: u8 = 0x00;
pub(super) const MODE_AUTH: u8 = 0x02;

/// Length of a serialized X25519 public key or encapsulated key.
pub const ENCAPSULATED_KEY_LEN: usize = 32;
/// Length of the AEAD key this suite derives.
pub const KEY_LEN: usize = 32;
/// Length of the AEAD base nonce this suite derives.
pub const NONCE_LEN: usize = 12;

/// An HPKE failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HpkeError {
    /// A peer public key was invalid or of small order.
    InvalidPeerKey,
    /// Key derivation was asked for more output than HKDF can produce.
    KeyDerivation,
    /// The payload could not be authenticated, or the suite is unsupported.
    Aead(AeadError),
}

impl core::fmt::Display for HpkeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidPeerKey => f.write_str("invalid or small-order peer public key"),
            Self::KeyDerivation => f.write_str("HPKE key derivation failed"),
            Self::Aead(error) => write!(f, "{error}"),
        }
    }
}

impl core::error::Error for HpkeError {}

impl From<AeadError> for HpkeError {
    fn from(error: AeadError) -> Self {
        Self::Aead(error)
    }
}

fn aead_id(suite: Suite) -> u16 {
    match suite {
        Suite::Aes256Gcm => 0x0002,
        Suite::ChaCha20Poly1305 | Suite::XChaCha20Poly1305 => 0x0003,
    }
}

fn kem_suite_id() -> [u8; 5] {
    let mut id = [0_u8; 5];
    id[..3].copy_from_slice(b"KEM");
    id[3..].copy_from_slice(&KEM_ID.to_be_bytes());
    id
}

fn hpke_suite_id(suite: Suite) -> [u8; 10] {
    let mut id = [0_u8; 10];
    id[..4].copy_from_slice(b"HPKE");
    id[4..6].copy_from_slice(&KEM_ID.to_be_bytes());
    id[6..8].copy_from_slice(&KDF_ID.to_be_bytes());
    id[8..].copy_from_slice(&aead_id(suite).to_be_bytes());
    id
}

fn labeled_extract(salt: &[u8], suite_id: &[u8], label: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut labeled =
        Vec::with_capacity(VERSION_LABEL.len() + suite_id.len() + label.len() + ikm.len());
    labeled.extend_from_slice(VERSION_LABEL);
    labeled.extend_from_slice(suite_id);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(ikm);
    let prk = hkdf_extract(salt, &labeled);
    secure_erase(&mut labeled);
    prk
}

fn labeled_expand(
    prk: &[u8; 32],
    suite_id: &[u8],
    label: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), HpkeError> {
    let mut labeled_info =
        Vec::with_capacity(2 + VERSION_LABEL.len() + suite_id.len() + label.len() + info.len());
    labeled_info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    labeled_info.extend_from_slice(VERSION_LABEL);
    labeled_info.extend_from_slice(suite_id);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);

    let ok = hkdf_expand(prk, &labeled_info, out);
    secure_erase(&mut labeled_info);
    if ok {
        Ok(())
    } else {
        Err(HpkeError::KeyDerivation)
    }
}

/// `ExtractAndExpand` from the DHKEM construction.
pub(super) fn extract_and_expand(dh: &[u8], kem_context: &[u8]) -> Result<Secret<32>, HpkeError> {
    let suite_id = kem_suite_id();
    let eae_prk = labeled_extract(&[], &suite_id, b"eae_prk", dh);
    let mut shared = Secret::zeroed();
    labeled_expand(
        &eae_prk,
        &suite_id,
        b"shared_secret",
        kem_context,
        shared.as_mut(),
    )?;
    Ok(shared)
}

/// The AEAD key and nonce a sender and receiver both arrive at.
pub(super) struct KeySchedule {
    pub(super) key: Secret<32>,
    pub(super) base_nonce: [u8; NONCE_LEN],
}

pub(super) fn key_schedule(
    suite: Suite,
    mode: u8,
    shared_secret: &[u8; 32],
    info: &[u8],
) -> Result<KeySchedule, HpkeError> {
    let suite_id = hpke_suite_id(suite);

    // With no PSK, both hashes are over empty inputs, but they still bind the
    // mode and the caller's info string into every derived key.
    let psk_id_hash = labeled_extract(&[], &suite_id, b"psk_id_hash", &[]);
    let info_hash = labeled_extract(&[], &suite_id, b"info_hash", info);

    let mut context = Vec::with_capacity(1 + 32 + 32);
    context.push(mode);
    context.extend_from_slice(&psk_id_hash);
    context.extend_from_slice(&info_hash);

    let secret = labeled_extract(shared_secret, &suite_id, b"secret", &[]);

    let mut key = Secret::zeroed();
    labeled_expand(&secret, &suite_id, b"key", &context, key.as_mut())?;
    let mut base_nonce = [0_u8; NONCE_LEN];
    labeled_expand(&secret, &suite_id, b"base_nonce", &context, &mut base_nonce)?;

    Ok(KeySchedule { key, base_nonce })
}

/// Derive an X25519 key pair deterministically from 32 bytes of input keying
/// material, following the DHKEM `DeriveKeyPair` construction.
pub fn derive_key_pair(ikm: &[u8]) -> StaticSecret {
    let suite_id = kem_suite_id();
    let dkp_prk = labeled_extract(&[], &suite_id, b"dkp_prk", ikm);
    let mut secret = [0_u8; 32];
    // `sk` is 32 bytes for X25519 and the expansion cannot fail at that size.
    let _ = labeled_expand(&dkp_prk, &suite_id, b"sk", &[], &mut secret);
    let key = StaticSecret::from_bytes(secret);
    secure_erase(&mut secret);
    key
}

/// Compute a public key without holding a [`StaticSecret`].
pub fn public_key_from_secret(secret: &[u8; 32]) -> [u8; 32] {
    public_key(secret)
}

/// Raw X25519 for callers that need the primitive directly.
pub fn diffie_hellman(secret: &[u8; 32], peer: &[u8; 32]) -> [u8; 32] {
    x25519(secret, peer)
}
