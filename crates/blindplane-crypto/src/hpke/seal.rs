//! Encapsulation: `mode_base` and `mode_auth` sealing.

use crate::aead::Suite;
use crate::montgomery::StaticSecret;
use crate::util::secure_erase;

use super::primitives::{HpkeError, MODE_AUTH, MODE_BASE, extract_and_expand, key_schedule};

/// Encapsulate to a recipient public key (`mode_base`).
///
/// Returns the encapsulated key and the sealed payload.
pub fn seal(
    suite: Suite,
    recipient_public_key: &[u8; 32],
    info: &[u8],
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), HpkeError> {
    let ephemeral = StaticSecret::generate().map_err(|_| HpkeError::KeyDerivation)?;
    seal_with_ephemeral(
        suite,
        &ephemeral,
        recipient_public_key,
        None,
        info,
        associated_data,
        plaintext,
    )
}

/// Encapsulate with sender authentication (`mode_auth`).
///
/// The receiver can only open the payload with the sender's public key, so a
/// successful open proves the sender holds `sender_secret`.
pub fn auth_seal(
    suite: Suite,
    sender_secret: &StaticSecret,
    recipient_public_key: &[u8; 32],
    info: &[u8],
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), HpkeError> {
    let ephemeral = StaticSecret::generate().map_err(|_| HpkeError::KeyDerivation)?;
    seal_with_ephemeral(
        suite,
        &ephemeral,
        recipient_public_key,
        Some(sender_secret),
        info,
        associated_data,
        plaintext,
    )
}

fn seal_with_ephemeral(
    suite: Suite,
    ephemeral: &StaticSecret,
    recipient_public_key: &[u8; 32],
    sender_secret: Option<&StaticSecret>,
    info: &[u8],
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), HpkeError> {
    let enc = ephemeral.public_key();
    let ephemeral_dh = ephemeral
        .diffie_hellman(recipient_public_key)
        .ok_or(HpkeError::InvalidPeerKey)?;

    let mut dh = Vec::with_capacity(64);
    dh.extend_from_slice(ephemeral_dh.as_bytes());

    let mut kem_context = Vec::with_capacity(96);
    kem_context.extend_from_slice(&enc);
    kem_context.extend_from_slice(recipient_public_key);

    let mode = if let Some(sender) = sender_secret {
        let static_dh = sender
            .diffie_hellman(recipient_public_key)
            .ok_or(HpkeError::InvalidPeerKey)?;
        dh.extend_from_slice(static_dh.as_bytes());
        kem_context.extend_from_slice(&sender.public_key());
        MODE_AUTH
    } else {
        MODE_BASE
    };

    let shared = extract_and_expand(&dh, &kem_context)?;
    secure_erase(&mut dh);

    let schedule = key_schedule(suite, mode, shared.as_bytes(), info)?;
    let ciphertext = suite.seal(
        schedule.key.as_bytes(),
        &schedule.base_nonce,
        associated_data,
        plaintext,
    )?;
    Ok((enc.to_vec(), ciphertext))
}
