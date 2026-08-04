//! Decapsulation: `mode_base` and `mode_auth` opening.

use crate::aead::Suite;
use crate::montgomery::StaticSecret;
use crate::util::secure_erase;

use super::primitives::{
    ENCAPSULATED_KEY_LEN, HpkeError, MODE_AUTH, MODE_BASE, extract_and_expand, key_schedule,
};

/// Decapsulate and open a `mode_base` payload.
pub fn open(
    suite: Suite,
    recipient_secret: &StaticSecret,
    encapsulated_key: &[u8],
    info: &[u8],
    associated_data: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, HpkeError> {
    open_inner(
        suite,
        recipient_secret,
        encapsulated_key,
        None,
        info,
        associated_data,
        ciphertext,
    )
}

/// Decapsulate and open a `mode_auth` payload, requiring the sender's key.
pub fn auth_open(
    suite: Suite,
    recipient_secret: &StaticSecret,
    sender_public_key: &[u8; 32],
    encapsulated_key: &[u8],
    info: &[u8],
    associated_data: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, HpkeError> {
    open_inner(
        suite,
        recipient_secret,
        encapsulated_key,
        Some(sender_public_key),
        info,
        associated_data,
        ciphertext,
    )
}

fn open_inner(
    suite: Suite,
    recipient_secret: &StaticSecret,
    encapsulated_key: &[u8],
    sender_public_key: Option<&[u8; 32]>,
    info: &[u8],
    associated_data: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, HpkeError> {
    if encapsulated_key.len() != ENCAPSULATED_KEY_LEN {
        return Err(HpkeError::InvalidPeerKey);
    }
    let mut enc = [0_u8; 32];
    enc.copy_from_slice(encapsulated_key);

    let ephemeral_dh = recipient_secret
        .diffie_hellman(&enc)
        .ok_or(HpkeError::InvalidPeerKey)?;

    let mut dh = Vec::with_capacity(64);
    dh.extend_from_slice(ephemeral_dh.as_bytes());

    let mut kem_context = Vec::with_capacity(96);
    kem_context.extend_from_slice(&enc);
    kem_context.extend_from_slice(&recipient_secret.public_key());

    let mode = if let Some(sender) = sender_public_key {
        let static_dh = recipient_secret
            .diffie_hellman(sender)
            .ok_or(HpkeError::InvalidPeerKey)?;
        dh.extend_from_slice(static_dh.as_bytes());
        kem_context.extend_from_slice(sender);
        MODE_AUTH
    } else {
        MODE_BASE
    };

    let shared = extract_and_expand(&dh, &kem_context)?;
    secure_erase(&mut dh);

    let schedule = key_schedule(suite, mode, shared.as_bytes(), info)?;
    let plaintext = suite.open(
        schedule.key.as_bytes(),
        &schedule.base_nonce,
        associated_data,
        ciphertext,
    )?;
    Ok(plaintext)
}
