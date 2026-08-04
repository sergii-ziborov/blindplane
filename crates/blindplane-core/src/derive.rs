//! Key derivation, HPKE envelope wrapping, and shared validation helpers.

use std::collections::HashSet;

use blindplane_crypto::aead::{Suite, TAG_LEN};
use blindplane_crypto::util::Secret;
use blindplane_crypto::{HmacSha256, ct_eq_bytes, hkdf_expand, hkdf_extract, hpke};
use blindplane_wire::{
    BlindIndex, RecipientEnvelope, RecordContext, SealedRecord, ValidationPolicy, WireError,
    push_bytes,
};

use crate::error::CryptoError;
use crate::identity::{Recipient, RecipientKeypair, recipient_key_id};

const DEK_LEN: usize = 32;
const HPKE_INFO_DOMAIN: &[u8] = b"blindplane/hpke-dek/v1";
const HPKE_AAD_DOMAIN: &[u8] = b"blindplane/hpke-envelope-aad/v1";
pub(crate) const INDEX_DOMAIN: &[u8] = b"blindplane/exact-index/v1";
pub(crate) const RECIPIENT_KEY_ID_DOMAIN: &[u8] = b"blindplane/recipient-key-id/v1";
const DATA_KEY_DOMAIN: &[u8] = b"blindplane/data-key/v1";
const COMMITMENT_KEY_DOMAIN: &[u8] = b"blindplane/commitment-key/v1";
const COMMITMENT_DOMAIN: &[u8] = b"blindplane/key-commitment/v1";

pub(crate) fn wrap_dek(
    recipient: &Recipient,
    object_secret: &[u8; DEK_LEN],
    context: &RecordContext,
) -> Result<RecipientEnvelope, CryptoError> {
    let info = hpke_info(context, recipient);
    let aad = hpke_aad(context, recipient);
    let (encapsulated_key, wrapped_dek) = hpke::seal(
        Suite::ChaCha20Poly1305,
        &recipient.public_key,
        &info,
        &aad,
        object_secret,
    )
    .map_err(|_| CryptoError::HpkeSeal)?;

    Ok(RecipientEnvelope {
        recipient_id: recipient.recipient_id.clone(),
        key_epoch: recipient.key_epoch,
        recipient_key_id: recipient.recipient_key_id,
        encapsulated_key,
        wrapped_dek,
    })
}

pub(crate) fn unwrap_dek(
    record: &SealedRecord,
    envelope: &RecipientEnvelope,
    recipient: &RecipientKeypair,
) -> Result<Secret<DEK_LEN>, CryptoError> {
    let descriptor = recipient.recipient();
    let info = hpke_info(&record.context, &descriptor);
    let aad = hpke_aad(&record.context, &descriptor);

    let bytes = hpke::open(
        Suite::ChaCha20Poly1305,
        &recipient.secret,
        &envelope.encapsulated_key,
        &info,
        &aad,
        &envelope.wrapped_dek,
    )
    .map_err(|_| CryptoError::HpkeOpen)?;

    let array: [u8; DEK_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::HpkeOpen)?;
    Ok(Secret::new(array))
}

pub(crate) fn derive_object_keys(
    object_secret: &[u8; DEK_LEN],
    context: &RecordContext,
) -> Result<(Secret<32>, Secret<32>), CryptoError> {
    let salt = context.canonical_bytes();
    let prk = hkdf_extract(&salt, object_secret);

    let mut data_key = Secret::zeroed();
    let mut commitment_key = Secret::zeroed();
    if !hkdf_expand(&prk, DATA_KEY_DOMAIN, data_key.as_mut())
        || !hkdf_expand(&prk, COMMITMENT_KEY_DOMAIN, commitment_key.as_mut())
    {
        return Err(CryptoError::KeyDerivation);
    }
    Ok((data_key, commitment_key))
}

pub(crate) fn commit_key(
    commitment_key: &[u8; 32],
    suite: Suite,
    context: &RecordContext,
) -> [u8; 32] {
    let mut mac = HmacSha256::new(commitment_key);
    mac.update(COMMITMENT_DOMAIN);
    mac.update(&[suite.code()]);
    mac_bytes(&mut mac, &context.canonical_bytes());
    mac.finalize()
}

pub(crate) fn preflight(
    context: &RecordContext,
    plaintext_len: usize,
    recipients: &[Recipient],
    indexes: &[BlindIndex],
) -> Result<(), CryptoError> {
    let policy = ValidationPolicy::default();
    let identifiers = [&context.tenant, &context.object_id, &context.field];
    if identifiers
        .into_iter()
        .any(|value| value.is_empty() || value.len() > policy.max_identifier_bytes)
        || context.epoch == 0
        || context.version == 0
        || context.schema_version == 0
    {
        return Err(CryptoError::InvalidRecordInput);
    }
    if plaintext_len.saturating_add(TAG_LEN) > policy.max_ciphertext_bytes {
        return Err(CryptoError::PayloadTooLarge);
    }
    if recipients.is_empty() {
        return Err(CryptoError::NoRecipients);
    }
    if recipients.len() > policy.max_recipients || indexes.len() > policy.max_indexes {
        return Err(CryptoError::InvalidRecordInput);
    }
    for recipient in recipients {
        let computed = recipient_key_id(&recipient.public_key);
        if recipient.recipient_id.is_empty()
            || recipient.recipient_id.len() > policy.max_identifier_bytes
            || recipient.key_epoch == 0
            || !ct_eq_bytes(&computed, &recipient.recipient_key_id).is_set()
        {
            return Err(CryptoError::InvalidKeyIdentity);
        }
    }
    for index in indexes {
        if index.label.is_empty()
            || index.label.len() > policy.max_identifier_bytes
            || index.canonicalizer_id.is_empty()
            || index.canonicalizer_id.len() > policy.max_identifier_bytes
            || index.schema_version == 0
            || index.canonicalizer_version == 0
            || index.key_epoch == 0
        {
            return Err(CryptoError::InvalidIndexScope);
        }
    }
    Ok(())
}

fn hpke_info(context: &RecordContext, recipient: &Recipient) -> Vec<u8> {
    let mut info = Vec::with_capacity(160);
    push_bytes(&mut info, HPKE_INFO_DOMAIN);
    push_bytes(&mut info, &context.canonical_bytes());
    push_bytes(&mut info, recipient.recipient_id.as_bytes());
    info.extend_from_slice(&recipient.key_epoch.to_be_bytes());
    info.extend_from_slice(&recipient.recipient_key_id);
    info
}

fn hpke_aad(context: &RecordContext, recipient: &Recipient) -> Vec<u8> {
    let mut aad = Vec::with_capacity(160);
    push_bytes(&mut aad, HPKE_AAD_DOMAIN);
    push_bytes(&mut aad, &context.canonical_bytes());
    push_bytes(&mut aad, recipient.recipient_id.as_bytes());
    aad.extend_from_slice(&recipient.key_epoch.to_be_bytes());
    aad.extend_from_slice(&recipient.recipient_key_id);
    aad
}

/// The [`push_bytes`] convention, written into a MAC instead of a buffer.
pub(crate) fn mac_bytes(mac: &mut HmacSha256, bytes: &[u8]) {
    let len = u64::try_from(bytes.len()).expect("usize fits into u64 on supported targets");
    mac.update(&len.to_be_bytes());
    mac.update(bytes);
}

/// Check a record we just signed ourselves.
///
/// Verifying our own fresh signature costs a third of the sealing time and
/// proves nothing against an adversary: the key is ours and the bytes have not
/// left the process. What it does catch is a hardware fault corrupting a
/// deterministic Ed25519 signature, which RFC 8032 section 8.5 warns can leak
/// the private key. That is a real but narrow threat, so the full check lives
/// behind the `fault-resistant` feature.
///
/// The feature is phrased positively — enabling it *adds* the check — because
/// Cargo unifies features additively. A negatively-phrased "skip the check"
/// flag could be switched on by any crate anywhere in the dependency graph and
/// would silently disable the protection process-wide.
pub(crate) fn validate_own(
    record: &SealedRecord,
    policy: &ValidationPolicy,
) -> Result<(), CryptoError> {
    if cfg!(feature = "fault-resistant") {
        record.validate(policy)?;
    } else {
        record.validate_shape(policy)?;
        if policy.allowed_signers.is_empty() {
            return Err(CryptoError::Wire(WireError::NoTrustedSigners));
        }
        if !policy.allowed_signers.contains(&record.signer_public_key) {
            return Err(CryptoError::Wire(WireError::UntrustedSigner));
        }
    }
    Ok(())
}

pub(crate) fn policy_for(signer: [u8; 32]) -> ValidationPolicy {
    ValidationPolicy {
        allowed_signers: HashSet::from([signer]),
        ..ValidationPolicy::default()
    }
}
