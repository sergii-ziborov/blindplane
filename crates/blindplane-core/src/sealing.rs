//! Sealing, opening, granting and rekeying signed records.

use blindplane_crypto::aead::Suite;
use blindplane_crypto::ct_eq_bytes;
use blindplane_crypto::rand;
use blindplane_crypto::util::SecretVec;
use blindplane_wire::{
    BlindIndex, FORMAT_VERSION, FreshnessHead, RecordContext, SealedRecord, ValidationPolicy,
    payload_aad,
};

use crate::derive::{
    commit_key, derive_object_keys, policy_for, preflight, unwrap_dek, validate_own, wrap_dek,
};
use crate::error::CryptoError;
use crate::identity::{Author, PinnedSigner, Recipient, RecipientKeypair};

/// Seal one payload for one or more independent recipients.
pub fn seal(
    author: &Author,
    context: RecordContext,
    plaintext: &[u8],
    recipients: &[Recipient],
    indexes: Vec<BlindIndex>,
    suite: Suite,
) -> Result<SealedRecord, CryptoError> {
    preflight(&context, plaintext.len(), recipients, &indexes)?;

    let mut sorted_recipients = recipients.to_vec();
    sorted_recipients.sort_by(|left, right| {
        (&left.recipient_id, left.key_epoch).cmp(&(&right.recipient_id, right.key_epoch))
    });
    if sorted_recipients.windows(2).any(|pair| {
        pair[0].recipient_id == pair[1].recipient_id && pair[0].key_epoch == pair[1].key_epoch
    }) {
        return Err(CryptoError::DuplicateRecipient);
    }

    let mut sorted_indexes = indexes;
    sorted_indexes
        .sort_by(|left, right| (&left.label, left.key_epoch).cmp(&(&right.label, right.key_epoch)));
    if sorted_indexes
        .windows(2)
        .any(|pair| pair[0].label == pair[1].label && pair[0].key_epoch == pair[1].key_epoch)
    {
        return Err(CryptoError::DuplicateIndex);
    }

    let object_secret = rand::secret_32().map_err(|_| CryptoError::Randomness)?;
    let (data_key, commitment_key) = derive_object_keys(object_secret.as_bytes(), &context)?;
    let key_commitment = commit_key(commitment_key.as_bytes(), suite, &context);

    let mut nonce = vec![0_u8; suite.nonce_len()];
    rand::fill(&mut nonce).map_err(|_| CryptoError::Randomness)?;
    let aad = payload_aad(suite, &context);
    let ciphertext = suite
        .seal(data_key.as_bytes(), &nonce, &aad, plaintext)
        .map_err(|_| CryptoError::PayloadSeal)?;

    let mut envelopes = Vec::with_capacity(sorted_recipients.len());
    for recipient in &sorted_recipients {
        envelopes.push(wrap_dek(recipient, object_secret.as_bytes(), &context)?);
    }

    let mut record = SealedRecord {
        format_version: FORMAT_VERSION,
        suite,
        context,
        manifest_revision: 1,
        previous_manifest_hash: [0; 32],
        key_commitment,
        nonce,
        ciphertext,
        recipients: envelopes,
        indexes: sorted_indexes,
        signer_public_key: author.public_key(),
        signature: vec![0_u8; 64],
    };
    author.sign(&mut record);
    validate_own(&record, &policy_for(author.public_key()))?;
    Ok(record)
}

/// Open a record after enforcing an expected signer pin.
pub fn open(
    record: &SealedRecord,
    recipient: &RecipientKeypair,
    expected_signer: [u8; 32],
) -> Result<SecretVec, CryptoError> {
    record.validate(&policy_for(expected_signer))?;
    open_validated(record, recipient)
}

/// [`open`] against a signer prepared once with [`PinnedSigner::new`](crate::PinnedSigner::new).
pub fn open_pinned(
    record: &SealedRecord,
    recipient: &RecipientKeypair,
    signer: &PinnedSigner,
) -> Result<SecretVec, CryptoError> {
    record.validate_pinned(&signer.verifier, &ValidationPolicy::default())?;
    open_validated(record, recipient)
}

/// The shared body of every open: envelope lookup, DEK unwrap, key
/// commitment, payload AEAD. Callers have already validated the record.
fn open_validated(
    record: &SealedRecord,
    recipient: &RecipientKeypair,
) -> Result<SecretVec, CryptoError> {
    let envelope = record
        .recipient(
            &recipient.recipient.recipient_id,
            recipient.recipient.key_epoch,
            &recipient.recipient.recipient_key_id,
        )
        .ok_or(CryptoError::NoEnvelopeForRecipient)?;

    let object_secret = unwrap_dek(record, envelope, recipient)?;
    let (data_key, commitment_key) = derive_object_keys(object_secret.as_bytes(), &record.context)?;

    // The key commitment makes a swapped key fail here rather than producing a
    // second valid plaintext under a different key.
    let commitment = commit_key(commitment_key.as_bytes(), record.suite, &record.context);
    if !ct_eq_bytes(&commitment, &record.key_commitment).is_set() {
        return Err(CryptoError::PayloadOpen);
    }

    let plaintext = record
        .suite
        .open(
            data_key.as_bytes(),
            &record.nonce,
            &record.payload_aad(),
            &record.ciphertext,
        )
        .map_err(|_| CryptoError::PayloadOpen)?;
    Ok(SecretVec::new(plaintext))
}

/// Open only when the record matches a persisted client freshness head.
///
/// This is what detects a server replaying an older, otherwise perfectly valid
/// record.
pub fn open_at_head(
    record: &SealedRecord,
    recipient: &RecipientKeypair,
    expected_signer: [u8; 32],
    head: &FreshnessHead,
) -> Result<SecretVec, CryptoError> {
    head.verify_current(record, &policy_for(expected_signer))?;
    open(record, recipient, expected_signer)
}

/// [`open_at_head`] against a signer prepared once with
/// [`PinnedSigner::new`](crate::PinnedSigner::new).
pub fn open_at_head_pinned(
    record: &SealedRecord,
    recipient: &RecipientKeypair,
    signer: &PinnedSigner,
    head: &FreshnessHead,
) -> Result<SecretVec, CryptoError> {
    head.verify_current_pinned(record, &signer.verifier, &ValidationPolicy::default())?;
    record.validate_pinned(&signer.verifier, &ValidationPolicy::default())?;
    open_validated(record, recipient)
}

/// Add a recipient envelope without re-encrypting the payload.
///
/// The caller must already be able to open the object secret and must hold the
/// pinned author key. The complete record is re-signed and the manifest chain
/// advances by one link.
pub fn grant_recipient(
    record: &SealedRecord,
    granting_recipient: &RecipientKeypair,
    author: &Author,
    new_recipient: &Recipient,
) -> Result<SealedRecord, CryptoError> {
    record.validate(&policy_for(author.public_key()))?;
    if record.recipients.iter().any(|existing| {
        existing.recipient_id == new_recipient.recipient_id
            && existing.key_epoch == new_recipient.key_epoch
    }) {
        return Err(CryptoError::DuplicateRecipient);
    }

    let current_envelope = record
        .recipient(
            &granting_recipient.recipient.recipient_id,
            granting_recipient.recipient.key_epoch,
            &granting_recipient.recipient.recipient_key_id,
        )
        .ok_or(CryptoError::NoEnvelopeForRecipient)?;
    let object_secret = unwrap_dek(record, current_envelope, granting_recipient)?;

    let mut updated = record.clone();
    updated.previous_manifest_hash = record.manifest_hash();
    updated.manifest_revision = record
        .manifest_revision
        .checked_add(1)
        .ok_or(CryptoError::ManifestRevisionOverflow)?;
    updated.recipients.push(wrap_dek(
        new_recipient,
        object_secret.as_bytes(),
        &record.context,
    )?);
    updated.recipients.sort_by(|left, right| {
        (&left.recipient_id, left.key_epoch).cmp(&(&right.recipient_id, right.key_epoch))
    });
    author.sign(&mut updated);
    validate_own(&updated, &policy_for(author.public_key()))?;
    Ok(updated)
}

/// Revoke access by generating a new object secret, nonce, epoch and envelopes
/// for the remaining recipients.
///
/// This cannot erase plaintext or old keys a former recipient already saved.
/// Revocation is forward-looking, and any documentation claiming otherwise is
/// selling something.
pub fn rekey(
    record: &SealedRecord,
    opening_recipient: &RecipientKeypair,
    author: &Author,
    mut next_context: RecordContext,
    remaining_recipients: &[Recipient],
    next_indexes: Vec<BlindIndex>,
) -> Result<SealedRecord, CryptoError> {
    if next_context.tenant != record.context.tenant
        || next_context.object_id != record.context.object_id
        || next_context.field != record.context.field
        || next_context.epoch <= record.context.epoch
        || next_context.version <= record.context.version
    {
        return Err(CryptoError::InvalidRekeyContext);
    }
    next_context.schema_version = next_context
        .schema_version
        .max(record.context.schema_version);

    let plaintext = open(record, opening_recipient, author.public_key())?;
    let mut next = seal(
        author,
        next_context,
        plaintext.as_bytes(),
        remaining_recipients,
        next_indexes,
        record.suite,
    )?;
    next.previous_manifest_hash = record.manifest_hash();
    next.manifest_revision = record
        .manifest_revision
        .checked_add(1)
        .ok_or(CryptoError::ManifestRevisionOverflow)?;
    author.sign(&mut next);
    validate_own(&next, &policy_for(author.public_key()))?;
    Ok(next)
}
