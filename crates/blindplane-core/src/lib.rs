//! Client-side sealing for Blindplane.
//!
//! A record carries a fresh random 256-bit object secret, a payload encrypted
//! under a key derived from it, one HPKE envelope per recipient, and an Ed25519
//! signature over the ciphertext, the routing context, the recipient grants and
//! any blind indexes.
//!
//! This crate is for trusted clients and trusted inference workers. Server
//! relays depend on `blindplane-wire` instead, whose dependency graph contains
//! no decryption API.
//!
//! # What the server learns anyway
//!
//! Being honest about the leaks is part of the design:
//!
//! - the routing context: tenant, object id, field name, epoch and version;
//! - the size of every ciphertext, rounded to nothing at all;
//! - which recipient identifiers can read which record, and when that changed;
//! - equality and frequency of any value you choose to blind-index;
//! - access patterns: who fetched what, and when.
//!
//! What it does not learn is the plaintext, and no configuration mistake on the
//! server side can change that, because the server never holds a key.

#![forbid(unsafe_code)]

use std::collections::HashSet;

use blindplane_crypto::aead::Suite;
use blindplane_crypto::argon2::{Argon2Params, argon2id};
use blindplane_crypto::montgomery::StaticSecret;
use blindplane_crypto::util::{Secret, SecretVec};
use blindplane_crypto::{
    HmacSha256, Sha256, SigningKey, ct_eq_bytes, hkdf_expand, hkdf_extract, hpke, rand,
};
use blindplane_wire::{
    BlindIndex, FORMAT_VERSION, FreshnessHead, RecipientEnvelope, RecordContext, SealedRecord,
    ValidationPolicy, WireError, payload_aad,
};

const DEK_LEN: usize = 32;
const HPKE_INFO_DOMAIN: &[u8] = b"blindplane/hpke-dek/v1";
const HPKE_AAD_DOMAIN: &[u8] = b"blindplane/hpke-envelope-aad/v1";
const INDEX_DOMAIN: &[u8] = b"blindplane/exact-index/v1";
const RECIPIENT_KEY_ID_DOMAIN: &[u8] = b"blindplane/recipient-key-id/v1";
const DATA_KEY_DOMAIN: &[u8] = b"blindplane/data-key/v1";
const COMMITMENT_KEY_DOMAIN: &[u8] = b"blindplane/commitment-key/v1";
const COMMITMENT_DOMAIN: &[u8] = b"blindplane/key-commitment/v1";

/// An Ed25519 record author and policy signer.
pub struct Author {
    signing_key: SigningKey,
}

impl Author {
    /// Generate a new signing identity from the operating-system CSPRNG.
    pub fn generate() -> Result<Self, CryptoError> {
        SigningKey::generate()
            .map(|signing_key| Self { signing_key })
            .map_err(|_| CryptoError::Randomness)
    }

    /// Restore an identity from 32 secret bytes.
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_seed(secret),
        }
    }

    /// The public key clients and servers pin to an authenticated identity.
    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key()
    }

    /// Export the secret for storage inside an encrypted client vault.
    pub fn secret_bytes(&self) -> Secret<32> {
        Secret::new(self.signing_key.to_seed())
    }

    fn sign(&self, record: &mut SealedRecord) {
        record.signer_public_key = self.public_key();
        record.signature = self.signing_key.sign(&record.signing_bytes()).to_vec();
    }
}

/// A public recipient and key epoch, used when granting read access.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Recipient {
    recipient_id: String,
    key_epoch: u64,
    recipient_key_id: [u8; 32],
    public_key: [u8; 32],
}

impl Recipient {
    /// Construct a recipient only when an independently pinned fingerprint
    /// matches the key.
    ///
    /// This is the step that stops the server from substituting its own key for
    /// a recipient's. The fingerprint has to arrive out of band or from key
    /// transparency; taking it from the same server that serves the key would
    /// make the check meaningless.
    pub fn from_verified_key(
        recipient_id: impl Into<String>,
        key_epoch: u64,
        public_key: [u8; 32],
        expected_key_id: [u8; 32],
    ) -> Result<Self, CryptoError> {
        let recipient_id = recipient_id.into();
        let actual_key_id = recipient_key_id(&public_key);
        if recipient_id.is_empty()
            || key_epoch == 0
            || !ct_eq_bytes(&actual_key_id, &expected_key_id).is_set()
        {
            return Err(CryptoError::InvalidKeyIdentity);
        }
        Ok(Self {
            recipient_id,
            key_epoch,
            recipient_key_id: actual_key_id,
            public_key,
        })
    }

    /// Stable recipient identifier.
    pub fn id(&self) -> &str {
        &self.recipient_id
    }

    /// Recipient key epoch.
    pub const fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    /// Pinned key fingerprint.
    pub const fn key_id(&self) -> [u8; 32] {
        self.recipient_key_id
    }

    /// Verified X25519 public key.
    pub const fn public_key(&self) -> [u8; 32] {
        self.public_key
    }
}

/// Compute the domain-separated fingerprint that must be verified out of band
/// before granting access.
pub fn recipient_key_id(public_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RECIPIENT_KEY_ID_DOMAIN);
    hasher.update(public_key);
    hasher.finalize()
}

/// A client-held X25519 key pair.
pub struct RecipientKeypair {
    recipient: Recipient,
    secret: StaticSecret,
}

impl RecipientKeypair {
    /// Generate a new recipient key pair.
    pub fn generate(recipient_id: impl Into<String>, key_epoch: u64) -> Result<Self, CryptoError> {
        let recipient_id = recipient_id.into();
        if recipient_id.is_empty() || key_epoch == 0 {
            return Err(CryptoError::InvalidKeyIdentity);
        }
        let secret = StaticSecret::generate().map_err(|_| CryptoError::Randomness)?;
        Ok(Self::assemble(recipient_id, key_epoch, secret))
    }

    /// Restore a recipient key pair from secret bytes.
    ///
    /// The public key is derived rather than accepted from the caller, so a
    /// mismatched pair cannot be constructed.
    pub fn from_secret_bytes(
        recipient_id: impl Into<String>,
        key_epoch: u64,
        secret_bytes: [u8; 32],
    ) -> Result<Self, CryptoError> {
        let recipient_id = recipient_id.into();
        if recipient_id.is_empty() || key_epoch == 0 {
            return Err(CryptoError::InvalidKeyIdentity);
        }
        Ok(Self::assemble(
            recipient_id,
            key_epoch,
            StaticSecret::from_bytes(secret_bytes),
        ))
    }

    fn assemble(recipient_id: String, key_epoch: u64, secret: StaticSecret) -> Self {
        let public_key = secret.public_key();
        Self {
            recipient: Recipient {
                recipient_id,
                key_epoch,
                recipient_key_id: recipient_key_id(&public_key),
                public_key,
            },
            secret,
        }
    }

    /// The public recipient descriptor, safe to share.
    pub fn recipient(&self) -> Recipient {
        self.recipient.clone()
    }

    /// Export the secret for an encrypted client vault.
    pub fn secret_bytes(&self) -> Secret<32> {
        Secret::new(self.secret.to_bytes())
    }
}

/// The secret key for scoped exact blind indexes.
pub struct SearchKey(Secret<32>);

/// A versioned definition of a raw-byte exact index.
///
/// Raw bytes are a deliberate default: equality means byte-for-byte equality.
/// Human-text normalization belongs in a separately specified and versioned
/// canonicalizer, never in undocumented application code, because two clients
/// that normalize differently silently stop finding each other's records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExactIndexDefinition {
    label: String,
    schema_version: u32,
    key_epoch: u64,
}

impl ExactIndexDefinition {
    /// Define a scoped raw-byte index.
    pub fn raw_bytes(
        label: impl Into<String>,
        schema_version: u32,
        key_epoch: u64,
    ) -> Result<Self, CryptoError> {
        let label = label.into();
        if label.is_empty() || label.len() > 255 || schema_version == 0 || key_epoch == 0 {
            return Err(CryptoError::InvalidIndexScope);
        }
        Ok(Self {
            label,
            schema_version,
            key_epoch,
        })
    }

    /// The visible index label.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The search-key epoch.
    pub const fn key_epoch(&self) -> u64 {
        self.key_epoch
    }
}

impl SearchKey {
    /// Generate from the operating-system CSPRNG.
    pub fn generate() -> Result<Self, CryptoError> {
        rand::secret_32()
            .map(Self)
            .map_err(|_| CryptoError::Randomness)
    }

    /// Restore from an encrypted vault.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Secret::new(bytes))
    }

    /// Export for an encrypted client vault.
    pub fn to_bytes(&self) -> Secret<32> {
        Secret::new(self.0.expose())
    }

    /// Create a 128-bit equality token scoped to a versioned definition.
    ///
    /// The server learns equality, frequency, query repetition and access
    /// patterns for the indexed field. It does not learn the value.
    pub fn exact_token_raw(
        &self,
        tenant: &str,
        definition: &ExactIndexDefinition,
        value: &[u8],
    ) -> Result<BlindIndex, CryptoError> {
        if tenant.is_empty() || tenant.len() > 255 {
            return Err(CryptoError::InvalidIndexScope);
        }
        let mut mac = HmacSha256::new(self.0.as_bytes());
        mac.update(INDEX_DOMAIN);
        mac_bytes(&mut mac, tenant.as_bytes());
        mac_bytes(&mut mac, definition.label.as_bytes());
        mac.update(&definition.schema_version.to_be_bytes());
        mac_bytes(&mut mac, b"raw_bytes");
        mac.update(&1_u16.to_be_bytes());
        mac.update(&definition.key_epoch.to_be_bytes());
        mac_bytes(&mut mac, value);

        let digest = mac.finalize();
        let mut token = [0_u8; 16];
        token.copy_from_slice(&digest[..16]);
        Ok(BlindIndex {
            label: definition.label.clone(),
            schema_version: definition.schema_version,
            canonicalizer_id: "raw_bytes".to_owned(),
            canonicalizer_version: 1,
            key_epoch: definition.key_epoch,
            token,
        })
    }
}

/// The fastest payload suite this CPU supports.
///
/// HPKE envelope wrapping stays on the fixed RFC 9180 ChaCha suite for wire
/// interoperability; this choice only affects bulk payload encryption.
pub fn fastest_payload_suite() -> Suite {
    Suite::fastest_available()
}

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

/// An owned work item for parallel sealing.
pub struct BatchItem {
    /// Authenticated routing context.
    pub context: RecordContext,
    /// Plaintext, retained only by the caller and the worker thread.
    pub plaintext: Vec<u8>,
    /// Independent recipients.
    pub recipients: Vec<Recipient>,
    /// Optional exact-search indexes.
    pub indexes: Vec<BlindIndex>,
}

/// Seal independent records across all available cores, preserving input order.
///
/// Sealing is embarrassingly parallel: each record has its own object secret,
/// so there is nothing to synchronize beyond collecting the results.
pub fn seal_batch(
    author: &Author,
    items: &[BatchItem],
    suite: Suite,
) -> Vec<Result<SealedRecord, CryptoError>> {
    let workers = std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .min(items.len().max(1));

    if workers <= 1 || items.len() <= 1 {
        return items
            .iter()
            .map(|item| {
                seal(
                    author,
                    item.context.clone(),
                    &item.plaintext,
                    &item.recipients,
                    item.indexes.clone(),
                    suite,
                )
            })
            .collect();
    }

    let mut results: Vec<Option<Result<SealedRecord, CryptoError>>> =
        (0..items.len()).map(|_| None).collect();

    std::thread::scope(|scope| {
        let chunk_size = items.len().div_ceil(workers);
        let mut handles = Vec::with_capacity(workers);
        for (chunk_index, chunk) in items.chunks(chunk_size).enumerate() {
            handles.push((
                chunk_index * chunk_size,
                scope.spawn(move || {
                    chunk
                        .iter()
                        .map(|item| {
                            seal(
                                author,
                                item.context.clone(),
                                &item.plaintext,
                                &item.recipients,
                                item.indexes.clone(),
                                suite,
                            )
                        })
                        .collect::<Vec<_>>()
                }),
            ));
        }
        for (offset, handle) in handles {
            let chunk_results = handle.join().expect("sealing worker panicked");
            for (i, result) in chunk_results.into_iter().enumerate() {
                results[offset + i] = Some(result);
            }
        }
    });

    results
        .into_iter()
        .map(|slot| slot.expect("every index is filled by exactly one worker"))
        .collect()
}

/// Derive a client vault key from a password.
///
/// The password never leaves the client and the derived key never reaches the
/// server. The cost parameters are the defence: see [`Argon2Params`].
pub fn derive_vault_key(
    password: &[u8],
    salt: &[u8],
    params: Argon2Params,
) -> Result<Secret<32>, CryptoError> {
    let derived =
        argon2id(password, salt, params).map_err(|_| CryptoError::InvalidVaultParameters)?;
    if derived.len() != 32 {
        return Err(CryptoError::InvalidVaultParameters);
    }
    let mut key = Secret::zeroed();
    key.as_mut().copy_from_slice(&derived);
    Ok(key)
}

fn wrap_dek(
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

fn unwrap_dek(
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

fn derive_object_keys(
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

fn commit_key(commitment_key: &[u8; 32], suite: Suite, context: &RecordContext) -> [u8; 32] {
    let mut mac = HmacSha256::new(commitment_key);
    mac.update(COMMITMENT_DOMAIN);
    mac.update(&[suite.code()]);
    mac_bytes(&mut mac, &context.canonical_bytes());
    mac.finalize()
}

fn preflight(
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
    if plaintext_len.saturating_add(16) > policy.max_ciphertext_bytes {
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

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u64::try_from(bytes.len()).expect("usize fits into u64 on supported targets");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

fn mac_bytes(mac: &mut HmacSha256, bytes: &[u8]) {
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
fn validate_own(record: &SealedRecord, policy: &ValidationPolicy) -> Result<(), CryptoError> {
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

fn policy_for(signer: [u8; 32]) -> ValidationPolicy {
    ValidationPolicy {
        allowed_signers: HashSet::from([signer]),
        ..ValidationPolicy::default()
    }
}

/// A client-side failure.
///
/// Decryption errors are deliberately coarse: a caller that could distinguish
/// "wrong key" from "tampered ciphertext" would be handing an attacker an
/// oracle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CryptoError {
    /// The operating-system CSPRNG failed.
    Randomness,
    /// A recipient id or epoch is invalid, or a key fingerprint did not match.
    InvalidKeyIdentity,
    /// At least one recipient is required.
    NoRecipients,
    /// A recipient id/epoch pair was repeated.
    DuplicateRecipient,
    /// An index label/epoch pair was repeated.
    DuplicateIndex,
    /// The index scope is invalid.
    InvalidIndexScope,
    /// The routing context, schema, or a count limit is invalid.
    InvalidRecordInput,
    /// The payload exceeds the single-record size limit; chunk it.
    PayloadTooLarge,
    /// Key derivation failed.
    KeyDerivation,
    /// HPKE envelope encryption failed.
    HpkeSeal,
    /// HPKE open failed, including wrong key and tampering.
    HpkeOpen,
    /// Bulk payload encryption failed.
    PayloadSeal,
    /// The record could not be opened.
    PayloadOpen,
    /// The record does not grant access to this id and key epoch.
    NoEnvelopeForRecipient,
    /// Rekey did not preserve identity and advance epoch and version.
    InvalidRekeyContext,
    /// The access-manifest revision cannot advance beyond `u64::MAX`.
    ManifestRevisionOverflow,
    /// Vault key-derivation parameters are outside the allowed range.
    InvalidVaultParameters,
    /// Keyless wire validation failed.
    Wire(WireError),
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Randomness => f.write_str("operating system CSPRNG failed"),
            Self::InvalidKeyIdentity => f.write_str("invalid recipient key identity"),
            Self::NoRecipients => f.write_str("at least one recipient is required"),
            Self::DuplicateRecipient => f.write_str("duplicate recipient"),
            Self::DuplicateIndex => f.write_str("duplicate blind index"),
            Self::InvalidIndexScope => f.write_str("invalid blind-index scope"),
            Self::InvalidRecordInput => f.write_str("invalid record input"),
            Self::PayloadTooLarge => f.write_str("payload exceeds the single-record size limit"),
            Self::KeyDerivation => f.write_str("object key derivation failed"),
            Self::HpkeSeal => f.write_str("HPKE envelope encryption failed"),
            Self::HpkeOpen | Self::PayloadOpen => f.write_str("record could not be opened"),
            Self::PayloadSeal => f.write_str("payload encryption failed"),
            Self::NoEnvelopeForRecipient => f.write_str("no envelope for recipient"),
            Self::InvalidRekeyContext => {
                f.write_str("rekey must preserve identity and advance epoch and version")
            }
            Self::ManifestRevisionOverflow => f.write_str("access-manifest revision overflow"),
            Self::InvalidVaultParameters => f.write_str("invalid vault key-derivation parameters"),
            Self::Wire(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<WireError> for CryptoError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> RecordContext {
        RecordContext {
            tenant: "acme".into(),
            object_id: "patient-42".into(),
            field: "diagnosis".into(),
            epoch: 1,
            version: 1,
            schema_version: 1,
        }
    }

    #[test]
    fn multi_recipient_round_trip_and_plaintext_absence() {
        let author = Author::generate().unwrap();
        let alice = RecipientKeypair::generate("alice", 1).unwrap();
        let bob = RecipientKeypair::generate("bob", 1).unwrap();
        let plaintext = b"server must never see this diagnosis";

        let record = seal(
            &author,
            context(),
            plaintext,
            &[alice.recipient(), bob.recipient()],
            vec![],
            fastest_payload_suite(),
        )
        .unwrap();

        assert_eq!(
            open(&record, &alice, author.public_key())
                .unwrap()
                .as_bytes(),
            plaintext
        );
        assert_eq!(
            open(&record, &bob, author.public_key()).unwrap().as_bytes(),
            plaintext
        );

        // The plaintext must not survive anywhere in the encoded record.
        let encoded = record.encode();
        assert!(
            !encoded
                .windows(plaintext.len())
                .any(|window| window == plaintext)
        );
    }

    #[test]
    fn encoded_records_round_trip_through_the_wire_format() {
        let author = Author::generate().unwrap();
        let alice = RecipientKeypair::generate("alice", 1).unwrap();
        let record = seal(
            &author,
            context(),
            b"payload",
            &[alice.recipient()],
            vec![],
            fastest_payload_suite(),
        )
        .unwrap();

        let encoded = record.encode();
        let decoded = SealedRecord::decode(&encoded, &policy_for(author.public_key())).unwrap();
        assert_eq!(decoded, record);
        assert_eq!(
            open(&decoded, &alice, author.public_key())
                .unwrap()
                .as_bytes(),
            b"payload"
        );
    }

    #[test]
    fn tamper_and_context_swap_fail_closed() {
        let author = Author::generate().unwrap();
        let alice = RecipientKeypair::generate("alice", 1).unwrap();
        let record = seal(
            &author,
            context(),
            b"secret",
            &[alice.recipient()],
            vec![],
            fastest_payload_suite(),
        )
        .unwrap();

        let mut ciphertext_tamper = record.clone();
        ciphertext_tamper.ciphertext[0] ^= 1;
        assert!(open(&ciphertext_tamper, &alice, author.public_key()).is_err());

        let mut context_tamper = record;
        context_tamper.context.tenant = "other".into();
        assert!(open(&context_tamper, &alice, author.public_key()).is_err());
    }

    #[test]
    fn signer_pin_rejects_substitution() {
        let author = Author::generate().unwrap();
        let attacker = Author::generate().unwrap();
        let alice = RecipientKeypair::generate("alice", 1).unwrap();
        let record = seal(
            &author,
            context(),
            b"secret",
            &[alice.recipient()],
            vec![],
            fastest_payload_suite(),
        )
        .unwrap();
        assert!(open(&record, &alice, attacker.public_key()).is_err());
    }

    #[test]
    fn grant_then_rekey_rotates_access() {
        let author = Author::generate().unwrap();
        let alice = RecipientKeypair::generate("alice", 1).unwrap();
        let bob = RecipientKeypair::generate("bob", 1).unwrap();
        let original = seal(
            &author,
            context(),
            b"secret",
            &[alice.recipient()],
            vec![],
            fastest_payload_suite(),
        )
        .unwrap();

        let shared = grant_recipient(&original, &alice, &author, &bob.recipient()).unwrap();
        assert_eq!(
            open(&shared, &bob, author.public_key()).unwrap().as_bytes(),
            b"secret"
        );

        let mut next = context();
        next.epoch = 2;
        next.version = 2;
        let revoked = rekey(&shared, &alice, &author, next, &[alice.recipient()], vec![]).unwrap();
        assert!(open(&revoked, &bob, author.public_key()).is_err());
        assert_eq!(
            open(&revoked, &alice, author.public_key())
                .unwrap()
                .as_bytes(),
            b"secret"
        );
    }

    #[test]
    fn persisted_freshness_head_rejects_valid_rollback() {
        let author = Author::generate().unwrap();
        let alice = RecipientKeypair::generate("alice", 1).unwrap();
        let bob = RecipientKeypair::generate("bob", 1).unwrap();
        let original = seal(
            &author,
            context(),
            b"secret",
            &[alice.recipient()],
            vec![],
            fastest_payload_suite(),
        )
        .unwrap();

        let policy = policy_for(author.public_key());
        let mut head = FreshnessHead::start(&original, &policy).unwrap();
        let shared = grant_recipient(&original, &alice, &author, &bob.recipient()).unwrap();
        head.advance(&shared, &policy).unwrap();

        assert!(open_at_head(&original, &alice, author.public_key(), &head).is_err());
        assert_eq!(
            open_at_head(&shared, &alice, author.public_key(), &head)
                .unwrap()
                .as_bytes(),
            b"secret"
        );
    }

    #[test]
    fn recipient_key_fingerprint_substitution_fails_preflight() {
        let author = Author::generate().unwrap();
        let mut recipient = RecipientKeypair::generate("alice", 1).unwrap().recipient();
        recipient.public_key[0] ^= 1;
        assert_eq!(
            seal(
                &author,
                context(),
                b"secret",
                &[recipient],
                vec![],
                fastest_payload_suite()
            ),
            Err(CryptoError::InvalidKeyIdentity)
        );
    }

    #[test]
    fn exact_indexes_are_stable_but_scope_separated() {
        let key = SearchKey::generate().unwrap();
        let definition = ExactIndexDefinition::raw_bytes("email", 1, 1).unwrap();
        let a = key
            .exact_token_raw("tenant-a", &definition, b"alice@example.com")
            .unwrap();
        let b = key
            .exact_token_raw("tenant-a", &definition, b"alice@example.com")
            .unwrap();
        let scoped = key
            .exact_token_raw("tenant-b", &definition, b"alice@example.com")
            .unwrap();

        assert_eq!(a.token, b.token);
        assert_ne!(a.token, scoped.token);
        assert_eq!(a.canonicalizer_id, "raw_bytes");
    }

    #[test]
    fn batch_sealing_preserves_order_and_opens() {
        let author = Author::generate().unwrap();
        let alice = RecipientKeypair::generate("alice", 1).unwrap();
        let items: Vec<BatchItem> = (0..64_u32)
            .map(|i| {
                let mut ctx = context();
                ctx.object_id = format!("object-{i}");
                BatchItem {
                    context: ctx,
                    plaintext: format!("payload {i}").into_bytes(),
                    recipients: vec![alice.recipient()],
                    indexes: vec![],
                }
            })
            .collect();

        let sealed = seal_batch(&author, &items, fastest_payload_suite());
        assert_eq!(sealed.len(), items.len());
        for (i, result) in sealed.into_iter().enumerate() {
            let record = result.unwrap();
            assert_eq!(record.context.object_id, format!("object-{i}"));
            assert_eq!(
                open(&record, &alice, author.public_key())
                    .unwrap()
                    .as_bytes(),
                format!("payload {i}").as_bytes()
            );
        }
    }

    #[test]
    fn every_suite_round_trips_across_many_payload_sizes() {
        let author = Author::generate().unwrap();
        let alice = RecipientKeypair::generate("alice", 1).unwrap();

        for suite in [
            Suite::Aes256Gcm,
            Suite::XChaCha20Poly1305,
            Suite::ChaCha20Poly1305,
        ] {
            if !suite.is_available() {
                continue;
            }
            for len in [0_usize, 1, 1024, 65_536] {
                let payload: Vec<u8> = (0..len).map(|i| (i * 13) as u8).collect();
                let record = seal(
                    &author,
                    context(),
                    &payload,
                    &[alice.recipient()],
                    vec![],
                    suite,
                )
                .unwrap();
                assert_eq!(
                    open(&record, &alice, author.public_key())
                        .unwrap()
                        .as_bytes(),
                    payload.as_slice(),
                    "suite {suite:?} length {len}"
                );
            }
        }
    }
}
