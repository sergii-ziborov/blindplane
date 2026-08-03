//! Keyless, server-safe wire types for Blindplane.
//!
//! This crate deliberately contains no decryption key type and no decryption
//! function. A storage or relay service can validate sizes, canonical ordering,
//! signatures and monotonic versions without ever being able to read a payload.
//! That is not a promise in a document; it is a property of this crate's public
//! API, and a reviewer can confirm it by grepping for `open` and finding
//! nothing.
//!
//! Records use a canonical, length-prefixed binary encoding. There is no JSON
//! on the security path: canonical JSON is a well-known source of signature
//! confusion, and a byte-exact encoding removes the entire class.

#![forbid(unsafe_code)]

use std::collections::HashSet;

use blindplane_crypto::aead::Suite;
use blindplane_crypto::{Sha256, verify_strict};

/// Current binary wire format version.
pub const FORMAT_VERSION: u16 = 1;
/// Size of an exact blind-index token in bytes.
pub const INDEX_TOKEN_LEN: usize = 16;
/// Size of an X25519 public or encapsulated key.
pub const X25519_KEY_LEN: usize = 32;
/// An HPKE-wrapped 256-bit DEK plus its 128-bit authentication tag.
pub const WRAPPED_DEK_LEN: usize = 48;

/// Cleartext routing context, authenticated by both the payload AEAD and the
/// record signature.
///
/// The server is meant to see this. Never put a secret in it: tenant names,
/// object identifiers and field names are all visible to whoever stores the
/// record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordContext {
    /// Isolation boundary, normally a tenant or workspace identifier.
    pub tenant: String,
    /// Stable opaque record identifier.
    pub object_id: String,
    /// Security zone or encrypted field name.
    pub field: String,
    /// Access/key epoch. Increment when membership is reduced.
    pub epoch: u64,
    /// Monotonic object version used for replay protection.
    pub version: u64,
    /// Application schema version.
    pub schema_version: u32,
}

impl RecordContext {
    /// Deterministic, ambiguity-free encoding used as cryptographic context.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(64 + self.tenant.len() + self.object_id.len() + self.field.len());
        push_bytes(&mut out, b"blindplane/context/v1");
        push_bytes(&mut out, self.tenant.as_bytes());
        push_bytes(&mut out, self.object_id.as_bytes());
        push_bytes(&mut out, self.field.as_bytes());
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.schema_version.to_be_bytes());
        out
    }
}

/// Per-recipient HPKE envelope carrying the record's data-encryption key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipientEnvelope {
    /// Stable, non-secret recipient identifier.
    pub recipient_id: String,
    /// Recipient public-key version.
    pub key_epoch: u64,
    /// Domain-separated fingerprint of the verified recipient public key.
    pub recipient_key_id: [u8; 32],
    /// Serialized X25519 HPKE encapsulated key.
    pub encapsulated_key: Vec<u8>,
    /// HPKE ciphertext containing the 32-byte DEK.
    pub wrapped_dek: Vec<u8>,
}

/// Equality-search token.
///
/// Equality and frequency within a `(tenant, label, key_epoch)` scope are
/// deliberately leaked to the server: that is the price of exact search over
/// data the server cannot read, and it is stated here rather than buried.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlindIndex {
    /// Index/field label, visible to the server.
    pub label: String,
    /// Application schema that defines the indexed projection.
    pub schema_version: u32,
    /// Stable canonicalizer identifier, for example `raw_bytes`.
    pub canonicalizer_id: String,
    /// Canonicalizer algorithm version.
    pub canonicalizer_version: u16,
    /// Key epoch for independently rotating this index.
    pub key_epoch: u64,
    /// Truncated HMAC-SHA-256 token.
    pub token: [u8; INDEX_TOKEN_LEN],
}

/// A signed, multi-recipient encrypted record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedRecord {
    /// Wire format version.
    pub format_version: u16,
    /// Payload cipher suite.
    pub suite: Suite,
    /// Cleartext but authenticated routing context.
    pub context: RecordContext,
    /// Monotonic access-manifest revision. Granting access advances this
    /// without rewriting the immutable payload.
    pub manifest_revision: u64,
    /// Hash of the preceding signed manifest, or all zeroes for a genesis
    /// record. This is what turns a sequence of records into a chain a client
    /// can check for rollback.
    pub previous_manifest_hash: [u8; 32],
    /// Domain-separated commitment to the random object secret and header,
    /// which makes the payload key non-committing attacks fail closed.
    pub key_commitment: [u8; 32],
    /// Random AEAD nonce.
    pub nonce: Vec<u8>,
    /// AEAD ciphertext including its authentication tag.
    pub ciphertext: Vec<u8>,
    /// Sorted, unique recipient envelopes.
    pub recipients: Vec<RecipientEnvelope>,
    /// Sorted, unique optional blind indexes.
    pub indexes: Vec<BlindIndex>,
    /// Ed25519 verifying key for the author/policy signer.
    pub signer_public_key: [u8; 32],
    /// Ed25519 signature over every preceding field.
    pub signature: Vec<u8>,
}

impl SealedRecord {
    /// Canonical bytes signed by the record author.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            self.ciphertext.len() + self.recipients.len() * 128 + self.indexes.len() * 64 + 256,
        );
        push_bytes(&mut out, b"blindplane/record-signature/v1");
        out.extend_from_slice(&self.format_version.to_be_bytes());
        out.push(self.suite.code());
        push_bytes(&mut out, &self.context.canonical_bytes());
        out.extend_from_slice(&self.manifest_revision.to_be_bytes());
        out.extend_from_slice(&self.previous_manifest_hash);
        out.extend_from_slice(&self.key_commitment);
        push_bytes(&mut out, &self.nonce);
        push_bytes(&mut out, &self.ciphertext);
        push_len(&mut out, self.recipients.len());
        for envelope in &self.recipients {
            push_bytes(&mut out, envelope.recipient_id.as_bytes());
            out.extend_from_slice(&envelope.key_epoch.to_be_bytes());
            out.extend_from_slice(&envelope.recipient_key_id);
            push_bytes(&mut out, &envelope.encapsulated_key);
            push_bytes(&mut out, &envelope.wrapped_dek);
        }
        push_len(&mut out, self.indexes.len());
        for index in &self.indexes {
            push_bytes(&mut out, index.label.as_bytes());
            out.extend_from_slice(&index.schema_version.to_be_bytes());
            push_bytes(&mut out, index.canonicalizer_id.as_bytes());
            out.extend_from_slice(&index.canonicalizer_version.to_be_bytes());
            out.extend_from_slice(&index.key_epoch.to_be_bytes());
            out.extend_from_slice(&index.token);
        }
        out.extend_from_slice(&self.signer_public_key);
        out
    }

    /// Serialize to the canonical binary wire encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.signing_bytes();
        push_bytes(&mut out, &self.signature);
        out
    }

    /// Parse the canonical binary wire encoding.
    ///
    /// Parsing enforces the same structural limits a relay would apply, so a
    /// malformed or oversized record is rejected before any allocation the
    /// sender chose the size of.
    pub fn decode(bytes: &[u8], policy: &ValidationPolicy) -> Result<Self, WireError> {
        let mut cursor = Cursor::new(bytes);

        let domain = cursor.take_bytes(policy)?;
        if domain != b"blindplane/record-signature/v1" {
            return Err(WireError::UnsupportedFormat(0));
        }

        let format_version = cursor.take_u16()?;
        if format_version != FORMAT_VERSION {
            return Err(WireError::UnsupportedFormat(format_version));
        }
        let suite = suite_from_code(cursor.take_u8()?)?;

        let context_bytes = cursor.take_bytes(policy)?;
        let context = decode_context(context_bytes, policy)?;

        let manifest_revision = cursor.take_u64()?;
        let previous_manifest_hash = cursor.take_array32()?;
        let key_commitment = cursor.take_array32()?;
        let nonce = cursor.take_bytes(policy)?.to_vec();
        let ciphertext = cursor.take_bytes(policy)?.to_vec();

        let recipient_count = cursor.take_len(policy.max_recipients)?;
        let mut recipients = Vec::with_capacity(recipient_count);
        for _ in 0..recipient_count {
            recipients.push(RecipientEnvelope {
                recipient_id: cursor.take_string(policy)?,
                key_epoch: cursor.take_u64()?,
                recipient_key_id: cursor.take_array32()?,
                encapsulated_key: cursor.take_bytes(policy)?.to_vec(),
                wrapped_dek: cursor.take_bytes(policy)?.to_vec(),
            });
        }

        let index_count = cursor.take_len(policy.max_indexes)?;
        let mut indexes = Vec::with_capacity(index_count);
        for _ in 0..index_count {
            let label = cursor.take_string(policy)?;
            let schema_version = cursor.take_u32()?;
            let canonicalizer_id = cursor.take_string(policy)?;
            let canonicalizer_version = cursor.take_u16()?;
            let key_epoch = cursor.take_u64()?;
            let mut token = [0_u8; INDEX_TOKEN_LEN];
            token.copy_from_slice(cursor.take_exact(INDEX_TOKEN_LEN)?);
            indexes.push(BlindIndex {
                label,
                schema_version,
                canonicalizer_id,
                canonicalizer_version,
                key_epoch,
                token,
            });
        }

        let signer_public_key = cursor.take_array32()?;
        let signature = cursor.take_bytes(policy)?.to_vec();
        if !cursor.is_empty() {
            return Err(WireError::TrailingBytes);
        }

        let record = Self {
            format_version,
            suite,
            context,
            manifest_revision,
            previous_manifest_hash,
            key_commitment,
            nonce,
            ciphertext,
            recipients,
            indexes,
            signer_public_key,
            signature,
        };

        // Re-encoding must reproduce the input exactly. Two encodings of one
        // record would otherwise let a relay and a client disagree about what
        // was signed.
        if record.encode() != bytes {
            return Err(WireError::NonCanonicalEncoding);
        }
        record.validate_structure(policy)?;
        Ok(record)
    }

    /// Payload AEAD associated data.
    ///
    /// Recipient envelopes and indexes are excluded so an authorized signer can
    /// grant access without re-encrypting the payload; the outer signature
    /// still binds them.
    pub fn payload_aad(&self) -> Vec<u8> {
        payload_aad(self.suite, &self.context)
    }

    /// Domain-separated hash used to link signed access manifests.
    pub fn manifest_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"blindplane/manifest-hash/v1");
        hasher.update(&self.signing_bytes());
        hasher.update(&self.signature);
        hasher.finalize()
    }

    /// Verify structure, signature, and an explicitly pinned signer.
    ///
    /// An empty signer set fails closed: "trust nobody" must never mean "trust
    /// everybody".
    pub fn validate(&self, policy: &ValidationPolicy) -> Result<(), WireError> {
        self.validate_structure(policy)?;
        if policy.allowed_signers.is_empty() {
            return Err(WireError::NoTrustedSigners);
        }
        if !policy.allowed_signers.contains(&self.signer_public_key) {
            return Err(WireError::UntrustedSigner);
        }
        Ok(())
    }

    /// Verify limits, canonical form, and the self-declared signature without
    /// treating that signer as authorized. This is not authorization.
    pub fn validate_structure(&self, policy: &ValidationPolicy) -> Result<(), WireError> {
        if self.format_version != FORMAT_VERSION {
            return Err(WireError::UnsupportedFormat(self.format_version));
        }
        validate_context(&self.context, policy)?;
        if self.manifest_revision == 0
            || (self.manifest_revision == 1 && self.previous_manifest_hash != [0; 32])
            || (self.manifest_revision > 1 && self.previous_manifest_hash == [0; 32])
        {
            return Err(WireError::InvalidManifestChain);
        }
        if self.nonce.len() != self.suite.nonce_len() {
            return Err(WireError::InvalidNonceLength {
                expected: self.suite.nonce_len(),
                actual: self.nonce.len(),
            });
        }
        if self.ciphertext.len() < 16 || self.ciphertext.len() > policy.max_ciphertext_bytes {
            return Err(WireError::CiphertextSize(self.ciphertext.len()));
        }
        if self.recipients.is_empty() || self.recipients.len() > policy.max_recipients {
            return Err(WireError::RecipientCount(self.recipients.len()));
        }

        let mut previous_recipient: Option<(&str, u64)> = None;
        for envelope in &self.recipients {
            validate_label(&envelope.recipient_id, policy.max_identifier_bytes)?;
            if envelope.key_epoch == 0 {
                return Err(WireError::InvalidKeyEpoch);
            }
            let current = (envelope.recipient_id.as_str(), envelope.key_epoch);
            if previous_recipient.is_some_and(|previous| previous >= current) {
                return Err(WireError::NonCanonicalRecipients);
            }
            previous_recipient = Some(current);
            if envelope.encapsulated_key.len() != X25519_KEY_LEN {
                return Err(WireError::InvalidEncapsulatedKeyLength(
                    envelope.encapsulated_key.len(),
                ));
            }
            if envelope.wrapped_dek.len() != WRAPPED_DEK_LEN {
                return Err(WireError::InvalidWrappedDekLength(
                    envelope.wrapped_dek.len(),
                ));
            }
        }

        if self.indexes.len() > policy.max_indexes {
            return Err(WireError::IndexCount(self.indexes.len()));
        }
        let mut previous_index: Option<(&str, u64)> = None;
        for index in &self.indexes {
            validate_label(&index.label, policy.max_identifier_bytes)?;
            validate_label(&index.canonicalizer_id, policy.max_identifier_bytes)?;
            if index.key_epoch == 0 || index.schema_version == 0 || index.canonicalizer_version == 0
            {
                return Err(WireError::InvalidIndexDefinition);
            }
            let current = (index.label.as_str(), index.key_epoch);
            if previous_index.is_some_and(|previous| previous >= current) {
                return Err(WireError::NonCanonicalIndexes);
            }
            previous_index = Some(current);
        }

        let signature: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| WireError::InvalidSignatureLength(self.signature.len()))?;
        verify_strict(&self.signer_public_key, &self.signing_bytes(), &signature)
            .map_err(|_| WireError::InvalidSignature)
    }

    /// Find the envelope for one recipient and key epoch.
    pub fn recipient(
        &self,
        recipient_id: &str,
        key_epoch: u64,
        recipient_key_id: &[u8; 32],
    ) -> Option<&RecipientEnvelope> {
        self.recipients.iter().find(|candidate| {
            candidate.recipient_id == recipient_id
                && candidate.key_epoch == key_epoch
                && &candidate.recipient_key_id == recipient_key_id
        })
    }
}

/// Client-persisted freshness checkpoint for one record.
///
/// Persist this in the encrypted client vault. Without a checkpoint, a new
/// device cannot distinguish an old but perfectly valid record from the current
/// one: every signature still verifies, because the attacker is replaying the
/// author's own past work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FreshnessHead {
    /// Tenant identity.
    pub tenant: String,
    /// Object identity.
    pub object_id: String,
    /// Field/security zone.
    pub field: String,
    /// Latest observed access-manifest revision.
    pub manifest_revision: u64,
    /// Latest observed payload version.
    pub content_version: u64,
    /// Latest observed access epoch.
    pub epoch: u64,
    /// Latest signed manifest hash.
    pub manifest_hash: [u8; 32],
    /// Pinned author key for this chain.
    pub signer_public_key: [u8; 32],
}

impl FreshnessHead {
    /// Start tracking a validated, pinned record.
    pub fn start(record: &SealedRecord, policy: &ValidationPolicy) -> Result<Self, WireError> {
        record.validate(policy)?;
        Ok(Self::from_validated(record))
    }

    /// Require a fetched record to be exactly the persisted head.
    pub fn verify_current(
        &self,
        record: &SealedRecord,
        policy: &ValidationPolicy,
    ) -> Result<(), WireError> {
        record.validate(policy)?;
        if !self.same_identity(record)
            || self.manifest_revision != record.manifest_revision
            || self.content_version != record.context.version
            || self.epoch != record.context.epoch
            || self.manifest_hash != record.manifest_hash()
            || self.signer_public_key != record.signer_public_key
        {
            return Err(WireError::RollbackDetected);
        }
        Ok(())
    }

    /// Verify and advance by exactly one signed hash-chain link.
    pub fn advance(
        &mut self,
        record: &SealedRecord,
        policy: &ValidationPolicy,
    ) -> Result<(), WireError> {
        record.validate(policy)?;
        if !self.same_identity(record)
            || self.signer_public_key != record.signer_public_key
            || record.manifest_revision != self.manifest_revision.saturating_add(1)
            || record.previous_manifest_hash != self.manifest_hash
            || record.context.version < self.content_version
            || record.context.epoch < self.epoch
        {
            return Err(WireError::RollbackDetected);
        }
        *self = Self::from_validated(record);
        Ok(())
    }

    fn same_identity(&self, record: &SealedRecord) -> bool {
        self.tenant == record.context.tenant
            && self.object_id == record.context.object_id
            && self.field == record.context.field
    }

    fn from_validated(record: &SealedRecord) -> Self {
        Self {
            tenant: record.context.tenant.clone(),
            object_id: record.context.object_id.clone(),
            field: record.context.field.clone(),
            manifest_revision: record.manifest_revision,
            content_version: record.context.version,
            epoch: record.context.epoch,
            manifest_hash: record.manifest_hash(),
            signer_public_key: record.signer_public_key,
        }
    }
}

/// Build payload AEAD associated data before a record exists.
pub fn payload_aad(suite: Suite, context: &RecordContext) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + context.tenant.len() + context.object_id.len());
    push_bytes(&mut out, b"blindplane/payload-aad/v1");
    out.push(suite.code());
    push_bytes(&mut out, &context.canonical_bytes());
    out
}

/// Limits and signer pins enforced by a keyless server.
#[derive(Clone, Debug)]
pub struct ValidationPolicy {
    /// Maximum ciphertext size.
    pub max_ciphertext_bytes: usize,
    /// Maximum recipient envelopes per record.
    pub max_recipients: usize,
    /// Maximum blind indexes per record.
    pub max_indexes: usize,
    /// Maximum byte length of any routing identifier.
    pub max_identifier_bytes: usize,
    /// Pinned author/policy signing keys. Empty fails closed in `validate`.
    pub allowed_signers: HashSet<[u8; 32]>,
}

impl Default for ValidationPolicy {
    fn default() -> Self {
        Self {
            max_ciphertext_bytes: 8 * 1024 * 1024,
            max_recipients: 256,
            max_indexes: 32,
            max_identifier_bytes: 255,
            allowed_signers: HashSet::new(),
        }
    }
}

/// Keyless validation error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WireError {
    /// Unsupported record format.
    UnsupportedFormat(u16),
    /// A cleartext context identifier is empty or too large.
    IdentifierLength(usize),
    /// Epoch and version must be non-zero.
    InvalidVersion,
    /// Access manifest revision/hash linkage is malformed.
    InvalidManifestChain,
    /// Recipient key epochs must be non-zero.
    InvalidKeyEpoch,
    /// Blind-index fields and versions must be non-empty and non-zero.
    InvalidIndexDefinition,
    /// Nonce length does not match the selected cipher suite.
    InvalidNonceLength {
        /// Required nonce length for the selected suite.
        expected: usize,
        /// Received nonce length.
        actual: usize,
    },
    /// Ciphertext is too short or exceeds policy.
    CiphertextSize(usize),
    /// Recipient count is outside policy.
    RecipientCount(usize),
    /// Recipients must be sorted and unique.
    NonCanonicalRecipients,
    /// HPKE encapsulated key has the wrong size.
    InvalidEncapsulatedKeyLength(usize),
    /// Wrapped DEK has the wrong size.
    InvalidWrappedDekLength(usize),
    /// Index count exceeds policy.
    IndexCount(usize),
    /// Indexes must be sorted and unique.
    NonCanonicalIndexes,
    /// Signature verification failed.
    InvalidSignature,
    /// Signature must contain exactly 64 bytes.
    InvalidSignatureLength(usize),
    /// Signature is valid but the key is not pinned by policy.
    UntrustedSigner,
    /// Authorization requires at least one explicit signer pin.
    NoTrustedSigners,
    /// A valid but stale, forked, or non-successor record was observed.
    RollbackDetected,
    /// The encoding ended before the record did.
    Truncated,
    /// The encoding continued after the record ended.
    TrailingBytes,
    /// A length prefix exceeded policy.
    LengthLimit(usize),
    /// A record decoded but does not re-encode to the same bytes.
    NonCanonicalEncoding,
    /// An identifier was not valid UTF-8.
    InvalidUtf8,
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedFormat(v) => write!(f, "unsupported format version {v}"),
            Self::IdentifierLength(n) => write!(f, "invalid identifier length {n}"),
            Self::InvalidVersion => f.write_str("epoch and version must be non-zero"),
            Self::InvalidManifestChain => f.write_str("invalid access-manifest hash chain"),
            Self::InvalidKeyEpoch => f.write_str("recipient key epoch must be non-zero"),
            Self::InvalidIndexDefinition => f.write_str("invalid blind-index definition"),
            Self::InvalidNonceLength { expected, actual } => {
                write!(f, "invalid nonce length: expected {expected}, got {actual}")
            }
            Self::CiphertextSize(n) => write!(f, "invalid ciphertext size {n}"),
            Self::RecipientCount(n) => write!(f, "invalid recipient count {n}"),
            Self::NonCanonicalRecipients => {
                f.write_str("recipient envelopes are not sorted and unique")
            }
            Self::InvalidEncapsulatedKeyLength(n) => {
                write!(f, "invalid HPKE encapsulated key length {n}")
            }
            Self::InvalidWrappedDekLength(n) => write!(f, "invalid wrapped DEK length {n}"),
            Self::IndexCount(n) => write!(f, "invalid blind-index count {n}"),
            Self::NonCanonicalIndexes => f.write_str("blind indexes are not sorted and unique"),
            Self::InvalidSignature => f.write_str("record signature is invalid"),
            Self::InvalidSignatureLength(n) => write!(f, "invalid signature length {n}"),
            Self::UntrustedSigner => f.write_str("record signer is not trusted"),
            Self::NoTrustedSigners => f.write_str("no trusted signer is configured"),
            Self::RollbackDetected => f.write_str("record rollback or manifest fork detected"),
            Self::Truncated => f.write_str("record encoding is truncated"),
            Self::TrailingBytes => f.write_str("record encoding has trailing bytes"),
            Self::LengthLimit(n) => write!(f, "length prefix {n} exceeds policy"),
            Self::NonCanonicalEncoding => f.write_str("record encoding is not canonical"),
            Self::InvalidUtf8 => f.write_str("identifier is not valid UTF-8"),
        }
    }
}

impl std::error::Error for WireError {}

fn suite_from_code(code: u8) -> Result<Suite, WireError> {
    match code {
        1 => Ok(Suite::Aes256Gcm),
        2 => Ok(Suite::XChaCha20Poly1305),
        3 => Ok(Suite::ChaCha20Poly1305),
        _ => Err(WireError::UnsupportedFormat(u16::from(code))),
    }
}

fn decode_context(bytes: &[u8], policy: &ValidationPolicy) -> Result<RecordContext, WireError> {
    let mut cursor = Cursor::new(bytes);
    let domain = cursor.take_bytes(policy)?;
    if domain != b"blindplane/context/v1" {
        return Err(WireError::UnsupportedFormat(0));
    }
    let context = RecordContext {
        tenant: cursor.take_string(policy)?,
        object_id: cursor.take_string(policy)?,
        field: cursor.take_string(policy)?,
        epoch: cursor.take_u64()?,
        version: cursor.take_u64()?,
        schema_version: cursor.take_u32()?,
    };
    if !cursor.is_empty() {
        return Err(WireError::TrailingBytes);
    }
    Ok(context)
}

fn validate_context(context: &RecordContext, policy: &ValidationPolicy) -> Result<(), WireError> {
    validate_label(&context.tenant, policy.max_identifier_bytes)?;
    validate_label(&context.object_id, policy.max_identifier_bytes)?;
    validate_label(&context.field, policy.max_identifier_bytes)?;
    if context.epoch == 0 || context.version == 0 || context.schema_version == 0 {
        return Err(WireError::InvalidVersion);
    }
    Ok(())
}

fn validate_label(value: &str, max: usize) -> Result<(), WireError> {
    if value.is_empty() || value.len() > max {
        return Err(WireError::IdentifierLength(value.len()));
    }
    Ok(())
}

fn push_len(out: &mut Vec<u8>, len: usize) {
    let len = u64::try_from(len).expect("usize always fits into u64 on supported targets");
    out.extend_from_slice(&len.to_be_bytes());
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    push_len(out, bytes.len());
    out.extend_from_slice(bytes);
}

/// A bounds-checked reader over an untrusted encoding.
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    const fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn take_exact(&mut self, len: usize) -> Result<&'a [u8], WireError> {
        let end = self.offset.checked_add(len).ok_or(WireError::Truncated)?;
        if end > self.bytes.len() {
            return Err(WireError::Truncated);
        }
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn take_u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take_exact(1)?[0])
    }

    fn take_u16(&mut self) -> Result<u16, WireError> {
        let bytes: [u8; 2] = self.take_exact(2)?.try_into().expect("2 bytes");
        Ok(u16::from_be_bytes(bytes))
    }

    fn take_u32(&mut self) -> Result<u32, WireError> {
        let bytes: [u8; 4] = self.take_exact(4)?.try_into().expect("4 bytes");
        Ok(u32::from_be_bytes(bytes))
    }

    fn take_u64(&mut self) -> Result<u64, WireError> {
        let bytes: [u8; 8] = self.take_exact(8)?.try_into().expect("8 bytes");
        Ok(u64::from_be_bytes(bytes))
    }

    fn take_array32(&mut self) -> Result<[u8; 32], WireError> {
        Ok(self.take_exact(32)?.try_into().expect("32 bytes"))
    }

    /// Read a length-prefixed slice, refusing any length the policy would not
    /// accept before touching that many bytes.
    fn take_bytes(&mut self, policy: &ValidationPolicy) -> Result<&'a [u8], WireError> {
        let len = self.take_u64()?;
        let limit = policy.max_ciphertext_bytes.max(4096);
        let len = usize::try_from(len).map_err(|_| WireError::LengthLimit(usize::MAX))?;
        if len > limit {
            return Err(WireError::LengthLimit(len));
        }
        self.take_exact(len)
    }

    fn take_string(&mut self, policy: &ValidationPolicy) -> Result<String, WireError> {
        let bytes = self.take_bytes(policy)?;
        if bytes.len() > policy.max_identifier_bytes {
            return Err(WireError::IdentifierLength(bytes.len()));
        }
        core::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| WireError::InvalidUtf8)
    }

    fn take_len(&mut self, max: usize) -> Result<usize, WireError> {
        let len = self.take_u64()?;
        let len = usize::try_from(len).map_err(|_| WireError::LengthLimit(usize::MAX))?;
        if len > max {
            return Err(WireError::LengthLimit(len));
        }
        Ok(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_encoding_is_unambiguous() {
        let left = RecordContext {
            tenant: "ab".into(),
            object_id: "c".into(),
            field: "d".into(),
            epoch: 1,
            version: 1,
            schema_version: 1,
        };
        let right = RecordContext {
            tenant: "a".into(),
            object_id: "bc".into(),
            field: "d".into(),
            epoch: 1,
            version: 1,
            schema_version: 1,
        };
        assert_ne!(left.canonical_bytes(), right.canonical_bytes());
    }

    #[test]
    fn truncated_input_is_rejected_without_panicking() {
        let policy = ValidationPolicy::default();
        for len in 0..64 {
            let bytes = vec![0_u8; len];
            assert!(SealedRecord::decode(&bytes, &policy).is_err());
        }
    }

    #[test]
    fn oversized_length_prefix_is_rejected_before_allocating() {
        let policy = ValidationPolicy::default();
        let mut bytes = Vec::new();
        push_bytes(&mut bytes, b"blindplane/record-signature/v1");
        bytes.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
        bytes.push(1);
        // A context length prefix claiming 2^60 bytes must not be believed.
        bytes.extend_from_slice(&(1_u64 << 60).to_be_bytes());
        assert_eq!(
            SealedRecord::decode(&bytes, &policy),
            Err(WireError::LengthLimit(1 << 60))
        );
    }
}
