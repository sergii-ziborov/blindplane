//! Cleartext routing context, recipient envelopes and blind-index records.

use blindplane_crypto::aead::Suite;

use crate::INDEX_TOKEN_LEN;
use crate::encode::push_bytes;

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

/// Build payload AEAD associated data before a record exists.
pub fn payload_aad(suite: Suite, context: &RecordContext) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + context.tenant.len() + context.object_id.len());
    push_bytes(&mut out, b"blindplane/payload-aad/v1");
    out.push(suite.code());
    push_bytes(&mut out, &context.canonical_bytes());
    out
}
