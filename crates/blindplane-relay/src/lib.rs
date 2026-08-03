//! Framework-neutral keyless relay logic.
//!
//! A relay accepts sealed records, checks that they are well formed, signed by
//! a pinned author and strictly newer than what it already holds, and answers
//! blind-index lookups. It cannot read a payload, and this crate's dependency
//! graph is the proof: it depends on `blindplane-wire` and nothing else, and
//! `blindplane-wire` has no decryption function to call.
//!
//! Transport lives in the adapters. This crate does no I/O, which is what lets
//! the same logic run under Blazingly, under any other server, or inside a test
//! with no socket at all.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::RwLock;

use blindplane_wire::{SealedRecord, ValidationPolicy, WireError};

/// Identity of one stored record.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RecordKey {
    /// Tenant or workspace.
    pub tenant: String,
    /// Object identifier.
    pub object_id: String,
    /// Field or security zone.
    pub field: String,
}

impl RecordKey {
    /// Build a key from its three parts.
    pub fn new(
        tenant: impl Into<String>,
        object_id: impl Into<String>,
        field: impl Into<String>,
    ) -> Self {
        Self {
            tenant: tenant.into(),
            object_id: object_id.into(),
            field: field.into(),
        }
    }

    fn of(record: &SealedRecord) -> Self {
        Self {
            tenant: record.context.tenant.clone(),
            object_id: record.context.object_id.clone(),
            field: record.context.field.clone(),
        }
    }
}

/// What a relay refuses to do.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayError {
    /// The record failed keyless validation.
    Invalid(WireError),
    /// The route and the record's own context disagree.
    RouteContextMismatch,
    /// The write does not strictly advance the stored version chain.
    StaleWrite {
        /// Version the relay already holds.
        stored_version: u64,
        /// Version the client offered.
        offered_version: u64,
    },
    /// No record exists at this key.
    NotFound,
}

impl core::fmt::Display for RelayError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Invalid(error) => write!(f, "{error}"),
            Self::RouteContextMismatch => {
                f.write_str("route does not match the record's authenticated context")
            }
            Self::StaleWrite {
                stored_version,
                offered_version,
            } => write!(
                f,
                "stale write: stored version {stored_version}, offered {offered_version}"
            ),
            Self::NotFound => f.write_str("record not found"),
        }
    }
}

impl std::error::Error for RelayError {}

impl From<WireError> for RelayError {
    fn from(error: WireError) -> Self {
        Self::Invalid(error)
    }
}

/// The outcome of an accepted write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteReceipt {
    /// Accepted monotonic record version.
    pub version: u64,
    /// Accepted access-manifest revision.
    pub manifest_revision: u64,
    /// Hash the client persists as its next freshness checkpoint.
    pub manifest_hash: [u8; 32],
    /// Whether the record did not previously exist.
    pub created: bool,
}

/// An in-memory relay store.
///
/// The prototype keeps records in memory; a production adapter should preserve
/// the same two properties in a transactional database: writes advance
/// monotonically, and the secondary index is updated in the same transaction as
/// the record, so a lookup never returns a token that no longer applies.
#[derive(Default)]
pub struct MemoryStore {
    inner: RwLock<StoreInner>,
}

#[derive(Default)]
struct StoreInner {
    records: BTreeMap<RecordKey, SealedRecord>,
    /// `(tenant, label, key_epoch, token) -> keys`
    index: BTreeMap<(String, String, u64, [u8; 16]), BTreeSet<RecordKey>>,
}

impl MemoryStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate and store a record, refusing anything that is not strictly
    /// newer than what is already held.
    pub fn put(
        &self,
        record: SealedRecord,
        policy: &ValidationPolicy,
    ) -> Result<WriteReceipt, RelayError> {
        record.validate(policy)?;

        let key = RecordKey::of(&record);
        let mut inner = self
            .inner
            .write()
            .expect("relay store lock is not poisoned");

        let created = match inner.records.get(&key) {
            None => true,
            Some(existing) => {
                // Either the payload advanced, or the access manifest did.
                let advances_content = record.context.version > existing.context.version;
                let advances_manifest = record.context.version == existing.context.version
                    && record.manifest_revision > existing.manifest_revision;
                if !advances_content && !advances_manifest {
                    return Err(RelayError::StaleWrite {
                        stored_version: existing.context.version,
                        offered_version: record.context.version,
                    });
                }
                false
            }
        };

        let receipt = WriteReceipt {
            version: record.context.version,
            manifest_revision: record.manifest_revision,
            manifest_hash: record.manifest_hash(),
            created,
        };

        if let Some(previous) = inner.records.get(&key).cloned() {
            for index in &previous.indexes {
                let index_key = (
                    previous.context.tenant.clone(),
                    index.label.clone(),
                    index.key_epoch,
                    index.token,
                );
                if let Some(set) = inner.index.get_mut(&index_key) {
                    set.remove(&key);
                    if set.is_empty() {
                        inner.index.remove(&index_key);
                    }
                }
            }
        }

        for index in &record.indexes {
            let index_key = (
                record.context.tenant.clone(),
                index.label.clone(),
                index.key_epoch,
                index.token,
            );
            inner
                .index
                .entry(index_key)
                .or_default()
                .insert(key.clone());
        }
        inner.records.insert(key, record);

        Ok(receipt)
    }

    /// Fetch one record.
    pub fn get(&self, key: &RecordKey) -> Result<SealedRecord, RelayError> {
        self.inner
            .read()
            .expect("relay store lock is not poisoned")
            .records
            .get(key)
            .cloned()
            .ok_or(RelayError::NotFound)
    }

    /// Look up ciphertext candidates by blind-index token.
    ///
    /// The relay learns which records share a token. It does not learn the
    /// value behind it, and the client still has to decrypt and check every
    /// candidate.
    pub fn search(
        &self,
        tenant: &str,
        label: &str,
        key_epoch: u64,
        token: [u8; 16],
    ) -> Vec<SealedRecord> {
        let inner = self.inner.read().expect("relay store lock is not poisoned");
        inner
            .index
            .get(&(tenant.to_owned(), label.to_owned(), key_epoch, token))
            .into_iter()
            .flatten()
            .filter_map(|key| inner.records.get(key).cloned())
            .collect()
    }

    /// Number of stored records.
    pub fn len(&self) -> usize {
        self.inner
            .read()
            .expect("relay store lock is not poisoned")
            .records
            .len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A relay: a store plus the policy it enforces.
pub struct Relay {
    store: MemoryStore,
    policy: ValidationPolicy,
}

impl Relay {
    /// Build a relay that pins the given policy.
    pub fn new(policy: ValidationPolicy) -> Self {
        Self {
            store: MemoryStore::new(),
            policy,
        }
    }

    /// The enforced policy.
    pub const fn policy(&self) -> &ValidationPolicy {
        &self.policy
    }

    /// The underlying store.
    pub const fn store(&self) -> &MemoryStore {
        &self.store
    }

    /// Accept an encoded record for a route, checking that the route and the
    /// record's authenticated context agree.
    ///
    /// The route check matters: without it a client could store a record under
    /// one tenant's path whose signed context names another, and a later reader
    /// following the path would trust the wrong context.
    pub fn put_encoded(&self, key: &RecordKey, encoded: &[u8]) -> Result<WriteReceipt, RelayError> {
        let record = SealedRecord::decode(encoded, &self.policy)?;
        if record.context.tenant != key.tenant
            || record.context.object_id != key.object_id
            || record.context.field != key.field
        {
            return Err(RelayError::RouteContextMismatch);
        }
        self.store.put(record, &self.policy)
    }

    /// Fetch one record in its encoded form.
    pub fn get_encoded(&self, key: &RecordKey) -> Result<Vec<u8>, RelayError> {
        self.store.get(key).map(|record| record.encode())
    }

    /// Look up encoded ciphertext candidates by blind-index token.
    pub fn search_encoded(
        &self,
        tenant: &str,
        label: &str,
        key_epoch: u64,
        token: [u8; 16],
    ) -> Vec<Vec<u8>> {
        self.store
            .search(tenant, label, key_epoch, token)
            .into_iter()
            .map(|record| record.encode())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_record_is_not_found() {
        let relay = Relay::new(ValidationPolicy::default());
        assert_eq!(
            relay.get_encoded(&RecordKey::new("t", "o", "f")),
            Err(RelayError::NotFound)
        );
    }

    #[test]
    fn garbage_is_rejected_without_panicking() {
        let relay = Relay::new(ValidationPolicy::default());
        let key = RecordKey::new("t", "o", "f");
        for bytes in [vec![], vec![0_u8; 1], vec![0xff_u8; 512]] {
            assert!(relay.put_encoded(&key, &bytes).is_err());
        }
    }
}
