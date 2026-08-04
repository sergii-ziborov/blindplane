use std::collections::{BTreeMap, BTreeSet};
use std::sync::RwLock;

use blindplane_wire::{SealedRecord, ValidationPolicy};

use crate::error::RelayError;
use crate::record_key::RecordKey;

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
