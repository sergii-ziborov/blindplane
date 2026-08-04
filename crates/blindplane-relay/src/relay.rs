use blindplane_wire::{SealedRecord, ValidationPolicy};

use crate::error::RelayError;
use crate::record_key::RecordKey;
use crate::store::{MemoryStore, WriteReceipt};

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
