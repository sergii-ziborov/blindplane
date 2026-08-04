//! Client-persisted freshness checkpoints against replay and rollback.

use blindplane_crypto::PreparedVerifier;

use crate::error::WireError;
use crate::policy::ValidationPolicy;
use crate::record::SealedRecord;

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
        self.require_exact_head(record)
    }

    /// [`verify_current`](Self::verify_current) against a prepared signer.
    pub fn verify_current_pinned(
        &self,
        record: &SealedRecord,
        verifier: &PreparedVerifier,
        policy: &ValidationPolicy,
    ) -> Result<(), WireError> {
        record.validate_pinned(verifier, policy)?;
        self.require_exact_head(record)
    }

    fn require_exact_head(&self, record: &SealedRecord) -> Result<(), WireError> {
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
