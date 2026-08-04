use blazingly::prelude::*;

/// A record write.
#[api_model]
#[derive(Clone, Debug)]
pub struct StoreRequest {
    /// Tenant or workspace.
    #[min_length(1)]
    #[max_length(255)]
    pub tenant: String,
    /// Object identifier.
    #[min_length(1)]
    #[max_length(255)]
    pub object_id: String,
    /// Field or security zone.
    #[min_length(1)]
    #[max_length(255)]
    pub field: String,
    /// The canonical record encoding, base64.
    #[min_length(1)]
    pub record: String,
}

/// The receipt for an accepted write.
#[api_model]
#[derive(Clone, Debug)]
pub struct StoreResponse {
    /// Accepted monotonic record version.
    pub version: u64,
    /// Accepted access-manifest revision.
    pub manifest_revision: u64,
    /// Hash the client persists as its freshness checkpoint, hex encoded.
    pub manifest_hash: String,
    /// Whether the record did not previously exist.
    pub created: bool,
}

/// A record lookup by identity.
#[api_model]
#[derive(Clone, Debug)]
pub struct FetchRequest {
    /// Tenant or workspace.
    #[min_length(1)]
    #[max_length(255)]
    pub tenant: String,
    /// Object identifier.
    #[min_length(1)]
    #[max_length(255)]
    pub object_id: String,
    /// Field or security zone.
    #[min_length(1)]
    #[max_length(255)]
    pub field: String,
}

/// One record, still sealed.
#[api_model]
#[derive(Clone, Debug)]
pub struct RecordResponse {
    /// The canonical record encoding, base64.
    pub record: String,
}

/// A blind-index lookup.
#[api_model]
#[derive(Clone, Debug)]
pub struct SearchRequest {
    /// Tenant or workspace.
    #[min_length(1)]
    #[max_length(255)]
    pub tenant: String,
    /// Index label.
    #[min_length(1)]
    #[max_length(255)]
    pub label: String,
    /// Index key epoch.
    pub key_epoch: u64,
    /// The client-computed token, hex encoded.
    #[min_length(32)]
    #[max_length(32)]
    pub token: String,
}

/// Ciphertext candidates for a blind-index lookup.
#[api_model]
#[derive(Clone, Debug)]
pub struct SearchResponse {
    /// Matching sealed records, base64. Clients decrypt and check each one.
    pub records: Vec<String>,
}
