//! Limits and signer pins enforced by a keyless server.

use std::collections::HashSet;

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
