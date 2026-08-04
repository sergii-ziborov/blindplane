//! Blind-index search keys and definitions.

use blindplane_crypto::HmacSha256;
use blindplane_crypto::rand;
use blindplane_crypto::util::Secret;
use blindplane_wire::{BlindIndex, ValidationPolicy};

use crate::derive::{INDEX_DOMAIN, mac_bytes};
use crate::error::CryptoError;

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
        let max = ValidationPolicy::default().max_identifier_bytes;
        if label.is_empty() || label.len() > max || schema_version == 0 || key_epoch == 0 {
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
        if tenant.is_empty() || tenant.len() > ValidationPolicy::default().max_identifier_bytes {
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
