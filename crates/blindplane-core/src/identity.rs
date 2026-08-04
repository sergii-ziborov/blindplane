//! Author, recipient and pinned-signer identities.

use blindplane_crypto::montgomery::StaticSecret;
use blindplane_crypto::util::Secret;
use blindplane_crypto::{PreparedVerifier, Sha256, SigningKey, ct_eq_bytes};
use blindplane_wire::SealedRecord;

use crate::derive::RECIPIENT_KEY_ID_DOMAIN;
use crate::error::CryptoError;

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

    pub(crate) fn sign(&self, record: &mut SealedRecord) {
        record.signer_public_key = self.public_key();
        record.signature = self.signing_key.sign(&record.signing_bytes()).to_vec();
    }
}

/// A public recipient and key epoch, used when granting read access.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Recipient {
    pub(crate) recipient_id: String,
    pub(crate) key_epoch: u64,
    pub(crate) recipient_key_id: [u8; 32],
    pub(crate) public_key: [u8; 32],
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
    pub(crate) recipient: Recipient,
    pub(crate) secret: StaticSecret,
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

/// An expected signer whose Ed25519 verification state is prepared once.
///
/// Pinning an author is a per-session act; records verified against the pin
/// arrive constantly. Preparation pays the key's parsing, its small-order
/// rejection and its verification tables once, and [`open_pinned`](crate::open_pinned)
/// then verifies each record measurably faster than [`open`](crate::open), with
/// an identical accept set.
pub struct PinnedSigner {
    pub(crate) verifier: PreparedVerifier,
}

impl core::fmt::Debug for PinnedSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PinnedSigner({:?})", self.public_key())
    }
}

impl PinnedSigner {
    /// Prepare a pinned author key for repeated verification.
    pub fn new(public_key: [u8; 32]) -> Result<Self, CryptoError> {
        PreparedVerifier::new(&public_key)
            .map(|verifier| Self { verifier })
            .map_err(|_| CryptoError::InvalidSignerKey)
    }

    /// The pinned 32-byte public key.
    pub fn public_key(&self) -> [u8; 32] {
        *self.verifier.public_key()
    }
}
