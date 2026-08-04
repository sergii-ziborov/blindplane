//! Client-side error type.

use blindplane_wire::WireError;

/// A client-side failure.
///
/// Decryption errors are deliberately coarse: a caller that could distinguish
/// "wrong key" from "tampered ciphertext" would be handing an attacker an
/// oracle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CryptoError {
    /// The operating-system CSPRNG failed.
    Randomness,
    /// A recipient id or epoch is invalid, or a key fingerprint did not match.
    InvalidKeyIdentity,
    /// The pinned signer key is not a usable Ed25519 public key.
    InvalidSignerKey,
    /// At least one recipient is required.
    NoRecipients,
    /// A recipient id/epoch pair was repeated.
    DuplicateRecipient,
    /// An index label/epoch pair was repeated.
    DuplicateIndex,
    /// The index scope is invalid.
    InvalidIndexScope,
    /// The routing context, schema, or a count limit is invalid.
    InvalidRecordInput,
    /// The payload exceeds the single-record size limit; chunk it.
    PayloadTooLarge,
    /// Key derivation failed.
    KeyDerivation,
    /// HPKE envelope encryption failed.
    HpkeSeal,
    /// HPKE open failed, including wrong key and tampering.
    HpkeOpen,
    /// Bulk payload encryption failed.
    PayloadSeal,
    /// The record could not be opened.
    PayloadOpen,
    /// The record does not grant access to this id and key epoch.
    NoEnvelopeForRecipient,
    /// Rekey did not preserve identity and advance epoch and version.
    InvalidRekeyContext,
    /// The access-manifest revision cannot advance beyond `u64::MAX`.
    ManifestRevisionOverflow,
    /// Vault key-derivation parameters are outside the allowed range.
    InvalidVaultParameters,
    /// Keyless wire validation failed.
    Wire(WireError),
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Randomness => f.write_str("operating system CSPRNG failed"),
            Self::InvalidKeyIdentity => f.write_str("invalid recipient key identity"),
            Self::InvalidSignerKey => f.write_str("pinned signer key is not a usable public key"),
            Self::NoRecipients => f.write_str("at least one recipient is required"),
            Self::DuplicateRecipient => f.write_str("duplicate recipient"),
            Self::DuplicateIndex => f.write_str("duplicate blind index"),
            Self::InvalidIndexScope => f.write_str("invalid blind-index scope"),
            Self::InvalidRecordInput => f.write_str("invalid record input"),
            Self::PayloadTooLarge => f.write_str("payload exceeds the single-record size limit"),
            Self::KeyDerivation => f.write_str("object key derivation failed"),
            Self::HpkeSeal => f.write_str("HPKE envelope encryption failed"),
            Self::HpkeOpen | Self::PayloadOpen => f.write_str("record could not be opened"),
            Self::PayloadSeal => f.write_str("payload encryption failed"),
            Self::NoEnvelopeForRecipient => f.write_str("no envelope for recipient"),
            Self::InvalidRekeyContext => {
                f.write_str("rekey must preserve identity and advance epoch and version")
            }
            Self::ManifestRevisionOverflow => f.write_str("access-manifest revision overflow"),
            Self::InvalidVaultParameters => f.write_str("invalid vault key-derivation parameters"),
            Self::Wire(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<WireError> for CryptoError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}
