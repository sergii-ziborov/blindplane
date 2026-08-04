//! Keyless validation error.

/// Keyless validation error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WireError {
    /// Unsupported record format.
    UnsupportedFormat(u16),
    /// A cleartext context identifier is empty or too large.
    IdentifierLength(usize),
    /// Epoch and version must be non-zero.
    InvalidVersion,
    /// Access manifest revision/hash linkage is malformed.
    InvalidManifestChain,
    /// Recipient key epochs must be non-zero.
    InvalidKeyEpoch,
    /// Blind-index fields and versions must be non-empty and non-zero.
    InvalidIndexDefinition,
    /// Nonce length does not match the selected cipher suite.
    InvalidNonceLength {
        /// Required nonce length for the selected suite.
        expected: usize,
        /// Received nonce length.
        actual: usize,
    },
    /// Ciphertext is too short or exceeds policy.
    CiphertextSize(usize),
    /// Recipient count is outside policy.
    RecipientCount(usize),
    /// Recipients must be sorted and unique.
    NonCanonicalRecipients,
    /// HPKE encapsulated key has the wrong size.
    InvalidEncapsulatedKeyLength(usize),
    /// Wrapped DEK has the wrong size.
    InvalidWrappedDekLength(usize),
    /// Index count exceeds policy.
    IndexCount(usize),
    /// Indexes must be sorted and unique.
    NonCanonicalIndexes,
    /// Signature verification failed.
    InvalidSignature,
    /// Signature must contain exactly 64 bytes.
    InvalidSignatureLength(usize),
    /// Signature is valid but the key is not pinned by policy.
    UntrustedSigner,
    /// Authorization requires at least one explicit signer pin.
    NoTrustedSigners,
    /// A valid but stale, forked, or non-successor record was observed.
    RollbackDetected,
    /// The encoding ended before the record did.
    Truncated,
    /// The encoding continued after the record ended.
    TrailingBytes,
    /// A length prefix exceeded policy.
    LengthLimit(usize),
    /// A record decoded but does not re-encode to the same bytes.
    NonCanonicalEncoding,
    /// An identifier was not valid UTF-8.
    InvalidUtf8,
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedFormat(v) => write!(f, "unsupported format version {v}"),
            Self::IdentifierLength(n) => write!(f, "invalid identifier length {n}"),
            Self::InvalidVersion => f.write_str("epoch and version must be non-zero"),
            Self::InvalidManifestChain => f.write_str("invalid access-manifest hash chain"),
            Self::InvalidKeyEpoch => f.write_str("recipient key epoch must be non-zero"),
            Self::InvalidIndexDefinition => f.write_str("invalid blind-index definition"),
            Self::InvalidNonceLength { expected, actual } => {
                write!(f, "invalid nonce length: expected {expected}, got {actual}")
            }
            Self::CiphertextSize(n) => write!(f, "invalid ciphertext size {n}"),
            Self::RecipientCount(n) => write!(f, "invalid recipient count {n}"),
            Self::NonCanonicalRecipients => {
                f.write_str("recipient envelopes are not sorted and unique")
            }
            Self::InvalidEncapsulatedKeyLength(n) => {
                write!(f, "invalid HPKE encapsulated key length {n}")
            }
            Self::InvalidWrappedDekLength(n) => write!(f, "invalid wrapped DEK length {n}"),
            Self::IndexCount(n) => write!(f, "invalid blind-index count {n}"),
            Self::NonCanonicalIndexes => f.write_str("blind indexes are not sorted and unique"),
            Self::InvalidSignature => f.write_str("record signature is invalid"),
            Self::InvalidSignatureLength(n) => write!(f, "invalid signature length {n}"),
            Self::UntrustedSigner => f.write_str("record signer is not trusted"),
            Self::NoTrustedSigners => f.write_str("no trusted signer is configured"),
            Self::RollbackDetected => f.write_str("record rollback or manifest fork detected"),
            Self::Truncated => f.write_str("record encoding is truncated"),
            Self::TrailingBytes => f.write_str("record encoding has trailing bytes"),
            Self::LengthLimit(n) => write!(f, "length prefix {n} exceeds policy"),
            Self::NonCanonicalEncoding => f.write_str("record encoding is not canonical"),
            Self::InvalidUtf8 => f.write_str("identifier is not valid UTF-8"),
        }
    }
}

impl std::error::Error for WireError {}
