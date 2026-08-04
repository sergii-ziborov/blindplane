//! Canonical binary encoding and decoding.

use blindplane_crypto::aead::Suite;

use crate::context::{BlindIndex, RecipientEnvelope, RecordContext};
use crate::error::WireError;
use crate::policy::ValidationPolicy;
use crate::record::SealedRecord;
use crate::{FORMAT_VERSION, INDEX_TOKEN_LEN};

impl SealedRecord {
    /// Serialize to the canonical binary wire encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.signing_bytes();
        push_bytes(&mut out, &self.signature);
        out
    }

    /// Parse the canonical binary wire encoding.
    ///
    /// Parsing enforces the same structural limits a relay would apply, so a
    /// malformed or oversized record is rejected before any allocation the
    /// sender chose the size of.
    pub fn decode(bytes: &[u8], policy: &ValidationPolicy) -> Result<Self, WireError> {
        let mut cursor = Cursor::new(bytes);

        let domain = cursor.take_bytes(policy)?;
        if domain != b"blindplane/record-signature/v1" {
            return Err(WireError::UnsupportedFormat(0));
        }

        let format_version = cursor.take_u16()?;
        if format_version != FORMAT_VERSION {
            return Err(WireError::UnsupportedFormat(format_version));
        }
        let suite = suite_from_code(cursor.take_u8()?)?;

        let context_bytes = cursor.take_bytes(policy)?;
        let context = decode_context(context_bytes, policy)?;

        let manifest_revision = cursor.take_u64()?;
        let previous_manifest_hash = cursor.take_array32()?;
        let key_commitment = cursor.take_array32()?;
        let nonce = cursor.take_bytes(policy)?.to_vec();
        let ciphertext = cursor.take_bytes(policy)?.to_vec();

        let recipient_count = cursor.take_len(policy.max_recipients)?;
        let mut recipients = Vec::with_capacity(recipient_count);
        for _ in 0..recipient_count {
            recipients.push(RecipientEnvelope {
                recipient_id: cursor.take_string(policy)?,
                key_epoch: cursor.take_u64()?,
                recipient_key_id: cursor.take_array32()?,
                encapsulated_key: cursor.take_bytes(policy)?.to_vec(),
                wrapped_dek: cursor.take_bytes(policy)?.to_vec(),
            });
        }

        let index_count = cursor.take_len(policy.max_indexes)?;
        let mut indexes = Vec::with_capacity(index_count);
        for _ in 0..index_count {
            let label = cursor.take_string(policy)?;
            let schema_version = cursor.take_u32()?;
            let canonicalizer_id = cursor.take_string(policy)?;
            let canonicalizer_version = cursor.take_u16()?;
            let key_epoch = cursor.take_u64()?;
            let mut token = [0_u8; INDEX_TOKEN_LEN];
            token.copy_from_slice(cursor.take_exact(INDEX_TOKEN_LEN)?);
            indexes.push(BlindIndex {
                label,
                schema_version,
                canonicalizer_id,
                canonicalizer_version,
                key_epoch,
                token,
            });
        }

        let signer_public_key = cursor.take_array32()?;
        let signature = cursor.take_bytes(policy)?.to_vec();
        if !cursor.is_empty() {
            return Err(WireError::TrailingBytes);
        }

        let record = Self {
            format_version,
            suite,
            context,
            manifest_revision,
            previous_manifest_hash,
            key_commitment,
            nonce,
            ciphertext,
            recipients,
            indexes,
            signer_public_key,
            signature,
        };

        // Re-encoding must reproduce the input exactly. Two encodings of one
        // record would otherwise let a relay and a client disagree about what
        // was signed.
        if record.encode() != bytes {
            return Err(WireError::NonCanonicalEncoding);
        }
        record.validate_structure(policy)?;
        Ok(record)
    }
}

fn suite_from_code(code: u8) -> Result<Suite, WireError> {
    match code {
        1 => Ok(Suite::Aes256Gcm),
        2 => Ok(Suite::XChaCha20Poly1305),
        3 => Ok(Suite::ChaCha20Poly1305),
        _ => Err(WireError::UnsupportedFormat(u16::from(code))),
    }
}

fn decode_context(bytes: &[u8], policy: &ValidationPolicy) -> Result<RecordContext, WireError> {
    let mut cursor = Cursor::new(bytes);
    let domain = cursor.take_bytes(policy)?;
    if domain != b"blindplane/context/v1" {
        return Err(WireError::UnsupportedFormat(0));
    }
    let context = RecordContext {
        tenant: cursor.take_string(policy)?,
        object_id: cursor.take_string(policy)?,
        field: cursor.take_string(policy)?,
        epoch: cursor.take_u64()?,
        version: cursor.take_u64()?,
        schema_version: cursor.take_u32()?,
    };
    if !cursor.is_empty() {
        return Err(WireError::TrailingBytes);
    }
    Ok(context)
}

/// Append a length as eight big-endian bytes.
///
/// The canonical encoding is length-prefixed everywhere so that no two
/// different field sequences can produce the same bytes — the property that
/// makes a signature over these bytes unambiguous. Anything that builds
/// domain-separated input destined to be signed or MACed alongside a record
/// must use this same convention, so it is public rather than private.
pub fn push_len(out: &mut Vec<u8>, len: usize) {
    let len = u64::try_from(len).expect("usize always fits into u64 on supported targets");
    out.extend_from_slice(&len.to_be_bytes());
}

/// Append a length-prefixed byte string, per [`push_len`].
pub fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    push_len(out, bytes.len());
    out.extend_from_slice(bytes);
}

/// A bounds-checked reader over an untrusted encoding.
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    const fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn take_exact(&mut self, len: usize) -> Result<&'a [u8], WireError> {
        let end = self.offset.checked_add(len).ok_or(WireError::Truncated)?;
        if end > self.bytes.len() {
            return Err(WireError::Truncated);
        }
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn take_u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take_exact(1)?[0])
    }

    fn take_u16(&mut self) -> Result<u16, WireError> {
        let bytes: [u8; 2] = self.take_exact(2)?.try_into().expect("2 bytes");
        Ok(u16::from_be_bytes(bytes))
    }

    fn take_u32(&mut self) -> Result<u32, WireError> {
        let bytes: [u8; 4] = self.take_exact(4)?.try_into().expect("4 bytes");
        Ok(u32::from_be_bytes(bytes))
    }

    fn take_u64(&mut self) -> Result<u64, WireError> {
        let bytes: [u8; 8] = self.take_exact(8)?.try_into().expect("8 bytes");
        Ok(u64::from_be_bytes(bytes))
    }

    fn take_array32(&mut self) -> Result<[u8; 32], WireError> {
        Ok(self.take_exact(32)?.try_into().expect("32 bytes"))
    }

    /// Read a length-prefixed slice, refusing any length the policy would not
    /// accept before touching that many bytes.
    fn take_bytes(&mut self, policy: &ValidationPolicy) -> Result<&'a [u8], WireError> {
        let len = self.take_u64()?;
        let limit = policy.max_ciphertext_bytes.max(4096);
        let len = usize::try_from(len).map_err(|_| WireError::LengthLimit(usize::MAX))?;
        if len > limit {
            return Err(WireError::LengthLimit(len));
        }
        self.take_exact(len)
    }

    fn take_string(&mut self, policy: &ValidationPolicy) -> Result<String, WireError> {
        let bytes = self.take_bytes(policy)?;
        if bytes.len() > policy.max_identifier_bytes {
            return Err(WireError::IdentifierLength(bytes.len()));
        }
        core::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| WireError::InvalidUtf8)
    }

    fn take_len(&mut self, max: usize) -> Result<usize, WireError> {
        let len = self.take_u64()?;
        let len = usize::try_from(len).map_err(|_| WireError::LengthLimit(usize::MAX))?;
        if len > max {
            return Err(WireError::LengthLimit(len));
        }
        Ok(len)
    }
}
