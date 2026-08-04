//! The signed, multi-recipient sealed record and its validation.

use blindplane_crypto::aead::Suite;
use blindplane_crypto::{PreparedVerifier, Sha256, verify_strict};

use crate::context::{BlindIndex, RecipientEnvelope, RecordContext, payload_aad};
use crate::encode::{push_bytes, push_len};
use crate::error::WireError;
use crate::policy::ValidationPolicy;
use crate::{FORMAT_VERSION, WRAPPED_DEK_LEN, X25519_KEY_LEN};

/// A signed, multi-recipient encrypted record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedRecord {
    /// Wire format version.
    pub format_version: u16,
    /// Payload cipher suite.
    pub suite: Suite,
    /// Cleartext but authenticated routing context.
    pub context: RecordContext,
    /// Monotonic access-manifest revision. Granting access advances this
    /// without rewriting the immutable payload.
    pub manifest_revision: u64,
    /// Hash of the preceding signed manifest, or all zeroes for a genesis
    /// record. This is what turns a sequence of records into a chain a client
    /// can check for rollback.
    pub previous_manifest_hash: [u8; 32],
    /// Domain-separated commitment to the random object secret and header,
    /// which makes the payload key non-committing attacks fail closed.
    pub key_commitment: [u8; 32],
    /// Random AEAD nonce.
    pub nonce: Vec<u8>,
    /// AEAD ciphertext including its authentication tag.
    pub ciphertext: Vec<u8>,
    /// Sorted, unique recipient envelopes.
    pub recipients: Vec<RecipientEnvelope>,
    /// Sorted, unique optional blind indexes.
    pub indexes: Vec<BlindIndex>,
    /// Ed25519 verifying key for the author/policy signer.
    pub signer_public_key: [u8; 32],
    /// Ed25519 signature over every preceding field.
    pub signature: Vec<u8>,
}

impl SealedRecord {
    /// Canonical bytes signed by the record author.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            self.ciphertext.len() + self.recipients.len() * 128 + self.indexes.len() * 64 + 256,
        );
        push_bytes(&mut out, b"blindplane/record-signature/v1");
        out.extend_from_slice(&self.format_version.to_be_bytes());
        out.push(self.suite.code());
        push_bytes(&mut out, &self.context.canonical_bytes());
        out.extend_from_slice(&self.manifest_revision.to_be_bytes());
        out.extend_from_slice(&self.previous_manifest_hash);
        out.extend_from_slice(&self.key_commitment);
        push_bytes(&mut out, &self.nonce);
        push_bytes(&mut out, &self.ciphertext);
        push_len(&mut out, self.recipients.len());
        for envelope in &self.recipients {
            push_bytes(&mut out, envelope.recipient_id.as_bytes());
            out.extend_from_slice(&envelope.key_epoch.to_be_bytes());
            out.extend_from_slice(&envelope.recipient_key_id);
            push_bytes(&mut out, &envelope.encapsulated_key);
            push_bytes(&mut out, &envelope.wrapped_dek);
        }
        push_len(&mut out, self.indexes.len());
        for index in &self.indexes {
            push_bytes(&mut out, index.label.as_bytes());
            out.extend_from_slice(&index.schema_version.to_be_bytes());
            push_bytes(&mut out, index.canonicalizer_id.as_bytes());
            out.extend_from_slice(&index.canonicalizer_version.to_be_bytes());
            out.extend_from_slice(&index.key_epoch.to_be_bytes());
            out.extend_from_slice(&index.token);
        }
        out.extend_from_slice(&self.signer_public_key);
        out
    }

    /// Payload AEAD associated data.
    ///
    /// Recipient envelopes and indexes are excluded so an authorized signer can
    /// grant access without re-encrypting the payload; the outer signature
    /// still binds them.
    pub fn payload_aad(&self) -> Vec<u8> {
        payload_aad(self.suite, &self.context)
    }

    /// Domain-separated hash used to link signed access manifests.
    pub fn manifest_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"blindplane/manifest-hash/v1");
        hasher.update(&self.signing_bytes());
        hasher.update(&self.signature);
        hasher.finalize()
    }

    /// Verify structure, signature, and an explicitly pinned signer.
    ///
    /// An empty signer set fails closed: "trust nobody" must never mean "trust
    /// everybody".
    pub fn validate(&self, policy: &ValidationPolicy) -> Result<(), WireError> {
        self.validate_structure(policy)?;
        if policy.allowed_signers.is_empty() {
            return Err(WireError::NoTrustedSigners);
        }
        if !policy.allowed_signers.contains(&self.signer_public_key) {
            return Err(WireError::UntrustedSigner);
        }
        Ok(())
    }

    /// Verify structure, signature and the pin against a prepared signer.
    ///
    /// Behaves exactly like [`validate`](Self::validate) with a policy pinning
    /// only `verifier.public_key()` — same checks, same error variants — but
    /// the signer's key parsing and verification tables were paid once, at
    /// [`PreparedVerifier::new`], instead of per record. The policy supplies
    /// the limits; its `allowed_signers` set is not consulted, because the
    /// verifier *is* the pin.
    pub fn validate_pinned(
        &self,
        verifier: &PreparedVerifier,
        policy: &ValidationPolicy,
    ) -> Result<(), WireError> {
        self.validate_limits(policy)?;
        let signature: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| WireError::InvalidSignatureLength(self.signature.len()))?;

        if self.signer_public_key == *verifier.public_key() {
            verifier
                .verify_strict(&self.signing_bytes(), &signature)
                .map_err(|_| WireError::InvalidSignature)
        } else {
            // A record from some other signer is rejected either way; checking
            // its self-declared signature first keeps the error variants
            // exactly those of the cold path: a forgery is InvalidSignature,
            // a genuine record from the wrong author is UntrustedSigner.
            verify_strict(&self.signer_public_key, &self.signing_bytes(), &signature)
                .map_err(|_| WireError::InvalidSignature)?;
            Err(WireError::UntrustedSigner)
        }
    }

    /// Check limits and canonical form, but not the signature.
    ///
    /// This exists for one caller: a signer checking its own freshly built
    /// record. Verifying a signature you produced three lines earlier costs a
    /// third of the sealing time and proves nothing about an adversary — the
    /// key is yours and the bytes never left the process.
    ///
    /// It is not a substitute for [`validate`] on anything that arrived from
    /// elsewhere. Every ingress path must still verify.
    pub fn validate_shape(&self, policy: &ValidationPolicy) -> Result<(), WireError> {
        self.validate_limits(policy)
    }

    /// Verify limits, canonical form, and the self-declared signature without
    /// treating that signer as authorized. This is not authorization.
    pub fn validate_structure(&self, policy: &ValidationPolicy) -> Result<(), WireError> {
        self.validate_limits(policy)?;

        let signature: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| WireError::InvalidSignatureLength(self.signature.len()))?;
        verify_strict(&self.signer_public_key, &self.signing_bytes(), &signature)
            .map_err(|_| WireError::InvalidSignature)
    }

    /// Everything `validate_structure` checks except the signature itself.
    fn validate_limits(&self, policy: &ValidationPolicy) -> Result<(), WireError> {
        if self.format_version != FORMAT_VERSION {
            return Err(WireError::UnsupportedFormat(self.format_version));
        }
        validate_context(&self.context, policy)?;
        if self.manifest_revision == 0
            || (self.manifest_revision == 1 && self.previous_manifest_hash != [0; 32])
            || (self.manifest_revision > 1 && self.previous_manifest_hash == [0; 32])
        {
            return Err(WireError::InvalidManifestChain);
        }
        if self.nonce.len() != self.suite.nonce_len() {
            return Err(WireError::InvalidNonceLength {
                expected: self.suite.nonce_len(),
                actual: self.nonce.len(),
            });
        }
        if self.ciphertext.len() < 16 || self.ciphertext.len() > policy.max_ciphertext_bytes {
            return Err(WireError::CiphertextSize(self.ciphertext.len()));
        }
        if self.recipients.is_empty() || self.recipients.len() > policy.max_recipients {
            return Err(WireError::RecipientCount(self.recipients.len()));
        }

        let mut previous_recipient: Option<(&str, u64)> = None;
        for envelope in &self.recipients {
            validate_label(&envelope.recipient_id, policy.max_identifier_bytes)?;
            if envelope.key_epoch == 0 {
                return Err(WireError::InvalidKeyEpoch);
            }
            let current = (envelope.recipient_id.as_str(), envelope.key_epoch);
            if previous_recipient.is_some_and(|previous| previous >= current) {
                return Err(WireError::NonCanonicalRecipients);
            }
            previous_recipient = Some(current);
            if envelope.encapsulated_key.len() != X25519_KEY_LEN {
                return Err(WireError::InvalidEncapsulatedKeyLength(
                    envelope.encapsulated_key.len(),
                ));
            }
            if envelope.wrapped_dek.len() != WRAPPED_DEK_LEN {
                return Err(WireError::InvalidWrappedDekLength(
                    envelope.wrapped_dek.len(),
                ));
            }
        }

        if self.indexes.len() > policy.max_indexes {
            return Err(WireError::IndexCount(self.indexes.len()));
        }
        let mut previous_index: Option<(&str, u64)> = None;
        for index in &self.indexes {
            validate_label(&index.label, policy.max_identifier_bytes)?;
            validate_label(&index.canonicalizer_id, policy.max_identifier_bytes)?;
            if index.key_epoch == 0 || index.schema_version == 0 || index.canonicalizer_version == 0
            {
                return Err(WireError::InvalidIndexDefinition);
            }
            let current = (index.label.as_str(), index.key_epoch);
            if previous_index.is_some_and(|previous| previous >= current) {
                return Err(WireError::NonCanonicalIndexes);
            }
            previous_index = Some(current);
        }

        if self.signature.len() != 64 {
            return Err(WireError::InvalidSignatureLength(self.signature.len()));
        }
        Ok(())
    }

    /// Find the envelope for one recipient and key epoch.
    pub fn recipient(
        &self,
        recipient_id: &str,
        key_epoch: u64,
        recipient_key_id: &[u8; 32],
    ) -> Option<&RecipientEnvelope> {
        self.recipients.iter().find(|candidate| {
            candidate.recipient_id == recipient_id
                && candidate.key_epoch == key_epoch
                && &candidate.recipient_key_id == recipient_key_id
        })
    }
}

fn validate_context(context: &RecordContext, policy: &ValidationPolicy) -> Result<(), WireError> {
    validate_label(&context.tenant, policy.max_identifier_bytes)?;
    validate_label(&context.object_id, policy.max_identifier_bytes)?;
    validate_label(&context.field, policy.max_identifier_bytes)?;
    if context.epoch == 0 || context.version == 0 || context.schema_version == 0 {
        return Err(WireError::InvalidVersion);
    }
    Ok(())
}

fn validate_label(value: &str, max: usize) -> Result<(), WireError> {
    if value.is_empty() || value.len() > max {
        return Err(WireError::IdentifierLength(value.len()));
    }
    Ok(())
}
