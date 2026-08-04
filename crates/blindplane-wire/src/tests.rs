//! Unit tests for the canonical wire encoding.

use crate::encode::push_bytes;
use crate::{FORMAT_VERSION, RecordContext, SealedRecord, ValidationPolicy, WireError};

#[test]
fn context_encoding_is_unambiguous() {
    let left = RecordContext {
        tenant: "ab".into(),
        object_id: "c".into(),
        field: "d".into(),
        epoch: 1,
        version: 1,
        schema_version: 1,
    };
    let right = RecordContext {
        tenant: "a".into(),
        object_id: "bc".into(),
        field: "d".into(),
        epoch: 1,
        version: 1,
        schema_version: 1,
    };
    assert_ne!(left.canonical_bytes(), right.canonical_bytes());
}

#[test]
fn truncated_input_is_rejected_without_panicking() {
    let policy = ValidationPolicy::default();
    for len in 0..64 {
        let bytes = vec![0_u8; len];
        assert!(SealedRecord::decode(&bytes, &policy).is_err());
    }
}

#[test]
fn oversized_length_prefix_is_rejected_before_allocating() {
    let policy = ValidationPolicy::default();
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"blindplane/record-signature/v1");
    bytes.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    bytes.push(1);
    // A context length prefix claiming 2^60 bytes must not be believed.
    bytes.extend_from_slice(&(1_u64 << 60).to_be_bytes());
    assert_eq!(
        SealedRecord::decode(&bytes, &policy),
        Err(WireError::LengthLimit(1 << 60))
    );
}
