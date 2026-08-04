//! Parallel batch sealing and blind-index token tests.

use blindplane_crypto::aead::Suite;

use crate::{
    Author, BatchItem, ExactIndexDefinition, RecipientKeypair, SearchKey, fastest_payload_suite,
    open, seal, seal_batch,
};

use super::context;

#[test]
fn batch_sealing_preserves_order_and_opens() {
    let author = Author::generate().unwrap();
    let alice = RecipientKeypair::generate("alice", 1).unwrap();
    let items: Vec<BatchItem> = (0..64_u32)
        .map(|i| {
            let mut ctx = context();
            ctx.object_id = format!("object-{i}");
            BatchItem {
                context: ctx,
                plaintext: format!("payload {i}").into_bytes(),
                recipients: vec![alice.recipient()],
                indexes: vec![],
            }
        })
        .collect();

    let sealed = seal_batch(&author, &items, fastest_payload_suite());
    assert_eq!(sealed.len(), items.len());
    for (i, result) in sealed.into_iter().enumerate() {
        let record = result.unwrap();
        assert_eq!(record.context.object_id, format!("object-{i}"));
        assert_eq!(
            open(&record, &alice, author.public_key())
                .unwrap()
                .as_bytes(),
            format!("payload {i}").as_bytes()
        );
    }
}

#[test]
fn exact_indexes_are_stable_but_scope_separated() {
    let key = SearchKey::generate().unwrap();
    let definition = ExactIndexDefinition::raw_bytes("email", 1, 1).unwrap();
    let a = key
        .exact_token_raw("tenant-a", &definition, b"alice@example.com")
        .unwrap();
    let b = key
        .exact_token_raw("tenant-a", &definition, b"alice@example.com")
        .unwrap();
    let scoped = key
        .exact_token_raw("tenant-b", &definition, b"alice@example.com")
        .unwrap();

    assert_eq!(a.token, b.token);
    assert_ne!(a.token, scoped.token);
    assert_eq!(a.canonicalizer_id, "raw_bytes");
}

#[test]
fn every_suite_round_trips_across_many_payload_sizes() {
    let author = Author::generate().unwrap();
    let alice = RecipientKeypair::generate("alice", 1).unwrap();

    for suite in [
        Suite::Aes256Gcm,
        Suite::XChaCha20Poly1305,
        Suite::ChaCha20Poly1305,
    ] {
        if !suite.is_available() {
            continue;
        }
        for len in [0_usize, 1, 1024, 65_536] {
            let payload: Vec<u8> = (0..len).map(|i| (i * 13) as u8).collect();
            let record = seal(
                &author,
                context(),
                &payload,
                &[alice.recipient()],
                vec![],
                suite,
            )
            .unwrap();
            assert_eq!(
                open(&record, &alice, author.public_key())
                    .unwrap()
                    .as_bytes(),
                payload.as_slice(),
                "suite {suite:?} length {len}"
            );
        }
    }
}
