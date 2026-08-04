//! Prepared-verifier open paths agree with the cold path, case for case.

use blindplane_wire::FreshnessHead;

use crate::derive::policy_for;
use crate::{Author, CryptoError, PinnedSigner, RecipientKeypair, fastest_payload_suite};
use crate::{open, open_at_head, open_at_head_pinned, open_pinned, seal};

use super::context;

#[test]
fn pinned_open_agrees_with_cold_open_case_for_case() {
    let author = Author::generate().unwrap();
    let alice = RecipientKeypair::generate("alice", 1).unwrap();
    let bob = RecipientKeypair::generate("bob", 1).unwrap();
    let record = seal(
        &author,
        context(),
        b"pinned payload",
        &[alice.recipient()],
        vec![],
        fastest_payload_suite(),
    )
    .unwrap();

    let pinned = PinnedSigner::new(author.public_key()).unwrap();
    let stranger = Author::generate().unwrap();
    let wrong_pin = PinnedSigner::new(stranger.public_key()).unwrap();

    // The valid record opens identically through both paths.
    assert_eq!(
        open_pinned(&record, &alice, &pinned).unwrap().as_bytes(),
        open(&record, &alice, author.public_key())
            .unwrap()
            .as_bytes()
    );

    // Every rejection matches the cold path variant for variant: a wrong
    // pin, a recipient without an envelope, a tampered payload and a
    // tampered signature.
    assert_eq!(
        open_pinned(&record, &alice, &wrong_pin).unwrap_err(),
        open(&record, &alice, stranger.public_key()).unwrap_err()
    );
    assert_eq!(
        open_pinned(&record, &bob, &pinned).unwrap_err(),
        open(&record, &bob, author.public_key()).unwrap_err()
    );
    let mut tampered = record.clone();
    tampered.ciphertext[0] ^= 1;
    assert_eq!(
        open_pinned(&tampered, &alice, &pinned).unwrap_err(),
        open(&tampered, &alice, author.public_key()).unwrap_err()
    );
    let mut resigned = record.clone();
    resigned.signature[10] ^= 1;
    assert_eq!(
        open_pinned(&resigned, &alice, &pinned).unwrap_err(),
        open(&resigned, &alice, author.public_key()).unwrap_err()
    );

    // A key that is not a curve point fails at pin construction.
    assert_eq!(
        PinnedSigner::new([0xff; 32]).unwrap_err(),
        CryptoError::InvalidSignerKey
    );
}

#[test]
fn pinned_open_at_head_agrees_with_cold() {
    let author = Author::generate().unwrap();
    let alice = RecipientKeypair::generate("alice", 1).unwrap();
    let record = seal(
        &author,
        context(),
        b"head payload",
        &[alice.recipient()],
        vec![],
        fastest_payload_suite(),
    )
    .unwrap();
    let head = FreshnessHead::start(&record, &policy_for(author.public_key())).unwrap();
    let pinned = PinnedSigner::new(author.public_key()).unwrap();

    assert_eq!(
        open_at_head_pinned(&record, &alice, &pinned, &head)
            .unwrap()
            .as_bytes(),
        open_at_head(&record, &alice, author.public_key(), &head)
            .unwrap()
            .as_bytes()
    );

    // A different record against this head is a rollback on both paths.
    let mut newer_context = context();
    newer_context.version += 1;
    let newer = seal(
        &author,
        newer_context,
        b"newer",
        &[alice.recipient()],
        vec![],
        fastest_payload_suite(),
    )
    .unwrap();
    assert_eq!(
        open_at_head_pinned(&newer, &alice, &pinned, &head).unwrap_err(),
        open_at_head(&newer, &alice, author.public_key(), &head).unwrap_err()
    );
}
