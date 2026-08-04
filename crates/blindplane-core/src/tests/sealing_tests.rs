//! Seal/open lifecycle: round trips, tampering, signer pins, grant and rekey.

use blindplane_wire::{FreshnessHead, SealedRecord};

use crate::derive::policy_for;
use crate::{Author, CryptoError, RecipientKeypair, fastest_payload_suite};
use crate::{grant_recipient, open, open_at_head, rekey, seal};

use super::context;

#[test]
fn multi_recipient_round_trip_and_plaintext_absence() {
    let author = Author::generate().unwrap();
    let alice = RecipientKeypair::generate("alice", 1).unwrap();
    let bob = RecipientKeypair::generate("bob", 1).unwrap();
    let plaintext = b"server must never see this diagnosis";

    let record = seal(
        &author,
        context(),
        plaintext,
        &[alice.recipient(), bob.recipient()],
        vec![],
        fastest_payload_suite(),
    )
    .unwrap();

    assert_eq!(
        open(&record, &alice, author.public_key())
            .unwrap()
            .as_bytes(),
        plaintext
    );
    assert_eq!(
        open(&record, &bob, author.public_key()).unwrap().as_bytes(),
        plaintext
    );

    // The plaintext must not survive anywhere in the encoded record.
    let encoded = record.encode();
    assert!(
        !encoded
            .windows(plaintext.len())
            .any(|window| window == plaintext)
    );
}

#[test]
fn encoded_records_round_trip_through_the_wire_format() {
    let author = Author::generate().unwrap();
    let alice = RecipientKeypair::generate("alice", 1).unwrap();
    let record = seal(
        &author,
        context(),
        b"payload",
        &[alice.recipient()],
        vec![],
        fastest_payload_suite(),
    )
    .unwrap();

    let encoded = record.encode();
    let decoded = SealedRecord::decode(&encoded, &policy_for(author.public_key())).unwrap();
    assert_eq!(decoded, record);
    assert_eq!(
        open(&decoded, &alice, author.public_key())
            .unwrap()
            .as_bytes(),
        b"payload"
    );
}

#[test]
fn tamper_and_context_swap_fail_closed() {
    let author = Author::generate().unwrap();
    let alice = RecipientKeypair::generate("alice", 1).unwrap();
    let record = seal(
        &author,
        context(),
        b"secret",
        &[alice.recipient()],
        vec![],
        fastest_payload_suite(),
    )
    .unwrap();

    let mut ciphertext_tamper = record.clone();
    ciphertext_tamper.ciphertext[0] ^= 1;
    assert!(open(&ciphertext_tamper, &alice, author.public_key()).is_err());

    let mut context_tamper = record;
    context_tamper.context.tenant = "other".into();
    assert!(open(&context_tamper, &alice, author.public_key()).is_err());
}

#[test]
fn signer_pin_rejects_substitution() {
    let author = Author::generate().unwrap();
    let attacker = Author::generate().unwrap();
    let alice = RecipientKeypair::generate("alice", 1).unwrap();
    let record = seal(
        &author,
        context(),
        b"secret",
        &[alice.recipient()],
        vec![],
        fastest_payload_suite(),
    )
    .unwrap();
    assert!(open(&record, &alice, attacker.public_key()).is_err());
}

#[test]
fn recipient_key_fingerprint_substitution_fails_preflight() {
    let author = Author::generate().unwrap();
    let mut recipient = RecipientKeypair::generate("alice", 1).unwrap().recipient();
    recipient.public_key[0] ^= 1;
    assert_eq!(
        seal(
            &author,
            context(),
            b"secret",
            &[recipient],
            vec![],
            fastest_payload_suite()
        ),
        Err(CryptoError::InvalidKeyIdentity)
    );
}

#[test]
fn grant_then_rekey_rotates_access() {
    let author = Author::generate().unwrap();
    let alice = RecipientKeypair::generate("alice", 1).unwrap();
    let bob = RecipientKeypair::generate("bob", 1).unwrap();
    let original = seal(
        &author,
        context(),
        b"secret",
        &[alice.recipient()],
        vec![],
        fastest_payload_suite(),
    )
    .unwrap();

    let shared = grant_recipient(&original, &alice, &author, &bob.recipient()).unwrap();
    assert_eq!(
        open(&shared, &bob, author.public_key()).unwrap().as_bytes(),
        b"secret"
    );

    let mut next = context();
    next.epoch = 2;
    next.version = 2;
    let revoked = rekey(&shared, &alice, &author, next, &[alice.recipient()], vec![]).unwrap();
    assert!(open(&revoked, &bob, author.public_key()).is_err());
    assert_eq!(
        open(&revoked, &alice, author.public_key())
            .unwrap()
            .as_bytes(),
        b"secret"
    );
}

#[test]
fn persisted_freshness_head_rejects_valid_rollback() {
    let author = Author::generate().unwrap();
    let alice = RecipientKeypair::generate("alice", 1).unwrap();
    let bob = RecipientKeypair::generate("bob", 1).unwrap();
    let original = seal(
        &author,
        context(),
        b"secret",
        &[alice.recipient()],
        vec![],
        fastest_payload_suite(),
    )
    .unwrap();

    let policy = policy_for(author.public_key());
    let mut head = FreshnessHead::start(&original, &policy).unwrap();
    let shared = grant_recipient(&original, &alice, &author, &bob.recipient()).unwrap();
    head.advance(&shared, &policy).unwrap();

    assert!(open_at_head(&original, &alice, author.public_key(), &head).is_err());
    assert_eq!(
        open_at_head(&shared, &alice, author.public_key(), &head)
            .unwrap()
            .as_bytes(),
        b"secret"
    );
}
