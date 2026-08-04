//! Unit tests for HPKE seal and open.

use super::*;
use crate::aead::Suite;
use crate::montgomery::StaticSecret;

#[test]
fn base_mode_round_trip() {
    for suite in [Suite::ChaCha20Poly1305, Suite::Aes256Gcm] {
        if !suite.is_available() {
            continue;
        }
        let recipient = StaticSecret::generate().unwrap();
        let (enc, ciphertext) = seal(
            suite,
            &recipient.public_key(),
            b"info",
            b"aad",
            b"hpke payload",
        )
        .unwrap();
        assert_eq!(enc.len(), ENCAPSULATED_KEY_LEN);

        let opened = open(suite, &recipient, &enc, b"info", b"aad", &ciphertext).unwrap();
        assert_eq!(opened, b"hpke payload");
    }
}

#[test]
fn info_and_aad_are_bound() {
    let recipient = StaticSecret::generate().unwrap();
    let (enc, ciphertext) = seal(
        Suite::ChaCha20Poly1305,
        &recipient.public_key(),
        b"info",
        b"aad",
        b"payload",
    )
    .unwrap();

    assert!(
        open(
            Suite::ChaCha20Poly1305,
            &recipient,
            &enc,
            b"other info",
            b"aad",
            &ciphertext
        )
        .is_err()
    );
    assert!(
        open(
            Suite::ChaCha20Poly1305,
            &recipient,
            &enc,
            b"info",
            b"other aad",
            &ciphertext
        )
        .is_err()
    );
}

#[test]
fn auth_mode_requires_the_right_sender() {
    let sender = StaticSecret::generate().unwrap();
    let impostor = StaticSecret::generate().unwrap();
    let recipient = StaticSecret::generate().unwrap();

    let (enc, ciphertext) = auth_seal(
        Suite::ChaCha20Poly1305,
        &sender,
        &recipient.public_key(),
        b"info",
        b"aad",
        b"authenticated payload",
    )
    .unwrap();

    let opened = auth_open(
        Suite::ChaCha20Poly1305,
        &recipient,
        &sender.public_key(),
        &enc,
        b"info",
        b"aad",
        &ciphertext,
    )
    .unwrap();
    assert_eq!(opened, b"authenticated payload");

    // The wrong claimed sender must not open it.
    assert!(
        auth_open(
            Suite::ChaCha20Poly1305,
            &recipient,
            &impostor.public_key(),
            &enc,
            b"info",
            b"aad",
            &ciphertext,
        )
        .is_err()
    );

    // Nor may base mode open an authenticated payload.
    assert!(
        open(
            Suite::ChaCha20Poly1305,
            &recipient,
            &enc,
            b"info",
            b"aad",
            &ciphertext
        )
        .is_err()
    );
}

#[test]
fn wrong_recipient_cannot_open() {
    let recipient = StaticSecret::generate().unwrap();
    let other = StaticSecret::generate().unwrap();
    let (enc, ciphertext) = seal(
        Suite::ChaCha20Poly1305,
        &recipient.public_key(),
        b"",
        b"",
        b"secret",
    )
    .unwrap();
    assert!(open(Suite::ChaCha20Poly1305, &other, &enc, b"", b"", &ciphertext).is_err());
}

#[test]
fn derive_key_pair_is_deterministic() {
    let a = derive_key_pair(b"seed material");
    let b = derive_key_pair(b"seed material");
    let c = derive_key_pair(b"other seed");
    assert_eq!(a.public_key(), b.public_key());
    assert_ne!(a.public_key(), c.public_key());
}
