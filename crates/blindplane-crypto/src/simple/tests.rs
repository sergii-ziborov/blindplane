//! Unit tests for the simple key and password API.

use super::*;

#[test]
fn round_trip_at_many_sizes() {
    let key = Key::generate().unwrap();
    for len in [0_usize, 1, 15, 16, 17, 1024, 100_000] {
        let message: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
        let sealed = key.encrypt(&message, b"ctx").unwrap();
        assert_eq!(key.decrypt(&sealed, b"ctx").unwrap(), message);
    }
}

#[test]
fn the_same_message_encrypts_differently_every_time() {
    // A fresh nonce per message, so identical plaintexts must not produce
    // identical ciphertexts; otherwise an observer learns which records match.
    let key = Key::generate().unwrap();
    let first = key.encrypt(b"same", b"ctx").unwrap();
    let second = key.encrypt(b"same", b"ctx").unwrap();
    assert_ne!(first, second);
    assert_eq!(key.decrypt(&first, b"ctx").unwrap(), b"same");
    assert_eq!(key.decrypt(&second, b"ctx").unwrap(), b"same");
}

#[test]
fn wrong_key_context_or_bit_all_fail() {
    let key = Key::generate().unwrap();
    let other = Key::generate().unwrap();
    let sealed = key.encrypt(b"secret", b"record:1").unwrap();

    assert_eq!(
        other.decrypt(&sealed, b"record:1"),
        Err(CryptoError::Unauthenticated)
    );
    assert_eq!(
        key.decrypt(&sealed, b"record:2"),
        Err(CryptoError::Unauthenticated)
    );

    for index in 0..sealed.len() {
        let mut tampered = sealed.clone();
        tampered[index] ^= 1;
        assert!(
            key.decrypt(&tampered, b"record:1").is_err(),
            "a flipped bit at {index} was accepted"
        );
    }
}

#[test]
fn truncated_input_is_rejected_without_panicking() {
    let key = Key::generate().unwrap();
    let sealed = key.encrypt(b"secret", b"ctx").unwrap();
    for len in 0..sealed.len() {
        assert!(key.decrypt(&sealed[..len], b"ctx").is_err());
    }
}

#[test]
fn password_hash_verifies_and_rejects() {
    let stored = hash_password("correct horse battery staple").unwrap();
    assert!(verify_password("correct horse battery staple", &stored));
    assert!(!verify_password("Correct horse battery staple", &stored));
    assert!(!verify_password("", &stored));
}

#[test]
fn password_hashes_are_salted() {
    // Two users with the same password must not share a stored value, or
    // one cracked hash breaks every account that reused that password.
    let first = hash_password("same password").unwrap();
    let second = hash_password("same password").unwrap();
    assert_ne!(first, second);
    assert!(verify_password("same password", &first));
    assert!(verify_password("same password", &second));
}

#[test]
fn malformed_stored_hashes_are_rejected_quietly() {
    for stored in [
        "",
        "not-a-hash",
        "argon2id$v=19$m=64,t=1,p=1$",
        "argon2id$v=19$m=64,t=1,p=2$aabbccdd$eeff",
        "bcrypt$v=19$m=64,t=1,p=1$aabbccddaabbccdd$eeff",
        "argon2id$v=19$m=64,t=1,p=1$zz$eeff",
    ] {
        assert!(!verify_password("anything", stored), "accepted {stored:?}");
    }
}

#[test]
fn a_password_derived_key_round_trips() {
    let salt = [7_u8; SALT_LEN];
    let key = Key::from_password("vault password", &salt).unwrap();
    let sealed = key.encrypt(b"vault contents", b"vault").unwrap();

    let reopened = Key::from_password("vault password", &salt).unwrap();
    assert_eq!(
        reopened.decrypt(&sealed, b"vault").unwrap(),
        b"vault contents"
    );

    let wrong = Key::from_password("wrong password", &salt).unwrap();
    assert!(wrong.decrypt(&sealed, b"vault").is_err());
}
