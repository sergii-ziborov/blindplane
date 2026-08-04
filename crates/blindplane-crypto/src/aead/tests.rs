//! Unit tests for the AEAD suites.

use super::*;
use crate::testutil::unhex as hex;

#[test]
fn rfc8439_aead_vector() {
    // RFC 8439, section 2.8.2.
    let key: [u8; 32] = core::array::from_fn(|i| (0x80 + i) as u8);
    let nonce = hex("070000004041424344454647");
    let aad = hex("50515253c0c1c2c3c4c5c6c7");
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you \
only one tip for the future, sunscreen would be it.";

    let sealed = Suite::ChaCha20Poly1305
        .seal(&key, &nonce, &aad, plaintext)
        .unwrap();

    let expected_ciphertext = hex(concat!(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6",
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36",
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc",
        "3ff4def08e4b7a9de576d26586cec64b6116"
    ));
    assert_eq!(&sealed[..sealed.len() - 16], &expected_ciphertext[..]);
    assert_eq!(
        &sealed[sealed.len() - 16..],
        &hex("1ae10b594f09e26a7e902ecbd0600691")[..]
    );

    let opened = Suite::ChaCha20Poly1305
        .open(&key, &nonce, &aad, &sealed)
        .unwrap();
    assert_eq!(opened, plaintext);
}

#[test]
fn xchacha20poly1305_round_trip() {
    let key = [3_u8; 32];
    let nonce = [7_u8; 24];
    let sealed = Suite::XChaCha20Poly1305
        .seal(&key, &nonce, b"context", b"secret message")
        .unwrap();
    let opened = Suite::XChaCha20Poly1305
        .open(&key, &nonce, b"context", &sealed)
        .unwrap();
    assert_eq!(opened, b"secret message");
}

#[test]
fn every_available_suite_round_trips_at_many_lengths() {
    for suite in Suite::ALL {
        if !suite.is_available() {
            continue;
        }
        let key = [11_u8; 32];
        let nonce = vec![2_u8; suite.nonce_len()];
        for len in [0_usize, 1, 15, 16, 17, 63, 64, 65, 1024, 4096, 10_000] {
            let plaintext: Vec<u8> = (0..len).map(|i| (i * 37) as u8).collect();
            let sealed = suite.seal(&key, &nonce, b"aad", &plaintext).unwrap();
            assert_eq!(sealed.len(), len + TAG_LEN);
            let opened = suite.open(&key, &nonce, b"aad", &sealed).unwrap();
            assert_eq!(opened, plaintext, "suite {suite:?} length {len}");
        }
    }
}

#[test]
fn tampering_is_rejected_by_every_suite() {
    for suite in Suite::ALL {
        if !suite.is_available() {
            continue;
        }
        let key = [13_u8; 32];
        let nonce = vec![5_u8; suite.nonce_len()];
        let sealed = suite.seal(&key, &nonce, b"aad", b"payload").unwrap();

        for index in 0..sealed.len() {
            let mut tampered = sealed.clone();
            tampered[index] ^= 0x01;
            assert_eq!(
                suite.open(&key, &nonce, b"aad", &tampered),
                Err(AeadError::Unauthenticated),
                "suite {suite:?} accepted a flipped bit at {index}"
            );
        }

        assert_eq!(
            suite.open(&key, &nonce, b"different", &sealed),
            Err(AeadError::Unauthenticated)
        );
    }
}
