//! Unit tests for AES-256-GCM.

use super::*;
use crate::testutil::unhex as hex;

#[test]
fn nist_gcm_test_case_13() {
    // NIST GCM test vectors, AES-256, empty plaintext and AAD.
    if !available() {
        return;
    }
    let key = [0_u8; 32];
    let nonce = [0_u8; 12];
    let mut buffer: Vec<u8> = Vec::new();
    let tag = seal_in_place(&key, &nonce, &[], &mut buffer).unwrap();
    assert_eq!(tag.to_vec(), hex("530f8afbc74536b9a963b4f1c4cb738b"));
}

#[test]
fn nist_gcm_test_case_14() {
    // AES-256, 16 zero bytes of plaintext, no AAD.
    if !available() {
        return;
    }
    let key = [0_u8; 32];
    let nonce = [0_u8; 12];
    let mut buffer = vec![0_u8; 16];
    let tag = seal_in_place(&key, &nonce, &[], &mut buffer).unwrap();
    assert_eq!(buffer, hex("cea7403d4d606b6e074ec5d3baf39d18"));
    assert_eq!(tag.to_vec(), hex("d0d1c8a799996bf0265b98b5d48ab919"));
}

#[test]
fn nist_gcm_test_case_16() {
    // AES-256 with associated data and a truncated final block.
    if !available() {
        return;
    }
    let key = hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
    let nonce = hex("cafebabefacedbaddecaf888");
    let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    let plaintext = hex(concat!(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72",
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
    ));

    let mut key_array = [0_u8; 32];
    key_array.copy_from_slice(&key);
    let mut nonce_array = [0_u8; 12];
    nonce_array.copy_from_slice(&nonce);

    let mut buffer = plaintext.clone();
    let tag = seal_in_place(&key_array, &nonce_array, &aad, &mut buffer).unwrap();
    assert_eq!(
        buffer,
        hex(concat!(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa",
            "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
        ))
    );
    assert_eq!(tag.to_vec(), hex("76fc6ece0f4e1768cddf8853bb2d551b"));

    let opened = open_in_place(&key_array, &nonce_array, &aad, &mut buffer, &tag).unwrap();
    assert!(opened);
    assert_eq!(buffer, plaintext);
}

#[test]
fn tampering_is_detected() {
    if !available() {
        return;
    }
    let key = [4_u8; 32];
    let nonce = [5_u8; 12];
    let mut buffer = b"authenticated payload".to_vec();
    let tag = seal_in_place(&key, &nonce, b"context", &mut buffer).unwrap();

    let mut tampered = buffer.clone();
    tampered[0] ^= 1;
    assert_eq!(
        open_in_place(&key, &nonce, b"context", &mut tampered, &tag),
        Some(false)
    );

    let mut wrong_aad = buffer.clone();
    assert_eq!(
        open_in_place(&key, &nonce, b"other", &mut wrong_aad, &tag),
        Some(false)
    );
}
