//! Unit tests for the Ed25519 group and signature operations.

use super::point::BASEPOINT;
use super::*;
use crate::scalar::Scalar;

#[test]
fn basepoint_has_prime_order() {
    // [L]B must be the identity; L is reduced to zero, so use L-1 and add B.
    let mut l_minus_one = [0_u8; 32];
    l_minus_one[..8].copy_from_slice(&0x5812631a5cf5d3ec_u64.to_le_bytes());
    l_minus_one[8..16].copy_from_slice(&0x14def9dea2f79cd6_u64.to_le_bytes());
    l_minus_one[24..32].copy_from_slice(&0x1000000000000000_u64.to_le_bytes());
    let scalar = Scalar::from_canonical_bytes(&l_minus_one).unwrap();
    let point = EdwardsPoint::mul_base(&scalar).add(&BASEPOINT);
    assert!(point.is_identity().is_set(), "[L]B must be the identity");
}

#[test]
fn compress_decompress_round_trip() {
    let mut seed = [0_u8; 32];
    seed[0] = 3;
    let scalar = Scalar::from_bytes_mod_order(&seed);
    let point = EdwardsPoint::mul_base(&scalar);
    let bytes = point.compress();
    let restored = EdwardsPoint::decompress(&bytes).unwrap();
    assert_eq!(restored.compress(), bytes);
}

#[test]
fn fixed_base_agrees_with_variable_base() {
    let mut bytes = [0_u8; 32];
    bytes[0] = 0x9d;
    bytes[5] = 0x11;
    bytes[31] = 0x0f;
    let scalar = Scalar::from_bytes_mod_order(&bytes);
    assert_eq!(
        EdwardsPoint::mul_base(&scalar).compress(),
        BASEPOINT.mul(&scalar).compress()
    );
}

#[test]
fn rfc8032_test_vector_1() {
    // RFC 8032, section 7.1, the empty message.
    let seed = hex32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let key = SigningKey::from_seed(&seed);
    assert_eq!(
        key.verifying_key(),
        hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    );
    let signature = key.sign(b"");
    let expected = hex64(concat!(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    ));
    assert_eq!(signature, expected);
    assert!(verify_strict(&key.verifying_key(), b"", &signature).is_ok());
}

#[test]
fn rfc8032_test_vector_2() {
    let seed = hex32("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    let key = SigningKey::from_seed(&seed);
    assert_eq!(
        key.verifying_key(),
        hex32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
    );
    let signature = key.sign(&[0x72]);
    let expected = hex64(concat!(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da",
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    ));
    assert_eq!(signature, expected);
    assert!(verify_strict(&key.verifying_key(), &[0x72], &signature).is_ok());
}

#[test]
fn rfc8032_test_vector_3() {
    let seed = hex32("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
    let key = SigningKey::from_seed(&seed);
    let message = [0xaf, 0x82];
    let signature = key.sign(&message);
    let expected = hex64(concat!(
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac",
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
    ));
    assert_eq!(signature, expected);
    assert!(verify_strict(&key.verifying_key(), &message, &signature).is_ok());
}

#[test]
fn tampered_message_is_rejected() {
    let key = SigningKey::from_seed(&[7_u8; 32]);
    let signature = key.sign(b"authentic");
    assert_eq!(
        verify_strict(&key.verifying_key(), b"forged", &signature),
        Err(SignatureError::VerificationFailed)
    );
}

#[test]
fn non_canonical_s_is_rejected() {
    let key = SigningKey::from_seed(&[9_u8; 32]);
    let mut signature = key.sign(b"message");
    // Set S to L, which is not canonically reduced.
    signature[32..].copy_from_slice(&[
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ]);
    assert_eq!(
        verify_strict(&key.verifying_key(), b"message", &signature),
        Err(SignatureError::NonCanonicalSignatureS)
    );
}

#[test]
fn prepared_verifier_agrees_with_the_free_function_case_for_case() {
    let key = SigningKey::from_seed(&[21_u8; 32]);
    let public = key.verifying_key();
    let prepared = PreparedVerifier::new(&public).unwrap();

    for length in [0_usize, 1, 32, 100, 1000] {
        let message: Vec<u8> = (0..length).map(|i| (i * 13) as u8).collect();
        let good = key.sign(&message);

        // The valid signature, then every single-field corruption, then a
        // non-canonically encoded S; the two paths must agree exactly.
        let mut r_corrupted = good;
        r_corrupted[0] ^= 0x01;
        let mut s_corrupted = good;
        s_corrupted[40] ^= 0x01;
        let mut wrong_message = message.clone();
        wrong_message.push(0x77);
        let mut non_canonical_s = good;
        non_canonical_s[32..].copy_from_slice(&[
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ]);

        for (case, message, signature) in [
            ("valid", &message, &good),
            ("corrupted R", &message, &r_corrupted),
            ("corrupted S", &message, &s_corrupted),
            ("wrong message", &wrong_message, &good),
            ("non-canonical S", &message, &non_canonical_s),
        ] {
            assert_eq!(
                prepared.verify_strict(message, signature),
                verify_strict(&public, message, signature),
                "length {length}, case {case}"
            );
        }
    }
}

#[test]
fn prepared_verifier_rejects_bad_keys_at_construction() {
    // The identity point encodes as y = 1 and has small order.
    let mut identity = [0_u8; 32];
    identity[0] = 1;
    assert_eq!(
        PreparedVerifier::new(&identity).unwrap_err(),
        SignatureError::SmallOrderPublicKey
    );

    // A y coordinate past the field modulus is not a canonical encoding.
    let invalid = [0xff_u8; 32];
    assert_eq!(
        PreparedVerifier::new(&invalid).unwrap_err(),
        SignatureError::InvalidPublicKey
    );
}

#[test]
fn prepared_verifier_passes_the_rfc_vector() {
    // RFC 8032, section 7.1, test 3, through the prepared path.
    let seed = hex32("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
    let key = SigningKey::from_seed(&seed);
    let prepared = PreparedVerifier::new(&key.verifying_key()).unwrap();
    let message = [0xaf, 0x82];
    let signature = hex64(concat!(
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac",
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
    ));
    assert!(prepared.verify_strict(&message, &signature).is_ok());
    // One preparation, many verifications: the intended shape.
    for extra in 0..8_u8 {
        let other = key.sign(&[extra]);
        assert!(prepared.verify_strict(&[extra], &other).is_ok());
    }
}

#[test]
fn small_order_public_key_is_rejected() {
    // The order-4 point with y = 0.
    let mut public = [0_u8; 32];
    public[0] = 0;
    let key = SigningKey::from_seed(&[1_u8; 32]);
    let signature = key.sign(b"m");
    let result = verify_strict(&public, b"m", &signature);
    assert!(matches!(
        result,
        Err(SignatureError::SmallOrderPublicKey | SignatureError::InvalidPublicKey)
    ));
}

fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0_u8; 32];
    decode_hex(s, &mut out);
    out
}

fn hex64(s: &str) -> [u8; 64] {
    let mut out = [0_u8; 64];
    decode_hex(s, &mut out);
    out
}

fn decode_hex(s: &str, out: &mut [u8]) {
    let bytes = s.as_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = (bytes[2 * i] as char).to_digit(16).unwrap() as u8;
        let lo = (bytes[2 * i + 1] as char).to_digit(16).unwrap() as u8;
        *slot = (hi << 4) | lo;
    }
}
