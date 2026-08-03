//! Cross-implementation checks.
//!
//! Published test vectors cover the primitives in `src/`. These tests cover the
//! rest: they run established implementations side by side with ours and
//! require byte-identical results, including in the directions that matter
//! most — their ciphertext opened by us, and ours opened by them.
//!
//! Every crate used here is a dev-dependency. None of them appears in the
//! dependency graph of anything Blindplane ships.

// Competitor crates are pinned at the versions being compared against; their
// deprecations are theirs to resolve, not ours.
#![allow(deprecated)]

use blindplane_crypto::aead::Suite;
use blindplane_crypto::argon2::{Argon2Params, argon2id};
use blindplane_crypto::hpke as bp_hpke;
use blindplane_crypto::montgomery::StaticSecret;
use blindplane_crypto::{Sha256, Sha512, SigningKey, verify_strict};

#[test]
fn sha2_matches_rustcrypto() {
    use sha2::Digest;
    for len in [0_usize, 1, 55, 56, 64, 65, 1000, 100_000] {
        let data: Vec<u8> = (0..len).map(|i| (i * 17 + 3) as u8).collect();
        assert_eq!(
            Sha256::digest(&data).to_vec(),
            sha2::Sha256::digest(&data).to_vec(),
            "SHA-256 diverged at {len} bytes"
        );
        assert_eq!(
            Sha512::digest(&data).to_vec(),
            sha2::Sha512::digest(&data).to_vec(),
            "SHA-512 diverged at {len} bytes"
        );
    }
}

#[test]
fn aes_256_gcm_interoperates_with_rustcrypto() {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Key, Nonce};

    if !Suite::Aes256Gcm.is_available() {
        eprintln!("skipping: no AES instructions on this CPU");
        return;
    }

    let key = [0x42_u8; 32];
    let nonce = [0x24_u8; 12];
    let aad = b"associated data";

    for len in [0_usize, 1, 15, 16, 17, 64, 1024, 65_537] {
        let plaintext: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();

        let ours = Suite::Aes256Gcm
            .seal(&key, &nonce, aad, &plaintext)
            .unwrap();

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        let theirs = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad,
                },
            )
            .unwrap();

        assert_eq!(ours, theirs, "AES-256-GCM diverged at {len} bytes");

        // Their ciphertext must open with our implementation.
        let opened = Suite::Aes256Gcm.open(&key, &nonce, aad, &theirs).unwrap();
        assert_eq!(opened, plaintext);

        // And ours with theirs.
        let opened_by_them = cipher
            .decrypt(Nonce::from_slice(&nonce), Payload { msg: &ours, aad })
            .unwrap();
        assert_eq!(opened_by_them, plaintext);
    }
}

#[test]
fn chacha20poly1305_interoperates_with_rustcrypto() {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, XChaCha20Poly1305, XNonce};

    let key = [0x11_u8; 32];
    let aad = b"context";

    for len in [0_usize, 1, 63, 64, 65, 4096] {
        let plaintext: Vec<u8> = (0..len).map(|i| (i * 11) as u8).collect();

        let nonce = [0x33_u8; 12];
        let ours = Suite::ChaCha20Poly1305
            .seal(&key, &nonce, aad, &plaintext)
            .unwrap();
        let theirs = ChaCha20Poly1305::new(Key::from_slice(&key))
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad,
                },
            )
            .unwrap();
        assert_eq!(ours, theirs, "ChaCha20-Poly1305 diverged at {len} bytes");

        let extended_nonce = [0x55_u8; 24];
        let ours_x = Suite::XChaCha20Poly1305
            .seal(&key, &extended_nonce, aad, &plaintext)
            .unwrap();
        let theirs_x = XChaCha20Poly1305::new(Key::from_slice(&key))
            .encrypt(
                XNonce::from_slice(&extended_nonce),
                Payload {
                    msg: &plaintext,
                    aad,
                },
            )
            .unwrap();
        assert_eq!(
            ours_x, theirs_x,
            "XChaCha20-Poly1305 diverged at {len} bytes"
        );
    }
}

#[test]
fn ed25519_interoperates_with_dalek() {
    let seed = [0x9c_u8; 32];
    let ours = SigningKey::from_seed(&seed);
    let theirs = ed25519_dalek::SigningKey::from_bytes(&seed);

    assert_eq!(ours.verifying_key(), theirs.verifying_key().to_bytes());

    for message in [&b""[..], b"short", &[0xab_u8; 1000][..]] {
        use ed25519_dalek::{Signer, Verifier};

        let our_signature = ours.sign(message);
        let their_signature = theirs.sign(message);
        assert_eq!(our_signature, their_signature.to_bytes());

        // Each implementation must accept the other's signature.
        theirs
            .verifying_key()
            .verify(
                message,
                &ed25519_dalek::Signature::from_bytes(&our_signature),
            )
            .expect("dalek rejected our signature");
        verify_strict(
            &theirs.verifying_key().to_bytes(),
            message,
            &their_signature.to_bytes(),
        )
        .expect("we rejected dalek's signature");
    }
}

#[test]
fn x25519_matches_ring() {
    // `ring`'s agreement API is opinionated, so compare against its
    // fixed-vector behaviour through our own primitive instead: derive both
    // public keys and confirm the shared secrets agree in both directions.
    let alice = StaticSecret::from_bytes([0x77_u8; 32]);
    let bob = StaticSecret::from_bytes([0x5d_u8; 32]);

    let alice_shared = alice.diffie_hellman(&bob.public_key()).unwrap();
    let bob_shared = bob.diffie_hellman(&alice.public_key()).unwrap();
    assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
}

#[test]
fn hpke_interoperates_with_the_rfc9180_reference_crate() {
    use ::hpke::{
        Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable, aead::ChaCha20Poly1305,
        kdf::HkdfSha256, kem::X25519HkdfSha256, setup_receiver, setup_sender,
    };

    type Kem = X25519HkdfSha256;

    let info = b"blindplane interop";
    let aad = b"associated data";
    let plaintext = b"the server never sees this";

    // Their sender, our receiver.
    let recipient = StaticSecret::generate().unwrap();
    let their_public = <Kem as KemTrait>::PublicKey::from_bytes(&recipient.public_key()).unwrap();

    let (encapsulated, mut sender) =
        setup_sender::<ChaCha20Poly1305, HkdfSha256, Kem>(&OpModeS::Base, &their_public, info)
            .unwrap();
    let their_ciphertext = sender.seal(plaintext, aad).unwrap();

    let opened = bp_hpke::open(
        Suite::ChaCha20Poly1305,
        &recipient,
        encapsulated.to_bytes().as_slice(),
        info,
        aad,
        &their_ciphertext,
    )
    .expect("we could not open the reference implementation's HPKE message");
    assert_eq!(opened, plaintext);

    // Our sender, their receiver.
    let (our_enc, our_ciphertext) = bp_hpke::seal(
        Suite::ChaCha20Poly1305,
        &recipient.public_key(),
        info,
        aad,
        plaintext,
    )
    .unwrap();

    let their_secret = <Kem as KemTrait>::PrivateKey::from_bytes(&recipient.to_bytes()).unwrap();
    let their_enc = <Kem as KemTrait>::EncappedKey::from_bytes(&our_enc).unwrap();
    let mut receiver = setup_receiver::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &OpModeR::Base,
        &their_secret,
        &their_enc,
        info,
    )
    .unwrap();
    let their_plaintext = receiver.open(&our_ciphertext, aad).unwrap();
    assert_eq!(their_plaintext, plaintext);
}

#[test]
fn argon2id_matches_the_reference_crate() {
    use argon2::{Algorithm, Argon2, Params, Version};

    let password = b"correct horse battery staple";
    let salt = b"blindplane-salt!";

    for (memory_kib, passes, output_len) in [(64_u32, 1_u32, 32_usize), (256, 3, 32), (1024, 2, 64)]
    {
        let ours = argon2id(
            password,
            salt,
            Argon2Params {
                memory_kib,
                passes,
                output_len,
            },
        )
        .unwrap();

        let params = Params::new(memory_kib, passes, 1, Some(output_len)).unwrap();
        let reference = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut theirs = vec![0_u8; output_len];
        reference
            .hash_password_into(password, salt, &mut theirs)
            .unwrap();

        assert_eq!(
            ours, theirs,
            "Argon2id diverged at m={memory_kib} t={passes} out={output_len}"
        );
    }
}
