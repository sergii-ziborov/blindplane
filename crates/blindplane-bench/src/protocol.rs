use std::fmt::Write as _;
use std::hint::black_box;

use blindplane_crypto::aead::Suite;
use blindplane_crypto::argon2::{Argon2Params, argon2id};
use blindplane_crypto::hpke as bp_hpke;
use blindplane_crypto::montgomery::StaticSecret;

use crate::measure;

pub(crate) fn bench_hpke(report: &mut String) {
    println!("== HPKE seal, ChaCha20-Poly1305 (ops/s) ==");
    let _ = writeln!(report, "## HPKE (RFC 9180) single-shot seal\n");
    let _ = writeln!(report, "| Implementation | ops/s |");
    let _ = writeln!(report, "|---|---:|");

    let recipient = StaticSecret::from_bytes([0x31_u8; 32]);
    let recipient_public = recipient.public_key();
    let payload = [0x7e_u8; 32];

    let ours = measure(|| {
        let result = bp_hpke::seal(
            Suite::ChaCha20Poly1305,
            &recipient_public,
            b"info",
            b"aad",
            &payload,
        );
        black_box(result.is_ok());
    });

    let theirs = {
        use ::hpke::{
            Deserializable, Kem as KemTrait, OpModeS, aead::ChaCha20Poly1305, kdf::HkdfSha256,
            kem::X25519HkdfSha256, setup_sender,
        };
        type Kem = X25519HkdfSha256;
        let public = <Kem as KemTrait>::PublicKey::from_bytes(&recipient_public).unwrap();
        measure(|| {
            let (encapsulated, mut sender) =
                setup_sender::<ChaCha20Poly1305, HkdfSha256, Kem>(&OpModeS::Base, &public, b"info")
                    .unwrap();
            let ciphertext = sender.seal(&payload, b"aad").unwrap();
            black_box((encapsulated, ciphertext));
        })
    };

    for (name, value) in [("**Blindplane HPKE**", ours), ("hpke crate", theirs)] {
        println!("  {name:34}{value:12.0}");
        let _ = writeln!(report, "| {name} | {value:.0} |");
    }
    println!();
    let _ = writeln!(report);
}

pub(crate) fn bench_password_hashing(report: &mut String) {
    println!("== Argon2id, 64 MiB x 3 passes (ops/s, lower bound is the point) ==");
    let _ = writeln!(report, "## Argon2id, m=64 MiB, t=3, p=1\n");
    let _ = writeln!(
        report,
        "Password hashing is meant to be slow. Parity with the reference implementation is the goal, not speed.\n"
    );
    let _ = writeln!(report, "| Implementation | ops/s | ms per hash |");
    let _ = writeln!(report, "|---|---:|---:|");

    let params = Argon2Params {
        memory_kib: 65_536,
        passes: 3,
        output_len: 32,
    };
    let ours = measure(|| {
        black_box(argon2id(b"correct horse battery staple", b"blindplane-salt!", params).unwrap());
    });

    let theirs = {
        use argon2::{Algorithm, Argon2, Params, Version};
        let reference = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(65_536, 3, 1, Some(32)).unwrap(),
        );
        measure(|| {
            let mut out = [0_u8; 32];
            reference
                .hash_password_into(
                    b"correct horse battery staple",
                    b"blindplane-salt!",
                    &mut out,
                )
                .unwrap();
            black_box(out);
        })
    };

    for (name, value) in [("**Blindplane Argon2id**", ours), ("argon2 crate", theirs)] {
        println!("  {name:34}{value:12.1}{:12.1}", 1000.0 / value);
        let _ = writeln!(report, "| {name} | {value:.1} | {:.1} |", 1000.0 / value);
    }
    println!();
    let _ = writeln!(report);
}
