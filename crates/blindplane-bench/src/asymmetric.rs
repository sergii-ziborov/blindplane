use std::fmt::Write as _;
use std::hint::black_box;

use blindplane_crypto::montgomery::StaticSecret;
use blindplane_crypto::{PreparedVerifier, SigningKey, verify_strict};

use crate::measure;

pub(crate) fn bench_asymmetric(report: &mut String) {
    println!("== Public key operations (ops/s, higher is better) ==");
    let _ = writeln!(report, "## Public-key operations\n");
    let _ = writeln!(report, "Operations per second on one core.\n");
    let _ = writeln!(report, "| Operation | Blindplane | Competitor | Ratio |");
    let _ = writeln!(report, "|---|---:|---:|---:|");

    // X25519.
    let ours_secret = StaticSecret::from_bytes([0x77_u8; 32]);
    let peer = StaticSecret::from_bytes([0x5d_u8; 32]).public_key();
    let our_x25519 = measure(|| {
        black_box(ours_secret.diffie_hellman(&peer));
    });
    let peer_secret = [0x5d_u8; 32];
    let dalek_x25519 = measure(|| {
        // One scalar multiplication, the same work our own call performs.
        black_box(x25519_dalek::x25519(peer_secret, ours_secret.public_key()));
    });

    // Ed25519 signing.
    let our_key = SigningKey::from_seed(&[0x9c_u8; 32]);
    let message = [0xab_u8; 256];
    let our_sign = measure(|| {
        black_box(our_key.sign(&message));
    });
    let dalek_key = ed25519_dalek::SigningKey::from_bytes(&[0x9c_u8; 32]);
    let dalek_sign = {
        use ed25519_dalek::Signer;
        measure(|| {
            black_box(dalek_key.sign(&message));
        })
    };

    // Ed25519 verification.
    let signature = our_key.sign(&message);
    let public_key = our_key.verifying_key();
    let our_verify = measure(|| {
        black_box(verify_strict(&public_key, &message, &signature).is_ok());
    });
    let dalek_verify = {
        use ed25519_dalek::Verifier;
        let verifying = dalek_key.verifying_key();
        let dalek_signature = ed25519_dalek::Signature::from_bytes(&signature);
        measure(|| {
            black_box(verifying.verify(&message, &dalek_signature).is_ok());
        })
    };

    // One author verified many times, the product's actual shape. This is
    // also the closer comparison: dalek's VerifyingKey above is itself a
    // pre-parsed point, while our plain row re-parses the key every call.
    let prepared = PreparedVerifier::new(&public_key).expect("valid key");
    let our_prepared = measure(|| {
        black_box(prepared.verify_strict(&message, &signature).is_ok());
    });

    for (name, ours, theirs, competitor) in [
        (
            "X25519 Diffie-Hellman",
            our_x25519,
            dalek_x25519,
            "x25519-dalek",
        ),
        ("Ed25519 sign", our_sign, dalek_sign, "ed25519-dalek"),
        (
            "Ed25519 verify (strict)",
            our_verify,
            dalek_verify,
            "ed25519-dalek",
        ),
        (
            "Ed25519 verify (prepared author)",
            our_prepared,
            dalek_verify,
            "ed25519-dalek",
        ),
    ] {
        println!("  {name:28}{ours:12.0}{theirs:12.0}   ({competitor})");
        let _ = writeln!(
            report,
            "| {name} | {ours:.0} | {theirs:.0} ({competitor}) | {:.2}x |",
            ours / theirs
        );
    }
    println!();
    let _ = writeln!(report);
}
