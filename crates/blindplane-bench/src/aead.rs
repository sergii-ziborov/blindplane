use std::fmt::Write as _;
use std::hint::black_box;

use blindplane_crypto::aead::Suite;

use crate::{measure, throughput};

pub(crate) fn bench_aead(report: &mut String) {
    println!("== AEAD encryption (GB/s, higher is better) ==");
    let _ = writeln!(report, "## AEAD encryption\n");
    let _ = writeln!(
        report,
        "Throughput in GB/s over plaintext bytes, with 16 bytes of associated data.\n"
    );
    let _ = writeln!(report, "| Implementation | 1 KiB | 64 KiB | 1 MiB |");
    let _ = writeln!(report, "|---|---:|---:|---:|");

    let sizes = [1024_usize, 65_536, 1_048_576];
    let key = [0x42_u8; 32];
    let aad = [0x11_u8; 16];

    let mut rows: Vec<(String, Vec<f64>)> = Vec::new();

    // Ours, AES-256-GCM.
    if Suite::Aes256Gcm.is_available() {
        rows.push((
            "**Blindplane AES-256-GCM**".to_owned(),
            sizes
                .iter()
                .map(|size| {
                    let nonce = [0x24_u8; 12];
                    let mut buffer = vec![0_u8; *size];
                    throughput(
                        *size,
                        measure(|| {
                            let tag = Suite::Aes256Gcm
                                .seal_in_place(&key, &nonce, &aad, &mut buffer)
                                .expect("seal");
                            black_box(tag);
                        }),
                    )
                })
                .collect(),
        ));
    }

    // Ours, ChaCha20-Poly1305.
    rows.push((
        "**Blindplane ChaCha20-Poly1305**".to_owned(),
        sizes
            .iter()
            .map(|size| {
                let nonce = [0x24_u8; 12];
                let mut buffer = vec![0_u8; *size];
                throughput(
                    *size,
                    measure(|| {
                        let tag = Suite::ChaCha20Poly1305
                            .seal_in_place(&key, &nonce, &aad, &mut buffer)
                            .expect("seal");
                        black_box(tag);
                    }),
                )
            })
            .collect(),
    ));

    // Ours, XChaCha20-Poly1305.
    rows.push((
        "**Blindplane XChaCha20-Poly1305**".to_owned(),
        sizes
            .iter()
            .map(|size| {
                let nonce = [0x24_u8; 24];
                let mut buffer = vec![0_u8; *size];
                throughput(
                    *size,
                    measure(|| {
                        let tag = Suite::XChaCha20Poly1305
                            .seal_in_place(&key, &nonce, &aad, &mut buffer)
                            .expect("seal");
                        black_box(tag);
                    }),
                )
            })
            .collect(),
    ));

    // ring.
    rows.push((
        "ring AES-256-GCM".to_owned(),
        sizes
            .iter()
            .map(|size| {
                use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
                let sealing = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key).unwrap());
                let mut buffer = Vec::with_capacity(*size + 16);
                throughput(
                    *size,
                    measure(|| {
                        buffer.clear();
                        buffer.resize(*size, 0);
                        sealing
                            .seal_in_place_append_tag(
                                Nonce::assume_unique_for_key([0x24; 12]),
                                Aad::from(&aad),
                                &mut buffer,
                            )
                            .expect("seal");
                        black_box(&buffer);
                    }),
                )
            })
            .collect(),
    ));

    rows.push((
        "ring ChaCha20-Poly1305".to_owned(),
        sizes
            .iter()
            .map(|size| {
                use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
                let sealing = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &key).unwrap());
                let mut buffer = Vec::with_capacity(*size + 16);
                throughput(
                    *size,
                    measure(|| {
                        buffer.clear();
                        buffer.resize(*size, 0);
                        sealing
                            .seal_in_place_append_tag(
                                Nonce::assume_unique_for_key([0x24; 12]),
                                Aad::from(&aad),
                                &mut buffer,
                            )
                            .expect("seal");
                        black_box(&buffer);
                    }),
                )
            })
            .collect(),
    ));

    // RustCrypto.
    rows.push((
        "RustCrypto aes-gcm".to_owned(),
        sizes
            .iter()
            .map(|size| {
                use aes_gcm::aead::{AeadInPlace, KeyInit};
                use aes_gcm::{Aes256Gcm, Key, Nonce};
                let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
                let nonce = Nonce::from_slice(&[0x24_u8; 12]);
                let mut buffer = vec![0_u8; *size];
                throughput(
                    *size,
                    measure(|| {
                        let tag = cipher
                            .encrypt_in_place_detached(nonce, &aad, &mut buffer)
                            .expect("seal");
                        black_box(tag);
                    }),
                )
            })
            .collect(),
    ));

    rows.push((
        "RustCrypto chacha20poly1305".to_owned(),
        sizes
            .iter()
            .map(|size| {
                use chacha20poly1305::aead::{AeadInPlace, KeyInit};
                use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
                let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
                let nonce = Nonce::from_slice(&[0x24_u8; 12]);
                let mut buffer = vec![0_u8; *size];
                throughput(
                    *size,
                    measure(|| {
                        let tag = cipher
                            .encrypt_in_place_detached(nonce, &aad, &mut buffer)
                            .expect("seal");
                        black_box(tag);
                    }),
                )
            })
            .collect(),
    ));

    for (name, values) in &rows {
        print!("  {name:34}");
        for value in values {
            print!("{value:9.2}");
        }
        println!();
        let _ = writeln!(
            report,
            "| {name} | {:.2} | {:.2} | {:.2} |",
            values[0], values[1], values[2]
        );
    }
    println!();
    let _ = writeln!(report);
}
