use std::fmt::Write as _;
use std::hint::black_box;

use blindplane_crypto::{Sha256, Sha512};

use crate::{measure, throughput};

pub(crate) fn bench_hashing(report: &mut String) {
    println!("== SHA-256 (GB/s, higher is better) ==");
    let _ = writeln!(report, "## SHA-256\n");
    let _ = writeln!(report, "| Implementation | 64 KiB |");
    let _ = writeln!(report, "|---|---:|");

    let size = 65_536;
    let data = vec![0x5a_u8; size];

    let ours = throughput(
        size,
        measure(|| {
            black_box(Sha256::digest(&data));
        }),
    );
    let rustcrypto = throughput(
        size,
        measure(|| {
            use sha2::Digest;
            black_box(sha2::Sha256::digest(&data));
        }),
    );
    let ring_rate = throughput(
        size,
        measure(|| {
            black_box(ring::digest::digest(&ring::digest::SHA256, &data));
        }),
    );

    let ours512 = throughput(
        size,
        measure(|| {
            black_box(Sha512::digest(&data));
        }),
    );
    let rc512 = throughput(
        size,
        measure(|| {
            use sha2::Digest;
            black_box(sha2::Sha512::digest(&data));
        }),
    );
    let ring512 = throughput(
        size,
        measure(|| {
            black_box(ring::digest::digest(&ring::digest::SHA512, &data));
        }),
    );

    for (name, value) in [
        ("**Blindplane SHA-256**", ours),
        ("RustCrypto sha2", rustcrypto),
        ("ring", ring_rate),
        ("**Blindplane SHA-512**", ours512),
        ("RustCrypto sha2 (512)", rc512),
        ("ring (512)", ring512),
    ] {
        println!("  {name:34}{value:9.2}");
        let _ = writeln!(report, "| {name} | {value:.2} |");
    }
    println!();
    let _ = writeln!(report);
}
