//! Where does ChaCha20-Poly1305 lose at record-sized payloads?
use blindplane_crypto::aead::Suite;
use blindplane_crypto::chacha::ChaCha20;
use blindplane_crypto::poly1305::Poly1305;
use std::hint::black_box;
use std::time::Instant;

fn measure(mut body: impl FnMut()) -> f64 {
    for _ in 0..8 {
        body();
    }
    let mut best = 0.0_f64;
    for _ in 0..5 {
        let mut n = 0u64;
        let s = Instant::now();
        loop {
            body();
            n += 1;
            if s.elapsed().as_millis() >= 250 {
                break;
            }
        }
        best = best.max(n as f64 / s.elapsed().as_secs_f64());
    }
    best
}

fn main() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let ad = [0u8; 16];

    // Cost of deriving the one-time Poly1305 key (block 0 of the keystream).
    let pk = measure(|| {
        let mut block = [0u8; 64];
        ChaCha20::new(&key, &nonce, 0).apply_keystream(&mut block);
        black_box(block);
    });
    println!("poly_key derivation      : {:.1} ns/call", 1e9 / pk);

    for size in [1024usize, 4096, 65536, 1_048_576] {
        let mut buf = vec![0u8; size];
        let aead = measure(|| {
            black_box(
                Suite::ChaCha20Poly1305
                    .seal_in_place(&key, &nonce, &ad, &mut buf)
                    .unwrap(),
            );
        });
        let ch = measure(|| {
            ChaCha20::new(&key, &nonce, 1).apply_keystream(&mut buf);
            black_box(&buf);
        });
        let po = measure(|| {
            let mut m = Poly1305::new(&key);
            m.update(&buf);
            black_box(m.finalize());
        });
        let ns = |r: f64| 1e9 / r;
        println!(
            "{:>8} B | AEAD {:6.2} GB/s ({:8.0} ns) = chacha {:8.0} + poly {:8.0} + polykey {:5.0} + slack {:7.0} ns",
            size,
            aead * size as f64 / 1e9,
            ns(aead),
            ns(ch),
            ns(po),
            ns(pk),
            ns(aead) - ns(ch) - ns(po) - ns(pk)
        );
    }
}
