//! Current measured AEAD throughput on the working tree.
use blindplane_crypto::aead::Suite;
use std::hint::black_box;
use std::time::Instant;

fn measure(mut body: impl FnMut()) -> f64 {
    for _ in 0..4 { body(); }
    let mut best = 0.0_f64;
    for _ in 0..5 {
        let mut n = 0u64;
        let start = Instant::now();
        loop { body(); n += 1; if start.elapsed().as_millis() >= 250 { break; } }
        best = best.max(n as f64 / start.elapsed().as_secs_f64());
    }
    best
}

fn main() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let ad = [0u8; 16];
    for size in [1024usize, 65536, 1_048_576] {
        let mut buf = vec![0u8; size];
        let r = measure(|| {
            let t = Suite::ChaCha20Poly1305.seal_in_place(&key, &nonce, &ad, &mut buf).unwrap();
            black_box(t);
        });
        println!("blindplane ChaCha20-Poly1305 {:>8} B: {:.3} GB/s", size, r * size as f64 / 1e9);
    }
}
