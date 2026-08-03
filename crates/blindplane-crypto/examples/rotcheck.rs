//! Amdahl check: how much of ChaCha20-Poly1305 is keystream vs Poly1305?
use blindplane_crypto::aead::ChaCha20Poly1305;
use blindplane_crypto::chacha::ChaCha20;
use blindplane_crypto::poly1305::Poly1305;
use std::time::Instant;

fn bench(name: &str, bytes: usize, iters: usize, mut f: impl FnMut()) -> f64 {
    for _ in 0..(iters / 5).max(1) {
        f();
    }
    let t = Instant::now();
    for _ in 0..iters {
        f();
    }
    let e = t.elapsed().as_secs_f64();
    let g = (bytes as f64 * iters as f64) / e / 1e9;
    println!("{name:<48} {g:>7.3} GB/s   ({:.2} ns/MiB)", e / iters as f64 * 1e9);
    g
}

fn main() {
    const N: usize = 1 << 20;
    let mut buf = vec![0u8; N + 16];
    let key = [9u8; 32];
    let nonce = [4u8; 12];

    let ks = bench("ChaCha20 keystream only 1 MiB", N, 300, || {
        let mut c = ChaCha20::new(&key, &nonce, 1);
        c.apply_keystream(&mut buf[..N]);
        std::hint::black_box(&buf);
    });

    let po = bench("Poly1305 only 1 MiB", N, 300, || {
        let mut p = Poly1305::new(&key);
        p.update(&buf[..N]);
        std::hint::black_box(p.finalize());
    });

    let ae = bench("ChaCha20Poly1305 seal 1 MiB", N, 200, || {
        let mut b = buf.clone();
        let _ = ChaCha20Poly1305::new(&key).seal(&nonce, &[], &mut b, N);
        std::hint::black_box(&b);
    });

    println!();
    println!("serial model 1/(1/ks + 1/poly) = {:.3} GB/s", 1.0 / (1.0 / ks + 1.0 / po));
    println!("measured AEAD                  = {:.3} GB/s", ae);
    println!();
    // If keystream became infinitely fast, AEAD would be capped at `po`.
    println!("AEAD ceiling if keystream were FREE = {po:.3} GB/s");
    println!("=> max possible AEAD speedup from any ChaCha work = {:.3}x", po / ae);
}
