use blindplane_crypto::chacha::ChaCha20;
use blindplane_crypto::poly1305::Poly1305;
use std::hint::black_box;
use std::time::Instant;
fn measure(mut body: impl FnMut()) -> f64 {
    for _ in 0..4 { body(); }
    let mut best = 0.0f64;
    for _ in 0..5 {
        let mut n = 0u64; let s = Instant::now();
        loop { body(); n += 1; if s.elapsed().as_millis() >= 200 { break; } }
        best = best.max(n as f64 / s.elapsed().as_secs_f64());
    }
    best
}
fn main() {
    let sz = 1usize << 20;
    let mut buf = vec![0u8; sz];
    let key = [0x42u8; 32]; let nonce = [0x24u8; 12];
    let r = measure(|| { let mut c = ChaCha20::new(&key, &nonce, 1); c.apply_keystream(&mut buf); black_box(&buf); });
    println!("ChaCha20 alone (NEON)   1 MiB: {:.3} GB/s", r * sz as f64 / 1e9);
    let r2 = measure(|| { let mut p = Poly1305::new(&key); p.update(&buf); black_box(p.finish()); });
    println!("Poly1305 alone (scalar) 1 MiB: {:.3} GB/s", r2 * sz as f64 / 1e9);
    println!("=> combined predicted: {:.3} GB/s", 1.0/(1e9/(r*sz as f64) + 1e9/(r2*sz as f64)));
}
