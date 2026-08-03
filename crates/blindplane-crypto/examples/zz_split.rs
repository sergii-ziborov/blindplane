use blindplane_crypto::aead::Suite;
use std::hint::black_box;
use std::time::{Duration, Instant};
fn threaded(suite: Suite, nthreads: usize, chunk: usize) -> f64 {
    let secs = 2.0;
    let total: u64 = std::thread::scope(|s| {
        let hs: Vec<_> = (0..nthreads).map(|_| s.spawn(move || {
            let key = [0x42u8; 32]; let nonce = [0x24u8; 12]; let ad = [0u8; 16];
            let mut buf = vec![0u8; chunk];
            // warm
            for _ in 0..4 { let _ = suite.seal_in_place(&key, &nonce, &ad, &mut buf); }
            let st = Instant::now(); let mut n = 0u64;
            while st.elapsed() < Duration::from_secs_f64(secs) {
                black_box(suite.seal_in_place(&key, &nonce, &ad, &mut buf).unwrap());
                n += 1;
            }
            n * chunk as u64
        })).collect();
        hs.into_iter().map(|h| h.join().unwrap()).sum()
    });
    total as f64 / secs / 1e9
}
fn main() {
    let chunk = 1 << 20;
    println!("threads |  ChaCha20-Poly1305  |  AES-256-GCM   (GB/s, 1 MiB chunks)");
    for &t in &[1usize, 4, 8, 10] {
        let c = threaded(Suite::ChaCha20Poly1305, t, chunk);
        let a = threaded(Suite::Aes256Gcm, t, chunk);
        println!("   {t:2}   |      {c:6.2}         |     {a:6.2}");
    }
}
