//! Measurement lab: quantify headroom from unused M4 instruction-set features.
use std::time::Instant;

fn bench<F: FnMut()>(name: &str, bytes_per_iter: usize, iters: usize, mut f: F) -> f64 {
    for _ in 0..iters / 10 + 1 {
        f();
    }
    let t = Instant::now();
    for _ in 0..iters {
        f();
    }
    let el = t.elapsed().as_secs_f64();
    let gbps = (bytes_per_iter * iters) as f64 / el / 1e9;
    println!("{name:<52} {gbps:>8.3} GB/s");
    gbps
}

fn bench_ops<F: FnMut()>(name: &str, iters: usize, mut f: F) -> f64 {
    for _ in 0..iters / 10 + 1 {
        f();
    }
    let t = Instant::now();
    for _ in 0..iters {
        f();
    }
    let el = t.elapsed().as_secs_f64();
    let ops = iters as f64 / el;
    println!("{name:<52} {ops:>10.0} op/s");
    ops
}

#[cfg(target_arch = "aarch64")]
mod neon_chacha {
    use core::arch::aarch64::*;

    const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

    #[inline(always)]
    unsafe fn rotl16(x: uint32x4_t) -> uint32x4_t {
        unsafe { vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(x))) }
    }
    #[inline(always)]
    unsafe fn rotl8(x: uint32x4_t, tbl: uint8x16_t) -> uint32x4_t {
        unsafe { vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(x), tbl)) }
    }
    #[inline(always)]
    unsafe fn rotl12(x: uint32x4_t) -> uint32x4_t {
        unsafe { vsriq_n_u32::<20>(vshlq_n_u32::<12>(x), x) }
    }
    #[inline(always)]
    unsafe fn rotl7(x: uint32x4_t) -> uint32x4_t {
        unsafe { vsriq_n_u32::<25>(vshlq_n_u32::<7>(x), x) }
    }

    #[target_feature(enable = "neon")]
    unsafe fn four_blocks(state: &[u32; 16], counter: u32, out: &mut [u8; 256]) {
        unsafe {
            let tbl =
                vld1q_u8([3u8, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14].as_ptr());
            let mut v = [vdupq_n_u32(0); 16];
            for i in 0..16 {
                v[i] = vdupq_n_u32(state[i]);
            }
            let ctr = [
                counter,
                counter.wrapping_add(1),
                counter.wrapping_add(2),
                counter.wrapping_add(3),
            ];
            v[12] = vld1q_u32(ctr.as_ptr());
            let initial = v;

            macro_rules! qr {
                ($a:expr, $b:expr, $c:expr, $d:expr) => {
                    v[$a] = vaddq_u32(v[$a], v[$b]);
                    v[$d] = rotl16(veorq_u32(v[$d], v[$a]));
                    v[$c] = vaddq_u32(v[$c], v[$d]);
                    v[$b] = rotl12(veorq_u32(v[$b], v[$c]));
                    v[$a] = vaddq_u32(v[$a], v[$b]);
                    v[$d] = rotl8(veorq_u32(v[$d], v[$a]), tbl);
                    v[$c] = vaddq_u32(v[$c], v[$d]);
                    v[$b] = rotl7(veorq_u32(v[$b], v[$c]));
                };
            }

            for _ in 0..10 {
                qr!(0, 4, 8, 12);
                qr!(1, 5, 9, 13);
                qr!(2, 6, 10, 14);
                qr!(3, 7, 11, 15);
                qr!(0, 5, 10, 15);
                qr!(1, 6, 11, 12);
                qr!(2, 7, 8, 13);
                qr!(3, 4, 9, 14);
            }
            for i in 0..16 {
                v[i] = vaddq_u32(v[i], initial[i]);
            }
            let mut tmp = [0u32; 64];
            for i in 0..16 {
                vst1q_u32(tmp.as_mut_ptr().add(i * 4), v[i]);
            }
            for b in 0..4 {
                for w in 0..16 {
                    let x = tmp[w * 4 + b].to_le_bytes();
                    out[b * 64 + w * 4..b * 64 + w * 4 + 4].copy_from_slice(&x);
                }
            }
        }
    }

    pub fn apply(key: &[u8; 32], nonce: &[u8; 12], data: &mut [u8]) {
        let mut state = [0u32; 16];
        state[..4].copy_from_slice(&SIGMA);
        for i in 0..8 {
            state[4 + i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 0..3 {
            state[13 + i] = u32::from_le_bytes(nonce[i * 4..i * 4 + 4].try_into().unwrap());
        }
        let mut ks = [0u8; 256];
        let mut ctr = 0u32;
        let mut off = 0;
        while off < data.len() {
            unsafe { four_blocks(&state, ctr, &mut ks) };
            let take = core::cmp::min(256, data.len() - off);
            for (b, k) in data[off..off + take].iter_mut().zip(ks.iter()) {
                *b ^= *k;
            }
            ctr = ctr.wrapping_add(4);
            off += take;
        }
    }
}

const REFERENCE_HEX: &str = "b4de0d25a81f4dfd11f05a5096c3eedf28f5b4f757b5bcf9edcd285956d58f751e003343c26c4129f6f72e753d2de42f3fbf52b9051e811150e148d27e0997a7eba64d67969458f9593b91ddcbe96831fc941bb3bc8ba7ad108ad2cb58ca28ae0ad9043fe106341fdee349c7e4d03515b7bd7ebec07e51a93f487561367e92ad15693549ea9aaeae565e4398e0b60a5ede314ab4cfd57c7e183dc379c2b905e6a106a386dade9fed45b0f183cc359a1ed356c67286ed41c1c52cba6d22464032a1fc49964aab6293a0704b89b5037258cc67f835666128b5c40428ab1c1aa99ec2bd5b8c3e63e8bfe842149a66dca04399910e21001e5cbf749c69bda9350e88de6b187de3fae74591c8c4705f7b40443e2464598e88cccd0a6807d3d4769d137edc3c05715e9171723117b1e6cdeb002adccf0d1736643e042a89520e2f9ad7ab8b34fa174abb282d765585381a5ce34853cda5ac66239db8d6810bfbde7850661a2f9776c8dfd66218a40e5539da5b6d26da2e74d8426adea41799ec4e4de5861fb8f59b4a5bfef38906945fdbf12421b4af24a38163c587c88beb2cc8965b19bdd29471fec27d7bb4b545c325d87fc37dd943d3bc56224c1b2286f15c0eb17f55c807eecbd82d2cfb528c96577fc25fe07abb919cb5dbabb93261cf73cd7886ecdad04c9e617aa365f4dc217871c06ee32a0284aed580f193846da6ecd3e33d66c1017d8a2aee7652bd547816b43e3830418143ee3e02349d0400e80169b98956fc0256a0ec61a51510e80111e9ef28385def3465cf1dd29706e00cfbe378ca663c394d19e2aa2bc58f6a7b22249c1713c94cf216bcac0d521ee4690f09bdd7ced631852ff3cf879352cdfc333541c4b9bac911179bac49ba89405b86e992812e06893cffebaa1a05d7ac26023b47a4effbd2ded2d333b4f16da1a67ae8c4bb54d19901bcd2801c18d9b3c2158f8a72f22bb961fd9bcdf3680df66badd15683f82a1c3bfe3585a2c01144d03a4e588c96d9a653f8c7a38c8fdbb0cd473eac0747a8df1362c8c902c1c2bca382d48831cc70cb9f4b2522e83f6a43d02c3a2856cccd9064074b85a0f86934eb944f2655fc190981b18cf41afe6125efb5ee91f66fd120e82e1b486eb6a84a24ded78e5ce3f17e1c1b00e1cca4d5f9e635331fe659627e45886438754013e94b5b618cc309a30007e7593faaee0407b91e15c4cc2c0e2040a49f64040bfbf8f03f4bebba5e40bf72c3824c570f68c6167b51c400b15a840fa233332e73f3a4e3a5e53148f1b0a785318c23997ec5aaada9dab2187f091f58264b1bcc3779c71e76c955684995645e4c99d21106429f7fe5adcf50204899047e72f5d3c7fee88b49c731fb2dd8e8209b7405a83d7c9af3b1062c465f2d548a7dab8a";

fn main() {
    println!("=== Apple M4 crypto headroom lab ===\n");
    const N: usize = 1 << 20;
    let data = vec![0xABu8; N];
    let mut sink = 0u8;

    // Correctness check for the hand NEON ChaCha against the crate.
    #[cfg(target_arch = "aarch64")]
    {
        let key = [7u8; 32];
        let nonce = [3u8; 12];
        let mut a = vec![0u8; 1000];
        let mut b = vec![0u8; 1000];
        blindplane_crypto::chacha::ChaCha20::new(&key, &nonce, 0).apply_keystream(&mut a);
        neon_chacha::apply(&key, &nonce, &mut b);
        let reference: Vec<u8> = REFERENCE_HEX
            .as_bytes()
            .chunks(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect();
        let da: Vec<usize> = (0..1000).filter(|&i| a[i] != reference[i]).collect();
        let db: Vec<usize> = (0..1000).filter(|&i| b[i] != reference[i]).collect();
        println!("blindplane HEAD (autovec)  vs RFC reference: {} mismatched bytes", da.len());
        if !da.is_empty() {
            println!("   first mismatch offsets: {:?}", &da[..da.len().min(12)]);
        }
        println!("my hand NEON            vs RFC reference: {} mismatched bytes", db.len());
        if !db.is_empty() {
            println!("   first mismatch offsets: {:?}", &db[..db.len().min(12)]);
        }
        println!();
    }

    println!("--- SHA-512: our SCALAR vs hardware SHA512H (ring) ---");
    let g_ours = bench("blindplane Sha512 1MiB  (pure scalar)", N, 200, || {
        sink ^= blindplane_crypto::Sha512::digest(&data)[0];
    });
    let g_ring = bench("ring SHA512 1MiB  (HW sha512h/su0/su1)", N, 200, || {
        sink ^= ring::digest::digest(&ring::digest::SHA512, &data).as_ref()[0];
    });
    let g_rc = bench("RustCrypto sha2::Sha512 1MiB", N, 200, || {
        use sha2::Digest;
        sink ^= sha2::Sha512::digest(&data)[0];
    });
    println!(
        "  >> HW SHA-512 is {:.2}x our scalar (RustCrypto {:.2}x)\n",
        g_ring / g_ours,
        g_rc / g_ours
    );

    println!("--- SHA-256: both use ARMv8 SHA-2 instructions ---");
    let s_ours = bench("blindplane Sha256 1MiB", N, 200, || {
        sink ^= blindplane_crypto::Sha256::digest(&data)[0];
    });
    let s_ring = bench("ring SHA256 1MiB", N, 200, || {
        sink ^= ring::digest::digest(&ring::digest::SHA256, &data).as_ref()[0];
    });
    println!("  >> ring/ours SHA-256 = {:.2}x\n", s_ring / s_ours);

    println!("--- ChaCha20 keystream ONLY (isolates rotate cost) ---");
    let key = [7u8; 32];
    let nonce = [3u8; 12];
    let mut buf = vec![0u8; N];
    let c_ours = bench("blindplane ChaCha20 1MiB (autovectorized)", N, 300, || {
        blindplane_crypto::chacha::ChaCha20::new(&key, &nonce, 0).apply_keystream(&mut buf);
    });
    #[cfg(target_arch = "aarch64")]
    {
        let c_neon = bench("hand NEON ChaCha20 1MiB (rev32/tbl/shl+sri)", N, 300, || {
            neon_chacha::apply(&key, &nonce, &mut buf);
        });
        println!("  >> hand NEON / ours = {:.2}x\n", c_neon / c_ours);
    }
    sink ^= buf[0];

    println!("--- ChaCha20-Poly1305 full AEAD ---");
    let a_ours = bench("blindplane ChaCha20Poly1305 seal 1MiB", N, 100, || {
        let out = blindplane_crypto::Suite::ChaCha20Poly1305
            .seal(&key, &nonce, &[], &data)
            .unwrap();
        sink ^= out[0];
    });
    {
        use ring::aead;
        let k =
            aead::LessSafeKey::new(aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key).unwrap());
        let a_ring = bench("ring ChaCha20Poly1305 seal 1MiB (FUSED asm)", N, 100, || {
            let mut io = data.clone();
            let n = aead::Nonce::assume_unique_for_key(nonce);
            k.seal_in_place_append_tag(n, aead::Aad::empty(), &mut io)
                .unwrap();
            sink ^= io[0];
        });
        println!("  >> ring/ours AEAD = {:.2}x\n", a_ring / a_ours);
    }

    println!("--- AES-256-GCM ---");
    let ag_ours = bench("blindplane Aes256Gcm seal 1MiB", N, 100, || {
        let out = blindplane_crypto::Suite::Aes256Gcm
            .seal(&key, &nonce, &[], &data)
            .unwrap();
        sink ^= out[0];
    });
    {
        use ring::aead;
        let k = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &key).unwrap());
        let ag_ring = bench("ring AES_256_GCM seal 1MiB (FUSED kernel)", N, 100, || {
            let mut io = data.clone();
            let n = aead::Nonce::assume_unique_for_key(nonce);
            k.seal_in_place_append_tag(n, aead::Aad::empty(), &mut io)
                .unwrap();
            sink ^= io[0];
        });
        println!("  >> ring/ours AES-GCM = {:.2}x\n", ag_ring / ag_ours);
    }

    println!("--- Ed25519 (SHA-512 on the critical path) ---");
    let sk = blindplane_crypto::SigningKey::from_seed(&[9u8; 32]);
    let vk = sk.verifying_key();
    let msg = [0x5Au8; 64];
    let sig = sk.sign(&msg);
    let sg = bench_ops("blindplane Ed25519 sign", 30000, || {
        sink ^= sk.sign(&msg)[0];
    });
    let vf = bench_ops("blindplane Ed25519 verify_strict", 20000, || {
        sink ^= u8::from(blindplane_crypto::verify_strict(&vk, &msg, &sig).is_ok());
    });

    println!("\n--- SHA-512 share of one Ed25519 sign ---");
    // sign() hashes (32B prefix || 64B msg) and (32B R || 32B A || 64B msg)
    let h1 = vec![0u8; 32 + 64];
    let h2 = vec![0u8; 32 + 32 + 64];
    let t = Instant::now();
    for _ in 0..300000 {
        sink ^= blindplane_crypto::Sha512::digest(&h1)[0];
        sink ^= blindplane_crypto::Sha512::digest(&h2)[0];
    }
    let hash_ns = t.elapsed().as_secs_f64() / 300000.0 * 1e9;
    let sign_ns = 1e9 / sg;
    println!("  two SHA-512 calls as in sign(): {hash_ns:.1} ns");
    println!("  one Ed25519 sign total:         {sign_ns:.1} ns");
    println!("  >> SHA-512 is {:.1}% of sign time", hash_ns / sign_ns * 100.0);
    let verify_ns = 1e9 / vf;
    let t = Instant::now();
    for _ in 0..300000 {
        sink ^= blindplane_crypto::Sha512::digest(&h2)[0];
    }
    let vh_ns = t.elapsed().as_secs_f64() / 300000.0 * 1e9;
    println!("  one SHA-512 call as in verify(): {vh_ns:.1} ns");
    println!("  one Ed25519 verify_strict total: {verify_ns:.1} ns");
    println!("  >> SHA-512 is {:.1}% of verify time", vh_ns / verify_ns * 100.0);

    println!("\n(sink={sink})");
}
