// Standalone probe: isolate AES-CTR, current GHASH (reduce-per-block),
// and deferred-reduction GHASH. Mirrors blindplane-crypto/src/aes.rs exactly.
#![allow(non_snake_case)]
use core::arch::aarch64::*;
use std::time::Instant;

// ---------- shared AES ----------
#[target_feature(enable = "aes")]
unsafe fn encrypt_block(rk: &[uint8x16_t; 15], block: uint8x16_t) -> uint8x16_t {
    let mut s = block;
    for k in rk.iter().take(13) {
        s = vaesmcq_u8(vaeseq_u8(s, *k));
    }
    s = vaeseq_u8(s, rk[13]);
    veorq_u8(s, rk[14])
}

#[target_feature(enable = "aes")]
unsafe fn sub_word(word: u32) -> u32 {
    let mut b = [0u8; 16];
    for c in 0..4 {
        b[c * 4..c * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    let s = vaeseq_u8(vld1q_u8(b.as_ptr()), vdupq_n_u8(0));
    let mut o = [0u8; 16];
    vst1q_u8(o.as_mut_ptr(), s);
    u32::from_le_bytes([o[0], o[1], o[2], o[3]])
}

#[target_feature(enable = "aes")]
unsafe fn expand_key(key: &[u8; 32]) -> [uint8x16_t; 15] {
    const RCON: [u8; 7] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];
    let mut w = [0u32; 60];
    for i in 0..8 {
        w[i] = u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
    }
    for i in 8..60 {
        let mut t = w[i - 1];
        if i % 8 == 0 {
            t = sub_word(t.rotate_right(8)) ^ u32::from(RCON[i / 8 - 1]);
        } else if i % 8 == 4 {
            t = sub_word(t);
        }
        w[i] = w[i - 8] ^ t;
    }
    let mut rk = [vdupq_n_u8(0); 15];
    for (r, slot) in rk.iter_mut().enumerate() {
        let mut b = [0u8; 16];
        for j in 0..4 {
            b[j * 4..j * 4 + 4].copy_from_slice(&w[r * 4 + j].to_le_bytes());
        }
        *slot = vld1q_u8(b.as_ptr());
    }
    rk
}

#[target_feature(enable = "neon")]
unsafe fn counter_block(nonce: &[u8; 12], counter: u32) -> uint8x16_t {
    let mut b = [0u8; 16];
    b[..12].copy_from_slice(nonce);
    b[12..].copy_from_slice(&counter.to_be_bytes());
    vld1q_u8(b.as_ptr())
}

// ---------- CURRENT gf_mul: full reduction inside every multiply ----------
#[target_feature(enable = "aes,neon")]
unsafe fn gf_mul(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    let a_p: poly64x2_t = vreinterpretq_p64_u8(a);
    let b_p: poly64x2_t = vreinterpretq_p64_u8(b);
    let a_lo = vgetq_lane_u64(vreinterpretq_u64_u8(a), 0);
    let a_hi = vgetq_lane_u64(vreinterpretq_u64_u8(a), 1);
    let b_lo = vgetq_lane_u64(vreinterpretq_u64_u8(b), 0);
    let b_hi = vgetq_lane_u64(vreinterpretq_u64_u8(b), 1);
    let low = vreinterpretq_u8_p128(vmull_p64(a_lo, b_lo));
    let high = vreinterpretq_u8_p128(vmull_high_p64(a_p, b_p));
    let middle = veorq_u8(
        veorq_u8(vreinterpretq_u8_p128(vmull_p64(a_lo ^ a_hi, b_lo ^ b_hi)), low),
        high,
    );
    let zero = vdupq_n_u8(0);
    let product_low = veorq_u8(low, vextq_u8(zero, middle, 8));
    let product_high = veorq_u8(high, vextq_u8(middle, zero, 8));
    let h_lo = vgetq_lane_u64(vreinterpretq_u64_u8(product_high), 0);
    let h_hi = vgetq_lane_u64(vreinterpretq_u64_u8(product_high), 1);
    let fold_lo = vreinterpretq_u8_p128(vmull_p64(h_lo, 0x87));
    let fold_hi = vreinterpretq_u8_p128(vmull_p64(h_hi, 0x87));
    let mut r = veorq_u8(product_low, fold_lo);
    r = veorq_u8(r, vextq_u8(zero, fold_hi, 8));
    let spill = vgetq_lane_u64(vreinterpretq_u64_u8(fold_hi), 1);
    veorq_u8(r, vreinterpretq_u8_p128(vmull_p64(spill, 0x87)))
}

// ---------- DEFERRED: raw 3-product Karatsuba, no reduction ----------
#[target_feature(enable = "aes,neon")]
unsafe fn karatsuba(a: uint8x16_t, b: uint8x16_t) -> (uint8x16_t, uint8x16_t, uint8x16_t) {
    let a_p: poly64x2_t = vreinterpretq_p64_u8(a);
    let b_p: poly64x2_t = vreinterpretq_p64_u8(b);
    let a_lo = vgetq_lane_u64(vreinterpretq_u64_u8(a), 0);
    let a_hi = vgetq_lane_u64(vreinterpretq_u64_u8(a), 1);
    let b_lo = vgetq_lane_u64(vreinterpretq_u64_u8(b), 0);
    let b_hi = vgetq_lane_u64(vreinterpretq_u64_u8(b), 1);
    let low = vreinterpretq_u8_p128(vmull_p64(a_lo, b_lo));
    let high = vreinterpretq_u8_p128(vmull_high_p64(a_p, b_p));
    let mid = vreinterpretq_u8_p128(vmull_p64(a_lo ^ a_hi, b_lo ^ b_hi));
    (high, mid, low)
}

/// Single reduction of an accumulated (HI, MIDraw, LO) triple.
#[target_feature(enable = "aes,neon")]
unsafe fn reduce(high: uint8x16_t, mid_raw: uint8x16_t, low: uint8x16_t) -> uint8x16_t {
    let middle = veorq_u8(veorq_u8(mid_raw, low), high);
    let zero = vdupq_n_u8(0);
    let product_low = veorq_u8(low, vextq_u8(zero, middle, 8));
    let product_high = veorq_u8(high, vextq_u8(middle, zero, 8));
    let h_lo = vgetq_lane_u64(vreinterpretq_u64_u8(product_high), 0);
    let h_hi = vgetq_lane_u64(vreinterpretq_u64_u8(product_high), 1);
    let fold_lo = vreinterpretq_u8_p128(vmull_p64(h_lo, 0x87));
    let fold_hi = vreinterpretq_u8_p128(vmull_p64(h_hi, 0x87));
    let mut r = veorq_u8(product_low, fold_lo);
    r = veorq_u8(r, vextq_u8(zero, fold_hi, 8));
    let spill = vgetq_lane_u64(vreinterpretq_u64_u8(fold_hi), 1);
    veorq_u8(r, vreinterpretq_u8_p128(vmull_p64(spill, 0x87)))
}

#[target_feature(enable = "neon")]
unsafe fn reflect(v: uint8x16_t) -> uint8x16_t {
    vrbitq_u8(v)
}

struct Ghash {
    powers: [uint8x16_t; 8],
    acc: uint8x16_t,
}

impl Ghash {
    #[target_feature(enable = "aes,neon")]
    unsafe fn new(h_block: uint8x16_t) -> Self {
        let h = reflect(h_block);
        let h2 = gf_mul(h, h);
        let h3 = gf_mul(h2, h);
        let h4 = gf_mul(h3, h);
        let h5 = gf_mul(h4, h);
        let h6 = gf_mul(h5, h);
        let h7 = gf_mul(h6, h);
        let h8 = gf_mul(h7, h);
        Self { powers: [h8, h7, h6, h5, h4, h3, h2, h], acc: vdupq_n_u8(0) }
    }

    // ---- current: 8 independent gf_mul, each fully reduced (48 PMULL / 8 blk)
    #[target_feature(enable = "aes,neon")]
    unsafe fn absorb8_current(&mut self, c: [uint8x16_t; 8]) {
        let b0 = veorq_u8(self.acc, reflect(c[0]));
        let p0 = gf_mul(b0, self.powers[0]);
        let p1 = gf_mul(reflect(c[1]), self.powers[1]);
        let p2 = gf_mul(reflect(c[2]), self.powers[2]);
        let p3 = gf_mul(reflect(c[3]), self.powers[3]);
        let p4 = gf_mul(reflect(c[4]), self.powers[4]);
        let p5 = gf_mul(reflect(c[5]), self.powers[5]);
        let p6 = gf_mul(reflect(c[6]), self.powers[6]);
        let p7 = gf_mul(reflect(c[7]), self.powers[7]);
        self.acc = veorq_u8(
            veorq_u8(veorq_u8(p0, p1), veorq_u8(p2, p3)),
            veorq_u8(veorq_u8(p4, p5), veorq_u8(p6, p7)),
        );
    }

    // ---- deferred: 24 PMULL products + one 3-PMULL reduction (27 / 8 blk)
    #[target_feature(enable = "aes,neon")]
    unsafe fn absorb8_deferred(&mut self, c: [uint8x16_t; 8]) {
        let b0 = veorq_u8(self.acc, reflect(c[0]));
        let (h0, m0, l0) = karatsuba(b0, self.powers[0]);
        let (h1, m1, l1) = karatsuba(reflect(c[1]), self.powers[1]);
        let (h2, m2, l2) = karatsuba(reflect(c[2]), self.powers[2]);
        let (h3, m3, l3) = karatsuba(reflect(c[3]), self.powers[3]);
        let (h4, m4, l4) = karatsuba(reflect(c[4]), self.powers[4]);
        let (h5, m5, l5) = karatsuba(reflect(c[5]), self.powers[5]);
        let (h6, m6, l6) = karatsuba(reflect(c[6]), self.powers[6]);
        let (h7, m7, l7) = karatsuba(reflect(c[7]), self.powers[7]);
        let hi = veorq_u8(
            veorq_u8(veorq_u8(h0, h1), veorq_u8(h2, h3)),
            veorq_u8(veorq_u8(h4, h5), veorq_u8(h6, h7)),
        );
        let mi = veorq_u8(
            veorq_u8(veorq_u8(m0, m1), veorq_u8(m2, m3)),
            veorq_u8(veorq_u8(m4, m5), veorq_u8(m6, m7)),
        );
        let lo = veorq_u8(
            veorq_u8(veorq_u8(l0, l1), veorq_u8(l2, l3)),
            veorq_u8(veorq_u8(l4, l5), veorq_u8(l6, l7)),
        );
        self.acc = reduce(hi, mi, lo);
    }

    // RBIT-cost probe: identical work minus the 8 vrbitq_u8. Result is WRONG
    // on purpose; it only measures what removing RBIT could ever buy.
    #[target_feature(enable = "aes,neon")]
    unsafe fn absorb8_deferred_norbit(&mut self, c: [uint8x16_t; 8]) {
        let b0 = veorq_u8(self.acc, c[0]);
        let (h0, m0, l0) = karatsuba(b0, self.powers[0]);
        let (h1, m1, l1) = karatsuba(c[1], self.powers[1]);
        let (h2, m2, l2) = karatsuba(c[2], self.powers[2]);
        let (h3, m3, l3) = karatsuba(c[3], self.powers[3]);
        let (h4, m4, l4) = karatsuba(c[4], self.powers[4]);
        let (h5, m5, l5) = karatsuba(c[5], self.powers[5]);
        let (h6, m6, l6) = karatsuba(c[6], self.powers[6]);
        let (h7, m7, l7) = karatsuba(c[7], self.powers[7]);
        let hi = veorq_u8(veorq_u8(veorq_u8(h0,h1),veorq_u8(h2,h3)),veorq_u8(veorq_u8(h4,h5),veorq_u8(h6,h7)));
        let mi = veorq_u8(veorq_u8(veorq_u8(m0,m1),veorq_u8(m2,m3)),veorq_u8(veorq_u8(m4,m5),veorq_u8(m6,m7)));
        let lo = veorq_u8(veorq_u8(veorq_u8(l0,l1),veorq_u8(l2,l3)),veorq_u8(veorq_u8(l4,l5),veorq_u8(l6,l7)));
        self.acc = reduce(hi, mi, lo);
    }

    #[target_feature(enable = "aes,neon")]
    unsafe fn finish(self) -> [u8; 16] {
        let mut o = [0u8; 16];
        vst1q_u8(o.as_mut_ptr(), reflect(self.acc));
        o
    }
}

// ---------- workloads ----------

#[target_feature(enable = "aes,neon")]
unsafe fn ghash_only(h: uint8x16_t, data: &[u8], deferred: bool) -> [u8; 16] {
    let mut g = Ghash::new(h);
    let mut off = 0;
    while off + 128 <= data.len() {
        let p = data.as_ptr().add(off);
        let c = [
            vld1q_u8(p), vld1q_u8(p.add(16)), vld1q_u8(p.add(32)), vld1q_u8(p.add(48)),
            vld1q_u8(p.add(64)), vld1q_u8(p.add(80)), vld1q_u8(p.add(96)), vld1q_u8(p.add(112)),
        ];
        if deferred { g.absorb8_deferred(c) } else { g.absorb8_current(c) }
        off += 128;
    }
    g.finish()
}

/// CTR only, no GHASH at all: the ceiling if GHASH were free.
#[target_feature(enable = "aes,neon")]
unsafe fn ctr_only(rk: &[uint8x16_t; 15], nonce: &[u8; 12], buf: &mut [u8]) {
    let mut counter = 2u32;
    let mut off = 0;
    let len = buf.len();
    let base = buf.as_mut_ptr();
    while off + 128 <= len {
        let mut k = [vdupq_n_u8(0); 8];
        for i in 0..8 {
            k[i] = encrypt_block(rk, counter_block(nonce, counter + i as u32));
        }
        let p = base.add(off);
        for i in 0..8 {
            let q = p.add(i * 16);
            vst1q_u8(q, veorq_u8(vld1q_u8(q), k[i]));
        }
        counter = counter.wrapping_add(8);
        off += 128;
    }
}

/// Full one-pass seal, parameterised on which GHASH is used.
#[target_feature(enable = "aes,neon")]
unsafe fn seal(rk: &[uint8x16_t; 15], nonce: &[u8; 12], h: uint8x16_t, buf: &mut [u8], deferred: bool) -> [u8; 16] {
    let mut g = Ghash::new(h);
    let mut counter = 2u32;
    let mut off = 0;
    let len = buf.len();
    let base = buf.as_mut_ptr();
    while off + 128 <= len {
        let mut k = [vdupq_n_u8(0); 8];
        for i in 0..8 {
            k[i] = encrypt_block(rk, counter_block(nonce, counter + i as u32));
        }
        let p = base.add(off);
        let mut c = [vdupq_n_u8(0); 8];
        for i in 0..8 {
            let q = p.add(i * 16);
            c[i] = veorq_u8(vld1q_u8(q), k[i]);
            vst1q_u8(q, c[i]);
        }
        if deferred { g.absorb8_deferred(c) } else { g.absorb8_current(c) }
        counter = counter.wrapping_add(8);
        off += 128;
    }
    g.finish()
}

fn bench<F: FnMut() -> u64>(name: &str, bytes: usize, mut f: F) -> f64 {
    let mut best = f64::MAX;
    let mut sink = 0u64;
    for _ in 0..7 {
        // warm + timed run of >=250ms
        let mut iters = 0u64;
        let t0 = Instant::now();
        loop {
            sink = sink.wrapping_add(f());
            iters += 1;
            if t0.elapsed().as_secs_f64() > 0.25 { break; }
        }
        let el = t0.elapsed().as_secs_f64();
        let per = el / iters as f64;
        if per < best { best = per; }
    }
    std::hint::black_box(sink);
    let gbs = bytes as f64 / best / 1e9;
    println!("  {name:<38} {gbs:>7.3} GB/s   ({:.1} cyc/16B @4.4GHz)", best * 4.4e9 / (bytes as f64 / 16.0));
    gbs
}


#[target_feature(enable = "aes,neon")]
unsafe fn seal_cur(rk: &[uint8x16_t;15], nonce: &[u8;12], h: uint8x16_t, buf: &mut [u8]) -> [u8;16] {
    let mut g = Ghash::new(h);
    let (mut counter, mut off) = (2u32, 0usize);
    let (len, base) = (buf.len(), buf.as_mut_ptr());
    while off + 128 <= len {
        let mut k = [vdupq_n_u8(0); 8];
        for i in 0..8 { k[i] = encrypt_block(rk, counter_block(nonce, counter + i as u32)); }
        let p = base.add(off);
        let mut c = [vdupq_n_u8(0); 8];
        for i in 0..8 { let q = p.add(i*16); c[i] = veorq_u8(vld1q_u8(q), k[i]); vst1q_u8(q, c[i]); }
        g.absorb8_current(c);
        counter = counter.wrapping_add(8); off += 128;
    }
    g.finish()
}

#[target_feature(enable = "aes,neon")]
unsafe fn seal_def(rk: &[uint8x16_t;15], nonce: &[u8;12], h: uint8x16_t, buf: &mut [u8]) -> [u8;16] {
    let mut g = Ghash::new(h);
    let (mut counter, mut off) = (2u32, 0usize);
    let (len, base) = (buf.len(), buf.as_mut_ptr());
    while off + 128 <= len {
        let mut k = [vdupq_n_u8(0); 8];
        for i in 0..8 { k[i] = encrypt_block(rk, counter_block(nonce, counter + i as u32)); }
        let p = base.add(off);
        let mut c = [vdupq_n_u8(0); 8];
        for i in 0..8 { let q = p.add(i*16); c[i] = veorq_u8(vld1q_u8(q), k[i]); vst1q_u8(q, c[i]); }
        g.absorb8_deferred(c);
        counter = counter.wrapping_add(8); off += 128;
    }
    g.finish()
}

#[target_feature(enable = "aes,neon")]
unsafe fn seal_def_norbit(rk: &[uint8x16_t;15], nonce: &[u8;12], h: uint8x16_t, buf: &mut [u8]) -> [u8;16] {
    let mut g = Ghash::new(h);
    let (mut counter, mut off) = (2u32, 0usize);
    let (len, base) = (buf.len(), buf.as_mut_ptr());
    while off + 128 <= len {
        let mut k = [vdupq_n_u8(0); 8];
        for i in 0..8 { k[i] = encrypt_block(rk, counter_block(nonce, counter + i as u32)); }
        let p = base.add(off);
        let mut c = [vdupq_n_u8(0); 8];
        for i in 0..8 { let q = p.add(i*16); c[i] = veorq_u8(vld1q_u8(q), k[i]); vst1q_u8(q, c[i]); }
        g.absorb8_deferred_norbit(c);
        counter = counter.wrapping_add(8); off += 128;
    }
    g.finish()
}

/// Full per-message cost incl. key expansion and the 7-deep H-power chain.
#[target_feature(enable = "aes,neon")]
unsafe fn full_seal_cur(key: &[u8;32], nonce: &[u8;12], buf: &mut [u8]) -> [u8;16] {
    let rk = expand_key(key);
    let h = encrypt_block(&rk, vdupq_n_u8(0));
    seal_cur(&rk, nonce, h, buf)
}
#[target_feature(enable = "aes,neon")]
unsafe fn full_seal_def(key: &[u8;32], nonce: &[u8;12], buf: &mut [u8]) -> [u8;16] {
    let rk = expand_key(key);
    let h = encrypt_block(&rk, vdupq_n_u8(0));
    seal_def(&rk, nonce, h, buf)
}

fn main() {
    unsafe {
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let rk = expand_key(&key);
        let h = encrypt_block(&rk, vdupq_n_u8(0));
        const N: usize = 1 << 20; // 1 MiB
        let mut buf = vec![0x5au8; N];
        let data = vec![0xa5u8; N];

        // correctness: deferred must equal current, bit for bit
        let a = ghash_only(h, &data, false);
        let b = ghash_only(h, &data, true);
        println!("GHASH equivalence current==deferred: {}", a == b);
        assert_eq!(a, b, "deferred reduction changed the result");
        let mut b1 = buf.clone();
        let mut b2 = buf.clone();
        let t1 = seal(&rk, &nonce, h, &mut b1, false);
        let t2 = seal(&rk, &nonce, h, &mut b2, true);
        println!("seal equivalence  current==deferred: {} / ct {}", t1 == t2, b1 == b2);
        assert_eq!(t1, t2);

        println!("\n== 1 MiB, best-of-7 ==");
        let ctr = bench("AES-CTR only (no GHASH)  [ceiling]", N, || {
            ctr_only(&rk, &nonce, &mut buf);
            buf[0] as u64
        });
        let gc = bench("GHASH only  CURRENT (reduce/block)", N, || {
            u64::from(ghash_only(h, &data, false)[0])
        });
        let gd = bench("GHASH only  DEFERRED (reduce/8)", N, || {
            u64::from(ghash_only(h, &data, true)[0])
        });
        let sc = bench("seal CURRENT (CTR+GHASH one pass)", N, || {
            u64::from(seal(&rk, &nonce, h, &mut b1, false)[0])
        });
        let sd = bench("seal DEFERRED (CTR+GHASH one pass)", N, || {
            u64::from(seal(&rk, &nonce, h, &mut b2, true)[0])
        });

        println!("\n== deltas ==");
        println!("  GHASH standalone speedup from deferring: {:.3}x", gd / gc);
        println!("  full seal speedup from deferring:        {:.3}x", sd / sc);
        println!("  seal CURRENT  as %% of CTR ceiling:       {:.1}%", 100.0 * sc / ctr);
        println!("  seal DEFERRED as %% of CTR ceiling:       {:.1}%", 100.0 * sd / ctr);
        // Amdahl check: model of serial CTR + serial GHASH
        let model = 1.0 / (1.0 / ctr + 1.0 / gc);
        println!("  serial model 1/(1/CTR+1/GHASHcur) =      {:.3} GB/s (actual {:.3})", model, sc);

        // ---- RBIT upper bound (1 MiB, hot loop only) ----
        println!("\n== RBIT elimination upper bound (1 MiB) ==");
        let d1 = bench("seal DEFERRED (with 8x rbit)", N, || u64::from(seal_def(&rk,&nonce,h,&mut b2)[0]));
        let d2 = bench("seal DEFERRED (rbit removed, WRONG)", N, || u64::from(seal_def_norbit(&rk,&nonce,h,&mut b2)[0]));
        println!("  max possible gain from dropping RBIT:    {:.3}x", d2/d1);

        // ---- the size we actually ship: 4 KiB records ----
        println!("\n== 4 KiB record payload, per-message (key expansion + H powers included) ==");
        const K: usize = 4096;
        let mut k1 = vec![0x5au8; K];
        let mut k2v = vec![0x5au8; K];
        let fc = bench("4KiB full seal CURRENT", K, || u64::from(full_seal_cur(&key,&nonce,&mut k1)[0]));
        let fd = bench("4KiB full seal DEFERRED", K, || u64::from(full_seal_def(&key,&nonce,&mut k2v)[0]));
        println!("  4 KiB per-message speedup:               {:.3}x", fd/fc);

        // ---- setup cost alone ----
        println!("\n== fixed per-message setup (expand_key + H + 7 serial gf_mul) ==");
        let t0 = std::time::Instant::now();
        let mut it = 0u64; let mut s = 0u64;
        while t0.elapsed().as_secs_f64() < 0.4 {
            let rk2 = expand_key(&key);
            let hh = encrypt_block(&rk2, vdupq_n_u8(0));
            let g = Ghash::new(hh);
            s = s.wrapping_add(u64::from(g.finish()[0]));
            it += 1;
        }
        std::hint::black_box(s);
        let ns = t0.elapsed().as_secs_f64() / it as f64 * 1e9;
        println!("  setup: {:.0} ns/message (~{:.0} cycles @4.4GHz)", ns, ns*4.4);
        println!("  4 KiB seal total: {:.0} ns  -> setup is {:.1}%% of it",
                 K as f64/fc/1e9*1e9, 100.0*ns/(K as f64/(fc*1e9)*1e9));
    }
}
