//! SHA-512 on the ARMv8.2 FEAT_SHA512 instructions, in stable Rust intrinsics.
//! Schedule transcribed from BoringSSL/ring `sha512_block_data_order_hw`.
#![allow(clippy::needless_range_loop)]

use core::arch::aarch64::*;

pub const K512: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

pub const IV: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

/// Compress whole 128-byte blocks using SHA512H/H2/SU0/SU1.
///
/// # Safety
/// Requires FEAT_SHA512. On `aarch64-apple-darwin` the `sha3` target feature
/// (which LLVM defines as "SHA512 and SHA3") is enabled by default, so this is
/// statically satisfied; elsewhere check `hw.optional.arm.FEAT_SHA512`.
#[target_feature(enable = "sha3")]
pub unsafe fn compress(state: &mut [u64; 8], data: &[u8]) {
    unsafe {
        let mut a = vld1q_u64(state.as_ptr());
        let mut b = vld1q_u64(state.as_ptr().add(2));
        let mut c = vld1q_u64(state.as_ptr().add(4));
        let mut d = vld1q_u64(state.as_ptr().add(6));

        for block in data.chunks_exact(128) {
            let (sa, sb, sc, sd) = (a, b, c, d);

            // SHA-512 is big-endian; NEON loads little-endian.
            let mut w = [vdupq_n_u64(0); 8];
            for i in 0..8 {
                w[i] = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block.as_ptr().add(i * 16))));
            }

            for step in 0..40 {
                let kw = vaddq_u64(vld1q_u64(K512.as_ptr().add(step * 2)), w[step % 8]);
                let kw = vextq_u64::<1>(kw, kw);

                let t5 = vextq_u64::<1>(c, d);
                let t6 = vextq_u64::<1>(b, c);

                if step < 32 {
                    w[step % 8] = vsha512su0q_u64(w[step % 8], w[(step + 1) % 8]);
                }

                let mut nd = vaddq_u64(d, kw);
                nd = vsha512hq_u64(nd, t5, t6);

                if step < 32 {
                    let ext = vextq_u64::<1>(w[(step + 4) % 8], w[(step + 5) % 8]);
                    w[step % 8] = vsha512su1q_u64(w[step % 8], w[(step + 7) % 8], ext);
                }

                let aux = vaddq_u64(b, nd);
                nd = vsha512h2q_u64(nd, b, a);

                // Roles rotate: (A,B,C,D) <- (D', A, aux, C).
                let (old_a, old_c) = (a, c);
                a = nd;
                b = old_a;
                c = aux;
                d = old_c;
            }

            a = vaddq_u64(a, sa);
            b = vaddq_u64(b, sb);
            c = vaddq_u64(c, sc);
            d = vaddq_u64(d, sd);
        }

        vst1q_u64(state.as_mut_ptr(), a);
        vst1q_u64(state.as_mut_ptr().add(2), b);
        vst1q_u64(state.as_mut_ptr().add(4), c);
        vst1q_u64(state.as_mut_ptr().add(6), d);
    }
}

/// One-shot SHA-512 digest over `msg`, using the hardware compression above.
pub fn digest(msg: &[u8]) -> [u8; 64] {
    let mut state = IV;
    let full = msg.len() / 128 * 128;
    if full > 0 {
        unsafe { compress(&mut state, &msg[..full]) };
    }
    let mut tail = [0u8; 256];
    let rem = msg.len() - full;
    tail[..rem].copy_from_slice(&msg[full..]);
    tail[rem] = 0x80;
    let bitlen = (msg.len() as u128) * 8;
    let tail_len = if rem < 112 { 128 } else { 256 };
    tail[tail_len - 16..tail_len].copy_from_slice(&bitlen.to_be_bytes());
    unsafe { compress(&mut state, &tail[..tail_len]) };

    let mut out = [0u8; 64];
    for i in 0..8 {
        out[i * 8..i * 8 + 8].copy_from_slice(&state[i].to_be_bytes());
    }
    out
}
