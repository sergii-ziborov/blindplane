//! Poly1305 one-time authenticator (RFC 8439).
//!
//! The accumulator is two 64-bit limbs plus a small overflow word, the base
//! 2^64 layout OpenSSL's portable implementation uses: one block is four
//! 64x64->128 products plus two short products, against nine wide products
//! for the classic 44-bit-limb layout. The reduction leans on the clamp
//! guaranteeing `r1` is a multiple of four, so `r1 + (r1 >> 2)` is exactly
//! `r1 * 5 / 4` and folds the modulus without a branch. The final comparison
//! against `2^130 - 5` is done with a mask rather than a conditional jump.

use crate::util::{Choice, ct_eq_bytes};

/// Poly1305 over a one-time 256-bit key.
///
/// A key must never authenticate two different messages: doing so reveals `r`
/// and lets anyone forge tags. In the AEAD constructions here, the key is
/// derived from the cipher's first keystream block, which makes reuse
/// impossible as long as nonces are unique.
pub struct Poly1305 {
    r: [u64; 2],
    /// `r[1] * 5 / 4`, the folded high limb used by the reduction.
    s1: u64,
    /// `h[2]` never exceeds 4 between blocks; the bounds are in `absorb`.
    h: [u64; 3],
    pad: [u8; 16],
    buffer: [u8; 16],
    buffered: usize,
}

impl Poly1305 {
    /// Tag length in bytes.
    pub const TAG_LEN: usize = 16;

    /// Start an authenticator under a one-time key.
    pub fn new(key: &[u8; 32]) -> Self {
        let t0 = u64::from_le_bytes(key[0..8].try_into().expect("8 bytes"));
        let t1 = u64::from_le_bytes(key[8..16].try_into().expect("8 bytes"));

        // Clamping: the specified bits of r are forced to zero, which also
        // bounds both limbs below 2^60 and makes r[1] a multiple of four.
        let r = [t0 & 0x0ffffffc0fffffff, t1 & 0x0ffffffc0ffffffc];
        let s1 = r[1] + (r[1] >> 2);

        let mut pad = [0_u8; 16];
        pad.copy_from_slice(&key[16..32]);

        Self {
            r,
            s1,
            h: [0; 3],
            pad,
            buffer: [0; 16],
            buffered: 0,
        }
    }

    /// Absorb more message bytes.
    pub fn update(&mut self, mut data: &[u8]) {
        if self.buffered > 0 {
            let take = core::cmp::min(16 - self.buffered, data.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered == 16 {
                let block = self.buffer;
                self.absorb(&block, 1);
                self.buffered = 0;
            }
        }

        while data.len() >= 16 {
            let mut block = [0_u8; 16];
            block.copy_from_slice(&data[..16]);
            self.absorb(&block, 1);
            data = &data[16..];
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffered = data.len();
        }
    }

    /// Absorb zero bytes until the message length is a multiple of 16.
    ///
    /// The AEAD constructions use this between the associated data and the
    /// ciphertext so the two cannot be shifted into each other.
    pub fn pad_to_block(&mut self) {
        if self.buffered > 0 {
            let padding = 16 - self.buffered;
            self.update(&[0_u8; 16][..padding]);
        }
    }

    /// Finish and return the 16-byte tag.
    pub fn finalize(mut self) -> [u8; 16] {
        if self.buffered > 0 {
            let mut block = [0_u8; 16];
            block[..self.buffered].copy_from_slice(&self.buffer[..self.buffered]);
            block[self.buffered] = 1;
            self.buffered = 0;
            self.absorb(&block, 0);
        }

        let [h0, h1, h2] = self.h;

        // Compute h + 5 and keep it only if h >= 2^130 - 5. Between blocks
        // h2 <= 4, so h < 2^130 + 2^128 < 2p and one subtraction settles it.
        let t = u128::from(h0) + 5;
        let g0 = t as u64;
        let t = u128::from(h1) + (t >> 64);
        let g1 = t as u64;
        let g2 = h2.wrapping_add((t >> 64) as u64);

        // Bit 130 of h + 5 set means h >= p; select g in that case.
        let mask = 0_u64.wrapping_sub(g2 >> 2);
        let h0 = (h0 & !mask) | (g0 & mask);
        let h1 = (h1 & !mask) | (g1 & mask);

        // Add the key's second half modulo 2^128.
        let t0 = u64::from_le_bytes(self.pad[0..8].try_into().expect("8 bytes"));
        let t1 = u64::from_le_bytes(self.pad[8..16].try_into().expect("8 bytes"));
        let t = u128::from(h0) + u128::from(t0);
        let h0 = t as u64;
        let h1 = h1.wrapping_add(t1).wrapping_add((t >> 64) as u64);

        let mut tag = [0_u8; 16];
        tag[..8].copy_from_slice(&h0.to_le_bytes());
        tag[8..].copy_from_slice(&h1.to_le_bytes());
        self.s1 = 0;
        tag
    }

    /// Finish and compare against an expected tag in constant time.
    pub fn verify(self, expected: &[u8]) -> Choice {
        let tag = self.finalize();
        ct_eq_bytes(&tag, expected)
    }

    /// One block of `h = (h + m) * r mod (2^130 - 5)`, partially reduced.
    ///
    /// Bounds, so every step visibly fits: `h2 <= 4` on entry, so after the
    /// message add `h2 <= 6`. With both `r` limbs below 2^60, `h2 * s1` and
    /// `h2 * r0` stay below 2^63 and the wide sums below 2^126. The fold
    /// returns `h2` to at most 3 plus one carry, restoring the invariant.
    #[inline(always)]
    fn absorb(&mut self, block: &[u8; 16], padbit: u64) {
        let m0 = u64::from_le_bytes(block[0..8].try_into().expect("8 bytes"));
        let m1 = u64::from_le_bytes(block[8..16].try_into().expect("8 bytes"));

        let (r0, r1) = (self.r[0], self.r[1]);
        let s1 = self.s1;

        // h += m, with the padbit as bit 128.
        let t = u128::from(self.h[0]) + u128::from(m0);
        let h0 = t as u64;
        let t = u128::from(self.h[1]) + (t >> 64) + u128::from(m1);
        let h1 = t as u64;
        let h2 = self.h[2]
            .wrapping_add((t >> 64) as u64)
            .wrapping_add(padbit);

        // h *= r, folding 2^128 * x to (5/4) * r1 * x as it appears.
        let d0 = u128::from(h0) * u128::from(r0) + u128::from(h1) * u128::from(s1);
        let d1 = u128::from(h0) * u128::from(r1)
            + u128::from(h1) * u128::from(r0)
            + u128::from(h2.wrapping_mul(s1));
        let h2r = h2.wrapping_mul(r0);

        let h0 = d0 as u64;
        let d1 = d1 + (d0 >> 64);
        let h1 = d1 as u64;
        let h2 = h2r.wrapping_add((d1 >> 64) as u64);

        // Fold the bits at and above 2^130 back in: h += 5 * (h >> 130).
        let c = (h2 >> 2).wrapping_add(h2 & !3);
        let h2 = h2 & 3;
        let t = u128::from(h0) + u128::from(c);
        let h0 = t as u64;
        let t = u128::from(h1) + (t >> 64);
        let h1 = t as u64;
        let h2 = h2.wrapping_add((t >> 64) as u64);

        self.h = [h0, h1, h2];
    }
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        self.r = [0; 2];
        self.s1 = 0;
        self.h = [0; 3];
        crate::util::secure_erase(&mut self.pad);
        crate::util::secure_erase(&mut self.buffer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8439_tag() {
        // RFC 8439, section 2.5.2.
        let key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];
        let message = b"Cryptographic Forum Research Group";
        let mut mac = Poly1305::new(&key);
        mac.update(message);
        assert_eq!(
            mac.finalize(),
            [
                0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
                0x27, 0xa9
            ]
        );
    }

    #[test]
    fn all_zero_key_gives_zero_tag() {
        // RFC 8439 A.3, test vector 1.
        let mut mac = Poly1305::new(&[0_u8; 32]);
        mac.update(&[0_u8; 64]);
        assert_eq!(mac.finalize(), [0_u8; 16]);
    }

    #[test]
    fn wraparound_vector() {
        // RFC 8439 A.3, test vector 3: r = 0, s = key's second half.
        let mut key = [0_u8; 32];
        key[16..].copy_from_slice(&[
            0x36, 0xe5, 0xf6, 0xb5, 0xc5, 0xe0, 0x60, 0x70, 0xf0, 0xef, 0xca, 0x96, 0x22, 0x7a,
            0x86, 0x3e,
        ]);
        let mut mac = Poly1305::new(&key);
        mac.update(&[
            0x41, 0x6e, 0x79, 0x20, 0x73, 0x75, 0x62, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e,
            0x20, 0x74, 0x6f, 0x20, 0x74, 0x68, 0x65, 0x20, 0x49, 0x45, 0x54, 0x46, 0x20, 0x69,
            0x6e, 0x74, 0x65, 0x6e,
        ]);
        assert_eq!(
            mac.finalize(),
            [
                0x36, 0xe5, 0xf6, 0xb5, 0xc5, 0xe0, 0x60, 0x70, 0xf0, 0xef, 0xca, 0x96, 0x22, 0x7a,
                0x86, 0x3e
            ]
        );
    }

    #[test]
    fn streaming_matches_one_shot() {
        let key: [u8; 32] = core::array::from_fn(|i| (i * 7 + 1) as u8);
        let data: Vec<u8> = (0..333_u32).map(|i| (i * 5) as u8).collect();

        let mut one_shot = Poly1305::new(&key);
        one_shot.update(&data);
        let expected = one_shot.finalize();

        for chunk_size in [1_usize, 3, 15, 16, 17, 64] {
            let mut streamed = Poly1305::new(&key);
            for chunk in data.chunks(chunk_size) {
                streamed.update(chunk);
            }
            assert_eq!(streamed.finalize(), expected, "chunk size {chunk_size}");
        }
    }

    #[test]
    fn verification_rejects_modified_tag() {
        let key = [9_u8; 32];
        let mut mac = Poly1305::new(&key);
        mac.update(b"message");
        let mut tag = mac.finalize();

        let mut good = Poly1305::new(&key);
        good.update(b"message");
        assert!(good.verify(&tag).is_set());

        tag[0] ^= 1;
        let mut bad = Poly1305::new(&key);
        bad.update(b"message");
        assert!(!bad.verify(&tag).is_set());
    }

    /// Poly1305 evaluated directly from the RFC 8439 pseudocode with plain
    /// 320-bit school arithmetic. It shares no code, no representation and no
    /// reduction strategy with the production path, so a systematic limb or
    /// carry error there cannot also be here.
    mod reference {
        /// A little-endian 320-bit integer.
        type Wide = [u64; 5];

        fn add(a: Wide, b: Wide) -> Wide {
            let mut out = [0_u64; 5];
            let mut carry = 0_u128;
            for i in 0..5 {
                let t = u128::from(a[i]) + u128::from(b[i]) + carry;
                out[i] = t as u64;
                carry = t >> 64;
            }
            out
        }

        fn sub(a: Wide, b: Wide) -> Wide {
            let mut out = [0_u64; 5];
            let mut borrow = 0_i128;
            for i in 0..5 {
                let t = i128::from(a[i]) - i128::from(b[i]) - borrow;
                out[i] = t as u64;
                borrow = i128::from(t < 0);
            }
            out
        }

        fn geq(a: Wide, b: Wide) -> bool {
            for i in (0..5).rev() {
                if a[i] != b[i] {
                    return a[i] > b[i];
                }
            }
            true
        }

        fn mul(a: Wide, b: Wide) -> [u64; 10] {
            let mut out = [0_u64; 10];
            for i in 0..5 {
                let mut carry = 0_u128;
                for j in 0..5 {
                    let t = u128::from(out[i + j]) + u128::from(a[i]) * u128::from(b[j]) + carry;
                    out[i + j] = t as u64;
                    carry = t >> 64;
                }
                // Row i is the first to touch position i + 5.
                out[i + 5] = carry as u64;
            }
            out
        }

        /// Reduce a 320-bit value modulo `2^130 - 5` by folding the high bits
        /// down three times, then subtracting the modulus while it still fits.
        fn mod_p(x: [u64; 10]) -> Wide {
            fn fold(x: [u64; 10]) -> [u64; 10] {
                let mut high = [0_u64; 10];
                for i in 0..8 {
                    let next = if i + 3 < 10 { x[i + 3] } else { 0 };
                    high[i] = (x[i + 2] >> 2) | (next << 62);
                }
                let mut out = [x[0], x[1], x[2] & 3, 0, 0, 0, 0, 0, 0, 0];
                let mut carry = 0_u128;
                for i in 0..10 {
                    let t = u128::from(out[i]) + 5 * u128::from(high[i]) + carry;
                    out[i] = t as u64;
                    carry = t >> 64;
                }
                out
            }
            let x = fold(fold(fold(x)));
            let p: Wide = [0xffff_ffff_ffff_fffb, u64::MAX, 3, 0, 0];
            let mut n: Wide = [x[0], x[1], x[2], x[3], x[4]];
            for _ in 0..2 {
                if geq(n, p) {
                    n = sub(n, p);
                }
            }
            n
        }

        pub fn tag(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
            let r: Wide = [
                u64::from_le_bytes(key[0..8].try_into().unwrap()) & 0x0ffffffc0fffffff,
                u64::from_le_bytes(key[8..16].try_into().unwrap()) & 0x0ffffffc0ffffffc,
                0,
                0,
                0,
            ];
            let s: Wide = [
                u64::from_le_bytes(key[16..24].try_into().unwrap()),
                u64::from_le_bytes(key[24..32].try_into().unwrap()),
                0,
                0,
                0,
            ];

            let mut accumulator: Wide = [0; 5];
            for chunk in msg.chunks(16) {
                let mut block = [0_u8; 17];
                block[..chunk.len()].copy_from_slice(chunk);
                block[chunk.len()] = 1;
                let n: Wide = [
                    u64::from_le_bytes(block[0..8].try_into().unwrap()),
                    u64::from_le_bytes(block[8..16].try_into().unwrap()),
                    u64::from(block[16]),
                    0,
                    0,
                ];
                accumulator = mod_p(mul(add(accumulator, n), r));
            }

            let out = add(accumulator, s);
            let mut tag = [0_u8; 16];
            tag[..8].copy_from_slice(&out[0].to_le_bytes());
            tag[8..].copy_from_slice(&out[1].to_le_bytes());
            tag
        }
    }

    #[test]
    fn matches_rfc_pseudocode_reference_across_many_inputs() {
        let mut state = 0x243f_6a88_85a3_08d3_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        for case in 0..300_u32 {
            let mut key = [0_u8; 32];
            for byte in &mut key {
                *byte = next() as u8;
            }
            // Every seventh case uses the maximal clamped r, and every fifth
            // an all-ones message: the carry-heaviest corners.
            if case % 7 == 0 {
                key[..16].fill(0xff);
            }
            let len = (next() % 300) as usize;
            let mut msg = vec![0_u8; len];
            for byte in &mut msg {
                *byte = next() as u8;
            }
            if case % 5 == 0 {
                msg.fill(0xff);
            }

            let mut mac = Poly1305::new(&key);
            mac.update(&msg);
            assert_eq!(
                mac.finalize(),
                reference::tag(&key, &msg),
                "case {case} length {len}"
            );
        }
    }
}
