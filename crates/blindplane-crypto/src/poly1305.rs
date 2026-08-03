//! Poly1305 one-time authenticator (RFC 8439).
//!
//! The accumulator is held in three limbs of 44, 44 and 42 bits, so a block
//! multiplication is nine 64x64->128 products with no reduction branches. The
//! final comparison against `2^130 - 5` is done with a mask rather than a
//! conditional jump.

use crate::util::{Choice, ct_eq_bytes};

const LIMB_MASK: u64 = 0xfffffffffff; // 2^44 - 1
const TOP_MASK: u64 = 0x3ffffffffff; // 2^42 - 1

/// Poly1305 over a one-time 256-bit key.
///
/// A key must never authenticate two different messages: doing so reveals `r`
/// and lets anyone forge tags. In the AEAD constructions here, the key is
/// derived from the cipher's first keystream block, which makes reuse
/// impossible as long as nonces are unique.
pub struct Poly1305 {
    r: [u64; 3],
    s: [u64; 3],
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

        // Clamping: the specified bits of r are forced to zero.
        let r = [
            t0 & 0x0ffc0fffffff,
            ((t0 >> 44) | (t1 << 20)) & 0x0fffffc0ffff,
            (t1 >> 24) & 0x000ffffffc0f,
        ];
        // Precomputed r1*20 and r2*20 for the reduction step.
        let s = [0, r[1].wrapping_mul(20), r[2].wrapping_mul(20)];

        let mut pad = [0_u8; 16];
        pad.copy_from_slice(&key[16..32]);

        Self {
            r,
            s,
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
                self.absorb(&block, 1 << 40);
                self.buffered = 0;
            }
        }

        while data.len() >= 16 {
            let mut block = [0_u8; 16];
            block.copy_from_slice(&data[..16]);
            self.absorb(&block, 1 << 40);
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
            let buffered = self.buffered;
            self.buffered = 0;
            let _ = buffered;
            self.absorb(&block, 0);
        }

        let [mut h0, mut h1, mut h2] = self.h;

        // Fully carry the accumulator.
        let mut c = h1 >> 44;
        h1 &= LIMB_MASK;
        h2 = h2.wrapping_add(c);
        c = h2 >> 42;
        h2 &= TOP_MASK;
        h0 = h0.wrapping_add(c.wrapping_mul(5));
        c = h0 >> 44;
        h0 &= LIMB_MASK;
        h1 = h1.wrapping_add(c);
        c = h1 >> 44;
        h1 &= LIMB_MASK;
        h2 = h2.wrapping_add(c);
        c = h2 >> 42;
        h2 &= TOP_MASK;
        h0 = h0.wrapping_add(c.wrapping_mul(5));
        c = h0 >> 44;
        h0 &= LIMB_MASK;
        h1 = h1.wrapping_add(c);

        // Compute h + -p and keep it only if h >= p.
        let mut g0 = h0.wrapping_add(5);
        c = g0 >> 44;
        g0 &= LIMB_MASK;
        let mut g1 = h1.wrapping_add(c);
        c = g1 >> 44;
        g1 &= LIMB_MASK;
        let g2 = h2.wrapping_add(c).wrapping_sub(1_u64 << 42);

        let mask = (g2 >> 63).wrapping_sub(1); // all ones when h >= p
        g0 &= mask;
        g1 &= mask;
        let g2 = g2 & mask;
        let inverse = !mask;
        h0 = (h0 & inverse) | g0;
        h1 = (h1 & inverse) | g1;
        h2 = (h2 & inverse) | g2;

        // Add the key's second half.
        let t0 = u64::from_le_bytes(self.pad[0..8].try_into().expect("8 bytes"));
        let t1 = u64::from_le_bytes(self.pad[8..16].try_into().expect("8 bytes"));
        h0 = h0.wrapping_add(t0 & LIMB_MASK);
        c = h0 >> 44;
        h0 &= LIMB_MASK;
        h1 = h1
            .wrapping_add(((t0 >> 44) | (t1 << 20)) & LIMB_MASK)
            .wrapping_add(c);
        c = h1 >> 44;
        h1 &= LIMB_MASK;
        h2 = h2.wrapping_add((t1 >> 24) & TOP_MASK).wrapping_add(c);
        h2 &= TOP_MASK;

        let low = h0 | (h1 << 44);
        let high = (h1 >> 20) | (h2 << 24);

        let mut tag = [0_u8; 16];
        tag[..8].copy_from_slice(&low.to_le_bytes());
        tag[8..].copy_from_slice(&high.to_le_bytes());
        self.s = [0; 3];
        tag
    }

    /// Finish and compare against an expected tag in constant time.
    pub fn verify(self, expected: &[u8]) -> Choice {
        let tag = self.finalize();
        ct_eq_bytes(&tag, expected)
    }

    #[inline(always)]
    fn absorb(&mut self, block: &[u8; 16], high_bit: u64) {
        let t0 = u64::from_le_bytes(block[0..8].try_into().expect("8 bytes"));
        let t1 = u64::from_le_bytes(block[8..16].try_into().expect("8 bytes"));

        let h0 = self.h[0].wrapping_add(t0 & LIMB_MASK);
        let h1 = self.h[1].wrapping_add(((t0 >> 44) | (t1 << 20)) & LIMB_MASK);
        let h2 = self.h[2].wrapping_add(((t1 >> 24) & TOP_MASK) | high_bit);

        let (r0, r1, r2) = (self.r[0], self.r[1], self.r[2]);
        let (s1, s2) = (self.s[1], self.s[2]);

        let d0 = u128::from(h0) * u128::from(r0)
            + u128::from(h1) * u128::from(s2)
            + u128::from(h2) * u128::from(s1);
        let d1 = u128::from(h0) * u128::from(r1)
            + u128::from(h1) * u128::from(r0)
            + u128::from(h2) * u128::from(s2);
        let d2 = u128::from(h0) * u128::from(r2)
            + u128::from(h1) * u128::from(r1)
            + u128::from(h2) * u128::from(r0);

        let mut c = (d0 >> 44) as u64;
        let mut out0 = (d0 as u64) & LIMB_MASK;
        let d1 = d1 + u128::from(c);
        c = (d1 >> 44) as u64;
        let out1 = (d1 as u64) & LIMB_MASK;
        let d2 = d2 + u128::from(c);
        c = (d2 >> 42) as u64;
        let out2 = (d2 as u64) & TOP_MASK;

        out0 = out0.wrapping_add(c.wrapping_mul(5));
        let carry = out0 >> 44;
        out0 &= LIMB_MASK;

        self.h = [out0, out1.wrapping_add(carry), out2];
    }
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        self.r = [0; 3];
        self.s = [0; 3];
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
}
