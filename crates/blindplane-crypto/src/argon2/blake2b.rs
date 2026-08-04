//! BLAKE2b, the hash Argon2id builds its extended hash `H'` from.

use crate::util::secure_erase;

const BLAKE2B_IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// BLAKE2b with a configurable digest length of 1 to 64 bytes.
#[derive(Clone)]
pub struct Blake2b {
    h: [u64; 8],
    buffer: [u8; 128],
    buffered: usize,
    counter: u128,
    output_len: usize,
}

impl Blake2b {
    /// Start an unkeyed digest producing `output_len` bytes.
    pub fn new(output_len: usize) -> Self {
        assert!(
            (1..=64).contains(&output_len),
            "BLAKE2b output length must be 1..=64"
        );
        let mut h = BLAKE2B_IV;
        // Parameter block: digest length, key length 0, fanout 1, depth 1.
        h[0] ^= 0x0101_0000 ^ (output_len as u64);
        Self {
            h,
            buffer: [0; 128],
            buffered: 0,
            counter: 0,
            output_len,
        }
    }

    /// Absorb more input.
    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            if self.buffered == 128 {
                // A full buffer is only compressed once more input is known to
                // exist, because the last block is flagged differently.
                self.counter += 128;
                let block = self.buffer;
                let counter = self.counter;
                compress(&mut self.h, &block, counter, false);
                self.buffered = 0;
            }
            let take = core::cmp::min(128 - self.buffered, data.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
        }
    }

    /// Finish and write the digest.
    pub fn finalize_into(mut self, out: &mut [u8]) {
        assert_eq!(out.len(), self.output_len, "output buffer length mismatch");
        self.counter += self.buffered as u128;
        for byte in self.buffer.iter_mut().skip(self.buffered) {
            *byte = 0;
        }
        let block = self.buffer;
        let counter = self.counter;
        compress(&mut self.h, &block, counter, true);

        let mut digest = [0_u8; 64];
        for (i, word) in self.h.iter().enumerate() {
            digest[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
        }
        out.copy_from_slice(&digest[..self.output_len]);
        secure_erase(&mut digest);
    }

    /// One-shot digest into a fixed-size array.
    pub fn digest<const N: usize>(data: &[u8]) -> [u8; N] {
        let mut hasher = Self::new(N);
        hasher.update(data);
        let mut out = [0_u8; N];
        hasher.finalize_into(&mut out);
        out
    }
}

fn compress(h: &mut [u64; 8], block: &[u8; 128], counter: u128, last: bool) {
    let mut m = [0_u64; 16];
    for (i, word) in m.iter_mut().enumerate() {
        let mut buf = [0_u8; 8];
        buf.copy_from_slice(&block[i * 8..i * 8 + 8]);
        *word = u64::from_le_bytes(buf);
    }

    let mut v = [0_u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&BLAKE2B_IV);
    v[12] ^= counter as u64;
    v[13] ^= (counter >> 64) as u64;
    if last {
        v[14] = !v[14];
    }

    for round in 0..12 {
        let s = &SIGMA[round];
        mix(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        mix(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        mix(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        mix(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        mix(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        mix(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        mix(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        mix(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

#[inline(always)]
fn mix(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}
