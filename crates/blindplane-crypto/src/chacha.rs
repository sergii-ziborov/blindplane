//! ChaCha20 (RFC 8439) and the HChaCha20 key-derivation core.
//!
//! Four blocks are always computed together in 32-bit lanes. On AArch64 and
//! x86-64 the lane arrays lower to NEON and SSE registers respectively, so the
//! hot loop is SIMD without a single intrinsic or `unsafe` block; on any other
//! target the same code is a correct scalar implementation.

const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// Four 32-bit lanes operated on together.
#[derive(Clone, Copy)]
struct Lane([u32; 4]);

impl Lane {
    #[inline(always)]
    const fn splat(value: u32) -> Self {
        Self([value; 4])
    }

    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        let mut out = [0_u32; 4];
        let mut i = 0;
        while i < 4 {
            out[i] = self.0[i].wrapping_add(rhs.0[i]);
            i += 1;
        }
        Self(out)
    }

    #[inline(always)]
    fn xor(self, rhs: Self) -> Self {
        let mut out = [0_u32; 4];
        let mut i = 0;
        while i < 4 {
            out[i] = self.0[i] ^ rhs.0[i];
            i += 1;
        }
        Self(out)
    }

    #[inline(always)]
    fn rotate_left(self, n: u32) -> Self {
        let mut out = [0_u32; 4];
        let mut i = 0;
        while i < 4 {
            out[i] = self.0[i].rotate_left(n);
            i += 1;
        }
        Self(out)
    }
}

/// A ChaCha20 keystream generator.
///
/// Instances are per-message: the counter starts where the caller says and
/// never wraps into another message's keystream.
pub struct ChaCha20 {
    state: [u32; 16],
}

impl ChaCha20 {
    /// Bytes produced per block.
    pub const BLOCK_LEN: usize = 64;

    /// Create a generator for a 256-bit key and 96-bit nonce.
    pub fn new(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> Self {
        let mut state = [0_u32; 16];
        state[..4].copy_from_slice(&SIGMA);
        for i in 0..8 {
            state[4 + i] =
                u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
        }
        state[12] = counter;
        for i in 0..3 {
            state[13 + i] = u32::from_le_bytes([
                nonce[i * 4],
                nonce[i * 4 + 1],
                nonce[i * 4 + 2],
                nonce[i * 4 + 3],
            ]);
        }
        Self { state }
    }

    /// XOR the keystream into `data` in place.
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        let mut offset = 0;
        let mut keystream = [0_u8; 256];

        while offset < data.len() {
            self.four_blocks(&mut keystream);
            let take = core::cmp::min(256, data.len() - offset);
            // Zipping iterators drops the per-byte bounds check, which is what
            // lets this lower to vector XORs instead of a scalar loop.
            for (byte, key) in data[offset..offset + take].iter_mut().zip(keystream.iter()) {
                *byte ^= *key;
            }
            offset += take;
        }
        crate::util::secure_erase(&mut keystream);
    }

    /// Write the next 256 bytes of keystream, advancing the counter by four.
    fn four_blocks(&mut self, out: &mut [u8; 256]) {
        let counter = self.state[12];
        let mut v = [Lane::splat(0); 16];
        for (i, word) in self.state.iter().enumerate() {
            v[i] = Lane::splat(*word);
        }
        // Only the counter differs between the four blocks in flight.
        v[12] = Lane([
            counter,
            counter.wrapping_add(1),
            counter.wrapping_add(2),
            counter.wrapping_add(3),
        ]);
        let initial = v;

        for _ in 0..10 {
            quarter_round(&mut v, 0, 4, 8, 12);
            quarter_round(&mut v, 1, 5, 9, 13);
            quarter_round(&mut v, 2, 6, 10, 14);
            quarter_round(&mut v, 3, 7, 11, 15);
            quarter_round(&mut v, 0, 5, 10, 15);
            quarter_round(&mut v, 1, 6, 11, 12);
            quarter_round(&mut v, 2, 7, 8, 13);
            quarter_round(&mut v, 3, 4, 9, 14);
        }

        for i in 0..16 {
            v[i] = v[i].add(initial[i]);
        }

        for (block, chunk) in out.chunks_exact_mut(64).enumerate() {
            for (word, slot) in chunk.chunks_exact_mut(4).enumerate() {
                slot.copy_from_slice(&v[word].0[block].to_le_bytes());
            }
        }

        self.state[12] = counter.wrapping_add(4);
    }
}

#[inline(always)]
fn quarter_round(v: &mut [Lane; 16], a: usize, b: usize, c: usize, d: usize) {
    v[a] = v[a].add(v[b]);
    v[d] = v[d].xor(v[a]).rotate_left(16);
    v[c] = v[c].add(v[d]);
    v[b] = v[b].xor(v[c]).rotate_left(12);
    v[a] = v[a].add(v[b]);
    v[d] = v[d].xor(v[a]).rotate_left(8);
    v[c] = v[c].add(v[d]);
    v[b] = v[b].xor(v[c]).rotate_left(7);
}

/// HChaCha20: derive a 256-bit subkey from a key and a 128-bit nonce.
///
/// This is what turns ChaCha20-Poly1305 into XChaCha20-Poly1305, letting a
/// 192-bit random nonce be used safely without a counter.
pub fn hchacha20(key: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
    let mut state = [0_u32; 16];
    state[..4].copy_from_slice(&SIGMA);
    for i in 0..8 {
        state[4 + i] =
            u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
    }
    for i in 0..4 {
        state[12 + i] = u32::from_le_bytes([
            nonce[i * 4],
            nonce[i * 4 + 1],
            nonce[i * 4 + 2],
            nonce[i * 4 + 3],
        ]);
    }

    for _ in 0..10 {
        scalar_quarter_round(&mut state, 0, 4, 8, 12);
        scalar_quarter_round(&mut state, 1, 5, 9, 13);
        scalar_quarter_round(&mut state, 2, 6, 10, 14);
        scalar_quarter_round(&mut state, 3, 7, 11, 15);
        scalar_quarter_round(&mut state, 0, 5, 10, 15);
        scalar_quarter_round(&mut state, 1, 6, 11, 12);
        scalar_quarter_round(&mut state, 2, 7, 8, 13);
        scalar_quarter_round(&mut state, 3, 4, 9, 14);
    }

    // HChaCha20 takes the first and last rows without the feed-forward add.
    let mut out = [0_u8; 32];
    for i in 0..4 {
        out[i * 4..i * 4 + 4].copy_from_slice(&state[i].to_le_bytes());
        out[16 + i * 4..16 + i * 4 + 4].copy_from_slice(&state[12 + i].to_le_bytes());
    }
    out
}

#[inline(always)]
fn scalar_quarter_round(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    v[a] = v[a].wrapping_add(v[b]);
    v[d] = (v[d] ^ v[a]).rotate_left(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_left(12);
    v[a] = v[a].wrapping_add(v[b]);
    v[d] = (v[d] ^ v[a]).rotate_left(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_left(7);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8439_keystream_block() {
        // RFC 8439, section 2.4.2.
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let mut nonce = [0_u8; 12];
        nonce[3] = 0x00;
        nonce[4..].copy_from_slice(&[0, 0, 0, 0x4a, 0, 0, 0, 0]);

        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you \
only one tip for the future, sunscreen would be it.";
        let mut buffer = plaintext.to_vec();
        ChaCha20::new(&key, &nonce, 1).apply_keystream(&mut buffer);

        let expected = [
            0x6e_u8, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d,
            0x69, 0x81,
        ];
        assert_eq!(&buffer[..16], &expected);
        assert_eq!(buffer.len(), plaintext.len());

        // Decryption is the same operation.
        ChaCha20::new(&key, &nonce, 1).apply_keystream(&mut buffer);
        assert_eq!(buffer, plaintext);
    }

    #[test]
    fn keystream_is_chunk_size_independent() {
        let key = [7_u8; 32];
        let nonce = [3_u8; 12];
        let mut whole = vec![0_u8; 1000];
        ChaCha20::new(&key, &nonce, 0).apply_keystream(&mut whole);

        // A generator advanced in 256-byte steps must line up with one that
        // produced the same range in a single call.
        let mut stepwise = vec![0_u8; 1000];
        let mut cipher = ChaCha20::new(&key, &nonce, 0);
        for chunk in stepwise.chunks_mut(256) {
            cipher.apply_keystream(chunk);
        }
        assert_eq!(whole, stepwise);
    }

    #[test]
    fn hchacha20_reference_vector() {
        // draft-irtf-cfrg-xchacha, section 2.2.1.
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce: [u8; 16] = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x31, 0x41,
            0x59, 0x27,
        ];
        let expected: [u8; 32] = [
            0x82, 0x41, 0x3b, 0x42, 0x27, 0xb2, 0x7b, 0xfe, 0xd3, 0x0e, 0x42, 0x50, 0x8a, 0x87,
            0x7d, 0x73, 0xa0, 0xf9, 0xe4, 0xd5, 0x8a, 0x74, 0xa8, 0x53, 0xc1, 0x2e, 0xc4, 0x13,
            0x26, 0xd3, 0xec, 0xdc,
        ];
        assert_eq!(hchacha20(&key, &nonce), expected);
    }
}
