//! ChaCha20 (RFC 8439) and the HChaCha20 key-derivation core.
//!
//! Four blocks are always computed together in 32-bit lanes. On AArch64 and
//! x86-64 the lane arrays lower to NEON and SSE registers respectively, so the
//! hot loop is SIMD without a single intrinsic or `unsafe` block; on any other
//! target the same code is a correct scalar implementation.

#[cfg(all(feature = "accel", target_arch = "aarch64"))]
#[allow(
    clippy::cast_ptr_alignment,
    reason = "vld1q/vst1q perform unaligned NEON access by contract"
)]
mod neon;
#[cfg(test)]
mod tests;

const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// Four 32-bit lanes operated on together (portable fallback only).
#[cfg(not(all(feature = "accel", target_arch = "aarch64")))]
#[derive(Clone, Copy)]
struct Lane([u32; 4]);

#[cfg(not(all(feature = "accel", target_arch = "aarch64")))]
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
        #[cfg(all(feature = "accel", target_arch = "aarch64"))]
        // SAFETY: NEON is architecturally guaranteed on every AArch64 target
        // that runs this code, so no runtime probe is needed.
        unsafe {
            neon::apply_keystream(&mut self.state, data);
        }

        #[cfg(not(all(feature = "accel", target_arch = "aarch64")))]
        {
            let mut offset = 0;
            let mut keystream = [0_u8; 256];

            while offset < data.len() {
                let counter = self.state[12];
                self.four_blocks(&mut keystream);
                let take = core::cmp::min(256, data.len() - offset);
                for (byte, key) in data[offset..offset + take].iter_mut().zip(keystream.iter()) {
                    *byte ^= *key;
                }
                offset += take;

                // `four_blocks` always advances by four, but a short tail
                // consumes fewer; a later call on the same generator has to
                // resume at the next unused block, not skip ahead.
                let blocks = take.div_ceil(64) as u32;
                self.state[12] = counter.wrapping_add(blocks);
            }
            crate::util::secure_erase(&mut keystream);
        }
    }

    /// Write the next 256 bytes of keystream, advancing the counter by four.
    #[cfg(not(all(feature = "accel", target_arch = "aarch64")))]
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

#[cfg(not(all(feature = "accel", target_arch = "aarch64")))]
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
