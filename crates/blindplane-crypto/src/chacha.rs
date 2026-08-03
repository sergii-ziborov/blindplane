//! ChaCha20 (RFC 8439) and the HChaCha20 key-derivation core.
//!
//! Four blocks are always computed together in 32-bit lanes. On AArch64 and
//! x86-64 the lane arrays lower to NEON and SSE registers respectively, so the
//! hot loop is SIMD without a single intrinsic or `unsafe` block; on any other
//! target the same code is a correct scalar implementation.

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

/// ChaCha20 on NEON, four blocks at a time.
///
/// The portable path expresses lanes as `[u32; 4]` and hopes the autovectorizer
/// notices. It does not: that version measures 6.7 cycles per byte, roughly five
/// times what the hardware can do. This module spells the vectors out.
///
/// Two rotations get dedicated instructions rather than a shift pair:
/// `rotl(x, 16)` is a 16-bit element reverse, and `rotl(x, 8)` is a byte-table
/// permute. The other two use shift-right-and-insert, which fuses the shift and
/// the or.
#[cfg(all(feature = "accel", target_arch = "aarch64"))]
#[allow(
    clippy::cast_ptr_alignment,
    reason = "vld1q/vst1q perform unaligned NEON access by contract"
)]
mod neon {
    use core::arch::aarch64::{
        uint8x16_t, uint32x4_t, vaddq_u32, vdupq_n_u32, veorq_u32, vld1q_u8, vld1q_u32, vqtbl1q_u8,
        vreinterpretq_u8_u32, vreinterpretq_u16_u32, vreinterpretq_u32_u8, vreinterpretq_u32_u16,
        vreinterpretq_u32_u64, vreinterpretq_u64_u32, vrev32q_u16, vshlq_n_u32, vsriq_n_u32,
        vst1q_u32, vtrn1q_u32, vtrn1q_u64, vtrn2q_u32, vtrn2q_u64,
    };

    /// Byte permutation implementing a left rotate by 8 within each 32-bit lane.
    const ROT8: [u8; 16] = [3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14];

    #[inline(always)]
    unsafe fn rotl16(x: uint32x4_t) -> uint32x4_t {
        // Rotating a 32-bit lane by 16 is exactly swapping its two halves.
        unsafe { vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(x))) }
    }

    #[inline(always)]
    unsafe fn rotl8(x: uint32x4_t, table: uint8x16_t) -> uint32x4_t {
        unsafe { vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(x), table)) }
    }

    #[inline(always)]
    unsafe fn rotl12(x: uint32x4_t) -> uint32x4_t {
        unsafe { vsriq_n_u32::<20>(vshlq_n_u32::<12>(x), x) }
    }

    #[inline(always)]
    unsafe fn rotl7(x: uint32x4_t) -> uint32x4_t {
        unsafe { vsriq_n_u32::<25>(vshlq_n_u32::<7>(x), x) }
    }

    /// Transpose four vectors so lane `j` of each becomes vector `j`.
    #[inline(always)]
    unsafe fn transpose(
        a: uint32x4_t,
        b: uint32x4_t,
        c: uint32x4_t,
        d: uint32x4_t,
    ) -> [uint32x4_t; 4] {
        unsafe {
            let t0 = vtrn1q_u32(a, b);
            let t1 = vtrn2q_u32(a, b);
            let t2 = vtrn1q_u32(c, d);
            let t3 = vtrn2q_u32(c, d);
            [
                vreinterpretq_u32_u64(vtrn1q_u64(
                    vreinterpretq_u64_u32(t0),
                    vreinterpretq_u64_u32(t2),
                )),
                vreinterpretq_u32_u64(vtrn1q_u64(
                    vreinterpretq_u64_u32(t1),
                    vreinterpretq_u64_u32(t3),
                )),
                vreinterpretq_u32_u64(vtrn2q_u64(
                    vreinterpretq_u64_u32(t0),
                    vreinterpretq_u64_u32(t2),
                )),
                vreinterpretq_u32_u64(vtrn2q_u64(
                    vreinterpretq_u64_u32(t1),
                    vreinterpretq_u64_u32(t3),
                )),
            ]
        }
    }

    /// XOR the keystream into `data`, advancing `state`'s counter as it goes.
    ///
    /// # Safety
    ///
    /// NEON must be available, which it always is on AArch64.
    #[target_feature(enable = "neon")]
    pub unsafe fn apply_keystream(state: &mut [u32; 16], data: &mut [u8]) {
        // SAFETY: every load and store below is bounded by `data.len()`, and the
        // 64-byte tail is staged through a stack buffer.
        unsafe {
            let rot8 = vld1q_u8(ROT8.as_ptr());
            let mut offset = 0;
            let len = data.len();
            let base = data.as_mut_ptr();

            let lane_offsets = vld1q_u32([0_u32, 1, 2, 3].as_ptr());

            // Eight blocks at a time while there is room for them.
            //
            // Four blocks already fill the 128-bit lanes, so this second group
            // buys nothing in width — it buys independent work. One group is a
            // chain of dependent operations roughly thirteen deep per quarter
            // round, and with only four such chains in flight the core issues
            // about one vector operation per cycle against a budget of four.
            // Interleaving a second group nearly doubles the available
            // instruction-level parallelism.
            while len - offset >= 512 {
                let counter = state[12];

                let mut v = broadcast_state(state, counter, lane_offsets);
                let mut w = broadcast_state(state, counter.wrapping_add(4), lane_offsets);

                for _ in 0..10 {
                    // The two groups are interleaved in source order so the
                    // scheduler sees the independence without having to prove
                    // it across a loop-carried dependency.
                    quarter_round(&mut v, 0, 4, 8, 12, rot8);
                    quarter_round(&mut w, 0, 4, 8, 12, rot8);
                    quarter_round(&mut v, 1, 5, 9, 13, rot8);
                    quarter_round(&mut w, 1, 5, 9, 13, rot8);
                    quarter_round(&mut v, 2, 6, 10, 14, rot8);
                    quarter_round(&mut w, 2, 6, 10, 14, rot8);
                    quarter_round(&mut v, 3, 7, 11, 15, rot8);
                    quarter_round(&mut w, 3, 7, 11, 15, rot8);

                    quarter_round(&mut v, 0, 5, 10, 15, rot8);
                    quarter_round(&mut w, 0, 5, 10, 15, rot8);
                    quarter_round(&mut v, 1, 6, 11, 12, rot8);
                    quarter_round(&mut w, 1, 6, 11, 12, rot8);
                    quarter_round(&mut v, 2, 7, 8, 13, rot8);
                    quarter_round(&mut w, 2, 7, 8, 13, rot8);
                    quarter_round(&mut v, 3, 4, 9, 14, rot8);
                    quarter_round(&mut w, 3, 4, 9, 14, rot8);
                }

                feed_forward(&mut v, state, counter, lane_offsets);
                feed_forward(&mut w, state, counter.wrapping_add(4), lane_offsets);

                emit(base.add(offset), &v);
                emit(base.add(offset + 256), &w);

                offset += 512;
                state[12] = counter.wrapping_add(8);
            }

            while offset < len {
                let counter = state[12];

                let mut v = broadcast_state(state, counter, lane_offsets);

                for _ in 0..10 {
                    // Column rounds.
                    quarter_round(&mut v, 0, 4, 8, 12, rot8);
                    quarter_round(&mut v, 1, 5, 9, 13, rot8);
                    quarter_round(&mut v, 2, 6, 10, 14, rot8);
                    quarter_round(&mut v, 3, 7, 11, 15, rot8);
                    // Diagonal rounds.
                    quarter_round(&mut v, 0, 5, 10, 15, rot8);
                    quarter_round(&mut v, 1, 6, 11, 12, rot8);
                    quarter_round(&mut v, 2, 7, 8, 13, rot8);
                    quarter_round(&mut v, 3, 4, 9, 14, rot8);
                }

                feed_forward(&mut v, state, counter, lane_offsets);

                let remaining = len - offset;
                if remaining >= 256 {
                    emit(base.add(offset), &v);
                    offset += 256;
                    state[12] = counter.wrapping_add(4);
                } else {
                    // Stage the tail so a partial block cannot write past the end.
                    let g0 = transpose(v[0], v[1], v[2], v[3]);
                    let g1 = transpose(v[4], v[5], v[6], v[7]);
                    let g2 = transpose(v[8], v[9], v[10], v[11]);
                    let g3 = transpose(v[12], v[13], v[14], v[15]);
                    let mut keystream = [0_u8; 256];
                    for block in 0..4 {
                        let p = keystream.as_mut_ptr().add(block * 64);
                        vst1q_u32(p.cast::<u32>(), g0[block]);
                        vst1q_u32(p.add(16).cast::<u32>(), g1[block]);
                        vst1q_u32(p.add(32).cast::<u32>(), g2[block]);
                        vst1q_u32(p.add(48).cast::<u32>(), g3[block]);
                    }
                    for (byte, key) in data[offset..].iter_mut().zip(keystream.iter()) {
                        *byte ^= *key;
                    }
                    crate::util::secure_erase(&mut keystream);
                    // The counter must advance by the blocks actually produced,
                    // not a flat four: a later call on the same generator has to
                    // resume at the next unused block. Consuming a flat four here
                    // was invisible to single-shot use and to the AEAD (which
                    // uses a fresh generator each time), but corrupted any
                    // multi-call stream.
                    let blocks = remaining.div_ceil(64) as u32;
                    state[12] = counter.wrapping_add(blocks);
                    offset = len;
                }
            }
        }
    }

    /// Broadcast the state into four lanes, with per-lane counters.
    #[inline(always)]
    unsafe fn broadcast_state(
        state: &[u32; 16],
        counter: u32,
        lane_offsets: uint32x4_t,
    ) -> [uint32x4_t; 16] {
        unsafe {
            let mut v = [vdupq_n_u32(0); 16];
            for (i, slot) in v.iter_mut().enumerate() {
                *slot = vdupq_n_u32(state[i]);
            }
            v[12] = vaddq_u32(vdupq_n_u32(counter), lane_offsets);
            v
        }
    }

    /// The feed-forward addition of the initial state.
    ///
    /// The initial words are re-broadcast from `state` rather than kept live
    /// through the rounds: a second sixteen-vector copy would consume the whole
    /// AArch64 register file and spill the round loop itself.
    #[inline(always)]
    unsafe fn feed_forward(
        v: &mut [uint32x4_t; 16],
        state: &[u32; 16],
        counter: u32,
        lane_offsets: uint32x4_t,
    ) {
        unsafe {
            for (i, slot) in v.iter_mut().enumerate() {
                if i != 12 {
                    *slot = vaddq_u32(*slot, vdupq_n_u32(state[i]));
                }
            }
            v[12] = vaddq_u32(v[12], vaddq_u32(vdupq_n_u32(counter), lane_offsets));
        }
    }

    /// Transpose a finished group back into block order and XOR all 256 bytes.
    #[inline(always)]
    unsafe fn emit(pointer: *mut u8, v: &[uint32x4_t; 16]) {
        unsafe {
            let g0 = transpose(v[0], v[1], v[2], v[3]);
            let g1 = transpose(v[4], v[5], v[6], v[7]);
            let g2 = transpose(v[8], v[9], v[10], v[11]);
            let g3 = transpose(v[12], v[13], v[14], v[15]);
            for block in 0..4 {
                let p = pointer.add(block * 64);
                xor_store(p, g0[block]);
                xor_store(p.add(16), g1[block]);
                xor_store(p.add(32), g2[block]);
                xor_store(p.add(48), g3[block]);
            }
        }
    }

    /// XOR a keystream vector into 16 unaligned bytes.
    #[inline(always)]
    unsafe fn xor_store(pointer: *mut u8, keystream: uint32x4_t) {
        unsafe {
            let data = vld1q_u32(pointer.cast::<u32>());
            vst1q_u32(pointer.cast::<u32>(), veorq_u32(data, keystream));
        }
    }

    #[inline(always)]
    unsafe fn quarter_round(
        v: &mut [uint32x4_t; 16],
        a: usize,
        b: usize,
        c: usize,
        d: usize,
        rot8: uint8x16_t,
    ) {
        unsafe {
            v[a] = vaddq_u32(v[a], v[b]);
            v[d] = rotl16(veorq_u32(v[d], v[a]));
            v[c] = vaddq_u32(v[c], v[d]);
            v[b] = rotl12(veorq_u32(v[b], v[c]));
            v[a] = vaddq_u32(v[a], v[b]);
            v[d] = rotl8(veorq_u32(v[d], v[a]), rot8);
            v[c] = vaddq_u32(v[c], v[d]);
            v[b] = rotl7(veorq_u32(v[b], v[c]));
        }
    }
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

    /// A fully independent scalar ChaCha20 that shares no code with the
    /// production path, used to check the SIMD path across many blocks.
    ///
    /// The earlier tests only compared the first 16 bytes of one block, or
    /// compared the accelerated path against itself; a systematic SIMD error
    /// past the first block slipped through both. This checks every byte of a
    /// multi-group keystream against a reference written from the RFC by hand.
    fn reference_keystream(key: &[u8; 32], nonce: &[u8; 12], counter: u32, out: &mut [u8]) {
        fn qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
            s[a] = s[a].wrapping_add(s[b]);
            s[d] = (s[d] ^ s[a]).rotate_left(16);
            s[c] = s[c].wrapping_add(s[d]);
            s[b] = (s[b] ^ s[c]).rotate_left(12);
            s[a] = s[a].wrapping_add(s[b]);
            s[d] = (s[d] ^ s[a]).rotate_left(8);
            s[c] = s[c].wrapping_add(s[d]);
            s[b] = (s[b] ^ s[c]).rotate_left(7);
        }
        for (block, chunk) in out.chunks_mut(64).enumerate() {
            let mut s = [0_u32; 16];
            s[0..4].copy_from_slice(&SIGMA);
            for i in 0..8 {
                s[4 + i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
            }
            s[12] = counter.wrapping_add(block as u32);
            for i in 0..3 {
                s[13 + i] = u32::from_le_bytes(nonce[i * 4..i * 4 + 4].try_into().unwrap());
            }
            let start = s;
            for _ in 0..10 {
                qr(&mut s, 0, 4, 8, 12);
                qr(&mut s, 1, 5, 9, 13);
                qr(&mut s, 2, 6, 10, 14);
                qr(&mut s, 3, 7, 11, 15);
                qr(&mut s, 0, 5, 10, 15);
                qr(&mut s, 1, 6, 11, 12);
                qr(&mut s, 2, 7, 8, 13);
                qr(&mut s, 3, 4, 9, 14);
            }
            for i in 0..16 {
                s[i] = s[i].wrapping_add(start[i]);
            }
            for (i, slot) in chunk.chunks_mut(4).enumerate() {
                slot.copy_from_slice(&s[i].to_le_bytes()[..slot.len()]);
            }
        }
    }

    #[test]
    fn simd_keystream_matches_independent_reference_across_many_blocks() {
        let key: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
        let nonce: [u8; 12] = core::array::from_fn(|i| (i as u8).wrapping_mul(11));

        // 2049 bytes crosses the 8-block (512 B) and 4-block (256 B) paths and
        // ends on a partial block, exercising every branch of the SIMD loop.
        for len in [64_usize, 256, 257, 512, 513, 1024, 2049] {
            let mut reference = vec![0_u8; len];
            reference_keystream(&key, &nonce, 1, &mut reference);

            let mut produced = vec![0_u8; len];
            ChaCha20::new(&key, &nonce, 1).apply_keystream(&mut produced);

            assert_eq!(
                produced, reference,
                "SIMD keystream diverges from the reference at length {len}"
            );
        }
    }

    #[test]
    fn counter_advances_correctly_when_split_across_calls() {
        let key = [9_u8; 32];
        let nonce = [4_u8; 12];

        let mut whole = vec![0_u8; 1024];
        reference_keystream(&key, &nonce, 5, &mut whole);

        // Two calls on one generator must reproduce the single-shot keystream,
        // which fails if the counter does not carry between calls.
        let mut split = vec![0_u8; 1024];
        let mut generator = ChaCha20::new(&key, &nonce, 5);
        let (first, second) = split.split_at_mut(384);
        generator.apply_keystream(first);
        generator.apply_keystream(second);
        assert_eq!(split, whole);
    }
}
