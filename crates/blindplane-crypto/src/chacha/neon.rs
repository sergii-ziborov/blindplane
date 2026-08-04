//! ChaCha20 on NEON, four blocks at a time.
//!
//! The portable path expresses lanes as `[u32; 4]` and hopes the autovectorizer
//! notices. It does not: that version measures 6.7 cycles per byte, roughly five
//! times what the hardware can do. This module spells the vectors out.
//!
//! Two rotations get dedicated instructions rather than a shift pair:
//! `rotl(x, 16)` is a 16-bit element reverse, and `rotl(x, 8)` is a byte-table
//! permute. The other two use shift-right-and-insert, which fuses the shift and
//! the or.

use core::arch::aarch64::{
    uint8x16_t, uint32x4_t, vaddq_u32, vdupq_n_u32, veorq_u32, vld1q_u8, vld1q_u32, vqtbl1q_u8,
    vreinterpretq_u8_u32, vreinterpretq_u16_u32, vreinterpretq_u32_u8, vreinterpretq_u32_u16,
    vreinterpretq_u32_u64, vreinterpretq_u64_u32, vrev32q_u16, vshlq_n_u32, vsriq_n_u32, vst1q_u32,
    vtrn1q_u32, vtrn1q_u64, vtrn2q_u32, vtrn2q_u64,
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
unsafe fn transpose(a: uint32x4_t, b: uint32x4_t, c: uint32x4_t, d: uint32x4_t) -> [uint32x4_t; 4] {
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
