//! The fused seal pass and the verify-then-decrypt open path.

use core::arch::aarch64::{uint8x16_t, vdupq_n_u8, veorq_u8, vld1q_u8, vst1q_u8};

use crate::util::ct_eq_bytes;

use super::ghash::Ghash;
use super::key_schedule::{encrypt_block, expand_key};

/// Build the 16-byte counter block for a 96-bit nonce.
#[target_feature(enable = "neon")]
unsafe fn counter_block(nonce: &[u8; 12], counter: u32) -> uint8x16_t {
    // SAFETY: NEON is baseline on AArch64; the load reads 16 initialized
    // stack bytes.
    unsafe {
        let mut block = [0_u8; 16];
        block[..12].copy_from_slice(nonce);
        block[12..].copy_from_slice(&counter.to_be_bytes());
        vld1q_u8(block.as_ptr())
    }
}

/// Encrypt the buffer with CTR and authenticate with GHASH in one pass.
///
/// Encrypting and hashing separately walks the buffer twice and leaves the
/// AES and PMULL pipelines waiting for each other in turn. Hashing each
/// ciphertext block while it is still in a register keeps both busy and
/// halves the memory traffic.
#[target_feature(enable = "aes,neon")]
pub unsafe fn seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    associated_data: &[u8],
    buffer: &mut [u8],
) -> [u8; 16] {
    // SAFETY: the caller guarantees the AES and PMULL extensions. Every
    // pointer below stays within `buffer`, whose length bounds each loop.
    unsafe {
        let round_keys = expand_key(key);
        let h = encrypt_block(&round_keys, vdupq_n_u8(0));
        let tag_mask = encrypt_block(&round_keys, counter_block(nonce, 1));

        let mut ghash = Ghash::new(h);
        ghash.absorb(associated_data);

        let mut counter = 2_u32;
        let mut offset = 0;
        let len = buffer.len();
        let base = buffer.as_mut_ptr();

        // Eight blocks per pass. The AES rounds of all eight are
        // independent, as are the eight PMULLs inside the GHASH step, so
        // both pipelines stay full instead of waiting on a four-deep chain.
        while offset + 128 <= len {
            let k0 = encrypt_block(&round_keys, counter_block(nonce, counter));
            let k1 = encrypt_block(&round_keys, counter_block(nonce, counter + 1));
            let k2 = encrypt_block(&round_keys, counter_block(nonce, counter + 2));
            let k3 = encrypt_block(&round_keys, counter_block(nonce, counter + 3));
            let k4 = encrypt_block(&round_keys, counter_block(nonce, counter + 4));
            let k5 = encrypt_block(&round_keys, counter_block(nonce, counter + 5));
            let k6 = encrypt_block(&round_keys, counter_block(nonce, counter + 6));
            let k7 = encrypt_block(&round_keys, counter_block(nonce, counter + 7));

            let p = base.add(offset);
            let c0 = veorq_u8(vld1q_u8(p), k0);
            let c1 = veorq_u8(vld1q_u8(p.add(16)), k1);
            let c2 = veorq_u8(vld1q_u8(p.add(32)), k2);
            let c3 = veorq_u8(vld1q_u8(p.add(48)), k3);
            let c4 = veorq_u8(vld1q_u8(p.add(64)), k4);
            let c5 = veorq_u8(vld1q_u8(p.add(80)), k5);
            let c6 = veorq_u8(vld1q_u8(p.add(96)), k6);
            let c7 = veorq_u8(vld1q_u8(p.add(112)), k7);

            vst1q_u8(p, c0);
            vst1q_u8(p.add(16), c1);
            vst1q_u8(p.add(32), c2);
            vst1q_u8(p.add(48), c3);
            vst1q_u8(p.add(64), c4);
            vst1q_u8(p.add(80), c5);
            vst1q_u8(p.add(96), c6);
            vst1q_u8(p.add(112), c7);

            ghash.absorb_eight_vectors(c0, c1, c2, c3, c4, c5, c6, c7);

            counter = counter.wrapping_add(8);
            offset += 128;
        }

        while offset + 64 <= len {
            let k0 = encrypt_block(&round_keys, counter_block(nonce, counter));
            let k1 = encrypt_block(&round_keys, counter_block(nonce, counter + 1));
            let k2 = encrypt_block(&round_keys, counter_block(nonce, counter + 2));
            let k3 = encrypt_block(&round_keys, counter_block(nonce, counter + 3));

            let p = base.add(offset);
            let c0 = veorq_u8(vld1q_u8(p), k0);
            let c1 = veorq_u8(vld1q_u8(p.add(16)), k1);
            let c2 = veorq_u8(vld1q_u8(p.add(32)), k2);
            let c3 = veorq_u8(vld1q_u8(p.add(48)), k3);

            vst1q_u8(p, c0);
            vst1q_u8(p.add(16), c1);
            vst1q_u8(p.add(32), c2);
            vst1q_u8(p.add(48), c3);

            ghash.absorb_four_vectors(c0, c1, c2, c3);

            counter = counter.wrapping_add(4);
            offset += 64;
        }

        while offset + 16 <= len {
            let block = encrypt_block(&round_keys, counter_block(nonce, counter));
            let p = base.add(offset);
            let ciphertext = veorq_u8(vld1q_u8(p), block);
            vst1q_u8(p, ciphertext);

            let mut bytes = [0_u8; 16];
            vst1q_u8(bytes.as_mut_ptr(), ciphertext);
            ghash.absorb_block(&bytes);

            counter = counter.wrapping_add(1);
            offset += 16;
        }

        if offset < len {
            let block = encrypt_block(&round_keys, counter_block(nonce, counter));
            let mut keystream = [0_u8; 16];
            vst1q_u8(keystream.as_mut_ptr(), block);
            let mut tail = [0_u8; 16];
            for (index, key_byte) in keystream.iter().enumerate().take(len - offset) {
                let position = offset + index;
                buffer[position] ^= *key_byte;
                tail[index] = buffer[position];
            }
            ghash.absorb_block(&tail);
        }

        ghash.absorb_block(&length_block(associated_data.len(), len));

        let digest = ghash.finish();
        let mut mask = [0_u8; 16];
        vst1q_u8(mask.as_mut_ptr(), tag_mask);

        let mut tag = [0_u8; 16];
        for i in 0..16 {
            tag[i] = digest[i] ^ mask[i];
        }
        tag
    }
}

/// Verify the tag, then decrypt the buffer.
#[target_feature(enable = "aes,neon")]
pub unsafe fn open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    associated_data: &[u8],
    buffer: &mut [u8],
    tag: &[u8; 16],
) -> bool {
    // SAFETY: the caller guarantees the AES and PMULL extensions.
    unsafe {
        let round_keys = expand_key(key);
        let h = encrypt_block(&round_keys, vdupq_n_u8(0));
        let tag_mask = encrypt_block(&round_keys, counter_block(nonce, 1));

        let mut ghash = Ghash::new(h);
        ghash.absorb(associated_data);
        ghash.absorb(buffer);
        ghash.absorb_block(&length_block(associated_data.len(), buffer.len()));

        let digest = ghash.finish();
        let mut mask = [0_u8; 16];
        vst1q_u8(mask.as_mut_ptr(), tag_mask);

        let mut expected = [0_u8; 16];
        for i in 0..16 {
            expected[i] = digest[i] ^ mask[i];
        }

        // Authenticate before releasing any plaintext.
        if !ct_eq_bytes(&expected, tag).is_set() {
            return false;
        }
        apply_ctr(&round_keys, nonce, buffer);
        true
    }
}

/// CTR mode starting at counter 2, four blocks at a time.
///
/// The keystream is XORed straight from vector registers into the buffer:
/// staging it through a stack array and XORing byte by byte costs more than
/// the AES itself.
#[target_feature(enable = "aes,neon")]
unsafe fn apply_ctr(round_keys: &[uint8x16_t; 15], nonce: &[u8; 12], buffer: &mut [u8]) {
    // SAFETY: the caller guarantees the AES extension. Every pointer below
    // stays inside `buffer`, whose length bounds each loop.
    unsafe {
        let mut counter = 2_u32;
        let mut offset = 0;
        let len = buffer.len();
        let base = buffer.as_mut_ptr();

        while offset + 128 <= len {
            let k0 = encrypt_block(round_keys, counter_block(nonce, counter));
            let k1 = encrypt_block(round_keys, counter_block(nonce, counter + 1));
            let k2 = encrypt_block(round_keys, counter_block(nonce, counter + 2));
            let k3 = encrypt_block(round_keys, counter_block(nonce, counter + 3));
            let k4 = encrypt_block(round_keys, counter_block(nonce, counter + 4));
            let k5 = encrypt_block(round_keys, counter_block(nonce, counter + 5));
            let k6 = encrypt_block(round_keys, counter_block(nonce, counter + 6));
            let k7 = encrypt_block(round_keys, counter_block(nonce, counter + 7));

            let p = base.add(offset);
            vst1q_u8(p, veorq_u8(vld1q_u8(p), k0));
            vst1q_u8(p.add(16), veorq_u8(vld1q_u8(p.add(16)), k1));
            vst1q_u8(p.add(32), veorq_u8(vld1q_u8(p.add(32)), k2));
            vst1q_u8(p.add(48), veorq_u8(vld1q_u8(p.add(48)), k3));
            vst1q_u8(p.add(64), veorq_u8(vld1q_u8(p.add(64)), k4));
            vst1q_u8(p.add(80), veorq_u8(vld1q_u8(p.add(80)), k5));
            vst1q_u8(p.add(96), veorq_u8(vld1q_u8(p.add(96)), k6));
            vst1q_u8(p.add(112), veorq_u8(vld1q_u8(p.add(112)), k7));

            counter = counter.wrapping_add(8);
            offset += 128;
        }

        // Four independent blocks keep the AES pipeline full: the
        // instruction has multi-cycle latency but issues every cycle.
        while offset + 64 <= len {
            let k0 = encrypt_block(round_keys, counter_block(nonce, counter));
            let k1 = encrypt_block(round_keys, counter_block(nonce, counter + 1));
            let k2 = encrypt_block(round_keys, counter_block(nonce, counter + 2));
            let k3 = encrypt_block(round_keys, counter_block(nonce, counter + 3));

            let p = base.add(offset);
            vst1q_u8(p, veorq_u8(vld1q_u8(p), k0));
            vst1q_u8(p.add(16), veorq_u8(vld1q_u8(p.add(16)), k1));
            vst1q_u8(p.add(32), veorq_u8(vld1q_u8(p.add(32)), k2));
            vst1q_u8(p.add(48), veorq_u8(vld1q_u8(p.add(48)), k3));

            counter = counter.wrapping_add(4);
            offset += 64;
        }

        while offset + 16 <= len {
            let block = encrypt_block(round_keys, counter_block(nonce, counter));
            let p = base.add(offset);
            vst1q_u8(p, veorq_u8(vld1q_u8(p), block));
            counter = counter.wrapping_add(1);
            offset += 16;
        }

        if offset < len {
            let block = encrypt_block(round_keys, counter_block(nonce, counter));
            let mut keystream = [0_u8; 16];
            vst1q_u8(keystream.as_mut_ptr(), block);
            for (byte, key) in buffer[offset..].iter_mut().zip(keystream.iter()) {
                *byte ^= *key;
            }
        }
    }
}

fn length_block(aad_len: usize, ciphertext_len: usize) -> [u8; 16] {
    let mut block = [0_u8; 16];
    block[..8].copy_from_slice(&((aad_len as u64) * 8).to_be_bytes());
    block[8..].copy_from_slice(&((ciphertext_len as u64) * 8).to_be_bytes());
    block
}
