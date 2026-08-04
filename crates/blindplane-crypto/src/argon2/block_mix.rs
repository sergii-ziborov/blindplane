//! The Argon2 compression function `G` and block/byte conversions.

use super::argon2id::{BLOCK_LEN, Block, QWORDS};

/// The Argon2 compression function `G`.
pub(super) fn compress_blocks(x: &Block, y: &Block) -> Block {
    let mut r = [0_u64; QWORDS];
    for i in 0..QWORDS {
        r[i] = x[i] ^ y[i];
    }
    let mut z = r;

    // Rows: eight 16-word groups, each contiguous, permuted in place. No
    // gather is needed — a row *is* the sixteen-word window.
    for row in 0..8 {
        let window =
            <&mut [u64; 16]>::try_from(&mut z[row * 16..row * 16 + 16]).expect("sixteen words");
        permute(window);
    }

    // Columns: pairs (base, base+1) from each of the eight rows, gathered
    // with constant strides into a local window and scattered back.
    for col in 0..8 {
        let base = col * 2;
        let mut v = [0_u64; 16];
        for k in 0..8 {
            v[2 * k] = z[base + 16 * k];
            v[2 * k + 1] = z[base + 16 * k + 1];
        }
        permute(&mut v);
        for k in 0..8 {
            z[base + 16 * k] = v[2 * k];
            z[base + 16 * k + 1] = v[2 * k + 1];
        }
    }

    for i in 0..QWORDS {
        z[i] ^= r[i];
    }
    z
}

/// The BLAKE2b-derived permutation `P` over a sixteen-word window.
#[inline(always)]
fn permute(v: &mut [u64; 16]) {
    blamka(v, 0, 4, 8, 12);
    blamka(v, 1, 5, 9, 13);
    blamka(v, 2, 6, 10, 14);
    blamka(v, 3, 7, 11, 15);
    blamka(v, 0, 5, 10, 15);
    blamka(v, 1, 6, 11, 12);
    blamka(v, 2, 7, 8, 13);
    blamka(v, 3, 4, 9, 14);
}

#[inline(always)]
fn blamka(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize) {
    // Argon2 replaces BLAKE2b's addition with a multiply-and-add, which is
    // what makes the function expensive to run on cheap parallel hardware.
    v[a] = fused_add(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = fused_add(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = fused_add(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = fused_add(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

#[inline(always)]
fn fused_add(x: u64, y: u64) -> u64 {
    let low = (x & 0xffff_ffff).wrapping_mul(y & 0xffff_ffff);
    x.wrapping_add(y).wrapping_add(low.wrapping_mul(2))
}

pub(super) fn bytes_to_block(bytes: &[u8]) -> Block {
    let mut block = [0_u64; QWORDS];
    for (i, slot) in block.iter_mut().enumerate() {
        let mut buf = [0_u8; 8];
        buf.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
        *slot = u64::from_le_bytes(buf);
    }
    block
}

pub(super) fn block_to_bytes(block: &Block) -> Vec<u8> {
    let mut bytes = vec![0_u8; BLOCK_LEN];
    for (i, word) in block.iter().enumerate() {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}
