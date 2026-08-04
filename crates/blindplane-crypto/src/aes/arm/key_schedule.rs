//! AES-256 key expansion and single-block encryption.

use core::arch::aarch64::{
    uint8x16_t, vaeseq_u8, vaesmcq_u8, vdupq_n_u8, vdupq_n_u32, veorq_u8, vgetq_lane_u32, vld1q_u8,
    vreinterpretq_u8_u32, vreinterpretq_u32_u8,
};

/// AES-256 encryption of one block under an expanded key.
#[target_feature(enable = "aes")]
pub(super) unsafe fn encrypt_block(round_keys: &[uint8x16_t; 15], block: uint8x16_t) -> uint8x16_t {
    let mut state = block;
    for key in round_keys.iter().take(13) {
        // AESE performs AddRoundKey, SubBytes and ShiftRows together.
        state = vaesmcq_u8(vaeseq_u8(state, *key));
    }
    state = vaeseq_u8(state, round_keys[13]);
    veorq_u8(state, round_keys[14])
}

/// AES-256 key expansion.
///
/// `SubWord` is computed with `AESE` against a zero round key rather than
/// an S-box table, so expanding a key touches no key-dependent memory
/// address.
#[target_feature(enable = "aes")]
pub(super) unsafe fn expand_key(key: &[u8; 32]) -> [uint8x16_t; 15] {
    // SAFETY: the caller guarantees the AES extension.
    unsafe {
        const RCON: [u8; 7] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];

        let mut words = [0_u32; 60];
        for (i, word) in words.iter_mut().take(8).enumerate() {
            *word =
                u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
        }

        for i in 8..60 {
            let mut temp = words[i - 1];
            if i % 8 == 0 {
                temp = sub_word(temp.rotate_right(8)) ^ u32::from(RCON[i / 8 - 1]);
            } else if i % 8 == 4 {
                temp = sub_word(temp);
            }
            words[i] = words[i - 8] ^ temp;
        }

        // The words are little-endian u32s laid out contiguously, which is
        // exactly the byte order a round key loads with; no re-assembly.
        let mut round_keys = [vdupq_n_u8(0); 15];
        for (round, slot) in round_keys.iter_mut().enumerate() {
            *slot = vld1q_u8(words.as_ptr().cast::<u8>().add(round * 16));
        }
        round_keys
    }
}

/// Apply the AES S-box to each byte of a word using the AES instruction.
#[target_feature(enable = "aes")]
unsafe fn sub_word(word: u32) -> u32 {
    // With all four columns equal, ShiftRows is the identity, so
    // AESE(x, 0) reduces to SubBytes applied column-wise. Broadcast and
    // lane-extract keep the word in registers; round-tripping it through
    // the stack costs more than the substitution itself.
    let splat = vreinterpretq_u8_u32(vdupq_n_u32(word));
    let substituted = vaeseq_u8(splat, vdupq_n_u8(0));
    vgetq_lane_u32::<0>(vreinterpretq_u32_u8(substituted))
}
