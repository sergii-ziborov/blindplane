//! SHA-256 on the ARMv8 cryptographic extensions.

use super::K256;
use core::arch::aarch64::{
    vaddq_u32, vld1q_u8, vld1q_u32, vreinterpretq_u32_u8, vrev32q_u8, vsha256h2q_u32,
    vsha256hq_u32, vsha256su0q_u32, vsha256su1q_u32, vst1q_u32,
};
use std::sync::OnceLock;

/// Whether this CPU implements the SHA-2 instructions.
pub fn available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| std::arch::is_aarch64_feature_detected!("sha2"))
}

/// Compress whole 64-byte blocks.
///
/// # Safety
///
/// The CPU must implement the ARMv8 SHA-2 extension, which the caller
/// establishes with [`available`].
#[target_feature(enable = "sha2")]
pub unsafe fn compress(state: &mut [u32; 8], data: &[u8]) {
    // SAFETY: every intrinsic below is enabled by the `sha2` target
    // feature required by this function, and every load reads 16 bytes
    // from a slice this function has already bounds-checked.
    unsafe {
        let mut abcd = vld1q_u32(state.as_ptr());
        let mut efgh = vld1q_u32(state.as_ptr().add(4));

        // A round with its schedule update woven through it.
        //
        // The digest update is one unbroken dependency chain — SHA256H2
        // waits on SHA256H, and the next round waits on both — so nothing
        // inside it can overlap. The message schedule is the only
        // independent work available, and splitting it around the chain
        // (su0 issued before the hash pair, su1 after) is what fills those
        // stall slots. Doing both halves after the round, as the obvious
        // version does, leaves the pipeline idle waiting on latency.
        macro_rules! round {
            ($w0:ident, $w1:ident, $w2:ident, $w3:ident, $k:literal) => {{
                let wk = vaddq_u32($w0, vld1q_u32(K256.as_ptr().add($k * 4)));
                let scheduled = vsha256su0q_u32($w0, $w1);
                let previous_abcd = abcd;
                abcd = vsha256hq_u32(abcd, efgh, wk);
                efgh = vsha256h2q_u32(efgh, previous_abcd, wk);
                $w0 = vsha256su1q_u32(scheduled, $w2, $w3);
            }};
        }

        // The last four rounds consume the schedule without extending it.
        macro_rules! final_round {
            ($w:expr, $k:literal) => {{
                let wk = vaddq_u32($w, vld1q_u32(K256.as_ptr().add($k * 4)));
                let previous_abcd = abcd;
                abcd = vsha256hq_u32(abcd, efgh, wk);
                efgh = vsha256h2q_u32(efgh, previous_abcd, wk);
            }};
        }

        for block in data.chunks_exact(64) {
            let saved_abcd = abcd;
            let saved_efgh = efgh;

            // The digest is big-endian; NEON loads are little-endian.
            // Four named registers, not an array: an array indexed by
            // `round % 4` forces the schedule into memory, and the round
            // keys likewise want constant offsets so they fold into the
            // load rather than becoming a runtime table lookup.
            let mut m0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr())));
            let mut m1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr().add(16))));
            let mut m2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr().add(32))));
            let mut m3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr().add(48))));

            round!(m0, m1, m2, m3, 0);
            round!(m1, m2, m3, m0, 1);
            round!(m2, m3, m0, m1, 2);
            round!(m3, m0, m1, m2, 3);

            round!(m0, m1, m2, m3, 4);
            round!(m1, m2, m3, m0, 5);
            round!(m2, m3, m0, m1, 6);
            round!(m3, m0, m1, m2, 7);

            round!(m0, m1, m2, m3, 8);
            round!(m1, m2, m3, m0, 9);
            round!(m2, m3, m0, m1, 10);
            round!(m3, m0, m1, m2, 11);

            final_round!(m0, 12);
            final_round!(m1, 13);
            final_round!(m2, 14);
            final_round!(m3, 15);

            abcd = vaddq_u32(abcd, saved_abcd);
            efgh = vaddq_u32(efgh, saved_efgh);
        }

        vst1q_u32(state.as_mut_ptr(), abcd);
        vst1q_u32(state.as_mut_ptr().add(4), efgh);
    }
}
