//! SHA-512 on the ARMv8.2 FEAT_SHA512 instructions.
//!
//! The schedule follows the two-rounds-per-step structure that ring and
//! BoringSSL use for `sha512_block_data_order_hw`. The four intrinsics
//! (`SHA512H`, `SHA512H2`, `SHA512SU0`, `SHA512SU1`) live behind LLVM's `sha3`
//! target feature — the compiler rejects the name `sha512` — which is why the
//! gate below reads `sha3` for the instruction set but a separate,
//! feature-specific check confirms `FEAT_SHA512` before the path is used.

use super::K512;
use core::arch::aarch64::{
    vaddq_u64, vdupq_n_u64, vextq_u64, vld1q_u8, vld1q_u64, vreinterpretq_u64_u8, vrev64q_u8,
    vsha512h2q_u64, vsha512hq_u64, vsha512su0q_u64, vsha512su1q_u64, vst1q_u64,
};
use std::sync::OnceLock;

/// Whether this CPU implements the SHA-512 instructions.
///
/// `is_aarch64_feature_detected!("sha3")` proves EOR3/SHA-3 are present, but
/// SHA-512 is a distinct architectural feature that a CPU can lack while
/// still having SHA-3. Rust's detection macro has no `sha512` token, so the
/// positive confirmation comes from the operating system: on Apple Silicon
/// via the `hw.optional.arm.FEAT_SHA512` sysctl. On any target where that
/// cannot be confirmed, the portable SHA-512 is used instead — always
/// correct, only slower.
pub fn available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| std::arch::is_aarch64_feature_detected!("sha3") && feat_sha512())
}

#[cfg(target_os = "macos")]
fn feat_sha512() -> bool {
    // SAFETY: `sysctlbyname` reads a named integer into `value`; the sizes
    // and null-terminated name are correct, and a failure leaves the
    // conservative `0`.
    unsafe {
        let name = c"hw.optional.arm.FEAT_SHA512";
        let mut value: i32 = 0;
        let mut size = core::mem::size_of::<i32>();
        let rc = sysctlbyname(
            name.as_ptr(),
            core::ptr::from_mut(&mut value).cast(),
            core::ptr::from_mut(&mut size),
            core::ptr::null_mut(),
            0,
        );
        rc == 0 && value == 1
    }
}

#[cfg(not(target_os = "macos"))]
fn feat_sha512() -> bool {
    // No portable way to confirm FEAT_SHA512 off Apple platforms, so stay on
    // the always-correct portable path.
    false
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn sysctlbyname(
        name: *const core::ffi::c_char,
        oldp: *mut core::ffi::c_void,
        oldlenp: *mut usize,
        newp: *mut core::ffi::c_void,
        newlen: usize,
    ) -> core::ffi::c_int;
}

/// Compress whole 128-byte blocks.
///
/// # Safety
///
/// The CPU must implement FEAT_SHA512, which the caller establishes with
/// [`available`].
#[target_feature(enable = "sha3")]
pub unsafe fn compress(state: &mut [u64; 8], data: &[u8]) {
    // SAFETY: every intrinsic is covered by the enabled `sha3` feature, and
    // each load reads 16 bytes from a slice the caller sized to whole
    // 128-byte blocks.
    unsafe {
        let mut a = vld1q_u64(state.as_ptr());
        let mut b = vld1q_u64(state.as_ptr().add(2));
        let mut c = vld1q_u64(state.as_ptr().add(4));
        let mut d = vld1q_u64(state.as_ptr().add(6));

        for block in data.chunks_exact(128) {
            let (sa, sb, sc, sd) = (a, b, c, d);

            // SHA-512 is big-endian; NEON loads little-endian.
            let mut w = [vdupq_n_u64(0); 8];
            for (i, word) in w.iter_mut().enumerate() {
                *word = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block.as_ptr().add(i * 16))));
            }

            for step in 0..40 {
                let kw = vaddq_u64(vld1q_u64(K512.as_ptr().add(step * 2)), w[step % 8]);
                let kw = vextq_u64::<1>(kw, kw);

                let t5 = vextq_u64::<1>(c, d);
                let t6 = vextq_u64::<1>(b, c);

                if step < 32 {
                    w[step % 8] = vsha512su0q_u64(w[step % 8], w[(step + 1) % 8]);
                }

                let mut nd = vaddq_u64(d, kw);
                nd = vsha512hq_u64(nd, t5, t6);

                if step < 32 {
                    let ext = vextq_u64::<1>(w[(step + 4) % 8], w[(step + 5) % 8]);
                    w[step % 8] = vsha512su1q_u64(w[step % 8], w[(step + 7) % 8], ext);
                }

                let aux = vaddq_u64(b, nd);
                nd = vsha512h2q_u64(nd, b, a);

                // Roles rotate: (A,B,C,D) <- (D', A, aux, C).
                let (old_a, old_c) = (a, c);
                a = nd;
                b = old_a;
                c = aux;
                d = old_c;
            }

            a = vaddq_u64(a, sa);
            b = vaddq_u64(b, sb);
            c = vaddq_u64(c, sc);
            d = vaddq_u64(d, sd);
        }

        vst1q_u64(state.as_mut_ptr(), a);
        vst1q_u64(state.as_mut_ptr().add(2), b);
        vst1q_u64(state.as_mut_ptr().add(4), c);
        vst1q_u64(state.as_mut_ptr().add(6), d);
    }
}
