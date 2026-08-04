//! AES-256-GCM on CPU cryptographic extensions.
//!
//! There is deliberately **no** software fallback. A portable AES built on
//! lookup tables leaks the key through cache timing, and a constant-time
//! bitsliced one would be slower than ChaCha20-Poly1305 anyway. When the CPU
//! has no AES instructions, [`available`] reports `false` and callers use the
//! ChaCha suite instead, which is uniformly fast and constant time in software.
//!
//! The GHASH field element is held bit-reversed inside each byte, which is the
//! representation that turns GCM's polynomial into an ordinary little-endian
//! integer and lets `PMULL` do the multiplication directly.

#[cfg(all(feature = "accel", target_arch = "aarch64"))]
mod arm;
#[cfg(test)]
mod tests;

/// Whether this CPU can run AES-256-GCM.
pub fn available() -> bool {
    #[cfg(all(feature = "accel", target_arch = "aarch64"))]
    {
        arm::available()
    }
    #[cfg(not(all(feature = "accel", target_arch = "aarch64")))]
    {
        false
    }
}

/// Encrypt in place and return the 16-byte tag.
///
/// Returns `None` when the CPU has no AES instructions.
pub fn seal_in_place(
    key: &[u8; 32],
    nonce: &[u8; 12],
    associated_data: &[u8],
    buffer: &mut [u8],
) -> Option<[u8; 16]> {
    #[cfg(all(feature = "accel", target_arch = "aarch64"))]
    {
        if arm::available() {
            // SAFETY: `available()` confirmed the AES and PMULL instructions
            // exist, which is the only precondition of the accelerated path.
            return Some(unsafe { arm::seal(key, nonce, associated_data, buffer) });
        }
    }
    let _ = (key, nonce, associated_data, buffer);
    None
}

/// Decrypt in place after verifying the tag.
///
/// Returns `Some(true)` when the tag verified, `Some(false)` when it did not
/// (the buffer is then zeroed), and `None` when the CPU has no AES support.
pub fn open_in_place(
    key: &[u8; 32],
    nonce: &[u8; 12],
    associated_data: &[u8],
    buffer: &mut [u8],
    tag: &[u8; 16],
) -> Option<bool> {
    #[cfg(all(feature = "accel", target_arch = "aarch64"))]
    {
        if arm::available() {
            // SAFETY: as above, the required CPU features were just checked.
            return Some(unsafe { arm::open(key, nonce, associated_data, buffer, tag) });
        }
    }
    let _ = (key, nonce, associated_data, buffer, tag);
    None
}
