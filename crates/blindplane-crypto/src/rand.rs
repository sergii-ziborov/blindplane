//! Operating-system entropy.
//!
//! There is no userspace PRNG here on purpose: every random byte this library
//! uses comes from the kernel, so there is no seed to mismanage, no state to
//! fork-duplicate, and nothing to back up into a snapshot.

/// The operating system refused to provide entropy.
///
/// This is not recoverable by retrying in a loop; a system that cannot produce
/// random bytes cannot produce keys, and callers must fail the operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RandomError;

impl core::fmt::Display for RandomError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("operating system entropy source failed")
    }
}

impl core::error::Error for RandomError {}

/// Fill a buffer with cryptographically secure random bytes.
#[cfg(feature = "std")]
pub fn fill(buffer: &mut [u8]) -> Result<(), RandomError> {
    #[cfg(unix)]
    {
        // `getentropy` is the modern interface on both macOS and Linux and
        // cannot partially succeed, but it caps each call at 256 bytes.
        for chunk in buffer.chunks_mut(256) {
            // SAFETY: `getentropy` writes exactly `len` bytes to `ptr`; the
            // pointer and length come from a live mutable slice.
            let status = unsafe { getentropy(chunk.as_mut_ptr(), chunk.len()) };
            if status != 0 {
                return fill_from_dev_urandom(buffer);
            }
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fill_from_dev_urandom(buffer)
    }
}

#[cfg(all(feature = "std", unix))]
unsafe extern "C" {
    /// Present on macOS 10.12+, Linux (glibc 2.25+), and the BSDs.
    fn getentropy(buffer: *mut u8, length: usize) -> i32;
}

/// Fallback for systems whose libc lacks `getentropy`.
#[cfg(feature = "std")]
fn fill_from_dev_urandom(buffer: &mut [u8]) -> Result<(), RandomError> {
    use std::io::Read;

    let mut file = std::fs::File::open("/dev/urandom").map_err(|_| RandomError)?;
    file.read_exact(buffer).map_err(|_| RandomError)
}

/// A fresh 32-byte secret.
#[cfg(feature = "std")]
pub fn secret_32() -> Result<crate::util::Secret<32>, RandomError> {
    let mut secret = crate::util::Secret::zeroed();
    fill(secret.as_mut())?;
    Ok(secret)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn produces_distinct_output() {
        let mut a = [0_u8; 64];
        let mut b = [0_u8; 64];
        fill(&mut a).unwrap();
        fill(&mut b).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0_u8; 64]);
    }

    #[test]
    fn fills_lengths_across_the_chunk_boundary() {
        for len in [0_usize, 1, 255, 256, 257, 1024] {
            let mut buffer = vec![0_u8; len];
            fill(&mut buffer).unwrap();
            if len >= 32 {
                assert!(buffer.iter().any(|b| *b != 0));
            }
        }
    }
}
