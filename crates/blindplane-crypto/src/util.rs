//! Constant-time primitives and secret erasure.

use core::ops::{BitAnd, BitOr, BitXor, Not};

/// A boolean that never reaches a branch.
///
/// Internally this is `0` or `u64::MAX`, so it can be used directly as a
/// selection mask. Converting back into `bool` is possible but deliberately
/// explicit, so it is visible in review where a secret-dependent branch is
/// being introduced.
#[derive(Clone, Copy, Debug)]
pub struct Choice(u64);

impl Choice {
    /// A set choice.
    pub const TRUE: Self = Self(u64::MAX);
    /// An unset choice.
    pub const FALSE: Self = Self(0);

    /// Build from the low bit of `bit`.
    #[inline(always)]
    pub const fn from_bit(bit: u64) -> Self {
        Self(0_u64.wrapping_sub(bit & 1))
    }

    /// The selection mask: all ones when set, all zeros when unset.
    #[inline(always)]
    pub const fn mask(self) -> u64 {
        self.0
    }

    /// Whether the choice is set.
    ///
    /// Calling this on a secret-derived value converts a constant-time value
    /// into a branchable one; only do it once the result is public, such as
    /// after a completed authentication check.
    #[inline(always)]
    pub const fn is_set(self) -> bool {
        self.0 == u64::MAX
    }
}

impl From<bool> for Choice {
    #[inline(always)]
    fn from(value: bool) -> Self {
        Self::from_bit(u64::from(value))
    }
}

impl BitAnd for Choice {
    type Output = Self;
    #[inline(always)]
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl BitOr for Choice {
    type Output = Self;
    #[inline(always)]
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl BitXor for Choice {
    type Output = Self;
    #[inline(always)]
    fn bitxor(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }
}

impl Not for Choice {
    type Output = Self;
    #[inline(always)]
    fn not(self) -> Self {
        Self(!self.0)
    }
}

/// Compare two byte slices in time that depends only on their length.
///
/// Slices of different lengths compare unequal without inspecting contents.
#[inline]
pub fn ct_eq_bytes(a: &[u8], b: &[u8]) -> Choice {
    if a.len() != b.len() {
        return Choice::FALSE;
    }
    let mut diff = 0_u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    // `diff` is zero exactly when every byte matched.
    Choice::from_bit(is_zero_u64(u64::from(diff)))
}

#[inline(always)]
const fn is_zero_u64(value: u64) -> u64 {
    // (x | -x) >> 63 is 1 for any non-zero x and 0 for zero.
    let nonzero = (value | value.wrapping_neg()) >> 63;
    nonzero ^ 1
}

/// Overwrite a buffer so a secret does not outlive its scope.
///
/// The zeroing is followed by a compiler fence and an opaque read of the
/// buffer's address, which keeps the writes from being removed as dead stores
/// without needing a volatile intrinsic.
#[inline(never)]
pub fn secure_erase(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        *byte = 0;
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    core::hint::black_box(bytes);
}

/// A byte buffer that erases itself when dropped.
#[derive(Clone)]
pub struct Secret<const N: usize>([u8; N]);

impl<const N: usize> Secret<N> {
    /// Wrap an array, taking responsibility for erasing it.
    pub const fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// A zeroed buffer, ready to be filled in place.
    pub const fn zeroed() -> Self {
        Self([0_u8; N])
    }

    /// Read the secret bytes.
    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    /// Mutate the secret bytes in place.
    pub const fn as_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }

    /// Copy the secret out. The copy is no longer erased automatically.
    pub const fn expose(&self) -> [u8; N] {
        self.0
    }
}

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        secure_erase(&mut self.0);
    }
}

impl<const N: usize> core::fmt::Debug for Secret<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Secret<{N}>(redacted)")
    }
}

/// A heap byte buffer that erases itself when dropped.
#[cfg(feature = "std")]
#[derive(Clone)]
pub struct SecretVec(Vec<u8>);

#[cfg(feature = "std")]
impl SecretVec {
    /// Take ownership of a heap buffer.
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Read the secret bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Copy the secret out. The copy is no longer erased automatically.
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.clone()
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(feature = "std")]
impl Drop for SecretVec {
    fn drop(&mut self) {
        secure_erase(&mut self.0);
    }
}

#[cfg(feature = "std")]
impl core::fmt::Debug for SecretVec {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecretVec({} bytes, redacted)", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equality_is_value_correct() {
        assert!(ct_eq_bytes(b"abc", b"abc").is_set());
        assert!(!ct_eq_bytes(b"abc", b"abd").is_set());
        assert!(!ct_eq_bytes(b"abc", b"ab").is_set());
        assert!(ct_eq_bytes(b"", b"").is_set());
    }

    #[test]
    fn the_choice_constants_carry_the_masks_they_promise() {
        assert_eq!(Choice::TRUE.mask(), u64::MAX);
        assert_eq!(Choice::FALSE.mask(), 0);
        assert!(Choice::TRUE.is_set());
        assert!(!Choice::FALSE.is_set());
    }

    #[test]
    fn erase_clears_buffer() {
        let mut buffer = [7_u8; 16];
        secure_erase(&mut buffer);
        assert_eq!(buffer, [0_u8; 16]);
    }
}
