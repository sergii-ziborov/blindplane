//! Hex conversion shared by the test modules.
//!
//! Five modules had grown their own copy of these, in two different flavours.
//! Test helpers are not the place to spend attention: the redundancy that
//! earns its keep in this crate is the independent *reference implementations*
//! (the school-arithmetic Poly1305, the from-scratch scalar ChaCha), not five
//! spellings of base-16.

/// Decode a hex string. Panics on anything that is not valid hex, which in a
/// test means a mistyped vector.
pub(crate) fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "hex needs an even length");
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).expect("valid hex"))
        .collect()
}

/// Decode a hex string into a fixed-size array.
pub(crate) fn unhex_array<const N: usize>(text: &str) -> [u8; N] {
    unhex(text).try_into().expect("hex of the expected length")
}

/// Encode bytes as lowercase hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
