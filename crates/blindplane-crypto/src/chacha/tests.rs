//! Unit tests for ChaCha20 and HChaCha20.

use super::*;

#[test]
fn rfc8439_keystream_block() {
    // RFC 8439, section 2.4.2.
    let key: [u8; 32] = core::array::from_fn(|i| i as u8);
    let mut nonce = [0_u8; 12];
    nonce[3] = 0x00;
    nonce[4..].copy_from_slice(&[0, 0, 0, 0x4a, 0, 0, 0, 0]);

    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you \
only one tip for the future, sunscreen would be it.";
    let mut buffer = plaintext.to_vec();
    ChaCha20::new(&key, &nonce, 1).apply_keystream(&mut buffer);

    let expected = [
        0x6e_u8, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d,
        0x69, 0x81,
    ];
    assert_eq!(&buffer[..16], &expected);
    assert_eq!(buffer.len(), plaintext.len());

    // Decryption is the same operation.
    ChaCha20::new(&key, &nonce, 1).apply_keystream(&mut buffer);
    assert_eq!(buffer, plaintext);
}

#[test]
fn keystream_is_chunk_size_independent() {
    let key = [7_u8; 32];
    let nonce = [3_u8; 12];
    let mut whole = vec![0_u8; 1000];
    ChaCha20::new(&key, &nonce, 0).apply_keystream(&mut whole);

    // A generator advanced in 256-byte steps must line up with one that
    // produced the same range in a single call.
    let mut stepwise = vec![0_u8; 1000];
    let mut cipher = ChaCha20::new(&key, &nonce, 0);
    for chunk in stepwise.chunks_mut(256) {
        cipher.apply_keystream(chunk);
    }
    assert_eq!(whole, stepwise);
}

#[test]
fn hchacha20_reference_vector() {
    // draft-irtf-cfrg-xchacha, section 2.2.1.
    let key: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let nonce: [u8; 16] = [
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x31, 0x41, 0x59,
        0x27,
    ];
    let expected: [u8; 32] = [
        0x82, 0x41, 0x3b, 0x42, 0x27, 0xb2, 0x7b, 0xfe, 0xd3, 0x0e, 0x42, 0x50, 0x8a, 0x87, 0x7d,
        0x73, 0xa0, 0xf9, 0xe4, 0xd5, 0x8a, 0x74, 0xa8, 0x53, 0xc1, 0x2e, 0xc4, 0x13, 0x26, 0xd3,
        0xec, 0xdc,
    ];
    assert_eq!(hchacha20(&key, &nonce), expected);
}

/// A fully independent scalar ChaCha20 that shares no code with the
/// production path, used to check the SIMD path across many blocks.
///
/// The earlier tests only compared the first 16 bytes of one block, or
/// compared the accelerated path against itself; a systematic SIMD error
/// past the first block slipped through both. This checks every byte of a
/// multi-group keystream against a reference written from the RFC by hand.
fn reference_keystream(key: &[u8; 32], nonce: &[u8; 12], counter: u32, out: &mut [u8]) {
    fn qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        s[a] = s[a].wrapping_add(s[b]);
        s[d] = (s[d] ^ s[a]).rotate_left(16);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] = (s[b] ^ s[c]).rotate_left(12);
        s[a] = s[a].wrapping_add(s[b]);
        s[d] = (s[d] ^ s[a]).rotate_left(8);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] = (s[b] ^ s[c]).rotate_left(7);
    }
    for (block, chunk) in out.chunks_mut(64).enumerate() {
        let mut s = [0_u32; 16];
        s[0..4].copy_from_slice(&SIGMA);
        for i in 0..8 {
            s[4 + i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
        }
        s[12] = counter.wrapping_add(block as u32);
        for i in 0..3 {
            s[13 + i] = u32::from_le_bytes(nonce[i * 4..i * 4 + 4].try_into().unwrap());
        }
        let start = s;
        for _ in 0..10 {
            qr(&mut s, 0, 4, 8, 12);
            qr(&mut s, 1, 5, 9, 13);
            qr(&mut s, 2, 6, 10, 14);
            qr(&mut s, 3, 7, 11, 15);
            qr(&mut s, 0, 5, 10, 15);
            qr(&mut s, 1, 6, 11, 12);
            qr(&mut s, 2, 7, 8, 13);
            qr(&mut s, 3, 4, 9, 14);
        }
        for i in 0..16 {
            s[i] = s[i].wrapping_add(start[i]);
        }
        for (i, slot) in chunk.chunks_mut(4).enumerate() {
            slot.copy_from_slice(&s[i].to_le_bytes()[..slot.len()]);
        }
    }
}

#[test]
fn simd_keystream_matches_independent_reference_across_many_blocks() {
    let key: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    let nonce: [u8; 12] = core::array::from_fn(|i| (i as u8).wrapping_mul(11));

    // 2049 bytes crosses the 8-block (512 B) and 4-block (256 B) paths and
    // ends on a partial block, exercising every branch of the SIMD loop.
    for len in [64_usize, 256, 257, 512, 513, 1024, 2049] {
        let mut reference = vec![0_u8; len];
        reference_keystream(&key, &nonce, 1, &mut reference);

        let mut produced = vec![0_u8; len];
        ChaCha20::new(&key, &nonce, 1).apply_keystream(&mut produced);

        assert_eq!(
            produced, reference,
            "SIMD keystream diverges from the reference at length {len}"
        );
    }
}

#[test]
fn counter_advances_correctly_when_split_across_calls() {
    let key = [9_u8; 32];
    let nonce = [4_u8; 12];

    let mut whole = vec![0_u8; 1024];
    reference_keystream(&key, &nonce, 5, &mut whole);

    // Two calls on one generator must reproduce the single-shot keystream,
    // which fails if the counter does not carry between calls.
    let mut split = vec![0_u8; 1024];
    let mut generator = ChaCha20::new(&key, &nonce, 5);
    let (first, second) = split.split_at_mut(384);
    generator.apply_keystream(first);
    generator.apply_keystream(second);
    assert_eq!(split, whole);
}
