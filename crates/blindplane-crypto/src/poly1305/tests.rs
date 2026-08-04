//! Unit tests for Poly1305.

use super::*;

#[test]
fn rfc8439_tag() {
    // RFC 8439, section 2.5.2.
    let key: [u8; 32] = [
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06,
        0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49,
        0xf5, 0x1b,
    ];
    let message = b"Cryptographic Forum Research Group";
    let mut mac = Poly1305::new(&key);
    mac.update(message);
    assert_eq!(
        mac.finalize(),
        [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
            0x27, 0xa9
        ]
    );
}

#[test]
fn all_zero_key_gives_zero_tag() {
    // RFC 8439 A.3, test vector 1.
    let mut mac = Poly1305::new(&[0_u8; 32]);
    mac.update(&[0_u8; 64]);
    assert_eq!(mac.finalize(), [0_u8; 16]);
}

#[test]
fn wraparound_vector() {
    // RFC 8439 A.3, test vector 3: r = 0, s = key's second half.
    let mut key = [0_u8; 32];
    key[16..].copy_from_slice(&[
        0x36, 0xe5, 0xf6, 0xb5, 0xc5, 0xe0, 0x60, 0x70, 0xf0, 0xef, 0xca, 0x96, 0x22, 0x7a, 0x86,
        0x3e,
    ]);
    let mut mac = Poly1305::new(&key);
    mac.update(&[
        0x41, 0x6e, 0x79, 0x20, 0x73, 0x75, 0x62, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x20,
        0x74, 0x6f, 0x20, 0x74, 0x68, 0x65, 0x20, 0x49, 0x45, 0x54, 0x46, 0x20, 0x69, 0x6e, 0x74,
        0x65, 0x6e,
    ]);
    assert_eq!(
        mac.finalize(),
        [
            0x36, 0xe5, 0xf6, 0xb5, 0xc5, 0xe0, 0x60, 0x70, 0xf0, 0xef, 0xca, 0x96, 0x22, 0x7a,
            0x86, 0x3e
        ]
    );
}

#[test]
fn streaming_matches_one_shot() {
    let key: [u8; 32] = core::array::from_fn(|i| (i * 7 + 1) as u8);
    let data: Vec<u8> = (0..333_u32).map(|i| (i * 5) as u8).collect();

    let mut one_shot = Poly1305::new(&key);
    one_shot.update(&data);
    let expected = one_shot.finalize();

    for chunk_size in [1_usize, 3, 15, 16, 17, 64] {
        let mut streamed = Poly1305::new(&key);
        for chunk in data.chunks(chunk_size) {
            streamed.update(chunk);
        }
        assert_eq!(streamed.finalize(), expected, "chunk size {chunk_size}");
    }
}

#[test]
fn verification_rejects_modified_tag() {
    let key = [9_u8; 32];
    let mut mac = Poly1305::new(&key);
    mac.update(b"message");
    let mut tag = mac.finalize();

    let mut good = Poly1305::new(&key);
    good.update(b"message");
    assert!(good.verify(&tag).is_set());

    tag[0] ^= 1;
    let mut bad = Poly1305::new(&key);
    bad.update(b"message");
    assert!(!bad.verify(&tag).is_set());
}

/// Poly1305 evaluated directly from the RFC 8439 pseudocode with plain
/// 320-bit school arithmetic. It shares no code, no representation and no
/// reduction strategy with the production path, so a systematic limb or
/// carry error there cannot also be here.
mod reference {
    /// A little-endian 320-bit integer.
    type Wide = [u64; 5];

    fn add(a: Wide, b: Wide) -> Wide {
        let mut out = [0_u64; 5];
        let mut carry = 0_u128;
        for i in 0..5 {
            let t = u128::from(a[i]) + u128::from(b[i]) + carry;
            out[i] = t as u64;
            carry = t >> 64;
        }
        out
    }

    fn sub(a: Wide, b: Wide) -> Wide {
        let mut out = [0_u64; 5];
        let mut borrow = 0_i128;
        for i in 0..5 {
            let t = i128::from(a[i]) - i128::from(b[i]) - borrow;
            out[i] = t as u64;
            borrow = i128::from(t < 0);
        }
        out
    }

    fn geq(a: Wide, b: Wide) -> bool {
        for i in (0..5).rev() {
            if a[i] != b[i] {
                return a[i] > b[i];
            }
        }
        true
    }

    fn mul(a: Wide, b: Wide) -> [u64; 10] {
        let mut out = [0_u64; 10];
        for i in 0..5 {
            let mut carry = 0_u128;
            for j in 0..5 {
                let t = u128::from(out[i + j]) + u128::from(a[i]) * u128::from(b[j]) + carry;
                out[i + j] = t as u64;
                carry = t >> 64;
            }
            // Row i is the first to touch position i + 5.
            out[i + 5] = carry as u64;
        }
        out
    }

    /// Reduce a 320-bit value modulo `2^130 - 5` by folding the high bits
    /// down three times, then subtracting the modulus while it still fits.
    fn mod_p(x: [u64; 10]) -> Wide {
        fn fold(x: [u64; 10]) -> [u64; 10] {
            let mut high = [0_u64; 10];
            for i in 0..8 {
                let next = if i + 3 < 10 { x[i + 3] } else { 0 };
                high[i] = (x[i + 2] >> 2) | (next << 62);
            }
            let mut out = [x[0], x[1], x[2] & 3, 0, 0, 0, 0, 0, 0, 0];
            let mut carry = 0_u128;
            for i in 0..10 {
                let t = u128::from(out[i]) + 5 * u128::from(high[i]) + carry;
                out[i] = t as u64;
                carry = t >> 64;
            }
            out
        }
        let x = fold(fold(fold(x)));
        let p: Wide = [0xffff_ffff_ffff_fffb, u64::MAX, 3, 0, 0];
        let mut n: Wide = [x[0], x[1], x[2], x[3], x[4]];
        for _ in 0..2 {
            if geq(n, p) {
                n = sub(n, p);
            }
        }
        n
    }

    pub fn tag(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
        let r: Wide = [
            u64::from_le_bytes(key[0..8].try_into().unwrap()) & 0x0ffffffc0fffffff,
            u64::from_le_bytes(key[8..16].try_into().unwrap()) & 0x0ffffffc0ffffffc,
            0,
            0,
            0,
        ];
        let s: Wide = [
            u64::from_le_bytes(key[16..24].try_into().unwrap()),
            u64::from_le_bytes(key[24..32].try_into().unwrap()),
            0,
            0,
            0,
        ];

        let mut accumulator: Wide = [0; 5];
        for chunk in msg.chunks(16) {
            let mut block = [0_u8; 17];
            block[..chunk.len()].copy_from_slice(chunk);
            block[chunk.len()] = 1;
            let n: Wide = [
                u64::from_le_bytes(block[0..8].try_into().unwrap()),
                u64::from_le_bytes(block[8..16].try_into().unwrap()),
                u64::from(block[16]),
                0,
                0,
            ];
            accumulator = mod_p(mul(add(accumulator, n), r));
        }

        let out = add(accumulator, s);
        let mut tag = [0_u8; 16];
        tag[..8].copy_from_slice(&out[0].to_le_bytes());
        tag[8..].copy_from_slice(&out[1].to_le_bytes());
        tag
    }
}

#[test]
fn matches_rfc_pseudocode_reference_across_many_inputs() {
    let mut state = 0x243f_6a88_85a3_08d3_u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    for case in 0..300_u32 {
        let mut key = [0_u8; 32];
        for byte in &mut key {
            *byte = next() as u8;
        }
        // Every seventh case uses the maximal clamped r, and every fifth
        // an all-ones message: the carry-heaviest corners.
        if case % 7 == 0 {
            key[..16].fill(0xff);
        }
        let len = (next() % 300) as usize;
        let mut msg = vec![0_u8; len];
        for byte in &mut msg {
            *byte = next() as u8;
        }
        if case % 5 == 0 {
            msg.fill(0xff);
        }

        let mut mac = Poly1305::new(&key);
        mac.update(&msg);
        assert_eq!(
            mac.finalize(),
            reference::tag(&key, &msg),
            "case {case} length {len}"
        );
    }
}
