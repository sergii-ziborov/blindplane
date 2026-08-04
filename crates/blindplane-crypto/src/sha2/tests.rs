//! Unit tests for SHA-256 and SHA-512.

use super::sha256::{H256, compress256_portable};
use super::sha512::{H512, compress512, compress512_blocks};
use super::*;
use crate::testutil::hex;

#[test]
fn sha256_known_answers() {
    assert_eq!(
        hex(&Sha256::digest(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        hex(&Sha256::digest(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hex(&Sha256::digest(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        )),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

#[test]
fn sha512_accelerated_matches_portable() {
    // If the hardware path is active, it must agree with the portable one
    // on every length across the block boundary; if it is not active this
    // still exercises the portable path.
    for len in [0_usize, 1, 111, 112, 127, 128, 129, 255, 256, 1000, 4096] {
        let data: Vec<u8> = (0..len).map(|i| (i * 29 + 5) as u8).collect();

        let mut portable = H512;
        for block in data.chunks_exact(128) {
            let mut fixed = [0_u8; 128];
            fixed.copy_from_slice(block);
            compress512(&mut portable, &fixed);
        }
        let mut accelerated = H512;
        let full = data.len() / 128 * 128;
        compress512_blocks(&mut accelerated, &data[..full]);

        assert_eq!(
            portable, accelerated,
            "SHA-512 block path mismatch at {len}"
        );
    }
}

#[test]
fn sha256_million_a() {
    let mut hasher = Sha256::new();
    for _ in 0..1000 {
        hasher.update(&[b'a'; 1000]);
    }
    assert_eq!(
        hex(&hasher.finalize()),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}

#[test]
fn sha256_accelerated_matches_portable() {
    // Cover every offset within a block plus multi-block inputs.
    for len in [0_usize, 1, 55, 56, 63, 64, 65, 119, 128, 1000, 4096] {
        let data: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();

        let mut portable_state = H256;
        let mut padded = data.clone();
        let bit_len = (data.len() as u64) * 8;
        padded.push(0x80);
        while padded.len() % 64 != 56 {
            padded.push(0);
        }
        padded.extend_from_slice(&bit_len.to_be_bytes());
        for block in padded.chunks_exact(64) {
            let mut fixed = [0_u8; 64];
            fixed.copy_from_slice(block);
            compress256_portable(&mut portable_state, &fixed);
        }
        let mut expected = [0_u8; 32];
        for (i, word) in portable_state.iter().enumerate() {
            expected[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }

        assert_eq!(Sha256::digest(&data), expected, "mismatch at length {len}");
    }
}

#[test]
fn sha256_streaming_matches_one_shot() {
    let data: Vec<u8> = (0..1000_u32).map(|i| i as u8).collect();
    let mut hasher = Sha256::new();
    for chunk in data.chunks(7) {
        hasher.update(chunk);
    }
    assert_eq!(hasher.finalize(), Sha256::digest(&data));
}

#[test]
fn sha512_known_answers() {
    assert_eq!(
        hex(&Sha512::digest(b"")),
        concat!(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        )
    );
    assert_eq!(
        hex(&Sha512::digest(b"abc")),
        concat!(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a",
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        )
    );
}

#[test]
fn sha512_streaming_matches_one_shot() {
    let data: Vec<u8> = (0..777_u32).map(|i| (i * 13) as u8).collect();
    let mut hasher = Sha512::new();
    for chunk in data.chunks(13) {
        hasher.update(chunk);
    }
    assert_eq!(hasher.finalize(), Sha512::digest(&data));
}
