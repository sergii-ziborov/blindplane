//! SHA-256 and SHA-512.
//!
//! SHA-256 has two interchangeable implementations: a portable one and one
//! built on the ARMv8 SHA-2 instructions, chosen once per process by runtime
//! feature detection. Both produce identical digests; the tests assert that on
//! every input they are given.

const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H256: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K512: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

const H512: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// Streaming SHA-256.
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffered: usize,
    length: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// Digest length in bytes.
    pub const OUTPUT_LEN: usize = 32;
    /// Compression block length in bytes.
    pub const BLOCK_LEN: usize = 64;

    /// Start a new digest.
    pub const fn new() -> Self {
        Self {
            state: H256,
            buffer: [0; 64],
            buffered: 0,
            length: 0,
        }
    }

    /// Absorb more input.
    pub fn update(&mut self, mut data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);

        if self.buffered > 0 {
            let take = core::cmp::min(64 - self.buffered, data.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered == 64 {
                let block = self.buffer;
                compress256(&mut self.state, &block);
                self.buffered = 0;
            }
        }

        let full = data.len() / 64 * 64;
        if full > 0 {
            compress256_blocks(&mut self.state, &data[..full]);
            data = &data[full..];
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffered = data.len();
        }
    }

    /// Finish and return the digest.
    pub fn finalize(mut self) -> [u8; 32] {
        let bit_length = self.length.wrapping_mul(8);
        self.update(&[0x80]);
        // `update` counted the padding byte; the length field must not.
        self.length = self.length.wrapping_sub(1);
        while self.buffered != 56 {
            self.update(&[0]);
            self.length = self.length.wrapping_sub(1);
        }
        self.update(&bit_length.to_be_bytes());

        let mut out = [0_u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// One-shot digest.
    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

/// Streaming SHA-512.
#[derive(Clone)]
pub struct Sha512 {
    state: [u64; 8],
    buffer: [u8; 128],
    buffered: usize,
    length: u128,
}

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha512 {
    /// Digest length in bytes.
    pub const OUTPUT_LEN: usize = 64;
    /// Compression block length in bytes.
    pub const BLOCK_LEN: usize = 128;

    /// Start a new digest.
    pub const fn new() -> Self {
        Self {
            state: H512,
            buffer: [0; 128],
            buffered: 0,
            length: 0,
        }
    }

    /// Absorb more input.
    pub fn update(&mut self, mut data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u128);

        if self.buffered > 0 {
            let take = core::cmp::min(128 - self.buffered, data.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered == 128 {
                let block = self.buffer;
                compress512(&mut self.state, &block);
                self.buffered = 0;
            }
        }

        while data.len() >= 128 {
            let mut block = [0_u8; 128];
            block.copy_from_slice(&data[..128]);
            compress512(&mut self.state, &block);
            data = &data[128..];
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffered = data.len();
        }
    }

    /// Finish and return the digest.
    pub fn finalize(mut self) -> [u8; 64] {
        let bit_length = self.length.wrapping_mul(8);
        self.update(&[0x80]);
        self.length = self.length.wrapping_sub(1);
        while self.buffered != 112 {
            self.update(&[0]);
            self.length = self.length.wrapping_sub(1);
        }
        self.update(&bit_length.to_be_bytes());

        let mut out = [0_u8; 64];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// One-shot digest.
    pub fn digest(data: &[u8]) -> [u8; 64] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

fn compress256_blocks(state: &mut [u32; 8], data: &[u8]) {
    #[cfg(all(feature = "accel", target_arch = "aarch64"))]
    {
        if arm::available() {
            // SAFETY: `available()` confirmed the SHA-2 instructions exist on
            // this CPU, which is the only precondition of `compress_arm`.
            unsafe { arm::compress(state, data) };
            return;
        }
    }
    for block in data.chunks_exact(64) {
        let mut fixed = [0_u8; 64];
        fixed.copy_from_slice(block);
        compress256_portable(state, &fixed);
    }
}

fn compress256(state: &mut [u32; 8], block: &[u8; 64]) {
    compress256_blocks(state, block);
}

fn compress256_portable(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0_u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K256[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

fn compress512(state: &mut [u64; 8], block: &[u8; 128]) {
    let mut w = [0_u64; 80];
    for i in 0..16 {
        let mut buf = [0_u8; 8];
        buf.copy_from_slice(&block[i * 8..i * 8 + 8]);
        w[i] = u64::from_be_bytes(buf);
    }
    for i in 16..80 {
        let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
        let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for i in 0..80 {
        let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K512[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// SHA-256 on the ARMv8 cryptographic extensions.
#[cfg(all(feature = "accel", target_arch = "aarch64"))]
mod arm {
    use super::K256;
    use core::arch::aarch64::{
        uint32x4_t, vaddq_u32, vld1q_u8, vld1q_u32, vreinterpretq_u8_u32, vreinterpretq_u32_u8,
        vrev32q_u8, vsha256h2q_u32, vsha256hq_u32, vsha256su0q_u32, vsha256su1q_u32, vst1q_u32,
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

            let mut round_keys = [vld1q_u32(K256.as_ptr()); 16];
            for (i, key) in round_keys.iter_mut().enumerate() {
                *key = vld1q_u32(K256.as_ptr().add(i * 4));
            }

            for block in data.chunks_exact(64) {
                let saved_abcd = abcd;
                let saved_efgh = efgh;

                // The digest is big-endian; NEON loads are little-endian.
                let mut msg: [uint32x4_t; 4] = [
                    vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr()))),
                    vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr().add(16)))),
                    vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr().add(32)))),
                    vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr().add(48)))),
                ];

                for round in 0..16 {
                    let wk = vaddq_u32(msg[round % 4], round_keys[round]);
                    let previous_abcd = abcd;
                    abcd = vsha256hq_u32(abcd, efgh, wk);
                    efgh = vsha256h2q_u32(efgh, previous_abcd, wk);

                    if round < 12 {
                        // Four schedule words at a time: su0 mixes w[i-15],
                        // su1 folds in w[i-7] and w[i-2].
                        msg[round % 4] = vsha256su1q_u32(
                            vsha256su0q_u32(msg[round % 4], msg[(round + 1) % 4]),
                            msg[(round + 2) % 4],
                            msg[(round + 3) % 4],
                        );
                    }
                }

                abcd = vaddq_u32(abcd, saved_abcd);
                efgh = vaddq_u32(efgh, saved_efgh);
            }

            vst1q_u32(state.as_mut_ptr(), abcd);
            vst1q_u32(state.as_mut_ptr().add(4), efgh);
            let _ = vreinterpretq_u8_u32(abcd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

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
}
