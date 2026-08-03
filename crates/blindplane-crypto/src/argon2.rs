//! BLAKE2b and Argon2id (RFC 9106).
//!
//! Argon2id is what turns a password into a vault key. Only the single-lane
//! configuration is implemented: parallelism above one buys throughput on a
//! defender's machine and on an attacker's alike, while single-lane keeps the
//! indexing logic small enough to read in one sitting.

use crate::util::secure_erase;

const BLAKE2B_IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// BLAKE2b with a configurable digest length of 1 to 64 bytes.
#[derive(Clone)]
pub struct Blake2b {
    h: [u64; 8],
    buffer: [u8; 128],
    buffered: usize,
    counter: u128,
    output_len: usize,
}

impl Blake2b {
    /// Start an unkeyed digest producing `output_len` bytes.
    pub fn new(output_len: usize) -> Self {
        assert!(
            (1..=64).contains(&output_len),
            "BLAKE2b output length must be 1..=64"
        );
        let mut h = BLAKE2B_IV;
        // Parameter block: digest length, key length 0, fanout 1, depth 1.
        h[0] ^= 0x0101_0000 ^ (output_len as u64);
        Self {
            h,
            buffer: [0; 128],
            buffered: 0,
            counter: 0,
            output_len,
        }
    }

    /// Absorb more input.
    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            if self.buffered == 128 {
                // A full buffer is only compressed once more input is known to
                // exist, because the last block is flagged differently.
                self.counter += 128;
                let block = self.buffer;
                let counter = self.counter;
                compress(&mut self.h, &block, counter, false);
                self.buffered = 0;
            }
            let take = core::cmp::min(128 - self.buffered, data.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
        }
    }

    /// Finish and write the digest.
    pub fn finalize_into(mut self, out: &mut [u8]) {
        assert_eq!(out.len(), self.output_len, "output buffer length mismatch");
        self.counter += self.buffered as u128;
        for byte in self.buffer.iter_mut().skip(self.buffered) {
            *byte = 0;
        }
        let block = self.buffer;
        let counter = self.counter;
        compress(&mut self.h, &block, counter, true);

        let mut digest = [0_u8; 64];
        for (i, word) in self.h.iter().enumerate() {
            digest[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
        }
        out.copy_from_slice(&digest[..self.output_len]);
        secure_erase(&mut digest);
    }

    /// One-shot digest into a fixed-size array.
    pub fn digest<const N: usize>(data: &[u8]) -> [u8; N] {
        let mut hasher = Self::new(N);
        hasher.update(data);
        let mut out = [0_u8; N];
        hasher.finalize_into(&mut out);
        out
    }
}

fn compress(h: &mut [u64; 8], block: &[u8; 128], counter: u128, last: bool) {
    let mut m = [0_u64; 16];
    for (i, word) in m.iter_mut().enumerate() {
        let mut buf = [0_u8; 8];
        buf.copy_from_slice(&block[i * 8..i * 8 + 8]);
        *word = u64::from_le_bytes(buf);
    }

    let mut v = [0_u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&BLAKE2B_IV);
    v[12] ^= counter as u64;
    v[13] ^= (counter >> 64) as u64;
    if last {
        v[14] = !v[14];
    }

    for round in 0..12 {
        let s = &SIGMA[round];
        mix(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        mix(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        mix(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        mix(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        mix(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        mix(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        mix(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        mix(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

#[inline(always)]
fn mix(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// Argon2's variable-length hash `H'`, which chains BLAKE2b past 64 bytes.
fn hash_prime(input: &[u8], out: &mut [u8]) {
    let out_len = out.len();
    if out_len <= 64 {
        let mut hasher = Blake2b::new(out_len);
        hasher.update(&(out_len as u32).to_le_bytes());
        hasher.update(input);
        hasher.finalize_into(out);
        return;
    }

    let mut block = [0_u8; 64];
    let mut hasher = Blake2b::new(64);
    hasher.update(&(out_len as u32).to_le_bytes());
    hasher.update(input);
    hasher.finalize_into(&mut block);

    out[..32].copy_from_slice(&block[..32]);
    let mut written = 32;

    // Each further step hashes the previous 64-byte block and emits 32 bytes,
    // until the tail, which emits a full final block.
    while out_len - written > 64 {
        let mut next = [0_u8; 64];
        let mut hasher = Blake2b::new(64);
        hasher.update(&block);
        hasher.finalize_into(&mut next);
        out[written..written + 32].copy_from_slice(&next[..32]);
        block = next;
        written += 32;
    }

    let tail = out_len - written;
    let mut hasher = Blake2b::new(tail);
    hasher.update(&block);
    hasher.finalize_into(&mut out[written..]);
    secure_erase(&mut block);
}

const BLOCK_LEN: usize = 1024;
const QWORDS: usize = BLOCK_LEN / 8;

type Block = [u64; QWORDS];

/// Argon2 parameters that are not the password or salt.
#[derive(Clone, Copy, Debug)]
pub struct Argon2Params {
    /// Memory in kibibytes. Must be at least 8.
    pub memory_kib: u32,
    /// Number of passes over memory. Must be at least 1.
    pub passes: u32,
    /// Output length in bytes. Must be at least 4.
    pub output_len: usize,
}

impl Default for Argon2Params {
    /// RFC 9106's "second recommended" option, scaled to a client login:
    /// 64 MiB and three passes, which costs a few tens of milliseconds on a
    /// current laptop and is painful to run billions of times on a GPU.
    fn default() -> Self {
        Self {
            memory_kib: 65_536,
            passes: 3,
            output_len: 32,
        }
    }
}

/// Argon2id parameter validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidParams;

impl core::fmt::Display for InvalidParams {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("invalid Argon2id parameters")
    }
}

impl core::error::Error for InvalidParams {}

/// Derive a key from a password with Argon2id, single lane.
///
/// `salt` must be unique per password and at least 8 bytes; 16 random bytes is
/// the usual choice.
pub fn argon2id(
    password: &[u8],
    salt: &[u8],
    params: Argon2Params,
) -> Result<Vec<u8>, InvalidParams> {
    if params.memory_kib < 8 || params.passes == 0 || params.output_len < 4 || salt.len() < 8 {
        return Err(InvalidParams);
    }

    // Single lane, four slices per pass.
    let lanes = 1_u32;
    let blocks = (params.memory_kib / 4) * 4;
    let segment_length = (blocks / 4) as usize;
    let block_count = blocks as usize;

    // H0 binds every parameter, so changing any of them changes the output.
    let mut h0_input = Vec::with_capacity(64 + password.len() + salt.len());
    h0_input.extend_from_slice(&lanes.to_le_bytes());
    h0_input.extend_from_slice(&(params.output_len as u32).to_le_bytes());
    h0_input.extend_from_slice(&params.memory_kib.to_le_bytes());
    h0_input.extend_from_slice(&params.passes.to_le_bytes());
    h0_input.extend_from_slice(&0x13_u32.to_le_bytes()); // version 1.3
    h0_input.extend_from_slice(&2_u32.to_le_bytes()); // Argon2id
    h0_input.extend_from_slice(&(password.len() as u32).to_le_bytes());
    h0_input.extend_from_slice(password);
    h0_input.extend_from_slice(&(salt.len() as u32).to_le_bytes());
    h0_input.extend_from_slice(salt);
    h0_input.extend_from_slice(&0_u32.to_le_bytes()); // no secret
    h0_input.extend_from_slice(&0_u32.to_le_bytes()); // no associated data

    let mut h0 = [0_u8; 64];
    let mut hasher = Blake2b::new(64);
    hasher.update(&h0_input);
    hasher.finalize_into(&mut h0);
    secure_erase(&mut h0_input);

    let mut memory: Vec<Block> = vec![[0_u64; QWORDS]; block_count];

    // The first two blocks come straight from H0.
    for index in 0..2_u32 {
        let mut input = [0_u8; 72];
        input[..64].copy_from_slice(&h0);
        input[64..68].copy_from_slice(&index.to_le_bytes());
        input[68..72].copy_from_slice(&0_u32.to_le_bytes()); // lane 0
        let mut bytes = vec![0_u8; BLOCK_LEN];
        hash_prime(&input, &mut bytes);
        memory[index as usize] = bytes_to_block(&bytes);
        secure_erase(&mut bytes);
    }
    secure_erase(&mut h0);

    for pass in 0..params.passes {
        for slice in 0..4_usize {
            // Argon2id: the first half of the first pass is data independent.
            let data_independent = pass == 0 && slice < 2;
            let mut address_block = [0_u64; QWORDS];
            let mut input_block = [0_u64; QWORDS];
            let mut address_counter = 0_u64;

            if data_independent {
                input_block[0] = u64::from(pass);
                input_block[1] = 0; // lane
                input_block[2] = slice as u64;
                input_block[3] = u64::from(blocks);
                input_block[4] = u64::from(params.passes);
                input_block[5] = 2; // Argon2id
            }

            let start = if pass == 0 && slice == 0 { 2 } else { 0 };
            if data_independent && start == 2 {
                // The first segment starts at index 2, so the modular trigger
                // inside the loop would never fire for it; the first address
                // block has to be generated here instead.
                address_counter += 1;
                input_block[6] = address_counter;
                address_block = next_address_block(&input_block);
            }

            for index in start..segment_length {
                let current = slice * segment_length + index;
                let previous = if current == 0 {
                    block_count - 1
                } else {
                    current - 1
                };

                let pseudo_random = if data_independent {
                    if index % QWORDS == 0 {
                        address_counter += 1;
                        input_block[6] = address_counter;
                        address_block = next_address_block(&input_block);
                    }
                    address_block[index % QWORDS]
                } else {
                    memory[previous][0]
                };

                let reference = reference_index(
                    pseudo_random,
                    pass,
                    slice,
                    index,
                    segment_length,
                    block_count,
                );

                let mixed = compress_blocks(&memory[previous], &memory[reference]);
                if pass == 0 {
                    memory[current] = mixed;
                } else {
                    for (slot, value) in memory[current].iter_mut().zip(mixed.iter()) {
                        *slot ^= *value;
                    }
                }
            }
        }
    }

    let final_block = memory[block_count - 1];
    let mut final_bytes = block_to_bytes(&final_block);
    let mut out = vec![0_u8; params.output_len];
    hash_prime(&final_bytes, &mut out);

    secure_erase(&mut final_bytes);
    for block in &mut memory {
        block.fill(0);
    }
    Ok(out)
}

/// Generate the next block of data-independent addresses.
fn next_address_block(input_block: &Block) -> Block {
    let zero = [0_u64; QWORDS];
    let first = compress_blocks(&zero, input_block);
    compress_blocks(&zero, &first)
}

/// Map a pseudo-random word onto an index into the already-filled memory.
fn reference_index(
    pseudo_random: u64,
    pass: u32,
    slice: usize,
    index: usize,
    segment_length: usize,
    block_count: usize,
) -> usize {
    let (reference_area_size, start_position) = if pass == 0 {
        (slice * segment_length + index - 1, 0)
    } else {
        let area = block_count - segment_length + index - 1;
        let start = if slice == 3 {
            0
        } else {
            (slice + 1) * segment_length
        };
        (area, start)
    };

    // The quadratic map concentrates references on recent blocks, which is
    // what forces an attacker to keep memory rather than recompute it.
    let j1 = pseudo_random & 0xffff_ffff;
    let mut relative = (j1 * j1) >> 32;
    relative = (reference_area_size as u64) - 1 - (((reference_area_size as u64) * relative) >> 32);
    (start_position + relative as usize) % block_count
}

/// The Argon2 compression function `G`.
fn compress_blocks(x: &Block, y: &Block) -> Block {
    let mut r = [0_u64; QWORDS];
    for i in 0..QWORDS {
        r[i] = x[i] ^ y[i];
    }
    let mut z = r;

    // Rows: eight 16-word groups.
    for row in 0..8 {
        let base = row * 16;
        permute(
            &mut z,
            [
                base,
                base + 1,
                base + 2,
                base + 3,
                base + 4,
                base + 5,
                base + 6,
                base + 7,
                base + 8,
                base + 9,
                base + 10,
                base + 11,
                base + 12,
                base + 13,
                base + 14,
                base + 15,
            ],
        );
    }

    // Columns: eight interleaved 16-word groups.
    for col in 0..8 {
        let base = col * 2;
        permute(
            &mut z,
            [
                base,
                base + 1,
                base + 16,
                base + 17,
                base + 32,
                base + 33,
                base + 48,
                base + 49,
                base + 64,
                base + 65,
                base + 80,
                base + 81,
                base + 96,
                base + 97,
                base + 112,
                base + 113,
            ],
        );
    }

    for i in 0..QWORDS {
        z[i] ^= r[i];
    }
    z
}

/// The BLAKE2b-derived permutation `P` over sixteen selected words.
fn permute(state: &mut Block, i: [usize; 16]) {
    let mut v = [0_u64; 16];
    for (slot, index) in v.iter_mut().zip(i.iter()) {
        *slot = state[*index];
    }

    blamka(&mut v, 0, 4, 8, 12);
    blamka(&mut v, 1, 5, 9, 13);
    blamka(&mut v, 2, 6, 10, 14);
    blamka(&mut v, 3, 7, 11, 15);
    blamka(&mut v, 0, 5, 10, 15);
    blamka(&mut v, 1, 6, 11, 12);
    blamka(&mut v, 2, 7, 8, 13);
    blamka(&mut v, 3, 4, 9, 14);

    for (index, value) in i.iter().zip(v.iter()) {
        state[*index] = *value;
    }
}

#[inline(always)]
fn blamka(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize) {
    // Argon2 replaces BLAKE2b's addition with a multiply-and-add, which is
    // what makes the function expensive to run on cheap parallel hardware.
    v[a] = fused_add(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = fused_add(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = fused_add(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = fused_add(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

#[inline(always)]
fn fused_add(x: u64, y: u64) -> u64 {
    let low = (x & 0xffff_ffff).wrapping_mul(y & 0xffff_ffff);
    x.wrapping_add(y).wrapping_add(low.wrapping_mul(2))
}

fn bytes_to_block(bytes: &[u8]) -> Block {
    let mut block = [0_u64; QWORDS];
    for (i, slot) in block.iter_mut().enumerate() {
        let mut buf = [0_u8; 8];
        buf.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
        *slot = u64::from_le_bytes(buf);
    }
    block
}

fn block_to_bytes(block: &Block) -> Vec<u8> {
    let mut bytes = vec![0_u8; BLOCK_LEN];
    for (i, word) in block.iter().enumerate() {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn blake2b_rfc7693_abc() {
        let digest: [u8; 64] = Blake2b::digest(b"abc");
        assert_eq!(
            hex(&digest),
            concat!(
                "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1",
                "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
            )
        );
    }

    #[test]
    fn blake2b_empty_input() {
        let digest: [u8; 64] = Blake2b::digest(b"");
        assert_eq!(
            hex(&digest),
            concat!(
                "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419",
                "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
            )
        );
    }

    #[test]
    fn blake2b_short_output() {
        let digest: [u8; 32] = Blake2b::digest(b"");
        assert_eq!(
            hex(&digest),
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
        );
    }

    #[test]
    fn blake2b_streaming_matches_one_shot() {
        let data: Vec<u8> = (0..500_u32).map(|i| (i * 3) as u8).collect();
        let mut hasher = Blake2b::new(64);
        for chunk in data.chunks(17) {
            hasher.update(chunk);
        }
        let mut streamed = [0_u8; 64];
        hasher.finalize_into(&mut streamed);
        let one_shot: [u8; 64] = Blake2b::digest(&data);
        assert_eq!(streamed, one_shot);
    }

    #[test]
    fn argon2id_is_deterministic_and_parameter_bound() {
        let params = Argon2Params {
            memory_kib: 64,
            passes: 2,
            output_len: 32,
        };
        let a = argon2id(b"password", b"saltsaltsaltsalt", params).unwrap();
        let b = argon2id(b"password", b"saltsaltsaltsalt", params).unwrap();
        assert_eq!(a, b);

        let different_salt = argon2id(b"password", b"other-salt-here!", params).unwrap();
        assert_ne!(a, different_salt);

        let different_password = argon2id(b"password2", b"saltsaltsaltsalt", params).unwrap();
        assert_ne!(a, different_password);

        let more_passes = argon2id(
            b"password",
            b"saltsaltsaltsalt",
            Argon2Params {
                passes: 3,
                ..params
            },
        )
        .unwrap();
        assert_ne!(a, more_passes);
    }

    #[test]
    fn argon2id_rejects_weak_parameters() {
        let params = Argon2Params {
            memory_kib: 4,
            passes: 1,
            output_len: 32,
        };
        assert_eq!(argon2id(b"p", b"saltsalt", params), Err(InvalidParams));
        assert_eq!(
            argon2id(
                b"p",
                b"short",
                Argon2Params {
                    memory_kib: 64,
                    ..params
                }
            ),
            Err(InvalidParams)
        );
    }
}
