//! Argon2id's parameters, memory-filling pass, and the driving function.

use crate::util::secure_erase;

use super::blake2b::Blake2b;
use super::block_mix::{block_to_bytes, bytes_to_block, compress_blocks};

pub(super) const BLOCK_LEN: usize = 1024;
pub(super) const QWORDS: usize = BLOCK_LEN / 8;

pub(super) type Block = [u64; QWORDS];

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
