//! BLAKE2b and Argon2id (RFC 9106).
//!
//! Argon2id is what turns a password into a vault key. Only the single-lane
//! configuration is implemented: parallelism above one buys throughput on a
//! defender's machine and on an attacker's alike, while single-lane keeps the
//! indexing logic small enough to read in one sitting.

mod argon2id;
mod blake2b;
mod block_mix;
#[cfg(test)]
mod tests;

pub use argon2id::{Argon2Params, InvalidParams, argon2id};
pub use blake2b::Blake2b;
