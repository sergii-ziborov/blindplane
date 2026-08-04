//! Framework-neutral keyless relay logic.
//!
//! A relay accepts sealed records, checks that they are well formed, signed by
//! a pinned author and strictly newer than what it already holds, and answers
//! blind-index lookups. It cannot read a payload, and this crate's dependency
//! graph is the proof: it depends on `blindplane-wire` and nothing else, and
//! `blindplane-wire` has no decryption function to call.
//!
//! Transport lives in the adapters. This crate does no I/O, which is what lets
//! the same logic run under Blazingly, under any other server, or inside a test
//! with no socket at all.

#![forbid(unsafe_code)]

mod error;
mod record_key;
mod relay;
mod store;

pub use error::RelayError;
pub use record_key::RecordKey;
pub use relay::Relay;
pub use store::{MemoryStore, WriteReceipt};
