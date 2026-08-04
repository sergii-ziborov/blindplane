//! Client-side sealing for Blindplane.
//!
//! A record carries a fresh random 256-bit object secret, a payload encrypted
//! under a key derived from it, one HPKE envelope per recipient, and an Ed25519
//! signature over the ciphertext, the routing context, the recipient grants and
//! any blind indexes.
//!
//! This crate is for trusted clients and trusted inference workers. Server
//! relays depend on `blindplane-wire` instead, whose dependency graph contains
//! no decryption API.
//!
//! # What the server learns anyway
//!
//! Being honest about the leaks is part of the design:
//!
//! - the routing context: tenant, object id, field name, epoch and version;
//! - the size of every ciphertext, rounded to nothing at all;
//! - which recipient identifiers can read which record, and when that changed;
//! - equality and frequency of any value you choose to blind-index;
//! - access patterns: who fetched what, and when.
//!
//! What it does not learn is the plaintext, and no configuration mistake on the
//! server side can change that, because the server never holds a key.

#![forbid(unsafe_code)]

mod batch;
mod derive;
mod error;
mod identity;
mod indexes;
mod sealing;
#[cfg(test)]
mod tests;
mod vault;

pub use batch::{BatchItem, seal_batch};
pub use error::CryptoError;
pub use identity::{Author, PinnedSigner, Recipient, RecipientKeypair, recipient_key_id};
pub use indexes::{ExactIndexDefinition, SearchKey};
pub use sealing::{
    grant_recipient, open, open_at_head, open_at_head_pinned, open_pinned, rekey, seal,
};
pub use vault::{derive_vault_key, fastest_payload_suite};
