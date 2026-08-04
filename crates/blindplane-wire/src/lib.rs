//! Keyless, server-safe wire types for Blindplane.
//!
//! This crate deliberately contains no decryption key type and no decryption
//! function. A storage or relay service can validate sizes, canonical ordering,
//! signatures and monotonic versions without ever being able to read a payload.
//! That is not a promise in a document; it is a property of this crate's public
//! API, and a reviewer can confirm it by grepping for `open` and finding
//! nothing.
//!
//! Records use a canonical, length-prefixed binary encoding. There is no JSON
//! on the security path: canonical JSON is a well-known source of signature
//! confusion, and a byte-exact encoding removes the entire class.

#![forbid(unsafe_code)]

mod context;
mod encode;
mod error;
mod head;
mod policy;
mod record;
#[cfg(test)]
mod tests;

pub use context::{BlindIndex, RecipientEnvelope, RecordContext, payload_aad};
pub use error::WireError;
pub use head::FreshnessHead;
pub use policy::ValidationPolicy;
pub use record::SealedRecord;

/// Current binary wire format version.
pub const FORMAT_VERSION: u16 = 1;
/// Size of an exact blind-index token in bytes.
pub const INDEX_TOKEN_LEN: usize = 16;
/// Size of an X25519 public or encapsulated key.
pub const X25519_KEY_LEN: usize = 32;
/// An HPKE-wrapped 256-bit DEK plus its 128-bit authentication tag.
pub const WRAPPED_DEK_LEN: usize = 48;
