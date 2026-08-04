//! Blazingly adapter for the Blindplane keyless relay.
//!
//! The operations here move ciphertext. They validate structure, signatures and
//! monotonic versions, and they answer blind-index lookups — all without a
//! decryption key type existing anywhere in this crate's dependency graph.
//!
//! Records travel as base64 inside typed models rather than as a raw body, so
//! the whole surface stays inside Blazingly's contract, OpenAPI and MCP
//! projection instead of sitting outside it as an opaque blob.

#![forbid(unsafe_code)]

mod codec;
mod error;
mod models;
mod routes;
mod state;

pub use codec::{base64_decode, base64_encode, hex_decode, hex_encode};
pub use error::BlindplaneError;
pub use models::{
    FetchRequest, RecordResponse, SearchRequest, SearchResponse, StoreRequest, StoreResponse,
};
pub use routes::plugin;
pub use state::RelayState;
