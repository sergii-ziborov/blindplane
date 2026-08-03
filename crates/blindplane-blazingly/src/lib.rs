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

use std::rc::Rc;

use blazingly::prelude::*;
use blindplane_relay::{RecordKey, Relay, RelayError};
use blindplane_wire::ValidationPolicy;

/// Shared relay state, injected into every operation.
#[derive(Clone)]
pub struct RelayState(Rc<Relay>);

impl RelayState {
    /// Build state around a policy.
    pub fn new(policy: ValidationPolicy) -> Self {
        Self(Rc::new(Relay::new(policy)))
    }

    /// The underlying relay.
    pub fn relay(&self) -> &Relay {
        &self.0
    }
}

/// A record write.
#[api_model]
#[derive(Clone, Debug)]
pub struct StoreRequest {
    /// Tenant or workspace.
    #[min_length(1)]
    #[max_length(255)]
    pub tenant: String,
    /// Object identifier.
    #[min_length(1)]
    #[max_length(255)]
    pub object_id: String,
    /// Field or security zone.
    #[min_length(1)]
    #[max_length(255)]
    pub field: String,
    /// The canonical record encoding, base64.
    #[min_length(1)]
    pub record: String,
}

/// The receipt for an accepted write.
#[api_model]
#[derive(Clone, Debug)]
pub struct StoreResponse {
    /// Accepted monotonic record version.
    pub version: u64,
    /// Accepted access-manifest revision.
    pub manifest_revision: u64,
    /// Hash the client persists as its freshness checkpoint, hex encoded.
    pub manifest_hash: String,
    /// Whether the record did not previously exist.
    pub created: bool,
}

/// A record lookup by identity.
#[api_model]
#[derive(Clone, Debug)]
pub struct FetchRequest {
    /// Tenant or workspace.
    #[min_length(1)]
    #[max_length(255)]
    pub tenant: String,
    /// Object identifier.
    #[min_length(1)]
    #[max_length(255)]
    pub object_id: String,
    /// Field or security zone.
    #[min_length(1)]
    #[max_length(255)]
    pub field: String,
}

/// One record, still sealed.
#[api_model]
#[derive(Clone, Debug)]
pub struct RecordResponse {
    /// The canonical record encoding, base64.
    pub record: String,
}

/// A blind-index lookup.
#[api_model]
#[derive(Clone, Debug)]
pub struct SearchRequest {
    /// Tenant or workspace.
    #[min_length(1)]
    #[max_length(255)]
    pub tenant: String,
    /// Index label.
    #[min_length(1)]
    #[max_length(255)]
    pub label: String,
    /// Index key epoch.
    pub key_epoch: u64,
    /// The client-computed token, hex encoded.
    #[min_length(32)]
    #[max_length(32)]
    pub token: String,
}

/// Ciphertext candidates for a blind-index lookup.
#[api_model]
#[derive(Clone, Debug)]
pub struct SearchResponse {
    /// Matching sealed records, base64. Clients decrypt and check each one.
    pub records: Vec<String>,
}

/// Failures a relay can report.
///
/// None of these distinguish "wrong key" from "tampered": the relay has no key
/// and cannot tell, which is the point.
#[api_error]
pub enum BlindplaneError {
    /// The record failed keyless validation.
    #[status(400)]
    #[code("record_invalid")]
    #[message("The record failed keyless validation.")]
    RecordInvalid,
    /// The route and the record's authenticated context disagree.
    #[status(400)]
    #[code("route_context_mismatch")]
    #[message("The route does not match the record's authenticated context.")]
    RouteContextMismatch,
    /// The body was not valid base64 or hex.
    #[status(400)]
    #[code("malformed_encoding")]
    #[message("A field was not valid base64 or hexadecimal.")]
    MalformedEncoding,
    /// The write does not advance the stored version.
    #[status(409)]
    #[code("stale_write")]
    #[message("The write does not advance the stored version.")]
    StaleWrite,
    /// No record exists at this identity.
    #[status(404)]
    #[code("record_not_found")]
    #[message("No record exists at this identity.")]
    NotFound,
}

impl From<RelayError> for BlindplaneError {
    fn from(error: RelayError) -> Self {
        match error {
            RelayError::Invalid(_) => Self::RecordInvalid,
            RelayError::RouteContextMismatch => Self::RouteContextMismatch,
            RelayError::StaleWrite { .. } => Self::StaleWrite,
            RelayError::NotFound => Self::NotFound,
        }
    }
}

/// Liveness probe.
#[get("/health", id = "blindplane.health", summary = "Liveness probe")]
fn health() -> Json<&'static str> {
    Json("ok")
}

/// Store a sealed record.
#[post(
    "/v1/records",
    id = "blindplane.records.store",
    summary = "Store a sealed record"
)]
fn store_record(
    Json(input): Json<StoreRequest>,
    state: RelayState,
) -> Result<Json<StoreResponse>, BlindplaneError> {
    let encoded = base64_decode(&input.record).ok_or(BlindplaneError::MalformedEncoding)?;
    let key = RecordKey::new(input.tenant, input.object_id, input.field);
    let receipt = state.relay().put_encoded(&key, &encoded)?;
    Ok(Json(StoreResponse {
        version: receipt.version,
        manifest_revision: receipt.manifest_revision,
        manifest_hash: hex_encode(&receipt.manifest_hash),
        created: receipt.created,
    }))
}

/// Fetch a sealed record.
#[post(
    "/v1/records/fetch",
    id = "blindplane.records.fetch",
    summary = "Fetch a sealed record"
)]
fn fetch_record(
    Json(input): Json<FetchRequest>,
    state: RelayState,
) -> Result<Json<RecordResponse>, BlindplaneError> {
    let key = RecordKey::new(input.tenant, input.object_id, input.field);
    let encoded = state.relay().get_encoded(&key)?;
    Ok(Json(RecordResponse {
        record: base64_encode(&encoded),
    }))
}

/// Look up ciphertext candidates by blind-index token.
#[post(
    "/v1/search",
    id = "blindplane.search",
    summary = "Look up ciphertext by blind-index token"
)]
fn search_records(
    Json(input): Json<SearchRequest>,
    state: RelayState,
) -> Result<Json<SearchResponse>, BlindplaneError> {
    let token: [u8; 16] = hex_decode(&input.token)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(BlindplaneError::MalformedEncoding)?;
    let records = state
        .relay()
        .search_encoded(&input.tenant, &input.label, input.key_epoch, token)
        .iter()
        .map(|record| base64_encode(record))
        .collect();
    Ok(Json(SearchResponse { records }))
}

/// Build a Blazingly plugin serving the keyless relay.
pub fn plugin(state: RelayState) -> Plugin {
    // The relay is built once and shared: it owns the store, so a per-request
    // instance would hand every request a fresh empty database.
    Plugin::new("blindplane")
        .provide(Provider::singleton(move || state.clone()))
        .routes(routes![health, store_record, fetch_record, search_records])
}

/// Standard base64 with padding.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(ALPHABET[((triple >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((triple >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(triple & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Standard base64 with padding. Returns `None` for anything malformed.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let mut triple = 0_u32;
        let mut padding = 0;
        for (i, byte) in chunk.iter().enumerate() {
            let value = match byte {
                b'A'..=b'Z' => u32::from(byte - b'A'),
                b'a'..=b'z' => u32::from(byte - b'a') + 26,
                b'0'..=b'9' => u32::from(byte - b'0') + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' if i >= 2 => {
                    padding += 1;
                    0
                }
                _ => return None,
            };
            triple = (triple << 6) | value;
        }
        out.push((triple >> 16) as u8);
        if padding < 2 {
            out.push((triple >> 8) as u8);
        }
        if padding < 1 {
            out.push(triple as u8);
        }
    }
    Some(out)
}

fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 15)] as char);
    }
    out
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)? as u8;
        let lo = (pair[1] as char).to_digit(16)? as u8;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips_every_tail_length() {
        for len in 0..64 {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 7 + 1) as u8).collect();
            let encoded = base64_encode(&bytes);
            assert_eq!(base64_decode(&encoded).unwrap(), bytes, "length {len}");
        }
    }

    #[test]
    fn base64_rejects_malformed_input() {
        assert!(base64_decode("A").is_none());
        assert!(base64_decode("!!!!").is_none());
        assert!(base64_decode("=AAA").is_none());
    }

    #[test]
    fn hex_round_trips() {
        let bytes = [0_u8, 1, 15, 16, 254, 255];
        assert_eq!(hex_encode(&bytes), "00010f10feff");
        assert_eq!(hex_decode("00010f10feff").unwrap(), bytes);
        assert!(hex_decode("abc").is_none());
        assert!(hex_decode("zz").is_none());
    }
}
