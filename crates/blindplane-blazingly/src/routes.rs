use blazingly::prelude::*;

use blindplane_relay::RecordKey;

use crate::codec::{base64_decode, base64_encode, hex_decode, hex_encode};
use crate::error::BlindplaneError;
use crate::models::{
    FetchRequest, RecordResponse, SearchRequest, SearchResponse, StoreRequest, StoreResponse,
};
use crate::state::RelayState;

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
