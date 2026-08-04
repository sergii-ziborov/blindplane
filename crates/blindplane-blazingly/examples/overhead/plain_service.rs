//! The baseline an ordinary service looks like: same framework, same codecs,
//! same payload — and the server holds the plaintext.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use blazingly::prelude::*;

/// The baseline service: same framework, same codecs, no protection.
#[derive(Clone, Default)]
pub struct PlainState(Rc<RefCell<HashMap<String, String>>>);

/// A plaintext write.
#[api_model]
struct PlainStoreRequest {
    /// Storage key.
    key: String,
    /// The payload itself, base64 — the server holds this verbatim.
    value: String,
}

/// A plaintext write receipt.
#[api_model]
struct PlainStoreResponse {
    /// Always true; there is nothing to reject.
    ok: bool,
}

/// A plaintext read.
#[api_model]
struct PlainFetchRequest {
    /// Storage key.
    key: String,
}

/// A plaintext read result.
#[api_model]
struct PlainFetchResponse {
    /// The payload, base64.
    value: String,
}

/// Store a payload the server can read.
#[post("/v1/plain", id = "plain.store", summary = "Store plaintext")]
fn plain_store(
    Json(input): Json<PlainStoreRequest>,
    state: PlainState,
) -> Json<PlainStoreResponse> {
    state.0.borrow_mut().insert(input.key, input.value);
    Json(PlainStoreResponse { ok: true })
}

/// Fetch a payload the server can read.
#[post("/v1/plain/fetch", id = "plain.fetch", summary = "Fetch plaintext")]
fn plain_fetch(
    Json(input): Json<PlainFetchRequest>,
    state: PlainState,
) -> Json<PlainFetchResponse> {
    let value = state
        .0
        .borrow()
        .get(&input.key)
        .cloned()
        .unwrap_or_default();
    Json(PlainFetchResponse { value })
}

pub fn plain_plugin(state: PlainState) -> Plugin {
    Plugin::new("plain")
        .provide(Provider::singleton(move || state.clone()))
        .routes(routes![plain_store, plain_fetch])
}
