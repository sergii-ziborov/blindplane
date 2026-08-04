//! The same keyless relay, served by axum instead of Blazingly.
//!
//! This example exists to keep one word in this crate's description honest:
//! *framework-neutral*. The relay does no I/O, holds no key type and makes no
//! assumption about who calls it, so an adapter is a few dozen lines whatever
//! the framework — and neither of the two here is privileged.
//!
//! It also shows that the wire shape is the adapter's choice, not the
//! library's. The Blazingly adapter carries records as base64 inside typed
//! JSON models so the whole surface stays inside that framework's OpenAPI and
//! MCP projection. This one takes the canonical bytes as a raw body under a
//! path — which is what an axum service would naturally do, and which skips
//! the base64 and JSON work that the `overhead` example measures at rather
//! more than half of a sealed round trip.
//!
//! `Relay` is `Send + Sync` (its store is behind an `RwLock`), so `Arc<Relay>`
//! is all the sharing a multi-threaded runtime needs.
//!
//! Run with `cargo run -p blindplane-relay --example axum_relay`.

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

use blindplane_relay::{RecordKey, Relay, RelayError};
use blindplane_wire::ValidationPolicy;

/// Map relay failures onto status codes. The relay holds no key, so it cannot
/// tell "wrong key" from "tampered" and does not pretend to.
fn status_for(error: &RelayError) -> StatusCode {
    match error {
        RelayError::Invalid(_) | RelayError::RouteContextMismatch => StatusCode::BAD_REQUEST,
        RelayError::StaleWrite { .. } => StatusCode::CONFLICT,
        RelayError::NotFound => StatusCode::NOT_FOUND,
    }
}

/// `POST /v1/records/{tenant}/{object_id}/{field}` — body is the canonical
/// record encoding, verbatim. No base64, no envelope.
async fn store_record(
    State(relay): State<Arc<Relay>>,
    Path((tenant, object_id, field)): Path<(String, String, String)>,
    body: Bytes,
) -> Response {
    let key = RecordKey::new(tenant, object_id, field);
    match relay.put_encoded(&key, &body) {
        Ok(receipt) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            format!(
                r#"{{"version":{},"manifest_revision":{},"created":{}}}"#,
                receipt.version, receipt.manifest_revision, receipt.created
            ),
        )
            .into_response(),
        Err(error) => (status_for(&error), error.to_string()).into_response(),
    }
}

/// `GET /v1/records/{tenant}/{object_id}/{field}` — the sealed record itself.
async fn fetch_record(
    State(relay): State<Arc<Relay>>,
    Path((tenant, object_id, field)): Path<(String, String, String)>,
) -> Response {
    let key = RecordKey::new(tenant, object_id, field);
    match relay.get_encoded(&key) {
        Ok(encoded) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/octet-stream")],
            encoded,
        )
            .into_response(),
        Err(error) => (status_for(&error), error.to_string()).into_response(),
    }
}

/// `POST /v1/search/{tenant}/{label}/{key_epoch}` — body is the 16-byte blind
/// index token. The relay answers equality without learning the value.
async fn search_records(
    State(relay): State<Arc<Relay>>,
    Path((tenant, label, key_epoch)): Path<(String, String, u64)>,
    body: Bytes,
) -> Response {
    let Ok(token) = <[u8; 16]>::try_from(body.as_ref()) else {
        return (StatusCode::BAD_REQUEST, "token must be 16 bytes").into_response();
    };
    let found = relay.search_encoded(&tenant, &label, key_epoch, token);
    // One length-prefixed record after another: the transport does not need to
    // understand the records to carry them.
    let mut out = Vec::new();
    for record in &found {
        out.extend_from_slice(&(record.len() as u32).to_be_bytes());
        out.extend_from_slice(record);
    }
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/octet-stream")],
        out,
    )
        .into_response()
}

/// Build the router. This is the whole adapter.
pub fn router(policy: ValidationPolicy) -> Router {
    Router::new()
        .route(
            "/v1/records/{tenant}/{object_id}/{field}",
            post(store_record).get(fetch_record),
        )
        .route(
            "/v1/search/{tenant}/{label}/{key_epoch}",
            post(search_records),
        )
        .route("/health", get(|| async { "ok" }))
        .with_state(Arc::new(Relay::new(policy)))
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    use blindplane_core::{
        Author, ExactIndexDefinition, PinnedSigner, RecipientKeypair, SearchKey,
        fastest_payload_suite, open_pinned, seal,
    };
    use blindplane_wire::{RecordContext, SealedRecord};

    let author = Author::generate().expect("OS entropy");
    let alice = RecipientKeypair::generate("alice", 1).expect("recipient keys");
    let search_key = SearchKey::generate().expect("search key");
    let policy = ValidationPolicy {
        allowed_signers: std::iter::once(author.public_key()).collect(),
        ..ValidationPolicy::default()
    };
    let app = router(policy.clone());

    let plaintext = b"axum carries this without being able to read it";
    let definition = ExactIndexDefinition::raw_bytes("email", 1, 1).expect("index scope");
    let index = search_key
        .exact_token_raw("acme", &definition, b"alice@example.com")
        .expect("index token");
    let token = index.token;
    let record = seal(
        &author,
        RecordContext {
            tenant: "acme".into(),
            object_id: "patient-42".into(),
            field: "notes".into(),
            epoch: 1,
            version: 1,
            schema_version: 1,
        },
        plaintext,
        &[alice.recipient()],
        vec![index],
        fastest_payload_suite(),
    )
    .expect("seal");

    // Drive the router in-process, the way axum's own tests do; a deployment
    // hands the same Router to `axum::serve` over a TcpListener.
    let stored = call(
        &app,
        "POST",
        "/v1/records/acme/patient-42/notes",
        record.encode(),
    )
    .await;
    assert_eq!(
        stored.0,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&stored.1)
    );
    println!("stored    {}", String::from_utf8_lossy(&stored.1));

    let found = call(&app, "POST", "/v1/search/acme/email/1", token.to_vec()).await;
    assert_eq!(found.0, StatusCode::OK);
    assert!(!found.1.is_empty(), "blind index missed");
    assert!(
        !found.1.windows(plaintext.len()).any(|w| w == plaintext),
        "search response leaked plaintext"
    );
    println!("searched  matched by blind token, no plaintext in the response");

    let fetched = call(&app, "GET", "/v1/records/acme/patient-42/notes", Vec::new()).await;
    assert_eq!(fetched.0, StatusCode::OK);
    assert!(
        !fetched.1.windows(plaintext.len()).any(|w| w == plaintext),
        "relay returned plaintext"
    );

    let pinned = PinnedSigner::new(author.public_key()).expect("author key");
    let returned = SealedRecord::decode(&fetched.1, &policy).expect("canonical record");
    let opened = open_pinned(&returned, &alice, &pinned).expect("authentic record");
    assert_eq!(opened.as_bytes(), plaintext);
    println!("opened    {:?}", String::from_utf8_lossy(opened.as_bytes()));

    let stranger = Author::generate().expect("OS entropy");
    let forged = seal(
        &stranger,
        RecordContext {
            tenant: "acme".into(),
            object_id: "forged".into(),
            field: "notes".into(),
            epoch: 1,
            version: 1,
            schema_version: 1,
        },
        b"forged",
        &[alice.recipient()],
        vec![],
        fastest_payload_suite(),
    )
    .expect("seal");
    let refused = call(
        &app,
        "POST",
        "/v1/records/acme/forged/notes",
        forged.encode(),
    )
    .await;
    assert_eq!(refused.0, StatusCode::BAD_REQUEST);
    println!("refused   a record from an unpinned signer, 400");
}

/// Send one request through the router and collect the response.
async fn call(app: &Router, method: &str, uri: &str, body: Vec<u8>) -> (StatusCode, Vec<u8>) {
    use axum::body::to_bytes;
    use axum::http::Request;
    use tower::ServiceExt as _;

    let request = Request::builder()
        .method(method)
        .uri(uri)
        .body(axum::body::Body::from(body))
        .expect("valid request");
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("router is infallible");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body collects");
    (status, bytes.to_vec())
}
