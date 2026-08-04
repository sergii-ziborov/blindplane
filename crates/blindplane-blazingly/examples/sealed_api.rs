//! One sealed record's whole life through the HTTP surface, step by step.
//!
//! This is the integration a client actually writes: generate identities,
//! seal on the client, store ciphertext through the API, find it again by
//! blind index, fetch it back, open it locally against a pinned author. The
//! serving process never holds a decryption key type — that is a property of
//! its dependency graph, not of its configuration.
//!
//! Run with `cargo run -p blindplane-blazingly --example sealed_api`.

use blazingly::prelude::*;
use blindplane_blazingly::{RelayState, base64_decode, base64_encode, hex_encode, plugin};
use blindplane_core::{
    Author, ExactIndexDefinition, PinnedSigner, RecipientKeypair, SearchKey, fastest_payload_suite,
    open_pinned, seal,
};
use blindplane_wire::{RecordContext, SealedRecord, ValidationPolicy};
use futures_lite::future::block_on;

fn main() {
    // 1. Identities. The author signs, Alice can read, the search key blinds
    //    index lookups. All three stay on clients; none reaches the server.
    let author = Author::generate().expect("OS entropy");
    let alice = RecipientKeypair::generate("alice", 1).expect("recipient keys");
    let search_key = SearchKey::generate().expect("search key");
    println!("author key   {}", hex_encode(&author.public_key()));

    // 2. The service pins the author. An empty signer set fails closed:
    //    "trust nobody" must never quietly mean "trust everybody".
    let policy = ValidationPolicy {
        allowed_signers: std::iter::once(author.public_key()).collect(),
        ..ValidationPolicy::default()
    };
    let app = ExecutableApp::from_plugin(plugin(RelayState::new(policy.clone())))
        .expect("relay contract");
    let client = TestApp::new(&app);

    // 3. Seal on the client: payload AEAD under a fresh object secret, one
    //    HPKE envelope for Alice, a blind index for equality search, and an
    //    Ed25519 signature over the whole canonical transcript.
    let plaintext = b"diagnosis: the relay cannot read this";
    let definition = ExactIndexDefinition::raw_bytes("email", 1, 1).expect("index scope");
    let index = search_key
        .exact_token_raw("acme", &definition, b"alice@example.com")
        .expect("index token");
    let token_hex = hex_encode(&index.token);
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
    let wire = record.encode();
    println!(
        "sealed       {} plaintext bytes -> {} wire bytes",
        plaintext.len(),
        wire.len()
    );

    // 4. Store. The service validates structure, the pinned signature and the
    //    monotonic version before it accepts a byte.
    let stored = post(
        &client,
        "/v1/records",
        format!(
            r#"{{"tenant":"acme","object_id":"patient-42","field":"notes","record":"{}"}}"#,
            base64_encode(&wire)
        ),
    );
    assert_eq!(stored.status(), 200, "{}", text(&stored));
    println!("stored       {}", text(&stored));

    // 5. Search by blind token. The service answers equality without ever
    //    learning the value being matched.
    let found = post(
        &client,
        "/v1/search",
        format!(r#"{{"tenant":"acme","label":"email","key_epoch":1,"token":"{token_hex}"}}"#),
    );
    assert_eq!(found.status(), 200, "{}", text(&found));
    assert!(!text(&found).contains(r#""records":[]"#), "index missed");
    println!("searched     blind token matched, plaintext never sent");

    // 6. Fetch the ciphertext back.
    let fetched = post(
        &client,
        "/v1/records/fetch",
        r#"{"tenant":"acme","object_id":"patient-42","field":"notes"}"#.to_owned(),
    );
    assert_eq!(fetched.status(), 200, "{}", text(&fetched));
    let returned = record_field(&fetched);

    // 7. Open locally. Pinning the author once prepares its verification
    //    state; every later record verifies against that instead of reparsing
    //    the key per record.
    let pinned = PinnedSigner::new(author.public_key()).expect("author key");
    let round_tripped = SealedRecord::decode(&returned, &policy).expect("canonical record");
    let opened = open_pinned(&round_tripped, &alice, &pinned).expect("authentic record");
    assert_eq!(opened.as_bytes(), plaintext);
    println!(
        "opened       {:?}",
        String::from_utf8_lossy(opened.as_bytes())
    );
}

fn post(client: &TestApp, path: &str, body: String) -> Response {
    block_on(
        client.call(
            Request::post(path)
                .body(body)
                .header("content-type", "application/json"),
        ),
    )
}

fn text(response: &Response) -> String {
    String::from_utf8_lossy(response.body()).into_owned()
}

fn record_field(response: &Response) -> Vec<u8> {
    let body = text(response);
    let start = body.find(r#""record":""#).expect("record field") + 10;
    let end = body[start..].find('"').expect("closing quote") + start;
    base64_decode(&body[start..end]).expect("valid base64")
}
