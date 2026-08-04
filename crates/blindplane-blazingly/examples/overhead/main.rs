//! What sealing costs an API, where that cost actually goes, and what it buys.
//!
//! Two services on the same framework move the same 4 KiB payload through the
//! same JSON-and-base64 surface. One keeps plaintext in a map. The other keeps
//! sealed records: client-side AEAD under a fresh object secret, an HPKE
//! envelope per recipient, a pinned Ed25519 signature the server verifies,
//! monotonic versions.
//!
//! The headline ratio between those two is real but nearly useless on its own:
//! the baseline is a hash-map insert with no disk, no network and no database,
//! so it measures the framework and little else. What the breakdown below is
//! for is the question that decides an integration — *of the time a sealed
//! request spends, how much is cryptography?* — and the answer is not the one
//! people expect.
//!
//! Run with `cargo run --release -p blindplane-blazingly --example overhead`.

use std::time::{Duration, Instant};

use blazingly::prelude::*;
use blindplane_blazingly::{RelayState, base64_decode, base64_encode, plugin};
use blindplane_core::{
    Author, PinnedSigner, RecipientKeypair, fastest_payload_suite, open_pinned, seal,
};
use blindplane_wire::{RecordContext, SealedRecord, ValidationPolicy};
use futures_lite::future::block_on;

mod plain_service;
use plain_service::{PlainState, plain_plugin};

/// Median round-trip rate over five rounds of at least 250 ms.
///
/// The median, not the best: a best-of can only ever be inflated by one lucky
/// scheduling window, which would flatter whichever side ran in the quieter
/// moment.
fn measure(mut body: impl FnMut(u64)) -> f64 {
    let mut sequence = 1_u64;
    for _ in 0..8 {
        body(sequence);
        sequence += 1;
    }
    let mut rates = [0.0_f64; 5];
    for rate in &mut rates {
        let mut iterations = 0_u32;
        let start = Instant::now();
        loop {
            body(sequence);
            sequence += 1;
            iterations += 1;
            if start.elapsed() >= Duration::from_millis(250) {
                break;
            }
        }
        *rate = f64::from(iterations) / start.elapsed().as_secs_f64();
    }
    rates.sort_unstable_by(f64::total_cmp);
    rates[2]
}

fn main() {
    let payload = vec![0x5a_u8; 4096];
    let author = Author::generate().expect("OS entropy");
    let alice = RecipientKeypair::generate("alice", 1).expect("recipient keys");
    let pinned = PinnedSigner::new(author.public_key()).expect("author key");
    let policy = ValidationPolicy {
        allowed_signers: std::iter::once(author.public_key()).collect(),
        ..ValidationPolicy::default()
    };

    let plain_app =
        ExecutableApp::from_plugin(plain_plugin(PlainState::default())).expect("plain contract");
    let plain = TestApp::new(&plain_app);
    let sealed_app = ExecutableApp::from_plugin(plugin(RelayState::new(policy.clone())))
        .expect("relay contract");
    let sealed = TestApp::new(&sealed_app);

    let encoded_payload = base64_encode(&payload);
    let plain_rate = measure(|sequence| {
        let stored = post(
            &plain,
            "/v1/plain",
            format!(r#"{{"key":"object-{sequence}","value":"{encoded_payload}"}}"#),
        );
        assert_eq!(stored.status(), 200);
        let fetched = post(
            &plain,
            "/v1/plain/fetch",
            format!(r#"{{"key":"object-{sequence}"}}"#),
        );
        assert_eq!(fetched.status(), 200);
    });

    let sealed_rate = measure(|sequence| {
        let record = seal(
            &author,
            context(sequence),
            &payload,
            &[alice.recipient()],
            vec![],
            fastest_payload_suite(),
        )
        .expect("seal");
        let stored = post(
            &sealed,
            "/v1/records",
            store_body(&base64_encode(&record.encode())),
        );
        assert_eq!(stored.status(), 200);
        let fetched = post(&sealed, "/v1/records/fetch", fetch_body());
        assert_eq!(fetched.status(), 200);
        let returned = record_field(&fetched);
        let decoded = SealedRecord::decode(&returned, &policy).expect("canonical");
        let opened = open_pinned(&decoded, &alice, &pinned).expect("authentic");
        assert_eq!(opened.as_bytes(), payload.as_slice());
    });

    // The cryptography alone, with no HTTP surface around it: seal, then
    // verify and open. This is the part that protection actually costs.
    let crypto_rate = measure(|sequence| {
        let record = seal(
            &author,
            context(sequence),
            &payload,
            &[alice.recipient()],
            vec![],
            fastest_payload_suite(),
        )
        .expect("seal");
        let opened = open_pinned(&record, &alice, &pinned).expect("authentic");
        assert_eq!(opened.as_bytes(), payload.as_slice());
    });

    let micros = |rate: f64| 1e6 / rate;
    let crypto_us = micros(crypto_rate);
    let sealed_us = micros(sealed_rate);
    let plain_us = micros(plain_rate);
    let envelope_us = sealed_us - crypto_us;

    println!("== 4 KiB payload, one store + fetch round trip ==\n");
    println!("plaintext service      {plain_rate:9.0} /s   {plain_us:8.1} us");
    println!("sealed service         {sealed_rate:9.0} /s   {sealed_us:8.1} us");
    println!(
        "  of which cryptography              {crypto_us:8.1} us  ({:.0}%)",
        crypto_us / sealed_us * 100.0
    );
    println!(
        "  of which base64 + JSON + routing   {envelope_us:8.1} us  ({:.0}%)",
        envelope_us / sealed_us * 100.0
    );
    println!(
        "\nThe cryptography is a fresh object secret, payload AEAD, an HPKE\n\
         envelope, an Ed25519 signature, server-side signature and version\n\
         validation, and a client-side verify and open — all of it on one\n\
         core. Read the split, not the ratio: the baseline is a hash-map\n\
         insert with no disk, no network and no database behind it, so it\n\
         measures the framework rather than any real service. Against a\n\
         backing store that answers in milliseconds, this whole column is\n\
         noise, and sealing parallelises across cores without sharing state.\n"
    );

    println!("== what the margin buys ==");

    let secret = b"the server must never see this";
    let record = seal(
        &author,
        RecordContext {
            object_id: "secret".into(),
            ..context(1)
        },
        secret,
        &[alice.recipient()],
        vec![],
        fastest_payload_suite(),
    )
    .expect("seal");
    let stored = post(
        &sealed,
        "/v1/records",
        format!(
            r#"{{"tenant":"acme","object_id":"secret","field":"notes","record":"{}"}}"#,
            base64_encode(&record.encode())
        ),
    );
    assert_eq!(stored.status(), 200);
    let fetched = post(
        &sealed,
        "/v1/records/fetch",
        r#"{"tenant":"acme","object_id":"secret","field":"notes"}"#.to_owned(),
    );
    let held = record_field(&fetched);
    assert!(!held.windows(secret.len()).any(|w| w == secret));
    println!("1. every byte the service stores and returns is ciphertext");

    let stranger = Author::generate().expect("OS entropy");
    let forged = seal(
        &stranger,
        context(1),
        b"forged",
        &[alice.recipient()],
        vec![],
        fastest_payload_suite(),
    )
    .expect("seal");
    let refused = post(
        &sealed,
        "/v1/records",
        store_body(&base64_encode(&forged.encode())),
    );
    assert_eq!(refused.status(), 400);
    println!("2. a record from an unpinned signer is refused with 400");

    let mut tampered = record.clone();
    tampered.ciphertext[0] ^= 1;
    assert!(open_pinned(&tampered, &alice, &pinned).is_err());
    println!("3. one flipped ciphertext bit fails authentication on open");

    // The baseline offers none of the three: it was handed the payload, it
    // would have accepted any writer, and it has nothing to authenticate.
    let leaked = post(
        &plain,
        "/v1/plain/fetch",
        r#"{"key":"object-9"}"#.to_owned(),
    );
    assert_eq!(leaked.status(), 200);
    let held_plain = base64_decode(&value_field(&leaked)).expect("valid base64");
    assert_eq!(
        held_plain, payload,
        "the plaintext service holds the payload"
    );
    println!(
        "\nThe plaintext service holds the payload verbatim, accepts any\nwriter, and cannot detect tampering at all."
    );
}

fn context(version: u64) -> RecordContext {
    RecordContext {
        tenant: "acme".into(),
        object_id: "object-1".into(),
        field: "notes".into(),
        epoch: 1,
        version,
        schema_version: 1,
    }
}

fn store_body(encoded: &str) -> String {
    format!(r#"{{"tenant":"acme","object_id":"object-1","field":"notes","record":"{encoded}"}}"#)
}

fn fetch_body() -> String {
    r#"{"tenant":"acme","object_id":"object-1","field":"notes"}"#.to_owned()
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

fn field(response: &Response, name: &str) -> String {
    let body = String::from_utf8_lossy(response.body()).into_owned();
    let needle = format!(r#""{name}":""#);
    let start = body.find(&needle).expect("field present") + needle.len();
    let end = body[start..].find('"').expect("closing quote") + start;
    body[start..end].to_owned()
}

fn record_field(response: &Response) -> Vec<u8> {
    base64_decode(&field(response, "record")).expect("valid base64")
}

fn value_field(response: &Response) -> String {
    field(response, "value")
}
