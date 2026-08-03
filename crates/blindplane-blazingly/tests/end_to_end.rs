//! One record's whole life, through the framework: sealed on a client, stored
//! by a Blazingly relay, found by blind index, fetched back and opened.
//!
//! The point of the test is the assertion in the middle: the bytes the relay
//! accepted, indexed and returned never contain the plaintext.

use blazingly::prelude::*;
use blindplane_blazingly::{RelayState, plugin};
use blindplane_core::{
    Author, ExactIndexDefinition, RecipientKeypair, SearchKey, fastest_payload_suite, open, seal,
};
use blindplane_wire::{RecordContext, SealedRecord, ValidationPolicy};
use futures_lite::future::block_on;

#[test]
fn a_record_survives_a_round_trip_through_the_relay_without_leaking() {
    let author = Author::generate().unwrap();
    let alice = RecipientKeypair::generate("alice", 1).unwrap();
    let search_key = SearchKey::generate().unwrap();
    let definition = ExactIndexDefinition::raw_bytes("email", 1, 1).unwrap();

    let plaintext = b"diagnosis: the relay cannot read this";
    let context = RecordContext {
        tenant: "acme".into(),
        object_id: "patient-42".into(),
        field: "notes".into(),
        epoch: 1,
        version: 1,
        schema_version: 1,
    };
    let index = search_key
        .exact_token_raw("acme", &definition, b"alice@example.com")
        .unwrap();
    let token_hex: String = index.token.iter().map(|b| format!("{b:02x}")).collect();

    let record = seal(
        &author,
        context,
        plaintext,
        &[alice.recipient()],
        vec![index],
        fastest_payload_suite(),
    )
    .unwrap();

    let policy = ValidationPolicy {
        allowed_signers: std::iter::once(author.public_key()).collect(),
        ..ValidationPolicy::default()
    };
    let app = ExecutableApp::from_plugin(plugin(RelayState::new(policy.clone())))
        .expect("relay contract should compile");
    let client = TestApp::new(&app);

    let encoded = base64(&record.encode());

    let stored = block_on(client.call(Request::post("/v1/records").body(
        format!(
            r#"{{"tenant":"acme","object_id":"patient-42","field":"notes","record":"{encoded}"}}"#
        ),
    ).header("content-type", "application/json")));
    assert_eq!(stored.status(), 200, "store: {}", body_text(&stored));
    assert!(body_text(&stored).contains(r#""created":true"#));

    // The relay is holding the record now. Whatever it holds must not contain
    // the plaintext anywhere.
    let found = block_on(
        client.call(
            Request::post("/v1/search")
                .body(format!(
                    r#"{{"tenant":"acme","label":"email","key_epoch":1,"token":"{token_hex}"}}"#
                ))
                .header("content-type", "application/json"),
        ),
    );
    assert_eq!(found.status(), 200, "search: {}", body_text(&found));
    let search_body = body_text(&found);
    assert!(
        !search_body
            .as_bytes()
            .windows(plaintext.len())
            .any(|w| w == plaintext),
        "search response leaked plaintext"
    );

    let fetched = block_on(
        client.call(
            Request::post("/v1/records/fetch")
                .body(r#"{"tenant":"acme","object_id":"patient-42","field":"notes"}"#)
                .header("content-type", "application/json"),
        ),
    );
    assert_eq!(fetched.status(), 200, "fetch: {}", body_text(&fetched));

    let returned = body_text(&fetched);
    let start = returned.find(r#""record":""#).expect("record field") + 10;
    let end = returned[start..].find('"').expect("closing quote") + start;
    let decoded = unbase64(&returned[start..end]);
    assert!(
        !decoded.windows(plaintext.len()).any(|w| w == plaintext),
        "relay returned plaintext"
    );

    let round_tripped = SealedRecord::decode(&decoded, &policy).unwrap();
    let opened = open(&round_tripped, &alice, author.public_key()).unwrap();
    assert_eq!(opened.as_bytes(), plaintext);
}

#[test]
fn a_record_signed_by_an_unpinned_key_is_refused() {
    let author = Author::generate().unwrap();
    let stranger = Author::generate().unwrap();
    let alice = RecipientKeypair::generate("alice", 1).unwrap();

    let record = seal(
        &stranger,
        RecordContext {
            tenant: "acme".into(),
            object_id: "o".into(),
            field: "f".into(),
            epoch: 1,
            version: 1,
            schema_version: 1,
        },
        b"payload",
        &[alice.recipient()],
        vec![],
        fastest_payload_suite(),
    )
    .unwrap();

    let policy = ValidationPolicy {
        allowed_signers: std::iter::once(author.public_key()).collect(),
        ..ValidationPolicy::default()
    };
    let app = ExecutableApp::from_plugin(plugin(RelayState::new(policy))).unwrap();
    let client = TestApp::new(&app);

    let encoded = base64(&record.encode());
    let response = block_on(
        client.call(
            Request::post("/v1/records")
                .body(format!(
                    r#"{{"tenant":"acme","object_id":"o","field":"f","record":"{encoded}"}}"#
                ))
                .header("content-type", "application/json"),
        ),
    );
    assert_eq!(response.status(), 400);
    assert!(body_text(&response).contains("record_invalid"));
}

fn body_text(response: &Response) -> String {
    String::from_utf8_lossy(response.body()).into_owned()
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
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

fn unbase64(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in text.as_bytes().chunks(4) {
        let mut triple = 0_u32;
        let mut padding = 0;
        for byte in chunk {
            let value = match byte {
                b'A'..=b'Z' => u32::from(byte - b'A'),
                b'a'..=b'z' => u32::from(byte - b'a') + 26,
                b'0'..=b'9' => u32::from(byte - b'0') + 52,
                b'+' => 62,
                b'/' => 63,
                _ => {
                    padding += 1;
                    0
                }
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
    out
}
