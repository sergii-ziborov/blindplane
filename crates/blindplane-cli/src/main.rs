//! Command-line tool for Blindplane.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use blindplane_core::{Author, RecipientKeypair, fastest_payload_suite, open, seal};
use blindplane_crypto::Acceleration;
use blindplane_relay::{RecordKey, Relay};
use blindplane_wire::{RecordContext, SealedRecord, ValidationPolicy};

fn main() -> ExitCode {
    let command = std::env::args().nth(1).unwrap_or_else(|| "help".to_owned());
    match command.as_str() {
        "selfcheck" => selfcheck(),
        "acceleration" => {
            println!("{}", Acceleration::detect());
            ExitCode::SUCCESS
        }
        _ => {
            println!("blindplane <selfcheck|acceleration>");
            ExitCode::SUCCESS
        }
    }
}

/// Run one full seal, relay round trip and open, reporting what happened.
fn selfcheck() -> ExitCode {
    println!("acceleration: {}", Acceleration::detect());

    let author = Author::generate().expect("CSPRNG");
    let alice = RecipientKeypair::generate("alice", 1).expect("keypair");
    let context = RecordContext {
        tenant: "acme".into(),
        object_id: "record-1".into(),
        field: "notes".into(),
        epoch: 1,
        version: 1,
        schema_version: 1,
    };
    let plaintext = b"the relay never sees this";

    let record = seal(
        &author,
        context.clone(),
        plaintext,
        &[alice.recipient()],
        vec![],
        fastest_payload_suite(),
    )
    .expect("seal");

    let policy = ValidationPolicy {
        allowed_signers: std::iter::once(author.public_key()).collect(),
        ..ValidationPolicy::default()
    };
    let relay = Relay::new(policy);
    let key = RecordKey::new(&context.tenant, &context.object_id, &context.field);
    let receipt = relay.put_encoded(&key, &record.encode()).expect("store");
    println!(
        "relay accepted version {} revision {}",
        receipt.version, receipt.manifest_revision
    );

    let fetched = relay.get_encoded(&key).expect("fetch");
    assert!(
        !fetched
            .windows(plaintext.len())
            .any(|window| window == plaintext),
        "plaintext must not appear in the stored bytes"
    );

    let decoded = SealedRecord::decode(&fetched, relay.policy()).expect("decode");
    let opened = open(&decoded, &alice, author.public_key()).expect("open");
    assert_eq!(opened.as_bytes(), plaintext);

    println!(
        "self-check passed: sealed, relayed, and opened {} bytes",
        plaintext.len()
    );
    ExitCode::SUCCESS
}
