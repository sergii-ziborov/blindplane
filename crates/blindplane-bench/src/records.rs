use std::fmt::Write as _;
use std::hint::black_box;

use blindplane_core::{
    Author, BatchItem, PinnedSigner, RecipientKeypair, open, open_pinned, seal, seal_batch,
};
use blindplane_crypto::aead::Suite;
use blindplane_wire::RecordContext;

use crate::measure;

pub(crate) fn bench_end_to_end(report: &mut String) {
    println!("== End-to-end records (ops/s) ==");
    let _ = writeln!(report, "## End-to-end sealed records\n");
    let _ = writeln!(
        report,
        "A full record: fresh object secret, payload AEAD, one HPKE envelope per recipient, key commitment, Ed25519 signature and canonical encoding.\n"
    );
    let _ = writeln!(report, "| Operation | ops/s |");
    let _ = writeln!(report, "|---|---:|");

    let author = Author::generate().unwrap();
    let alice = RecipientKeypair::generate("alice", 1).unwrap();
    let suite = Suite::fastest_available();
    let payload = vec![0x33_u8; 4096];
    let context = RecordContext {
        tenant: "acme".into(),
        object_id: "object-1".into(),
        field: "notes".into(),
        epoch: 1,
        version: 1,
        schema_version: 1,
    };

    let seal_rate = measure(|| {
        let record = seal(
            &author,
            context.clone(),
            &payload,
            &[alice.recipient()],
            vec![],
            suite,
        )
        .unwrap();
        black_box(record);
    });

    let record = seal(
        &author,
        context.clone(),
        &payload,
        &[alice.recipient()],
        vec![],
        suite,
    )
    .unwrap();
    let signer = author.public_key();
    let open_rate = measure(|| {
        black_box(open(&record, &alice, signer).unwrap());
    });

    // The pinned variant prepares the author's verification state once per
    // session instead of once per record — the shape a sync actually has.
    let pinned = PinnedSigner::new(signer).expect("author key is valid");
    let open_pinned_rate = measure(|| {
        black_box(open_pinned(&record, &alice, &pinned).unwrap());
    });

    let three: Vec<_> = (0..3)
        .map(|i| RecipientKeypair::generate(format!("user-{i}"), 1).unwrap())
        .collect();
    let three_recipients: Vec<_> = three.iter().map(RecipientKeypair::recipient).collect();
    let seal_three = measure(|| {
        let record = seal(
            &author,
            context.clone(),
            &payload,
            &three_recipients,
            vec![],
            suite,
        )
        .unwrap();
        black_box(record);
    });

    // Batch sealing across every core.
    let batch: Vec<BatchItem> = (0..256)
        .map(|i| BatchItem {
            context: RecordContext {
                object_id: format!("object-{i}"),
                ..context.clone()
            },
            plaintext: payload.clone(),
            recipients: vec![alice.recipient()],
            indexes: vec![],
        })
        .collect();
    let batch_rate = measure(|| {
        let results = seal_batch(&author, &batch, suite);
        black_box(results.len());
    }) * batch.len() as f64;

    for (name, value) in [
        ("seal, 4 KiB, 1 recipient", seal_rate),
        ("open, 4 KiB, 1 recipient", open_rate),
        ("open, 4 KiB, pinned author", open_pinned_rate),
        ("seal, 4 KiB, 3 recipients", seal_three),
        ("seal batch, all cores (records/s)", batch_rate),
    ] {
        println!("  {name:38}{value:12.0}");
        let _ = writeln!(report, "| {name} | {value:.0} |");
    }
    println!();
    let _ = writeln!(
        report,
        "\nBatch sealing scales across cores: each record has its own object secret, so nothing is shared and nothing needs locking.\n"
    );
}
