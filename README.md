# Blindplane

A server-blind data plane for Rust services. The server routes, stores, indexes
and serves records it cannot read, and that is a property of the code's shape
rather than of its configuration: the crates a server links have no decryption
function to call and no key type to hold.

Blindplane implements its own cryptography — ChaCha20-Poly1305, AES-256-GCM,
SHA-2, HMAC, HKDF, Argon2id, X25519, Ed25519 and HPKE — with **no third-party
runtime dependencies**, and ships an adapter for
[Blazingly](https://github.com/sergii-ziborov/blazingly).

> **Status: prototype, not audited.** The algorithms are standard and are
> verified against published test vectors and cross-checked byte for byte
> against established implementations, which is not the same thing as a
> security audit. Read [Security posture](#security-posture) before trusting it
> with anything real.

## The shape of it

```
client (trusted)                    relay (untrusted)              client (trusted)
──────────────────                  ─────────────────              ────────────────
seal ─── object secret ──▶   ciphertext + envelopes + signature   ──▶ open
     ├─ payload AEAD                validate structure                 verify signer pin
     ├─ HPKE per recipient          verify signature                   check freshness head
     ├─ key commitment              enforce monotonic version          unwrap DEK
     ├─ Ed25519 signature           index blind tokens                 check key commitment
     └─ blind index tokens          serve candidates                   decrypt
```

The relay never holds a key. It can refuse a write, lose data, or serve a stale
record — and the client detects the stale record through a signed hash chain —
but it cannot read one.

## What the server learns anyway

Every server-blind system leaks something. Naming the leaks is part of the
design, not a footnote:

- **Routing context** — tenant, object id, field name, epoch and version, all in
  the clear because the server routes on them.
- **Ciphertext length**, exactly, with no padding.
- **The access graph** — which recipient identifiers can read which record, and
  when that changed.
- **Equality and frequency** for any field you choose to blind-index, within its
  `(tenant, label, key_epoch)` scope.
- **Access patterns** — who fetched what, and when.

What it does not learn is plaintext. No server-side misconfiguration changes
that, because there is no server-side key to misconfigure.

## Crates

| Crate | Purpose | Runtime dependencies |
|---|---|---|
| `blindplane-crypto` | Every primitive, implemented here | **none** |
| `blindplane-wire` | Canonical binary records, signature and rollback validation. No decryption API. | `blindplane-crypto` |
| `blindplane-relay` | Framework-neutral relay: validation, monotonic writes, blind-index lookup | `blindplane-wire` |
| `blindplane-core` | Client-side sealing and opening | `blindplane-crypto`, `blindplane-wire` |
| `blindplane-blazingly` | Blazingly adapter: typed operations, OpenAPI and MCP projection | `blazingly` + relay |
| `blindplane-cli` | Key generation and a self-check | workspace only |

Verify the dependency claim rather than believing it:

```bash
cargo tree -p blindplane-core --edges normal
```

## Quick start

```rust
use blindplane_core::{Author, RecipientKeypair, fastest_payload_suite, open, seal};
use blindplane_wire::RecordContext;

let author = Author::generate()?;
let alice = RecipientKeypair::generate("alice", 1)?;

let record = seal(
    &author,
    RecordContext {
        tenant: "acme".into(),
        object_id: "patient-42".into(),
        field: "diagnosis".into(),
        epoch: 1,
        version: 1,
        schema_version: 1,
    },
    b"the relay never sees this",
    &[alice.recipient()],
    vec![],
    fastest_payload_suite(),
)?;

// `record.encode()` is what crosses the wire. The relay validates and stores it.
let plaintext = open(&record, &alice, author.public_key())?;
assert_eq!(plaintext.as_bytes(), b"the relay never sees this");
```

Serving it through Blazingly is four lines:

```rust
use blazingly::prelude::*;
use blindplane_blazingly::{RelayState, plugin};

let app = ExecutableApp::from_plugin(plugin(RelayState::new(policy)))?;
```

Run the self-check:

```bash
cargo run -p blindplane-cli -- selfcheck
```

## Security posture

**Design choices that are not negotiable in this codebase.**

- *Constant time by default.* Secret-dependent branches and secret-dependent
  memory addresses are treated as defects. Comparisons on secrets go through a
  masked `Choice`, never `==`.
- *No software AES.* A table-driven AES leaks its key through cache timing.
  Where the CPU has no AES instructions, `Suite::Aes256Gcm` reports itself
  unavailable and callers use ChaCha20-Poly1305, which is constant time in
  software everywhere.
- *Authenticate before decrypting.* No AEAD here returns unverified plaintext,
  and a failed open zeroes the buffer instead of leaving a partial result.
- *Key commitment.* Every record commits to its object secret, so a swapped key
  fails closed rather than producing a second valid plaintext.
- *Strict Ed25519.* Non-canonical `S` values and small-order public keys are
  rejected, which is what makes signatures non-malleable.
- *Canonical binary encoding.* Records decode only if they re-encode to the
  identical bytes. Canonical-JSON signature confusion is not a class of bug this
  format can have.
- *Rollback detection.* A client persists a signed manifest-hash chain head. A
  replayed old record still verifies — every signature on it is genuine — so the
  head is what catches it.

**Known limitations, stated plainly.**

- Not audited. Not fuzzed to exhaustion. `unsafe` appears only in
  `blindplane-crypto`'s accelerated paths and can be compiled out entirely with
  `--no-default-features --features std`.
- Password-derived vault keys use Argon2id and are therefore subject to offline
  dictionary attack by whoever holds the vault blob. This is **not** OPAQUE or
  any other PAKE; a PAKE would remove that exposure and is the main item on the
  roadmap.
- Revocation is forward-looking. `rekey` rotates the object secret so future
  reads are denied; it cannot un-read what a former recipient already saw.
- Recipient key pinning is only as good as the channel the fingerprint arrived
  on. Taking a fingerprint from the same server that serves the key is
  security theatre.
- AES-256-GCM is implemented for AArch64 only. x86-64 AES-NI is not written yet,
  so on x86-64 the ChaCha suite is used.

## Verification

Correctness is not asserted, it is tested:

- **Published vectors** — RFC 8439 (ChaCha20, Poly1305, AEAD), RFC 7748
  (X25519), RFC 8032 (Ed25519), FIPS 180-4 (SHA-256/512), NIST SP 800-38D
  (AES-256-GCM), RFC 4231 (HMAC), RFC 5869 (HKDF), RFC 7693 (BLAKE2b).
- **Cross-implementation interop** — every primitive is run side by side with an
  established implementation on identical input and required to produce
  identical bytes, in both directions where a protocol has two sides:
  RustCrypto (`aes-gcm`, `chacha20poly1305`, `sha2`), `ed25519-dalek`,
  `x25519-dalek`, the `hpke` reference crate, the `argon2` crate and `ring`.
  Our HPKE opens theirs and theirs opens ours; our Argon2id output is
  byte-identical to the reference at three parameter sets.
- **Negative tests** — every single-bit flip across a sealed record is rejected;
  truncated and oversized encodings are refused before allocating; unpinned
  signers, substituted recipient fingerprints and replayed records all fail
  closed.

These crates are dev-dependencies. None can reach a shipped binary.

```bash
cargo test --workspace
```

## Benchmarks

Full results, methodology and machine details: [`results/benchmarks.md`](results/benchmarks.md).
Reproduce with `cargo run --release -p blindplane-bench`.

Measured on an Apple M4 (10 cores), rustc 1.96.1, best of five rounds of at
least 250 ms each, identical inputs for every implementation, outputs checked.

**AEAD encryption, GB/s at 1 MiB — higher is better**

| Implementation | GB/s |
|---|---:|
| ring AES-256-GCM | 8.13 |
| RustCrypto aes-gcm | 6.76 |
| **Blindplane AES-256-GCM** | **5.85** |
| ring ChaCha20-Poly1305 | 2.26 |
| RustCrypto chacha20poly1305 | 1.12 |
| **Blindplane ChaCha20-Poly1305** | **0.95** |

**Public-key and protocol operations, operations/s — higher is better**

| Operation | Blindplane | Competitor | Ratio |
|---|---:|---:|---:|
| X25519 Diffie-Hellman | 59 682 | 50 139 (`x25519-dalek`) | **1.19x** |
| Ed25519 sign | 124 339 | 122 610 (`ed25519-dalek`) | 1.01x |
| Ed25519 verify (strict) | 39 391 | 55 473 (`ed25519-dalek`) | 0.71x |
| HPKE seal | 26 605 | 26 712 (`hpke`) | 1.00x |
| Argon2id, 64 MiB × 3 | 13.1 | 15.4 (`argon2`) | 0.85x |

**End-to-end sealed records**

| Operation | records/s |
|---|---:|
| seal, 4 KiB, 1 recipient | 10 233 |
| open, 4 KiB, 1 recipient | 17 584 |
| seal, 4 KiB, 3 recipients | 5 726 |
| seal batch, all 10 cores | 43 774 |

### Reading these numbers honestly

Blindplane is **fastest at X25519**, at **parity** for Ed25519 signing, HPKE and
Argon2id, and **behind** `ring` on bulk symmetric throughput and on Ed25519
verification. `ring`'s AArch64 AES-GCM and ChaCha are hand-written assembly with
fully interleaved pipelines; this crate is portable Rust plus intrinsics, and
the remaining gap is exactly that difference. Claiming otherwise would be easy
to write and trivial to disprove by running the harness.

Where the effort went, and what it bought: AES-256-GCM started at 1.46 GB/s and
finished at 5.85 GB/s, a 4× improvement from three changes — XORing the
keystream straight from vector registers instead of a staged byte loop,
precomputing H², H³ and H⁴ so four GHASH multiplications issue independently
rather than as a four-deep dependency chain, and fusing CTR with GHASH into a
single pass so ciphertext is authenticated while still in registers.

What would close the rest of the gap: aggregated GHASH reduction (one reduction
per four blocks instead of four), an eight-block AES pipeline, and a hand-written
ChaCha core using NEON intrinsics rather than relying on the autovectorizer.
Those are known work, not mysteries.

### Why not Core ML, the Neural Engine, or the GPU

This was investigated and rejected on the merits, not skipped.

- **The Neural Engine cannot express these algorithms.** It executes
  fixed-function tensor operations — convolutions and matrix multiplies over
  FP16 and INT8. There is no bitwise XOR, no rotate, no carry, no
  finite-field multiply, and no S-box lookup. ChaCha's rotations and AES's
  round function have no representation there at all.
- **The GPU can express them and still loses.** A Metal kernel launch costs tens
  of microseconds; encrypting 1 MiB on the CPU at 5.85 GB/s takes about 180 µs
  in total. Only very large batches would even break even, and GPU execution
  offers no constant-time guarantee while sharing caches across processes —
  which is precisely the property this library will not give up.
- **The CPU crypto extensions are the real Apple acceleration**, and they are
  what this crate uses: `AESE`/`AESMC` and `PMULL` for AES-GCM, the ARMv8 SHA-2
  instructions for SHA-256, selected once per process by runtime detection.
- **Multiple cores are the other real answer.** Records are independent, so
  batch sealing scales across all ten cores: 10 233 records/s on one core
  becomes 43 774 across the machine.

## Roadmap

1. A PAKE (OPAQUE) so a stolen vault blob is not offline-attackable.
2. x86-64 AES-NI and PCLMULQDQ, for parity with the AArch64 path.
3. Aggregated GHASH reduction and a hand-written NEON ChaCha core.
4. A persistent relay adapter with the same monotonic and atomic-index
   guarantees as the in-memory one.
5. Independent review, before anyone should consider this production ready.

## License

MIT OR Apache-2.0.
