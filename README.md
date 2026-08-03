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
  software everywhere. This is also why the GPU is not used for AES: a
  constant-time bitsliced GPU AES measured *slower* than the CPU's hardware
  instructions, and a fast table-based one would reintroduce the timing leak.
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

Measured on an Apple M4 (4 performance + 6 efficiency cores), rustc 1.96.1,
best of five rounds of at least 250 ms each, identical inputs for every
implementation, outputs checked. **Report ratios, not absolutes.** These
figures were captured on a shared developer machine, so the absolute GB/s runs
low and varies between passes; every comparison below ran back-to-back under
identical load, so the standings are stable even when the absolutes are not.

**AEAD encryption, GB/s at 1 MiB — median of three passes**

| Implementation | GB/s | vs `ring` |
|---|---:|---:|
| ring AES-256-GCM | 7.08 | 1.00x |
| **Blindplane AES-256-GCM** | **6.64** | **0.94x** |
| RustCrypto aes-gcm | 5.96 | 0.84x |
| ring ChaCha20-Poly1305 | 1.99 | 1.00x |
| **Blindplane ChaCha20-Poly1305** | **1.43** | **0.72x** |
| RustCrypto chacha20poly1305 | 0.99 | 0.50x |

**Hashing, GB/s at 64 KiB**

| Implementation | SHA-256 | SHA-512 |
|---|---:|---:|
| ring | 2.91 | 1.63 |
| RustCrypto | 2.51 | 1.67 |
| **Blindplane** | **2.44** | **1.55** |

**Public-key and protocol operations, ops/s — higher is better**

| Operation | Blindplane | Reference | Ratio |
|---|---:|---:|---:|
| X25519 Diffie-Hellman | **54 351** | 45 561 (`x25519-dalek`) | **1.19x** |
| Ed25519 sign | **116 653** | 110 371 (`ed25519-dalek`) | **1.06x** |
| Ed25519 verify (strict) | 37 889 | 50 150 (`ed25519-dalek`) | 0.76x |
| HPKE seal | **24 303** | 23 902 (`hpke`) | **1.02x** |
| Argon2id, 64 MiB × 3 | 10.6 | 11.5 (`argon2`) | 0.92x |

**End-to-end sealed records** — a full record: fresh object secret, payload
AEAD, one HPKE envelope per recipient, key commitment, Ed25519 signature and
canonical encoding.

| Operation | records/s |
|---|---:|
| seal, 4 KiB, 1 recipient | 16 019 |
| open, 4 KiB, 1 recipient | 16 557 |
| seal, 4 KiB, 3 recipients | 6 727 |
| seal batch, all 10 cores | 66 785 |

Where we lead: X25519, Ed25519 signing, HPKE, and the whole-record path. Where
we trail: bulk symmetric throughput against `ring`'s hand-written assembly, and
Ed25519 verification. Both are named in the [roadmap](#roadmap) with the
technique that would close them.

### What the acceleration pass changed

Every symmetric primitive was rewritten against the hardware it runs on:

- **ChaCha20** now uses hand-written NEON — `REV32` and a `TBL` permute for the
  two byte-aligned rotates, shift-insert for the other two — with two
  independent four-block groups interleaved so the core issues close to four
  vector operations per cycle instead of one. The autovectorized `[u32; 4]`
  version it replaced ran at 6.7 cycles/byte; this runs at 1.6.
- **AES-256-GCM** widened to an eight-block pipeline with eight precomputed
  powers of `H` and eight independent GHASH multiplies, and fuses CTR with
  GHASH into a single pass. 1.46 → ~6 GB/s.
- **SHA-512** moved onto the ARMv8.2 `SHA512H/H2/SU0/SU1` instructions, 2.6x
  over scalar, gated on a positive `FEAT_SHA512` check.
- **Ed25519 verification** caches its table points in projective- and
  affine-Niels form for 8- and 7-multiply mixed additions.

A correctness note, because it matters more than the speed: an adversarial
cross-check against an independent reference caught a bug in the new NEON
ChaCha — the counter advanced by a flat four blocks in the partial-tail path,
corrupting any multi-call keystream. Single-shot use and the AEAD were
unaffected, so every existing test passed. It is fixed, and the test suite now
checks a full multi-block keystream and the split-call counter against a
from-scratch reference.

### Which Apple hardware actually helps

The question "why not use the GPU, the Neural Engine, the matrix unit?" was
answered by **measurement on this exact M4**, not by assertion. The honest
answers differ per unit, and two of them vindicate the question.

- **The CPU crypto extensions are the primary win, and are in use:** `AESE`/
  `AESMC` + `PMULL` for AES-GCM, the ARMv8 `SHA256`/`SHA512` instructions, all
  selected once per process by runtime detection.
- **The SME streaming vector unit is a real, unused win.** The M4's Scalable
  Matrix Extension brings a 512-bit streaming vector unit (plus a fused
  XOR-rotate, `XAR`). Measured: ChaCha20 on it reaches **~11.5 GB/s on a single
  core — about 4x hand-written NEON** and well past `ring`. Better still,
  because streaming-SVE and NEON are different execution resources, running two
  SME threads alongside NEON threads measured **+57% over the best NEON-only
  configuration** — this is exactly the "use every unit at once" idea, and it
  works. It is reachable from Rust today with no third-party dependency, via a
  single `core::arch::asm!` block, and is the headline roadmap item.
- **The GPU wins only for bulk, and loses for records.** A constant-time
  ChaCha20-Poly1305 Metal kernel measured **39.8 GB/s at 4 MiB** — genuinely
  fast. But an empty kernel's launch-to-completion latency floor is **~150 µs**,
  which disqualifies it for the per-record workload (a whole record seals in
  less than that), and on a unified-memory part the GPU draws from the same
  ~90 GB/s memory pool the CPU already saturates across cores. Bitsliced AES on
  the GPU measured 21.8 GB/s — slower than the CPU's hardware AES — and
  table-based GPU AES reintroduces the cache-timing side channel this library
  refuses. So: a future bulk-stream API could offload to Metal; sealed records
  cannot.
- **The Neural Engine is genuinely closed.** It executes fixed-function tensor
  ops over FP16/INT8. The missing primitive is exact integer XOR — not a
  performance problem, an expressivity one. Nothing here can run on it.
- **The matrix tiles (SME ZA / AMX) do not help our arithmetic.** The outer-
  product accumulate is spectacular at int8/int16 MACs, but its fixed
  4-way-dot weighting is the wrong shape for schoolbook limb multiplication in
  Curve25519 or Poly1305 — measured a net loss. The published win for matrix
  units is lattice post-quantum (NTT), which this crate does not yet do.

The full research, with the measured numbers behind each verdict, is the basis
for the [roadmap](#roadmap).

## Roadmap

Ordered by measured value:

1. **SME streaming-SVE ChaCha20**, with a NEON+SME heterogeneous work queue —
   the measured path to *first* on ChaCha (~4x) and the realization of "use
   every Apple unit at once" (+57% heterogeneous).
2. **A PAKE (OPAQUE)** so a stolen vault blob is not offline-attackable.
3. **Ed25519 verify**: T-free doublings and a width-8 NAF affine basepoint
   table, to close the one public-key line still behind.
4. **Record-path throughput**: a batch API using Montgomery's inversion trick
   (measured 3.7–61x on the inversions), batch signature verification, and a
   dynamic P/E-aware work queue (measured +17.6% over static chunking).
5. **x86-64 AES-NI and PCLMULQDQ**, for parity with the AArch64 path.
6. **A bulk-stream API** that can offload multi-megabyte payloads to Metal,
   where the GPU's 39.8 GB/s actually pays off.
7. **A persistent relay adapter** with the same monotonic and atomic-index
   guarantees as the in-memory one.
8. **Independent review**, before anyone should consider this production ready.

## License

MIT OR Apache-2.0.
