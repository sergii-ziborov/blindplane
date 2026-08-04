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
  any other PAKE; a PAKE would remove that exposure and is on the
  [roadmap](#roadmap).
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

Measured on an Apple M4 (4 performance + 6 efficiency cores), rustc 1.96.1.
Each figure is the median of five rounds of at least 250 ms, identical inputs
for every implementation, outputs checked; the run below is the middle of
three full passes, which agreed within 3% on every single-core row.
**Report ratios, not absolutes.** This is a developer machine with background
load, so absolutes drift between sessions; every comparison ran back-to-back
in one process, so the standings hold even when the absolutes move.

**AEAD encryption, GB/s — higher is better**

| Implementation | 1 KiB | 64 KiB | 1 MiB |
|---|---:|---:|---:|
| ring AES-256-GCM | 5.20 | 7.74 | 7.36 |
| **Blindplane AES-256-GCM** | 3.20 | **7.23** | **7.37** |
| RustCrypto aes-gcm | 5.95 | 6.47 | 6.46 |
| ring ChaCha20-Poly1305 | 1.61 | 2.15 | 2.17 |
| **Blindplane ChaCha20-Poly1305** | **1.41** | **1.92** | **1.93** |
| RustCrypto chacha20poly1305 | 0.92 | 1.09 | 1.09 |

ChaCha20-Poly1305 stood at 0.72x of `ring` before the fused seal pass and the
base-2^64 Poly1305; it is now 0.89–0.90x at every size. AES-256-GCM is 0.93x
at 64 KiB and parity at 1 MiB. The honest weak row is short-message AES-GCM:
at 1 KiB we run 0.62x of `ring`, because every seal pays the full key schedule
and GHASH table setup. RustCrypto's aes-gcm leads everyone at 1 KiB for the
same reason in reverse — its cipher object amortises setup across calls, a
shape our fresh-key-per-record API deliberately does not have.

**Hashing, GB/s at 64 KiB**

| Implementation | SHA-256 | SHA-512 |
|---|---:|---:|
| ring | 3.39 | 1.90 |
| RustCrypto | 2.90 | 1.95 |
| **Blindplane** | 2.82 | 1.67 |

**Public-key and protocol operations, ops/s — higher is better**

| Operation | Blindplane | Reference | Ratio |
|---|---:|---:|---:|
| X25519 Diffie-Hellman | **58 855** | 49 533 (`x25519-dalek`) | **1.19x** |
| Ed25519 sign | **124 093** | 119 283 (`ed25519-dalek`) | **1.04x** |
| Ed25519 verify (strict) | 41 015 | 54 560 (`ed25519-dalek`) | 0.75x |
| HPKE seal | **26 598** | 26 056 (`hpke`) | **1.02x** |
| Argon2id, 64 MiB × 3 | 12.9 | 15.0 (`argon2`) | 0.86x |

**End-to-end sealed records** — a full record: fresh object secret, payload
AEAD, one HPKE envelope per recipient, key commitment, Ed25519 signature and
canonical encoding.

| Operation | records/s |
|---|---:|
| seal, 4 KiB, 1 recipient | 17 600 |
| open, 4 KiB, 1 recipient | 19 372 |
| seal, 4 KiB, 3 recipients | 7 445 |
| seal batch, all 10 cores | 75 507 |

Where we lead: X25519, Ed25519 signing, HPKE, and the whole-record path. Where
we trail: Ed25519 verification (0.75x), hashing against `ring`'s assembly, and
short-message AES-GCM. Each is named in the [roadmap](#roadmap) with the
technique that would close it.

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
- **Poly1305** moved from 44-bit limbs to the base-2^64 layout: four wide
  multiplies per block instead of nine, with the final fold carried explicitly
  so the accumulator bound holds by local inspection. A new test checks it
  against a 320-bit school-arithmetic reference evaluated straight from the
  RFC 8439 pseudocode.
- **ChaCha20-Poly1305 sealing** became one interleaved pass: encrypt a
  512-byte chunk on the vector pipes, MAC it on the scalar multiplier while
  the next chunk encrypts. The out-of-order window overlaps the two, which is
  what fused AEAD assembly arranges by hand. Together with the Poly1305
  rewrite: 0.72x → 0.90x of `ring`. Opening keeps its two passes on purpose —
  verify-then-decrypt is a documented property, not an implementation detail.
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
- **The SME streaming vector unit wins per core and loses per chip.** The M4's
  Scalable Matrix Extension brings a 512-bit streaming vector unit and a fused
  XOR-rotate (`XAR`), and ChaCha20 on it does reach **~11.5 GB/s on one core,
  about 4x hand-written NEON**. That number is real and it is also a trap: SME
  is **one shared unit per cluster, not one per core**. Measured chip-wide,
  streaming-SVE ChaCha saturates near 7.4 GB/s while NEON across ten threads
  reaches 7.81, and SMOPA throughput scales only 1.35x from one thread to ten
  against NEON's 8.7x. On the metric that matters — the whole machine —
  adopting it would be a **regression**. An earlier revision of this document
  claimed the opposite and named it the top roadmap item; that was wrong.
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

The conclusion is duller than the question deserves: **"use every compute unit"
reduces, on this hardware, to "saturate the ten cores' private units and stop
doing redundant work."** The largest single win of the whole optimisation pass
was not an instruction at all — it was deleting a signature verification of our
own freshly made signature, worth 1.51x on sealing.

Full measurements: [`docs/research/`](docs/research/). How we compare to the
published state of the art, and which techniques close the remaining gaps:
[`docs/research/literature-review.md`](docs/research/literature-review.md).

## Roadmap

Ordered by measured value. The former top two items — the fused
ChaCha20-Poly1305 pass and Poly1305 in base 2^64 — landed and took that suite
from 0.72x of `ring` to 0.90x; what remains of that path is below.

1. **GHASH down to 26 carry-less multiplies per 128 bytes** (we are at 48):
   precomputed folded Karatsuba keys, pre-twisted H powers to delete the
   per-block `RBIT`, and software-pipelining GHASH against the previous group.
   Also worth testing whether schoolbook beats Karatsuba on Apple cores, as the
   canonical ARMv8 GCM paper found.
2. **Short-message AES-GCM.** At 1 KiB we run 0.62x of `ring`: every seal pays
   the full key schedule and H-power table. Trim the setup or offer a
   reusable-key entry point for callers that legitimately reuse one.
3. **The last 10% of ChaCha20-Poly1305**: the chunked overlap still loses to
   `ring`'s hand-scheduled fusion; instruction-level interleaving of the
   Poly1305 chain into the cipher loop is the remaining technique.
4. **`PSTATE.DIT`** around every secret-handling path. Near-zero cost, and it
   turns "constant time" from an assumption about undocumented microarchitecture
   into an architectural guarantee.
5. **A PAKE (OPAQUE)** so a stolen vault blob is not offline-attackable.
6. **Ed25519 verify**: width-8 NAF, T-free projective doubling, affine-Niels
   basepoint table.
7. **Curve25519 scheduling** before any representation change — we are roughly
   2.2x above our own theoretical floor, and published work reports 1.9x from
   scheduling alone.
8. **Record-path throughput**: a batch API using Montgomery's inversion trick,
   batch signature verification (cofactored — *not* interchangeable with our
   strict verify), and a dynamic P/E-aware work queue.
9. **x86-64 AES-NI and PCLMULQDQ**, for parity with the AArch64 path.
10. **A bulk-stream API** that can offload multi-megabyte payloads to Metal,
    where the GPU's 39.8 GB/s actually pays off.
11. **A persistent relay adapter** with the same monotonic and atomic-index
    guarantees as the in-memory one.
12. **Cross-client fork detection.** Our rollback check is a per-client
    persisted head, which is weaker than SUNDR's fork consistency: a malicious
    server can still show two devices divergent histories indefinitely.
13. **Independent review**, before anyone should consider this production ready.

## License

MIT OR Apache-2.0.
