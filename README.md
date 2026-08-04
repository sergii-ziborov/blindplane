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

## What you get

- **A record format, not a cipher menu.** `seal` takes a payload, a routing
  context and a recipient list and returns one signed, self-describing record:
  payload AEAD under a fresh per-record secret, an HPKE envelope per recipient,
  a key commitment, an Ed25519 signature over a canonical binary encoding. You
  do not choose a mode, a nonce, or a KDF — those decisions are made once, in
  one place, and tested.
- **A server that cannot read.** The relay validates structure, signatures,
  route-to-context agreement and monotonic versions, and answers blind-index
  lookups, holding no key type at any point. `cargo tree` is the proof, and CI
  runs it.
- **Encrypted search that admits what it leaks.** Blind index tokens give
  equality lookups scoped to `(tenant, label, key_epoch)`; the server learns
  equality and frequency and nothing else, which is stated up front rather
  than glossed.
- **Rollback detection.** A client persists a signed manifest-hash chain head,
  so a server replaying an older-but-genuinely-signed record is caught.
- **Access changes without re-encryption.** `grant_recipient` adds an envelope;
  `rekey` rotates the object secret forward. Neither touches the payload
  ciphertext for existing readers.
- **Competitive speed, measured against the best available.** X25519 1.19x
  `x25519-dalek`, Ed25519 verification 1.09x `ed25519-dalek` with a pinned
  author, HPKE and Argon2id at parity, AEAD within 6–12% of `ring`'s
  hand-written assembly — with the numbers published as ratios and the losing
  rows named. See [Benchmarks](#benchmarks).
- **Two framework adapters, neither privileged**, and about sixty lines each:
  Blazingly and axum. See [Serving it](#serving-it).
- **Auditability as a constraint, not an aspiration.** Zero runtime
  dependencies, no file over 300 lines, `unsafe` confined to accelerated paths
  that compile out with one flag, and differential tests against independent
  from-scratch reference implementations.

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

Opening many records from one pinned author — a sync, in other words — prepares
that author's verification state once instead of per record, worth 1.09x:

```rust
use blindplane_core::{PinnedSigner, open_pinned};

let pinned = PinnedSigner::new(author.public_key())?;
for record in incoming {
    let plaintext = open_pinned(&record, &alice, &pinned)?;
}
```

Serving it is four lines, whichever framework you use — see
[Serving it](#serving-it):

```rust
use blazingly::prelude::*;
use blindplane_blazingly::{RelayState, plugin};

let app = ExecutableApp::from_plugin(plugin(RelayState::new(policy)))?;
```

Run the self-check:

```bash
cargo run -p blindplane-cli -- selfcheck
```

Two runnable examples carry the rest. `sealed_api` walks one record's whole
life through the HTTP surface — identities, seal, store, blind-index search,
fetch, open — with the reason for each step in a comment:

```bash
cargo run -p blindplane-blazingly --example sealed_api
```

`overhead` answers the question that decides an integration. It stands two
services side by side on the same framework, one holding plaintext in a map
and one holding sealed records, and prints where a sealed round trip's time
actually goes. The answer is not the expected one: base64 and JSON cost more
than every cryptographic operation combined. It then asserts the three
properties the sealed side buys and the plaintext side cannot have —
everything stored is ciphertext, an unpinned signer is refused, and one
flipped bit fails authentication:

```bash
cargo run --release -p blindplane-blazingly --example overhead
```

## Serving it

The relay does no I/O and holds no key type, so an adapter is the routes plus
an error mapping. There are two, and neither is privileged — the second exists
so that "framework-neutral" is something you can run rather than something you
have to believe.

| | Blazingly | axum |
|---|---|---|
| Adapter size | ~85 lines of routes | ~60 lines of routes |
| Record on the wire | base64 inside typed models | canonical bytes as a raw body |
| Buys | OpenAPI and MCP projection, validation attributes | no encoding layer at all |
| State | `RelayState(Rc<Relay>)` | `Arc<Relay>` — `Relay` is already `Send + Sync` |
| Try it | `--example sealed_api` | `--example axum_relay` |

The wire shape differs on purpose: it is the adapter's decision, not the
library's. Blazingly carries records as base64 so the whole surface stays
inside its OpenAPI and MCP projection; axum takes the bytes directly, which
skips the encoding work that [`overhead`](#quick-start) measures at more than
half of a sealed round trip.

```bash
cargo run -p blindplane-relay --example axum_relay
```

## In the browser

`blindplane-crypto` is `no_std` and dependency-free, which makes the client
side a compilation target rather than a rewrite:

```bash
cargo build --target wasm32-unknown-unknown -p blindplane-crypto --no-default-features
```

That builds today, unchanged. A release cdylib exercising the whole client
surface — AEAD, X25519, Ed25519 sign and verify, SHA-256 — measures **179 KB
raw, 57 KB gzipped**.

Two things a browser binding must handle, and both are known rather than
lurking. Entropy: there is no `/dev/urandom`, so `rand::fill` returns
`RandomError` — it **fails closed** rather than producing predictable keys, and
a binding to `crypto.getRandomValues` is the fix. Argon2id at 64 MiB will
block whatever thread it runs on, so vault derivation belongs in a Web Worker.

Reimplementing this protocol in JavaScript would be the wrong shape: constant
time is not achievable there, and two implementations of a canonical encoding
drift. Compiling this one keeps both properties by construction.

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
- **Independent references, on purpose** — the differential tests compare
  against implementations that share no code, no representation and no
  reduction strategy with the production path: a school-arithmetic Poly1305
  written straight from the RFC pseudocode, a from-scratch scalar ChaCha20.
  That redundancy is not duplication to be cleaned up; it is what caught a
  real multi-block SIMD divergence that every known-answer test passed.

These crates are dev-dependencies. None can reach a shipped binary.

```bash
cargo test --workspace
```

Auditability is also a layout question. No file in this workspace exceeds 300
lines, so every primitive is a directory whose pieces — the key schedule, the
GHASH, the sealing — can be read one at a time rather than scrolled past:

```bash
find crates -name '*.rs' | xargs wc -l | sort -rn | head
```

The configurations that must stay green, all of them enforced in CI:

```bash
cargo test --workspace --all-targets --all-features
cargo test -p blindplane-crypto --no-default-features --features std
cargo check -p blindplane-crypto --no-default-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

## Benchmarks

Full results, methodology and machine details: [`results/benchmarks.md`](results/benchmarks.md).
Reproduce with `cargo run --release -p blindplane-bench`.

Measured on an Apple M4 (4 performance + 6 efficiency cores), rustc 1.96.1.
Every figure is the median of five rounds of at least 250 ms; every
implementation gets identical inputs in the same process and has its output
checked, so a fast wrong answer cannot win.

**These are ratios, and that is deliberate.** This is a working developer
machine, and its absolute throughput moves by a factor of two depending on
what else is running — a number in GB/s here would say more about the browser
than about the code. What survives that is the paired comparison: competitor
and candidate run back-to-back in one process under the same conditions. The
ratios below are the median of three full passes that agreed to within 0.01
on every row. Absolute figures, from the last capture taken on a quiet
machine, are in [`results/benchmarks.md`](results/benchmarks.md).

**Symmetric, against `ring`'s hand-written assembly** — higher is better

| Operation | vs `ring` |
|---|---:|
| AES-256-GCM, 1 MiB | **0.93x** |
| AES-256-GCM, 64 KiB | **0.94x** |
| AES-256-GCM, 1 KiB | 0.69x |
| ChaCha20-Poly1305, 64 KiB | **0.88x** |
| ChaCha20-Poly1305, 1 KiB | **0.89x** |
| SHA-512, 64 KiB | **0.96x** |
| SHA-256, 64 KiB | 0.83x |

ChaCha20-Poly1305 stood at 0.72x before the fused seal pass and the base-2^64
Poly1305 — the two techniques the literature review named first. The honest
weak row is short-message AES-GCM at 0.69x, and the reason is a design choice
rather than a defect: every record gets a fresh key, so every seal pays a key
schedule and a GHASH table that `ring` and RustCrypto amortise across calls
from a long-lived cipher object. Trimming that setup bought back 7–11%; the
rest is the API's shape.

**Public-key and protocol** — higher is better

| Operation | vs reference |
|---|---:|
| X25519 Diffie-Hellman | **1.19x** (`x25519-dalek`) |
| Ed25519 verify, pinned author | **1.09x** (`ed25519-dalek`) |
| Ed25519 sign | **1.06x** (`ed25519-dalek`) |
| HPKE seal | **1.02x** (`hpke`) |
| Argon2id, 64 MiB × 3 | **1.02x** (`argon2`) |
| Ed25519 verify, cold key | 0.88x (`ed25519-dalek`) |

The two Ed25519 verification rows are the same algorithm differing only in
who pays for the key. The cold row parses the public key, rejects small-order
points and builds its tables on every call; dalek's `VerifyingKey` is a
pre-parsed point, so that row compares a from-scratch verification against one
that starts halfway. Records are verified far more often than authors change,
so `PinnedSigner` does the same preparation once per session — and then leads.

**End-to-end sealed records.** A record is a fresh object secret, payload
AEAD, one HPKE envelope per recipient, a key commitment, an Ed25519 signature
and a canonical encoding. Opening against a pinned author runs **1.09x** the
cold path (three runs, spread 0.004). Sealing parallelises cleanly across
cores: each record has its own object secret, so nothing is shared and nothing
locks — the batch path reaches roughly **4.5x** the single-core rate on ten
cores of this asymmetric chip.

Where we lead: X25519, Ed25519 signing and pinned verification, HPKE,
Argon2id, and the whole-record path. Where we trail: SHA-256 against `ring`'s
assembly, and short-message AES-GCM. Both are named in the
[roadmap](#roadmap) with the technique that would close them.

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
- **Ed25519 verification** stopped decompressing `R` on the success path (the
  byte comparison subsumes the validity check), moved its vartime loop to
  T-free projective doublings — four squarings and no multiplies per doubling
  — and widened the constant basepoint table to 64 odd multiples, normalised
  with one shared inversion. 0.75x → 0.89x of dalek; the remainder is field
  multiplication scheduling, not algorithm.
- **Argon2** permutes its rows in place — a row already is the sixteen-word
  window, so the gather through a runtime index array was 512 wasted memory
  operations per compression — and gathers columns with constant strides.
  0.86x → 1.02x of the reference `argon2` crate.
- **AES-GCM per-seal setup**: SubWord stays in registers, round keys load
  straight from the expanded schedule, and the GHASH key powers form a
  three-deep tree instead of a seven-deep ladder. Every seal pays setup once
  per fresh key, so short messages gain most: +11% at 256 B, +7% at 1 KiB.
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
2. **Short-message AES-GCM.** Every seal pays the key schedule and H-power
   table; the setup is register-resident now (+7–11% below 1 KiB), and the
   remaining gap to `ring` at 1 KiB is the measurement regime itself —
   competitors amortise an expanded key across calls. A reusable-key entry
   point would give callers that legitimately reuse a key the same economics.
3. **The last 10% of ChaCha20-Poly1305**: the chunked overlap still loses to
   `ring`'s hand-scheduled fusion; instruction-level interleaving of the
   Poly1305 chain into the cipher loop is the remaining technique.
4. **`PSTATE.DIT`** around every secret-handling path. Near-zero cost, and it
   turns "constant time" from an assumption about undocumented microarchitecture
   into an architectural guarantee.
5. **A PAKE (OPAQUE)** so a stolen vault blob is not offline-attackable.
6. **The cold Ed25519 verify path** (0.88x; the pinned path already leads at
   1.09x). The algorithm now matches dalek's — width-8 NAF, T-free doublings,
   affine-Niels tables — so what remains is the same field-arithmetic
   scheduling as the next item, plus the fact that a cold verify parses its
   key and dalek's `VerifyingKey` does not.
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
