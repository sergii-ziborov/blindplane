# Literature review: where blindplane-crypto stands, and what to do next

Scope: `crates/blindplane-crypto` on Apple M4. Compiled from three literature
sweeps (AArch64 symmetric crypto; Curve25519/Ed25519 and constant-time tooling;
SME/streaming-SVE and the system architecture), reconciled against the code at
`f93d870`, the measurements in `results/benchmarks.md`, and the adversarial
re-measurement pass recorded in `docs/research/apple-acceleration-findings.json`.

Raw sweep output is in `literature-review.json` (46 papers, 33 techniques).
This document is the verdict. It supersedes the earlier short version of this
file; several of that version's conclusions were built on stale benchmark
figures and are corrected in [Appendix A](#appendix-a-corrections).

---

## 0. Two things to settle before anything in section 1

### 0.1 Re-measure on an idle machine at a known clock

Every absolute in `results/benchmarks.md` was taken on a loaded machine — the
findings file states the first run's absolutes were depressed ~2x by a
concurrent `cargo build`. Ratios survive that; cycles-per-byte does not, and
cycles-per-byte is the only unit in which the published literature can be
compared against.

The evidence that the absolutes are unusable is internal. Assuming a 4.4 GHz
P-core, our SHA-512 lands at 2.84 cpb and ring's at 2.70 cpb, against a hard
issue-port floor of 1.75 cpb derived from the ARMv8.2 instruction mix (40
SHA512H + 40 SHA512H2 at throughput 2, 32 SHA512SU0 + 32 SHA512SU1 at
throughput 1, all on port u14, per Dougall Johnson's Firestorm tables). Two
independent implementations do not both sit 1.6x above a port-issue floor.
Either the sustained clock was nearer 2.7 GHz, or the measurement is wrong.

Until this is resolved, every "distance from the published record" figure in
section 2 carries a 1.6x error bar. Pin to a P-core, idle machine, measure the
clock rather than assuming it, report cycles/byte with error bars. This is also
experiment 4 in [§3.5](#35-experiments-still-required) and blocks publication
independently.

### 0.2 Rank by what the product actually spends time on

For blindplane's own workload the symmetric primitives are close to irrelevant.
Decomposing a 4 KiB single-recipient `seal` (16,508 ops/s = 60.6 µs), using the
component timings independently measured in the findings file (HPKE seal
39.04 µs, `verify_strict` 24.75 µs, AEAD step 0.786 µs for AES-256-GCM):

| Component | Cost | Share of seal |
|---|---:|---:|
| HPKE encap — 2 × X25519 (ephemeral keygen + DH) | ~39–41 µs | ~68% |
| Ed25519 sign | ~9 µs | ~14% |
| SHA-512/SHA-256 over the record body | ~5 µs | ~8% |
| AES-256-GCM over 4 KiB | ~0.8 µs | ~1.3% |
| encoding, KDF, allocation | remainder | ~9% |

`open` (56.6 µs) is ~44% Ed25519 verify and ~33% X25519.

The findings file's own refutation pass reaches the same conclusion by a
different route: the ceiling for an *infinitely fast* AEAD on the record path is
0.89% for seal and 0.18–0.41% for 64 B–1 KiB records.

So: the AEAD work that both symmetric sweeps concentrate on is worth **at most
~1% of a record**. It matters for the benchmark table and for anyone using
`blindplane-crypto` as a standalone library; it does not matter for blindplane.
The two objectives diverge, and the ranking below annotates which each item
serves — **P** for the product (record seal/open), **L** for the library
benchmark.

---

## 1. Techniques to adopt

Ranked by expected gain divided by effort.

### 1.1 Ranked summary

**Quantified** — every gain below is either measured on this machine or derived
from a published instruction-count/port model:

| # | Technique | Gain | Effort | Serves |
|---|---|---|---|---|
| 1 | Fixed-base X25519 public key via the Edwards table | ~2.5x on base mult → **~1.25x on every seal** | 1–2 d | P |
| 2 | Prepared-key APIs (AES-GCM, Ed25519 verifying key) | **1.9x at 1 KiB AES-GCM**; +7.5% on verify | 2 d | P, L |
| 3 | Ed25519 verify: T-free projective + width-8 NAF | **1.17x, measured on a working prototype** | 3–4 d | P |
| 4 | `PSTATE.DIT` guard | 0% perf; closes GoFetch on M3+ | 1 d | credibility |
| 5 | Fused lagged ChaCha20-Poly1305 seal | **1.66x, measured on a working prototype** | 3–5 d | L |
| 6 | Base-2^64 Poly1305 | 18 → 10 multiply-class instrs/block | 1 d | L |
| 7 | Fast path for `poly_key` | 166 ns/call; ~6% of a 4 KiB ChaCha AEAD | 0.5 d | L |
| 8 | Work-stealing batch queue | **+16–17% on `seal_batch`, measured** | 0.5 d | P |
| 9 | Folded Karatsuba keys; no GPR round-trips in GHASH | ~48 cross-domain moves/128 B removed | 1 d | L |
| 10 | `EOR3` in the GHASH accumulation tree | ~46 → ~28 XOR-class ops/128 B | 0.5 d | L |
| 11 | Eliminate the ladder conditional swap | 4 cswaps → 2 cselects × 255 steps | 1 d | P |
| 12 | `Fe::mul` codegen: explicit (lo,hi) instead of `u128` | up to ~1.5x on X25519 | 3–5 d | P |
| 13 | Pre-twisted H; delete the per-block `RBIT` | 8 RBIT/128 B, ~4% of AES-GCM | 3 d | L |
| 14 | dudect + TIMECOP + fiat-crypto differential CI | 0% perf; the only CT evidence we'd have | 5 d | credibility |
| 15 | safegcd inversion | ~6% of X25519 | 5 d | P |
| 16 | Batch inversion across records | **5.1% of a record, measured**; batch path only | 5 d | P |
| 17 | Software-pipeline AES-GCM (hash the previous group) | part of Arm's 20–30% on M1 | 5 d | L |
| 18 | Two-way multi-buffer SHA-256 | 1.28x, batch callers only | 5 d | L |
| 19 | AffineNiels constant-time basepoint table | ~20% of fixed-base mult; 80 KB → 30 KB | 3 d | P |
| 20 | 4×64 field radix | ~1.15–1.25x on X25519 | ~2 w | P |
| 21 | AEGIS-128L as a fourth suite | ~0.15 cpb vs GCM's ~0.38 floor | ~1 w | L |

**Speculative** — SME/SSVE, SLOTHY, Jasmin, mKEM, fork consistency — are in
[§1.4](#14-speculative-no-reliable-gain-estimate). None of them should be
scheduled against a promised number.

---

### 1.2 Detail — quantified items

#### 1. Fixed-base X25519 public key via the Edwards table

**What.** `montgomery::public_key` calls `x25519(secret, BASEPOINT)` — a full
255-step variable-base Montgomery ladder for an operation whose point is a
compile-time constant. Replace with an Edwards fixed-base scalar
multiplication using the table we already build for Ed25519, then map to the
Montgomery *u*-coordinate: `u = (1 + y) / (1 - y)`. The clamped X25519 scalar is
a multiple of 8, so the map is exact on the relevant subgroup.

**Source.** Not from the sweeps — a code-reading finding. The construction is
standard: libsodium's `crypto_scalarmult_base` (`ge25519_scalarmult_base` plus
the Edwards→Montgomery map) and BoringSSL's `X25519_public_from_private` both do
exactly this. The birational map is from the Ed25519 paper (Bernstein, Duif,
Lange, Schwabe, Yang, CHES 2011).

**Files.** `crates/blindplane-crypto/src/montgomery.rs` — `public_key`,
`StaticSecret::from_bytes`. Reuses `edwards.rs::EdwardsPoint::mul_base` and
`edwards.rs::basepoint_table`. New helper for the y→u map.

**Expected gain.** Derived. A variable-base ladder measures 18.5 µs
(54,062 ops/s). Ed25519 sign — which contains `mul_base`, a field inversion for
compression, SHA-512 and scalar reduction — measures 8.62 µs *in total*, so
`mul_base` plus inversion is bounded above by ~7 µs. The map folds into the
inversion we already pay. Expect base multiplication to fall from ~18.5 µs to
~6–7 µs, ~2.5x. Every `hpke::seal` performs exactly one
(`hpke.rs:175` and `hpke.rs:199` → `StaticSecret::generate` → `from_bytes` →
`public_key`), so HPKE encap should go from ~39 µs to ~27 µs and a 4 KiB
single-recipient `seal` from 60.6 µs to ~49 µs — **~1.25x on the whole product
hot path for one to two days of work.** Highest gain/effort item in this
document by a wide margin.

**Constant-time.** Yes. `mul_base` already uses `select_signed`, which touches
every entry of the selected row; the map is branch-free field arithmetic; the
inversion is a fixed addition chain. Validate against RFC 7748 vectors and
extend the existing `fixed_base_agrees_with_variable_base` test to the
Montgomery output.

#### 2. Prepared-key APIs

**What.** Three places where our API takes raw bytes and redoes per-call setup
that every competitor amortises:

- `aes.rs:443` and `aes.rs:568` call `expand_key` **and** `Ghash::new` on every
  `seal_in_place`/`open_in_place`. `Ghash::new` computes H² through H⁸ as seven
  *serially dependent* reduced multiplications — 42 PMULLs on a chain roughly
  7 × 15 = ~105 cycles deep — plus a 15-round key schedule.
- `edwards.rs:586` `verify_strict` takes `&[u8; 32]` and therefore decompresses
  the signer's public key on every call. Measured in the findings file at
  **1.94 µs, 7.5% of a verify**. ed25519-dalek takes a prepared `VerifyingKey`.
- `aead.rs:259` `poly_key` runs a whole `ChaCha20::new(...).apply_keystream` over
  a 64-byte block; measured at 166 ns (see item 7).

Introduce `Aes256GcmKey` (round keys + H powers + folded H powers), and a
`VerifyingKey` holding the decompressed `EdwardsPoint`.

**Source.** Our own benchmark curve plus the findings file's measurement. The
API shape is what RustCrypto (`Aes256Gcm::new`), ring (`LessSafeKey`), OpenSSL
(`gcm128_context`) and dalek (`VerifyingKey`) all already do.

**Files.** `aes.rs` (`seal_in_place`, `open_in_place`, `expand_key`,
`Ghash::new`), `aead.rs` (`Suite::seal_in_place`/`open_in_place` signatures),
`edwards.rs` (`verify_strict`, new `VerifyingKey`), and the
`blindplane-wire`/`blindplane-core` call sites.

**Expected gain.** Measured, from our own table: AES-256-GCM runs at 6.62 GB/s
at 64 KiB but **2.95 GB/s at 1 KiB** — a 2.25x cliff. ring degrades 7.09 → 4.72
(1.50x); RustCrypto is essentially flat (5.86 → 5.41) because it holds a
prepared key. At 1 KiB we are 0.62x of ring and **0.55x of RustCrypto** — the
only line in the entire benchmark table where RustCrypto beats us. Removing the
setup should bring 1 KiB to ~5.5–6 GB/s. At blindplane's 4 KiB record size the
AEAD gain is ~1.15x; the verify gain is a straight 7.5%, which is ~3.5% of every
`open`.

**Constant-time.** Yes — pure hoisting. New obligation: the key object holds H
powers and round keys, so it needs a `Drop` that zeroes them, matching
`Poly1305` and `Secret`.

#### 3. Ed25519 verify: T-free projective accumulator + width-8 NAF

**What.** Two changes to the variable-time verification path.

*T-free doubling.* `edwards.rs:173` `double()` computes `t = e*h`
unconditionally — 4S + 4M. Introduce `ProjectivePoint` and `CompletedPoint`;
the accumulator never materialises T, and `add_projective_niels` /
`add_affine_niels` return a `CompletedPoint` (3M to close) instead of a full
extended point (4M). The saving is 1M on **every** iteration, not only
doubling-only ones.

*Width-8 NAF for the basepoint scalar.* `scalar.rs:134` hardcodes
`const WIDTH: u64 = 5` and `edwards.rs:448` builds only 8 affine-Niels odd
multiples of the basepoint. In `vartime_double_scalar_mul_basepoint` the
basepoint scalar is public and the table is static, so it should use w=8 against
64 entries. w-NAF non-zero digit density is 1/(w+1), so expected basepoint
additions drop from ~43 to ~28 over 256 positions.

**Source.** curve25519-dalek `curve_models` (the Projective/Completed/Extended
distinction) and `backend/serial/scalar_mul/vartime_double_base.rs`
(`AFFINE_ODD_MULTIPLES_OF_BASEPOINT`, `non_adjacent_form(8)`); Hisil–Wong–
Carter–Dawson extended coordinates.

**Files.** `edwards.rs` — new `ProjectivePoint`/`CompletedPoint`, `double`,
`add_projective_niels`, `add_affine_niels`,
`vartime_double_scalar_mul_basepoint` (line 314), and the `mul`/`mul_base`
loops. `scalar.rs::non_adjacent_form` (parameterise the width).
`edwards.rs::build_basepoint_affine_odd_multiples` (8 → 64 entries, ~7.5 KB).

**Expected gain.** **Measured on a working prototype**, not modelled — the
findings file records a full implementation with head-to-head harnesses linking
ed25519-dalek 3.0 in the same process: **1.17x on `verify_strict`** (1.163x
rotating inputs, 1.176x fixed input, 1.177x under 4 MiB cache pollution), of
which T-free doublings are 1.124x and w=8 NAF adds +3.5%. That takes 37,904/s to
~44,100/s against a dalek reference of 45,801/s on this machine — i.e. **parity,
not "fastest"**. Combined with item 2's cached decompression it should edge past
dalek.

**Do this first, and recover the prototype.** It lives in a `/private/tmp`
scratchpad (`scratchpad/edtest`, with `src/bin/h2.rs` and `h3.rs`) which can be
garbage-collected at any time. Move it into the repository before anything else
in this list.

**Constant-time.** The NAF change is variable-time by design and correct — both
scalars are public in verification. Keep it strictly separated from signing,
which it already is. The T-free coordinate change is data-independent and
applies to the constant-time `mul_base` path too, where it saves the same
multiplication per doubling.

#### 4. `PSTATE.DIT` guard

**What.** Set FEAT_DIT (`msr DIT, #1`) on entry to every secret-handling
primitive and restore on exit, behind a `Drop` guard and a runtime feature
check. `grep -rn "DIT" crates/blindplane-crypto/src` returns nothing today.

**Source.** Chen, Wang, Shome, Fletcher, Kohlbrenner, Paccagnella, Genkin,
"GoFetch: Breaking Constant-Time Cryptographic Implementations Using Data
Memory-Dependent Prefetchers", USENIX Security 2024. Precedent: golang/go#49702,
open-quantum-safe/liboqs#1788.

**Files.** New `crates/blindplane-crypto/src/dit.rs`; applied at
`montgomery::x25519`, Ed25519 signing, `poly1305`, the `aes`/`chacha` key
schedules, `argon2`, `hpke`.

**Expected gain.** Zero throughput. The gain is that "constant-time on Apple
Silicon" stops being an assertion about undocumented microarchitecture and
becomes an architectural guarantee for the defined instruction subset — and on
M3/M4 it also disables the data memory-dependent prefetcher GoFetch exploits. It
does **not** close GoFetch on M1/M2, where DIT does not disable the DMP; the
README must say so. Our own lab work already confirms `FEAT_DIT = 1` on this
machine (`docs/research/lab/ct.c`) and that `MSR DIT` works inside SME streaming
mode.

**Constant-time.** This *is* the constant-time item, and it is the cheapest
thing that closes the gap between the README's claims and the code.

#### 5. Fused, lagged ChaCha20-Poly1305 seal

**What.** `aead.rs:222–230` runs `ChaCha20::apply_keystream` over the entire
buffer and *then* `Poly1305::update` over the entire buffer — two full passes,
no overlap, two trips through cache. Replace with one loop body that encrypts
block group *i* while folding group *i−1* into the MAC, so Poly1305 executes in
the integer pipes while ChaCha saturates the vector pipes.

**Source.** Vlad Krasnov, `crypto/cipher/asm/chacha20_poly1305_armv8.pl`, in
BoringSSL and vendored by ring: ChaCha runs 5 blocks in NEON (`chacha_qr_x5`,
4 lane-major via `ld4r` + 1 block-major), Poly1305 runs in scalar GPRs base 2^64
(`poly_stage1`/`poly_stage2`/`poly_reduce_stage`), interleaved as
`&poly_add(); &poly_mul();` between `chacha_qr_x5("left")` and
`chacha_qr_x5("right")`.

**Files.** `aead.rs` `chacha20poly1305_seal`; `chacha.rs` NEON path;
`poly1305.rs` (`absorb` must be callable per group).

**Expected gain.** **Measured on a working prototype**: the findings file
records a real fused kernel — the crate's own NEON 8-block ChaCha group
interleaved with the crate's own scalar Poly1305 absorb — bit-exact against the
two-pass reference on ciphertext, accumulator and counter, measured at
**1.66x** (1.682x at 16 KiB, 1.656x at 64 KiB, 1.660x at 1 MiB). Poly1305's
marginal cost when fused is 0.20 c/B against 1.38 c/B standalone, i.e. 85–87%
hidden, and the fused loop hits 89–90% of the pure-ChaCha ceiling. The gain is
identical at 16 KiB (resident in M4's 128 KiB L1D) as at 1 MiB, so it is genuine
dual-issue, not a locality artifact. Applied to our 1.43 GB/s that lands near
2.4 GB/s, **ahead of ring's 1.96**.

**Effort is lower than the literature suggests.** The sweep predicted
hand-written `.S` and two weeks. The prototype is ~200 lines of Rust intrinsics
plus scalar `u128`; LLVM schedules it to 89% of ceiling unaided, and the
disassembly confirms the interleave (a 400-instruction window contains 27 MUL,
27 UMULH, 20 ADDS, 19 ADC alongside 15 REV32.8H, 16 TBL.16B, 61 ADD.4S,
62 EOR.16B — the same census pattern as ring's assembly).

**Two caveats, both load-bearing.** (a) `open` gets **0x** unless you accept
transient unverified plaintext in the caller's in-place buffer, which
contradicts a documented invariant in `aead.rs`. Do not break that invariant for
throughput. (b) End-to-end records get ~0% because `fastest_available()` selects
AES-256-GCM; at most ~1.4% if the suite were switched. This is a
published-AEAD-table and non-AES-hardware item, not a record-rate item.

**Constant-time.** Yes, and marginally better: the tag is computed over data
already in registers. Care only in the tail, which is length-dependent, and
length is public.

**Conflict.** Do **not** combine this with scalar "mixin" ChaCha lanes
(Polyakov's `chacha-armv8.pl` 4+1 and 6+2 paths, worth 1.7x on Apple A7 for
*standalone* ChaCha20). They contend for the same integer pipes. Mixin lanes for
standalone ChaCha20; scalar Poly1305 for the AEAD.

#### 6. Base-2^64 three-limb Poly1305

**What.** `poly1305.rs` uses 44/44/42-bit limbs; `absorb` (lines 183–216)
computes `d0,d1,d2` as nine `u64 × u64 → u128` products = 18 multiply-class
instructions per 16-byte block. The AArch64 canonical form is base 2^64 with
`h0,h1,h2` (h2 two bits), `r0,r1`, `s1 = r1 + (r1 >> 2)`: 6 MUL + 4 UMULH = 10.
The h2 products need no UMULH because h2 is two bits wide.

**Source.** OpenSSL `crypto/poly1305/asm/poly1305-armv8.pl` scalar
`poly1305_blocks`; ring's `poly_stage1`/`poly_stage2`/`poly_reduce_stage`. The
principle is Bernstein–Schwabe, "NEON crypto", CHES 2012: pick the limb radix
from the multiplier width, not from the field. 26-bit limbs are right for NEON's
32×32→64 `vmlal`; 2^64 is right for scalar AArch64's MUL+UMULH. 44 bits matches
neither.

**Files.** `poly1305.rs` — `LIMB_MASK`, `TOP_MASK`, `Poly1305::new` limb
packing, `absorb`, `finalize`. ~80 lines.

**Expected gain.** At Firestorm's two multiply pipes (MUL and UMULH both latency
3, throughput 0.5, ports u5/u6), 18 uops/block = 9 cycles of pure multiply issue
= 0.56 cpb; 10 uops = 5 cycles = 0.31 cpb. A 1.8x reduction in the dominant
instruction class. Standalone Poly1305 measures 3.18 GB/s against ChaCha's
2.76, so it is the co-bottleneck of the current two-pass AEAD.

**Interaction with item 5.** Once fused, Poly1305's marginal cost is already
85–87% hidden, so this is worth much less *after* fusion than before. Do item 5
first, then re-measure before doing this. It remains worthwhile for
`Poly1305` used standalone and it shortens the fused loop's integer chain.

**Constant-time.** Yes, strictly better: the base-2^64 reduction is the standard
`and #3 / and #-4 / lsr #2 / adds / adcs` sequence, fewer carry-propagation
steps, no branches. The existing RFC 8439 vectors, the wraparound vector and the
streaming-consistency test cover it.

#### 7. Fast path for `poly_key`

**What.** `aead.rs:259` derives the one-time Poly1305 key by constructing a
full `ChaCha20` and running `apply_keystream` over a 64-byte block. Measured at
166 ns. Replace with a direct single-block permutation writing 32 bytes.

**Source.** Our own findings file, as a prerequisite noted alongside item 5.

**Files.** `aead.rs::poly_key`, `chacha.rs` (expose a single-block
`block(counter) -> [u8; 64]`).

**Expected gain.** 166 ns against a 4 KiB ChaCha20-Poly1305 seal of ~2.9 µs is
~5.8%; against 1 KiB (~0.9 µs) it is ~18%. It dominates exactly the 1–4 KiB
record sizes where fusion barely helps, so it is the short-message
counterpart of item 5.

**Constant-time.** Yes.

#### 8. Work-stealing batch queue

**What.** `blindplane-core/src/lib.rs` `seal_batch` splits work into static
chunks across `std::thread::scope`. Replace with an atomic-cursor work queue at
grain 1.

**Source.** Our own findings file; the underlying observation is that an M4 is
4 P-cores + 6 E-cores with roughly 2x throughput difference, so static chunking
strands work on the E-cores.

**Files.** `crates/blindplane-core/src/lib.rs` `seal_batch` (~line 549).

**Expected gain.** **Measured** by interleaved A/B on the shipped
256 × 4 KiB × 1-recipient workload: median 38,495 → 44,901 rec/s, best case
41,867 → 48,961 — **+16–17%**. Grain 1 is worth ~7 points over grain 8. Note the
optimistic "captures 100% of the hardware" framing in the original claim was
refuted: the dynamic queue reaches ~4.7–5.1x single-thread against a 7.02x
ideal, so 25–30% of the ceiling remains uncaptured.

**Effort caveat.** The obvious `Vec<Option<_>>` index-write design does not
compile under the crate's `forbid(unsafe_code)`; use per-worker `(index, result)`
buffers or an mpsc channel.

**Constant-time.** Not applicable — scheduling only, no secret-dependent
behaviour. Records are independent and share nothing.

#### 9. Precomputed folded Karatsuba keys; remove the GPR round-trips

**What.** `gf_mul_wide` (`aes.rs:183–210`) extracts all four 64-bit halves with
`vgetq_lane_u64` and XORs them in general-purpose registers
(`a_lo ^ a_hi`, `b_lo ^ b_hi`) before feeding them back to `vmull_p64`.
`gf_reduce` (`aes.rs:215–232`) does the same three more times. On Apple cores
every SIMD→GPR move is a cross-domain op with multi-cycle latency, and the
results must move back. Store `powers_folded[i] = swap64(H^i) ^ H^i` once in
`Ghash::new`, and fold only the data operand, in the vector domain, with
`vextq_u8` + `veorq_u8`.

**Source.** OpenSSL `crypto/modes/asm/ghashv8-armx.pl` — the `Hhl`, `H34k`,
`H56k` table entries, described in the source as "pack Karatsuba
pre-processed".

**Files.** `aes.rs` — `gf_mul_wide`, `gf_reduce`, the `Ghash` struct
(`powers` → `powers` + `powers_folded`), `Ghash::new`.

**Expected gain.** Not separately quantified in the source. Counted here: 4
extracts + 2 inserts per `gf_mul_wide` × 8 per 128 bytes ≈ 48 cross-domain ops
per 128 bytes, against a whole-loop issue-bound floor of ~48 cycles. Expect
several percent — and it removes the scheduling hazard that will otherwise block
item 17.

**Note on where GHASH actually stands.** Our PMULL count is already at parity
with the state of the art: eight `gf_mul_wide` (3 each) plus one `gf_reduce` (3)
= 27 carry-less multiplies per 128 bytes, against OpenSSL unroll8's 26. The
aggregated-reduction defect that the first sweep reports as our largest
available GHASH win **is already fixed** (task #7):
`absorb_eight_vectors` (`aes.rs:298`) sums eight `Unreduced` products and calls
`gf_reduce` once. What remains is the surrounding bookkeeping — items 9, 10, 13
and 17.

**Constant-time.** Yes — same operations, fewer of them, all data-independent.

#### 10. `EOR3` in the GHASH accumulation tree

**What.** `Unreduced::xor` is called seven times in `absorb_eight_vectors`
(14 `EOR`) and each `gf_mul_wide` performs four more (32 `EOR`) — ~46 XOR-class
ops per 128 bytes. OpenSSL's unroll8 uses 20 `EOR3` + 8 `EOR` = 28. We already
detect `sha3` at runtime for `sha2.rs:469`, so the feature gate exists.

**Source.** OpenSSL `aes-gcm-armv8-unroll8_64.pl`. Arm attributes ~33% on
Neoverse V1 and 20–30% on Apple M1 to unroll8 + EOR3 over the 4-block version;
that figure covers items 10, 13 and 17 together.

**Files.** `aes.rs` — a 3-input variant of `Unreduced::xor`, the
`p0.xor(p1)…` chain in `absorb_eight_vectors` and `absorb_four_vectors`, the
`middle` computation in `gf_mul_wide`, behind a `sha3`-gated duplicate path.

**Expected gain.** ~18 issue slots per 128 bytes at Firestorm's 4/cycle for
EOR/EOR3 ≈ 4.5 cycles on a ~48-cycle floor, ~9%. Derived from the Firestorm
tables.

**Constant-time.** Yes.

#### 11. Eliminate the ladder conditional swap

**What.** `montgomery.rs:24–48` performs four `Fe::conditional_swap` calls per
ladder step. The differential addition is symmetric in its two operands, so
compute `A,B,C,D` unconditionally and `cselect` `(A,B)` or `(C,D)` as the input
to the doubling — two selects of two values instead of four swaps of four.
RFC 7748 clamping fixes the last processed bit to 0, so no final swap is needed
either.

**Source.** Emil Lenngren, "AArch64 optimized implementation for X25519" (2019),
Algorithm 1 / §5.

**Files.** `montgomery.rs`; `field.rs` (add `conditional_select`).

**Expected gain.** Not quantified by the source. Each `conditional_swap` is 5
limb-wise mask/xor triples ≈ 15 ops; 4 per step × 255 steps ≈ 15,300 ops
removed, replaced by ~7,650. Against a ~81,400-cycle ladder that is a low
single-digit percentage, and it shortens the critical path at the top of each
step.

**Constant-time.** Yes, strictly better — fewer secret-dependent selects, all
mask-based.

#### 12. `Fe::mul` codegen — explicit (lo, hi) instead of `u128`

**What.** `field.rs:89–137` writes the 5×51 multiply and square as `u128`
arithmetic inside `const fn`s. LLVM materialises and re-materialises 128-bit
values and can spill. Hand-lower the accumulators to explicit `(lo, hi)` `u64`
pairs using widening-multiply/carrying-add intrinsics (or `core::arch::asm!`
with `umulh`), then read the emitted assembly and check for spills.

**Source.** SLOTHY (Abdulrahman, Becker, Kannwischer, Klein, TCHES 2024(1),
Table 5) is the quantified precedent for the class of change: the same X25519
kernel went from 265,739 cycles (readable, compiler-scheduled) to 139,752
(constraint-solver scheduled) on Cortex-A55 — a 1.90x swing from scheduling and
register allocation alone.

**Files.** `field.rs` — `mul`, `square`, `mul121666`, `carry`.

**Expected gain.** Derived. A ladder plus Fermat inversion is
255 × (5M + 4S + 1×121666) + (254S + 11M) ≈ 2,815 field operations. Our 18.5 µs
X25519 at 4.4 GHz is ~81,400 cycles = **~28.9 cycles per field operation**. The
5×51 multiplier-issue floor on a two-multiply-pipe core is ~25 cycles for a
multiply and ~15 for a square, giving a whole-ladder floor of ~53,000 cycles.
So roughly **1.5x is available inside the representation we already have**,
before any radix change. (The second sweep claims 2.2x; that was computed
against a stale 27,798 ops/s figure — see Appendix A.)

**Constant-time.** Yes — scheduling and register allocation only. Re-run the CT
tests afterwards: inline asm and intrinsics bypass whatever guarantees the
current pure-Rust form provides.

#### 13. Pre-twisted powers of H; delete the per-block `RBIT`

**What.** `reflect` (`aes.rs:245`) is `vrbitq_u8`, called eight times per
128 bytes in `absorb_eight_vectors`. OpenSSL and AArch64cryptolib store the
powers of H pre-"twisted" and use only `REV64` in the loop, paying no per-block
bit reflection.

**Source.** OpenSSL `aes-gcm-armv8_64.pl` ("twisted powers of H");
Gouvêa–López, CT-RSA 2015, note that AArch64's RBIT makes the classical
reflection trick unnecessary but do not eliminate it. Kurdi–Möller,
ePrint 2025/2171, generalise this to computing directly in the bit-reversed
representation, reporting GHASH at 0.34 cpb on POWER9 and 0.33 on Comet Lake,
11–35% over OpenSSL. **Caveat: that paper's body was not retrievable; its cpb
figures and its ~1.7x-over-Karatsuba claim come from the abstract and a search
summary, and one of them looks conflated with an unrelated Cortex-M4 result.
Treat 2025/2171 as a lead, not a number.**

**Files.** `aes.rs` — `reflect`, `Ghash::new`, `absorb_eight_vectors`,
`absorb_four_vectors`, `absorb_four`, `absorb_block`.

**Expected gain.** 8 RBIT per 128 bytes; RBIT is latency 2, throughput 0.25 on
Firestorm, so ~2 cycles on a ~48-cycle floor, ~4%. Small, but pure waste, and it
frees slots on the ports the PMULLs contend for.

**Effort note.** The fiddly part is the `H << 1` with the carry folded through
the reduction constant when building the twisted H (OpenSSL's `gcm_init_v8`).
Validate against the NIST GCM cases 13/14/16 already in `aes.rs`.

**Constant-time.** Yes — representation change only.

#### 14. Three-tier constant-time verification in CI

**What.** Tier 1: dudect (Welch's t-test over fixed-vs-random secret classes)
natively on the M4, wired into `blindplane-bench`. Tier 2: TIMECOP/ctgrind —
mark secret buffers uninitialised via Valgrind memcheck client requests, so any
branch or address derived from a secret is reported. Tier 3: differential-test
`field.rs` and `scalar.rs` against Coq-proven fiat-crypto `curve25519_64` output
behind a `verified` feature.

**Source.** Reparaz–Balasch–Verbauwhede, "Dude, is my code constant time?",
DATE 2017; Langley's ctgrind and SUPERCOP's TIMECOP; Erbsen et al.,
fiat-crypto, IEEE S&P 2019; the tool menu in Geimer et al., ePrint 2024/2060 and
the CROCS ct-tools catalogue.

**Practical constraint.** Valgrind has no usable arm64 macOS port, so tier 2
needs an aarch64 Linux CI runner. The macOS-native fallback is LLVM
MemorySanitizer via `-Zsanitizer=memory` with poison/unpoison shims.

**Expected gain.** No throughput. This is the difference between "we believe
this is constant-time" and "here is the evidence". Be precise about what each
tier buys: dudect is statistical evidence, not proof; TIMECOP proves the absence
of secret-dependent branches and addresses *along the paths executed*; neither
says anything about the DMP or any other microarchitectural channel.

#### 15. safegcd inversion

**What.** Replace the Fermat addition chain in `Fe::invert` (254 squarings + 11
multiplications ≈ 265 field operations, measured at 1.75 µs) with the
Bernstein–Yang constant-time divstep algorithm.

**Source.** Bernstein–Yang, "Fast constant-time gcd computation and modular
inversion", TCHES 2019(3) / ePrint 2019/266; the reduced-divstep follow-up
(~79.9% of the original iteration count); a machine-checked implementation proof
exists (arXiv 2507.17956). *The sweep could not retrieve the PDF; the "under
4000 cycles on Skylake" figure is from the abstract and should be confirmed.*

**Files.** `field.rs::invert`. Call sites are exactly two: `montgomery.rs:50`
and `edwards.rs:153`.

**Expected gain.** 1.75 µs is ~9.5% of an X25519 and is paid three times per
single-recipient record. safegcd should cut it ~3x, so ~6% of X25519. It is also
the fallback when there is only one record and item 16 does not apply.

**Constant-time.** Yes by construction: fixed iteration count, control flow
depends only on the low bit and the sign of an auxiliary counter, both
mask-handled. Strictly better than a Fermat chain, which has a data-independent
but structurally awkward squaring schedule.

#### 16. Batch inversion across records

**What.** Montgomery's trick: n inversions become 1 inversion + 3(n−1)
multiplications. Split the batch path into phases — all ladders, then one
batched inversion, then all outputs.

**Source.** Montgomery 1987; lib25519 exposes it as a first-class primitive
(`crypto_powbatch`/`inv25519`).

**Files.** `field.rs` (new `batch_invert`), `montgomery.rs` (a ladder variant
returning unreduced `(x2, z2)`), `blindplane-core` batch seal path.

**Expected gain.** **Measured** in the findings file against an independent
implementation verified bit-identical to `montgomery::x25519` for n = 4…256:
per-element inversion cost falls 1.75 µs → 0.13 µs at n=16 → 0.03 µs at n=256,
saving ~5.25 µs/record = **5.11% of a record**. The ceiling is hard: batch
inversion can never exceed ~8.7–10.4% of an X25519 on operation count alone.
Batch ≥16 captures essentially all of it; no benefit beyond ~32. **Applies only
to `seal_batch`** — the single-record number improves by 0%.

**Constant-time.** Yes, with the classic trap: a zero anywhere in the batch
zeroes the whole product. Handle with a constant-time conditional substitution
of 1 and a mask on the output — never a branch.

#### 17. Software-pipeline the AES-GCM loop

**What.** `aes.rs:458–491` computes `c0..c7` and immediately calls
`absorb_eight_vectors` on those same registers, so the GHASH PMULLs sit behind
the full 14-round AES dependency chain of the same iteration. Keep the previous
iteration's eight ciphertext registers live and GHASH them during the current
group's AES rounds, with a prologue and epilogue (OpenSSL's `PREPRETAIL`/`TAIL`).

**Source.** OpenSSL `aes-gcm-armv8-unroll8_64.pl` main-loop structure (PRE /
interleaved CTR+AES+GHASH / MODULO); Arm's AArch64cryptolib "merged kernel"
(Samuel Lee, Fangming Fang, Xiaokang Qian; OpenSSL PRs #9818, #15916, #27112).
The exact AES-256 target budget per 128 bytes: 112 AESE, 26 carry-less
multiplies (14 PMULL + 12 PMULL2), 20 EOR3, 8 EOR, 11 EXT, 8 REV64, 8 TRN.

**Files.** `aes.rs` `seal_in_place` (lines 458–491 and the 4-block loop at
493–515) and `open_in_place`.

**Expected gain.** Not separately quantified; Arm attributes 20–30% on Apple M1
to unroll8 + interleave + EOR3 together, and items 10, 13 and 17 are that change
split three ways.

**Risk.** LLVM may not honour the intended schedule from intrinsics. If the
measurement does not move, this is the first candidate for hand-written `.S` or
for SLOTHY ([§1.4](#14-speculative-no-reliable-gain-estimate)).

**Constant-time.** Yes — pure reordering. `open_in_place` must keep verifying
the tag before releasing plaintext.

#### 18. Two-way multi-buffer SHA-256

**What.** Add a `Sha256x2`/`digest_many` entry point keeping two abcd/efgh state
pairs and two message schedules, emitting the two instruction streams
interleaved.

**Source.** The technique is Gueron–Krasnov, "Simultaneous Hashing of Multiple
Messages", and Intel's `sha256-mb`; no AArch64 equivalent exists in OpenSSL or
BoringSSL. The applicability argument is derived from the Firestorm tables.

**Files.** `sha2.rs` hardware compress (~lines 602–640) plus a new two-message
API. Register budget is fine: 8 state + 8 schedule vectors per stream fits in 32.

**Expected gain.** Precisely bounded. Per 64-byte block, SHA-256 on ARMv8 needs
16 SHA256H + 16 SHA256H2 + 12 SHA256SU0 + 12 SHA256SU1 = 56 instructions, all on
the single port u14 at 1/cycle → a 56-cycle port floor = 0.875 cpb. The
dependency chain is 16 iterations × ~4.5 cycles ≈ 72 cycles = 1.125 cpb. The
latency bound exceeds the port bound by only 28%, leaving ~16 idle u14 slots per
block; two independent messages fill them exactly — 112 instructions in ~112
cycles for 128 bytes = 0.875 cpb, a **1.28x throughput gain**. A third stream
buys nothing. Contrast SHA-512, where SHA512H/H2 have throughput 2 on the same
port: 224 cycles per 128-byte block = 1.75 cpb port floor against a ~120-cycle
latency chain, i.e. already throughput-bound — which is exactly why SHA-512 sits
at 0.95x of ring while SHA-256 sits at 0.83x, and why multi-buffer would buy
nothing for SHA-512.

**Applicability.** Only where the caller has two independent messages:
Merkle/hash trees, batch signature verification, HKDF-Expand of several labels.
Blindplane's record path is a single streaming hash, so this is a library item.

**Constant-time.** Yes; the SHA-2 hardware instructions are inherently
constant-time. The API must pad both buffers to the same block count so that
which one finished first is not observable.

#### 19. AffineNiels constant-time basepoint table

**What.** `edwards.rs:426` builds `[[EdwardsPoint; 8]; 64]` — 64 rows × 8 entries
× 4 field elements × 40 bytes = **80 KB** — and `select_signed` touches every
entry of the selected row, so a fixed-base multiplication streams the whole
80 KB. Rebuild as `AffineNiels` (3 field elements → 60 KB), or adopt dalek's
32-row radix-16 layout with 8 doublings (~30 KB).

**Source.** curve25519-dalek `EdwardsBasepointTable`
(`LookupTable<AffineNielsPoint>`).

**Files.** `edwards.rs` — `basepoint_table`, `select_signed`, `mul_base`.
Composes with item 3.

**Expected gain.** Arithmetic: 64 generic 9-multiplication additions become 64
affine-Niels 7-multiplication mixed additions, ~128 field multiplications saved
out of ~600 in a fixed-base multiplication (~20%). Cache: 80 KB against a 128 KiB
L1D is most of L1, evicting everything else in the record path; 30 KB is not.
This compounds with item 1, which makes `mul_base` run twice per seal instead of
once. Note the findings file's caution: Niels-form tables for the *verify* path
already shipped in commit `771a81f`, so do not double-count that work — this
item is specifically the constant-time fixed-base table.

**Constant-time.** Yes, provided `select_signed` keeps touching every entry in
the selected row (it does). A smaller table also shrinks the DMP/GoFetch
surface.

#### 20. 4×64 radix for GF(2^255−19)

**What.** Replace the 5×51 representation with saturated radix-2^64 (4 limbs,
MUL + UMULH, 38× fold-back), keeping 5×51 as the portable fallback.

**Source.** AWS s2n-bignum `arm/curve25519/bignum_mul_p25519_alt.S`
(20 MUL + 20 UMULH + 23 ADCS + 11 ADDS + 9 ADC ≈ 100 instructions) and
`curve25519_x25519_alt.S`, whose README explicitly identifies Apple M1-class
cores as where the `_alt` path wins "because of higher multiplier throughput".
Every function carries a machine-checked HOL Light functional-correctness proof,
so it doubles as a correctness oracle. Licensed Apache-2.0 OR ISC OR MIT-0.

**Files.** `field.rs` in full, plus every `Fe` consumer.

**Expected gain.** Multiply uops per field multiplication fall from 50 (5×51:
25 MUL + 25 UMULH) to 40; per square from 30 to 28. The whole-ladder multiplier
floor falls from ~53,000 to ~45,000 cycles, ~1.18x. s2n-bignum's own comparison
of 4×64 against its Lenngren/SLOTHY 2^25.5 hybrid on a contemporary ARM core is
1.38x (19,297.7 ns vs 26,661.8 ns per X25519), but that is against a NEON hybrid
tuned for in-order cores, so 1.18x is the honest expectation here.

**Do item 12 first.** Changing the radix before fixing the scheduling is doing
the harder work for the smaller win.

**Constant-time — load-bearing caveat.** 64×64 MUL is fixed-latency on Apple
M-series, but Lenngren documents (§4.1) that on Cortex-A53/A55 plain MUL takes a
*data-dependent* 2 or 3 cycles and UMULH has 1/3 throughput, so a 4×64 path is
neither fast nor constant-time there. Gate it behind an Apple/out-of-order `cfg`
and keep 5×51 for A53/A55-class targets.

#### 21. AEGIS-128L as a fourth AEAD suite

**What.** Add AEGIS-128L to the `Suite` enum. It needs no GF(2^128) multiply at
all — only AES rounds — so on hardware AESE it is 2–3x cheaper per byte than
AES-GCM.

**Source.** "Bitslicing the AEGIS", ePrint 2026/1338: an AEGIS-128L state update
applies one AES round to eight state blocks at once, and it needs 2.5x fewer
parallel AES rounds per byte than bitsliced AES-128-CTR. *PDF not retrievable;
the ratio is from the abstract.*

**Files.** `aead.rs` `Suite` enum and wire code byte; new `aegis.rs`.

**Expected gain.** Estimated ~0.15 cpb against AES-GCM's ~0.38 cpb issue-bound
floor. If the objective is "fastest constant-time AEAD on M4" rather than
"fastest AES-GCM", this is the answer and it is not close — a headline number
ring, libsodium and RustCrypto cannot match on any platform.

**Cost.** It is a non-standard suite from a protocol perspective. Opt-in only,
never `fastest_available()`'s default, and it consumes a wire suite code.
AEGIS is now in CFRG draft, which helps.

**Constant-time.** Yes on hardware AESE.

---

### 1.3 Explicitly rejected, with reasons

Recorded so nobody re-derives them.

- **Karatsuba for GF(2^255−19).** Seo et al., ePrint 2021/185, tested schoolbook
  vs Karatsuba across Cortex-A and Apple ARM64: the advantage is a function of
  multiply CPI, and on Apple cores the extra add/sub chains dominate. At 4–5
  limbs there is almost nothing to save.
- **Lenngren's scalar/NEON hybrid ladder (radix 2^25.5).** An in-order-core
  artifact; it exists because Cortex-A53 has bad UMULH and data-dependent MUL.
  Copying it onto an out-of-order Apple core would be a mistake.
- **Batching X25519 on NEON.** In lib25519's speed table the "X batch" column is
  2.4x on Zen 4 and 3.0x on Tiger Lake (both AVX-512) but *identical to single*
  on Cortex-A76, Neoverse N1, Cortex-A72 and Cortex-A53. It is a vector-width
  win, not an algorithmic one, and 128-bit NEON is too narrow.
- **The Kummer line / genus-2 surfaces.** Naturally 4-way vectorisable, but a
  different curve with different keys and no X25519 interoperability. Unusable
  for anything that must speak HPKE/RFC 9180.
- **GHASH inside SME streaming mode.** SVE2's 8-bit polynomial multiply
  (`PMULLB .h`) *is* streaming-legal under `HasSVE2_or_SME`, so eight of them
  could synthesise a 64×64 carry-less multiply the way `VMULL.P8` does on
  ARMv7 — but that is 8 SSVE ops to replace 1 NEON PMULL, and NEON PMULL is
  already 4/cycle. AES-GCM stays a NEON-only kernel permanently, because AESE
  and the 128-bit PMULL require `HasSVEAES + HasNonStreamingSVE_or_SSVE_AES`.
- **SME ZA outer product (SMOPA) for Curve25519 or Poly1305 limbs.** Measured
  and refuted twice. The first measurement said 5–7x slower; the adversarial
  re-measurement (with core pinning, which the first lacked) says the multiply
  itself is actually *faster* than scalar when batched 8-wide (4.37 ns vs
  12.38 ns per field multiply) and the loss comes from mandatory 16-bit carry
  propagation at 27.07 ns — ~2.5x slower overall, not 5–7x. The decisive
  disqualifier is different again and neither claim identified it: **SME scales
  ~1.3x across cores** (330–516 G MAC/s at 1 thread → 596–668 G at 8) against
  6.4x for scalar integer multiply, so routing X25519 through SME would cut
  aggregate multicore throughput ~3x even if single-thread broke even.
- **GPU/Metal for the record path.** Independently re-measured: single-dispatch
  (what a synchronous `seal` costs) is 2.77 GB/s at 1 MiB and 9.15 GB/s at
  4 MiB, not the 18.7/39.8 originally claimed — the higher figures came from
  8,000 dispatches queued into one command buffer over the same cache-resident
  buffer. Dispatch floor is 90–106 µs min, 124–179 µs p50, against a whole
  60.6 µs record. One CPU core beats the whole GPU at 1 MiB.
- **Neural Engine.** Not for the reason originally given (XOR *is* expressible
  as `a+b−2ab` and is bit-exact in fp16 on this M4). The real blockers: the ANE
  IOKit user client is entitlement-gated and denied to unentitled code, and a
  bitsliced mapping needs ~4,000 fp16 elementwise ops per plaintext byte,
  landing below our existing NEON AES-GCM even at the headline fp16 rate.

---

### 1.4 Speculative — no reliable gain estimate

**SME streaming-SVE ChaCha20 (task #13, in progress).** SVL = 512 → 16 u32
lanes, plus `XAR` fusing xor-and-rotate into one instruction. Our own
measurement is 4.03x over our NEON on the *round function* (11.50–11.90 GB/s vs
2.86–3.03), decomposing into ~2.15x from lane width and ~1.87x from XAR. The
published comparator is Dolbeau's SUPERCOP
`crypto_stream/chacha20/dolbeau/arm-sve`, which is non-streaming SVE,
VL-agnostic and pre-XAR (3 instructions per rotate) — so "ChaCha20 on ARM
scalable vectors" is not new; "ChaCha20 in Arm SME streaming mode" is. OpenSSL's
`chacha-armv8-sve.pl` (Daniel Hu, PR #18522) is the production template, and its
`mixin` flag — pairing every SVE round instruction with a scalar A64 equivalent
so one extra block runs in the integer pipes — is directly stealable, since
streaming mode does not restrict base A64 integer instructions. Caveat from
tzakharko's M4 characterisation: plain SVE FMLA in streaming mode reaches only
~31 GFLOP/s FP32 where the SME-specific FMLA variant reaches ~250, so SSVE
vector arithmetic on M4 is not full-rate. Re-derive the 4x as ops/cycle before
sizing a 16-block pass.

**SME + NEON co-scheduling — status contested, resolve before relying on it.**
The findings file records 2 SME + 8 NEON threads at 29.87 GB/s against 19.0
NEON-only and 21.1 SME-only, +57%, with a full sweep showing 4 SME threads is
*worse* than 2 (1+0 = 11.63, 0+9 = 19.39, 1+9 = 26.77, **2+8 = 29.87**,
2+7 = 29.15, 3+7 = 27.41, 4+6 = 27.50, 0+10 = 18.99). The previous version of
this document states that a later measurement found the chip-wide SSVE ceiling
at ~7.4 GB/s, *below* NEON's 7.81 GB/s at ten threads, which would make adopting
it a regression. **These two cannot both be right and the discrepancy is not
resolved in any committed artifact.** Re-run the sweep on an idle, pinned
machine before this appears in a README or a paper. The architectural
explanation for the *mechanism* is in any case published: tzakharko established
that the M4's SME block is one unit per core cluster, shared by the four
P-cores, and that a single core can saturate it — so the additivity is a
corollary, and only the tuning curve is ours. The optimum also differs across
M4 / M4 Pro / M4 Max, so it must be probed at startup rather than hardcoded.

**SSVE Poly1305 with r^8 lanes at SVL = 512.** Recipe: OpenSSL
`poly1305-armv9-sve2.pl` (Iakov Polyak, Linaro, PR #28454, merged September
2025) — base 2^26 in even/odd lanes of 64-bit elements, `UMULLB`/`UMULLT`/
`UMLALB`/`UMLALT` widening MACs, `SHRNB` narrowing carries, `TBL` for the tail
r-power. All of those sit under `HasSVE2_or_SME` and are therefore
streaming-legal. But the one published data point is discouraging: on Graviton4
at VL = 128, SVE2 Poly1305 is 0.66 cpb against NEON's 0.62 — **6% slower** — and
OpenSSL ships it disabled below VL = 256. Gate this behind a cheap probe
(confirm those instructions execute in streaming mode on M4 and measure
throughput; an afternoon) before committing weeks. And do not do it at all if
item 5 lands, since a fused AEAD already hides 85–87% of Poly1305.

**SME batched X25519 — 8 independent ladders in 512-bit lanes.** The AVX-512
shape that gives lib25519 2.4–3.0x on x86, applied to the one ARM vector unit
wide enough to pay for it. MUL and UMULH are confirmed available in streaming
mode, and this is *not* the ZA-tile approach already refuted. But the ~1.3x
multicore SME scaling measured above is a serious obstacle: any win must survive
being divided across the cluster. Prototype a lane-parallel `Fe::mul` and
measure against 1-lane scalar *and* against 10-core scalar before committing.
Also verify that streaming-mode MUL/UMULH are fixed-latency and how `PSTATE.DIT`
interacts with streaming SVE (undocumented — measure it).

**SLOTHY with an Apple P-core model.** Our remaining symmetric deficits are
scheduling problems on kernels whose instruction selection is already right, and
item 17 in particular is the kind of search LLVM will not do from intrinsics.
It needs a Firestorm/M4 microarchitecture model — four SIMD ports u11–u14, the
single crypto-hash port u14, two multiply pipes u5/u6, AESE+AESMC and PMULL+EOR
macro-op fusion — which does not exist publicly and would itself be a
contribution.

**Jasmin/libjade for `Fe::mul`, `Fe::square` and the ladder step.** The only
ecosystem giving assembly-grade speed *and* a machine-checked constant-time
proof of the emitted assembly. 4–6 weeks including the toolchain. Worth it only
after the performance work lands, and only for primitives we would otherwise
hand-write in `.S`. Compare honestly with s2n-bignum, whose README states its
HOL Light proofs cover functional correctness only and that constant-time is
"not actually rigorously machine-checked at present".

**mKEM instead of N independent HPKE encapsulations.** Katsumata, Kwiatkowski,
Pintore, Prest, ASIACRYPT 2020 / ePrint 2020/1107. Our multi-recipient envelope
is N independent HPKE encapsulations — correct, standard, and strictly worse
than the literature. For X25519 the bandwidth saving is smaller than the lattice
case's ~16x, but the shared-randomness structure removes N−1 ephemeral scalar
multiplications from the seal path, which is exactly where the time goes
(`seal, 4 KiB, 3 recipients` = 7,205 ops/s against 16,508 for one). Deviates
from RFC 9180 single-recipient mode, so `hpke`-crate cross-checking would be
lost for the envelope, and mKEM carries its own security model. A real protocol
change, not a drop-in.

**Fork-consistency upgrade.** A per-client persisted head detects rollback *for
that client only*; a relay can equivocate between two clients indefinitely and
neither notices, because every signature it shows them is genuine. SUNDR
(OSDI 2004) gets fork consistency from signed version structures; SPORC
(OSDI 2010) adds automatic recovery; Caelus (S&P 2015) rotates the attester role
among a user's devices for near-real-time verification. Either adopt one or
state the weaker property explicitly in the README. A correctness-of-claims fix,
not a performance item.

---

## 2. Where we actually stand

All ratios from `results/benchmarks.md` (M4, best of 5, loaded machine). Cycle
figures assume a 4.4 GHz P-core and inherit the caveat in §0.1.

### 2.1 Symmetric

| Primitive | Ours | vs ring | Our cpb\* | Best published / computed floor | Verdict |
|---|---:|---:|---:|---|---|
| AES-256-GCM, 64 KiB | 6.62 GB/s | **0.93x** | 0.67 | ~0.38–0.45 cpb issue floor (OpenSSL unroll8 on Firestorm ports) | Behind — but so is ring |
| AES-256-GCM, 1 KiB | 2.95 GB/s | **0.62x** | 1.49 | RustCrypto 5.41 GB/s on the same run | **Clearly behind. Per-call setup.** |
| ChaCha20-Poly1305, 64 KiB | 1.43 GB/s | **0.73x** | 3.08 | ring 2.24 cpb; a fused kernel measured here reaches ~2.4 GB/s | **Clearly behind, with a measured fix in hand** |
| SHA-256, 64 KiB | 2.45 GB/s | **0.83x** | 1.80 | 1.125 cpb latency floor, 0.875 cpb port floor | Behind |
| SHA-512, 64 KiB | 1.55 GB/s | **0.95x** | 2.84 | 1.75 cpb port floor | Near parity with ring; both far from floor (§0.1) |
| Argon2id | 10.6 ops/s | **0.88x** vs `argon2` | — | n/a — deliberately slow | Slightly behind, immaterial |

\*at an assumed 4.4 GHz; see §0.1.

**Plainly: we are behind ring on every symmetric primitive.** The brief's framing
— "aiming to be the fastest constant-time implementation available" — is not
supported by any line of this table. The two real gaps are ChaCha20-Poly1305 (a
missing fused kernel, item 5, with a 1.66x fix already prototyped) and
short-message AES-GCM (a missing prepared-key API, item 2). SHA-512 is
essentially done. AES-GCM at 64 KiB is 7% off ring, within reach of items 9, 10,
13 and 17.

The absolute distance from the theoretical floors — 1.6x to 2.6x depending on
the primitive — is **not yet a meaningful claim**, because the same computation
puts ring 1.5x above the SHA-512 port floor, which is implausible. Resolve §0.1
before quoting any of it.

### 2.2 Asymmetric

| Operation | Ours | vs dalek | Our cycles\* | Best published / achievable | Verdict |
|---|---:|---:|---:|---|---|
| X25519 (variable base) | 54,062 ops/s (18.5 µs) | **1.18x** | ~81,400 | lib25519 on Cortex-A76: 111,516 cycles; s2n-bignum `_alt`: 19.3 µs | Ahead of dalek and of A76 in cycles; **~1.5x above our own 5×51 issue floor (~53k), ~1.8x above the 4×64 floor (~45k)** |
| X25519 **base** multiplication | (same 18.5 µs) | — | ~81,400 | ~6–7 µs using our own Edwards table | **Worst result in the project — wrong algorithm, not slow code** |
| Ed25519 sign | 116,030 ops/s (8.6 µs) | **1.06x** | ~37,900 | lib25519 on Cortex-A76: 54,687 cycles | At or beyond the state of the art for the hardware |
| Ed25519 verify (strict) | 37,741 ops/s (26.5 µs) | **0.75x** | ~116,600 | dalek on this machine: 45,801 ops/s; our own prototype reaches 44,100 | **Behind. Fixes measured at 1.17x → parity, not a lead.** |
| HPKE single-shot seal | 24,281 ops/s | **1.015x** vs `hpke` | — | dominated by the two X25519s above | Parity |

\*at an assumed 4.4 GHz.

**Plainly:** Ed25519 sign is at or beyond the published state of the art for this
hardware and needs nothing. X25519 variable-base is respectable — ahead of dalek,
ahead of a Cortex-A76 in cycles — but roughly 1.5x above what its own
representation can issue, so it is not at the record. Ed25519 verify is 1.21x
behind dalek on this machine, and the two known fixes have been prototyped and
measured at 1.17x, which reaches **parity, not a lead**; getting past dalek needs
item 2's cached decompression on top. And the X25519 **fixed-base** path is not
merely behind the state of the art, it uses the wrong algorithm — a variable-base
ladder for a constant point — which is the clearest defect in the codebase.

The second sweep's headline that we are "1.9–2.5x off the record" on X25519 and
signing was computed against stale benchmark figures (27,798 and 61,989 ops/s);
against the committed numbers it is wrong. See Appendix A.

### 2.3 The design, not the code

Every element of the server-blind data plane is a published, standard
composition, and no component of it is new:

- Per-recipient envelope wrapping → RFC 9180 HPKE; the optimised form is
  ASIACRYPT 2020 mKEM.
- Key-committing AEAD → Albertini, Duong, Gueron, Kölbl, Luykx, Schmieg,
  USENIX Security 2022; now tracked in `draft-irtf-cfrg-aead-properties`.
- Signed hash chain for rollback detection → this is *fork consistency*, SUNDR
  OSDI 2004, refined by BFT2F, SPORC OSDI 2010, Caelus S&P 2015. Our per-client
  head is **weaker** than what those achieve.
- Scoped blind indexes → IronCore Cloaked Search ships per-(tenant, index,
  field) keys, essentially our (tenant, label, key_epoch); MongoDB Queryable
  Encryption ships a stronger query model in a mainstream database; BlindexTEE
  (arXiv 2411.02084) uses the exact term in current literature. The leakage
  profile is CryptDB's deterministic onion, and the CryptDB/Mylar lineage was
  broken through exactly that leakage.
- Untrusted relay that orders and stores but cannot read → SPORC, the closest
  published ancestor of blindplane's overall shape.
- Access graph → we leak it; Chase–Perrin–Zaverucha (CCS 2020) show that is a
  design gap, not an inherent cost of server-blind storage.

The dependency-graph claim is the weakest of the three headline claims.
`cargo tree --edges normal | grep -v '^blindplane-'` establishes the absence of a
*crate name*, not the absence of a *capability*. Cocoon (OOPSLA 2024) and
Filament (arXiv 2604.14357) enforce Denning-style information-flow control inside
unmodified Rust with a stated adversary model and a semantic property; cap-std
does capability-oriented std; ArchUnit-style dependency conformance has existed
for two decades. Against that baseline our check is a lint — a good one, and a
legitimate README claim, but not a technique.

---

## 3. The publishable contribution

**Verdict: one paper, narrowly scoped, on SME — and it is not yet ready.
Nothing else here is publishable, and that is fine.**

### 3.1 What is not a contribution

- **The data-plane architecture.** A known composition of HPKE, key-committing
  AEAD, fork-detection hash chains and scoped blind indexes. No new primitive,
  no new security definition, no theorem, no leakage analysis in the structured-
  encryption framework. A reviewer will ask what it adds over SPORC and the
  honest answer is "modern primitives and a cleaner crate boundary".
- **Dependency-graph enforcement.** A CI grep with no threat model and no formal
  property, against a literature that has type-system-enforced non-interference.
- **The performance work.** Every technique in section 1 comes from an existing
  paper or an existing production kernel. Implementing them well is engineering.

The honest description of this project is a solid engineering artifact with an
unusually rigorous measurement and refutation story — the adversarial pass in
`apple-acceleration-findings.json`, which overturned roughly half its own
sweep's numbers, is genuinely better practice than most published implementation
work — plus one measurement campaign that nobody else has run.

### 3.2 What is

Precisely stated: **the M4's SME streaming-SVE unit is usable for
bitwise/integer symmetric cryptography, its ZA matrix tiles are not usable for
elliptic-curve or Poly1305 limb arithmetic, and both conclusions come with a
measured cost model and an instruction-availability map.**

Supporting evidence, in decreasing order of durability:

1. **The instruction-availability and hazard map for streaming mode on M4.**
   SVL = 512 bits; M4 has no non-streaming SVE at all (`ptrue p0.b` outside
   streaming mode SIGILLs); available in streaming mode: XAR, EOR3, TBL,
   MUL/UMULH `.d`; not available: AESE, PMULL, RAX1 (Apple does not advertise
   FEAT_SME_FA64); the `smstart`/`smstop` round trip costs 9.6 ns and **zeroes
   the entire vector register file including callee-saved v8–v15**; xnu
   context-switches ZA/ZT0 into kernel-side thread state via
   `machine_save_sme_context()`, so any secret left in ZA is spilled to kernel
   memory. The v8–v15 hazard appears to be written down nowhere public. Two
   corollaries fall straight out: AES-GCM and Keccak can never move into
   streaming mode, and ChaCha20-Poly1305 is therefore the right preferred suite
   on Apple hardware despite AES-GCM being faster single-threaded.
2. **The negative result on ZA, with the mechanism isolated.** Note the
   mechanism changed under adversarial re-measurement, which is itself worth
   reporting: without core pinning the loss looked like 5–7x from a slow
   multiply; with pinning, the batched SMOPA multiply is *faster* than scalar
   (4.37 ns vs 12.38 ns per field multiply) and the loss is 27.07 ns of
   mandatory 16-bit carry propagation, ~2.5x overall. The decisive disqualifier
   is neither: **SME scales ~1.3x across cores against 6.4x for scalar integer
   multiply**, so any single-thread win is erased at the aggregate level.
   Negative results with an identified mechanism do not get superseded the way a
   speedup does; this is the most durable material in the campaign.
3. **The 4.03x ChaCha20 round-function speedup with a causal decomposition**
   into ~2.15x lane width × ~1.87x XAR fusion.
4. **The constant-time characterisation of streaming mode**: `MSR DIT` works
   inside it, `smstart`/`smstop` is a free secret wipe, and the shared-cluster
   SME block is an SMT-like coarse contention channel across a boundary most
   people assume is not shared.
5. **The co-scheduling sweep** — *only if §1.4's contradiction resolves in its
   favour*. As it stands the +57% figure and the "SSVE ceiling is below NEON at
   ten threads" figure are inconsistent, and until that is settled this cannot
   go in a paper.

### 3.3 Prior art that narrows the claim

- tzakharko, `m4-sme-exploration`, already published that the SME block is one
  shared unit per core cluster, that one core saturates it, and that it is
  disjoint from the NEON pipes. Given that, "SME threads plus NEON threads add
  throughput" is a **corollary, not a discovery**. Re-scope to the
  quantification, the tuning curve and the security analysis. Occamy (2023) is
  prior art for the general shared-SIMD-coprocessor pattern; cite it defensively.
- Dolbeau's SUPERCOP `chacha20/dolbeau/arm-sve` means "ChaCha20 on ARM scalable
  vectors" is not new. Narrow to "first ChaCha20 in Arm SME streaming mode, and
  first quantification of XAR's contribution", and benchmark against a port of
  his code, not only against our own NEON.
- OpenSSL PR #18522 merged an SVE2 ChaCha20 in 2022, already using XAR. XAR as
  the SVE2 rotate idiom is public folklore (zingaburga's SVE2 gist). Using it
  for ChaCha is obvious to an implementer.
- ePrint 2026/093 (ML-KEM on ARMv9-A with SVE2 and SME, benchmarked on M4 Pro,
  up to 7.77x) is the closest existing work and the only cryptography paper on
  ePrint using SME. It is lattice/NTT and uses ZA for a workload matrix units
  are good at. It does not touch symmetric ciphers, streaming SVE for bitwise
  workloads, XAR, or SME/NEON concurrency.
- Searches that returned nothing: ePrint full-text for "Scalable Matrix
  Extension" (5 hits, only 2026/093 relevant) and "SVE2" (2 hits, both PQC);
  arXiv SME papers are all GEMM/HPC (2409.18779, 2512.21473, 2511.08158); no
  published SME/SSVE symmetric-crypto work at any venue 2024–2026; no published
  measurement of streaming-SVE and NEON running concurrently for throughput on
  any workload. **Caveat: the sweep had no Google Scholar or DBLP access and did
  not check the CHES 2025/2026 or SAC 2025 programmes or non-English venues. Do
  that manual pass before asserting absence of prior art in a submission.**

### 3.4 Venue

ePrint immediately — it costs nothing and establishes priority, which matters
because ePrint 2026/093 shows a group actively working the same hardware. Then
**Journal of Cryptographic Engineering**, the natural home for
implementation-and-characterisation work, with less novelty pressure than
CHES/TCHES. CHES is reachable but riskier: reviewers there want a record on a
widely available platform or a new side channel, and "macOS-only, single-vendor,
undocumented ISA extension, Rust inline asm" cuts against generality.

The higher-risk, higher-reward alternative: make **the shared-SME cross-core
contention channel** the paper. If a process on a sibling P-core can reliably
detect another process entering streaming mode, that is a security finding on a
shipping consumer platform, it lands at a security venue rather than an
implementation one, and it is substantially less work than finishing a cipher.
Right now it is asserted in our own findings file and unmeasured.

### 3.5 Experiments still required

1. A complete, test-vector-passing SSVE ChaCha20. Task #13 is in progress; the
   11.5 GB/s figure is a round-function microbenchmark, not a cipher.
2. Full AEAD numbers. Poly1305 cannot run in streaming mode, so every chunk pays
   `smstop`/`smstart`. Measure real end-to-end ChaCha20-Poly1305, not keystream.
3. Benchmark against the best available baseline — ring and OpenSSL hand-written
   assembly, plus a port of Dolbeau's arm-sve code. "4x our own previous code"
   is not a result.
4. Cycles per byte at a measured, pinned frequency on an idle machine, with error
   bars (§0.1). The adversarial pass already showed how much this matters: it
   overturned SMOPA numbers by 2–4.5x purely by adding core pinning.
5. Resolve the co-scheduling contradiction in §1.4.
6. More than one chip: M4, M4 Pro, M4 Max (different SME unit counts), and
   ideally a non-Apple SME2 part or Arm's FVP, to separate "Apple M4
   microarchitecture" from "the SME ISA".
7. Energy per byte via `powermetrics`. Nobody has published SME energy figures
   for crypto, and on a laptop part perf/W is arguably the more interesting axis.
8. Real constant-time evidence — dudect or a proper Welch t-test over many
   samples, not a 0.8% mean-timing spread. Ideally TIMECOP under emulation.
9. Measure the shared-SME contention channel in bit/s.
10. **Move the lab and prototype code into the repository and fix the
    findings-file paths that point at a `/private/tmp` scratchpad.** This
    currently includes the two most valuable prototypes in the project — the
    fused AEAD kernel and the Ed25519 verify rewrite. For an artifact-evaluated
    venue this is fatal; for engineering it is just reckless, because the
    directory can be garbage-collected at any time.
11. Extend to a second primitive to show the technique generalises: BLAKE2b or
    Argon2id's G function on `.d` lanes. Confirming RAX1's absence forecloses
    Keccak, which is itself worth stating.

### 3.6 What reviewers will attack, ranked

1. **"Aiming to be the fastest constant-time implementation available."** We are
   behind ring on every symmetric primitive (§2.1) and behind dalek on Ed25519
   verify. Only X25519 and Ed25519 sign are ahead of their comparators. Drop
   this framing.
2. **Rolling your own X25519, Ed25519, AES-GCM and HPKE, unaudited, in 2026.**
   The assurance bar is now formally verified (HACL*, fiat-crypto,
   Jasmin/libjade) or audited (ring, dalek). "Zero third-party runtime
   dependencies" reads to a security reviewer as a *reduction* in assurance
   presented as a feature. The README's status disclaimer already concedes this.
3. The headline SME number is a keystream microbenchmark of an unfinished
   implementation.
4. The 4x is measured against our own NEON, not the best available baseline.
5. The co-scheduling result is architecturally unsurprising once tzakharko's
   shared-cluster finding is known, decays to ~1.1x by ten threads, its optimum
   is chip-specific, and our own artifacts disagree about whether it exists.
6. Constant-time claims rest on mean-timing spreads (0.8%, 2.7%), which is not a
   constant-time argument, and `PSTATE.DIT` — the one thing Apple documents for
   this purpose — is set nowhere in the crate.
7. The shared SME unit creates an SMT-like cross-core contention channel our own
   findings file identifies and nobody has measured. It cuts against the
   security story of the whole library.
8. Blind-index leakage: equality and frequency within a scope is exactly what
   leakage-abuse attacks consume. Naming the leaks is not bounding them — there
   is no leakage function and no proof.
9. Rollback detection is weaker than fork consistency and the README reads as if
   the hash chain solves equivocation. It does not.
10. Reproducibility: absolutes on a loaded machine, lab and prototype code
    outside the repo, no error bars, no pinned frequency.
11. Generality: M4-only, macOS-only, `core::arch::asm!` only, on an ISA
    extension Apple does not document and whose SVL it can change.

---

## 4. Reading list

Ordered by what will change the code soonest.

1. **Vlad Krasnov, `chacha20_poly1305_armv8.pl`** (BoringSSL / ring). Read the
   source, not a paper. The exact kernel we lose to at 0.73x; the lagged
   interleave is not described anywhere else.
   <https://github.com/briansmith/ring/blob/main/crypto/cipher/asm/chacha20_poly1305_armv8.pl>
2. **curve25519-dalek, `backend/serial/scalar_mul/vartime_double_base.rs` and
   `curve_models.rs`.** Items 3 and 19 in full, from the implementation we are
   0.75x of. ~400 lines.
3. **Andy Polyakov, `poly1305-armv8.pl` and `ghashv8-armx.pl`** (OpenSSL). The
   base-2^64 scalar Poly1305 (item 6) and the packed-Karatsuba GHASH key
   pre-processing (item 9), both with per-core cycles/byte tables in the headers.
4. **Dougall Johnson, Apple Firestorm instruction tables.** Not a paper; the only
   source of measured latency/throughput/port data for Apple P-cores, and the
   basis of every floor computed here.
   <https://dougallj.github.io/applecpu/firestorm-simd.html> and `firestorm-int.html`
5. **Chen et al., "GoFetch", USENIX Security 2024.** Why item 4 is not optional,
   and why "constant-time on Apple Silicon" needs a qualifier for M1/M2.
   <https://gofetch.fail/>
6. **Gouvêa & López, "Implementing GCM on ARMv8", CT-RSA 2015 (LNCS 9048).** The
   canonical ARMv8 GCM paper: schoolbook-vs-Karatsuba on AArch64, PMULL-based
   reduction, lazy reduction. First-hand numbers (Apple A7: GCM auth-only
   0.51 cpb, AES-128-GCM 1.71 cpb).
   <https://conradoplg.modp.net/files/2010/12/gcm14.pdf>
7. **Arm AArch64cryptolib and OpenSSL `aes-gcm-armv8-unroll8_64.pl`.** The
   current state of the art for AES-GCM on AArch64 and the exact instruction
   budget to aim at (items 10, 13, 17).
8. **Emil Lenngren, "AArch64 optimized implementation for X25519" (2019).** §4.1
   for the definitive statement of when 4×64 is wrong (Cortex-A53/A55
   data-dependent MUL), §5 for the cswap elimination (item 11). Do not copy the
   NEON hybrid.
   <https://github.com/Emill/X25519-AArch64/blob/master/X25519_AArch64.pdf>
9. **AWS s2n-bignum, `arm/curve25519/curve25519_x25519_alt.S` and
   `bignum_mul_p25519_alt.S`.** The 4×64 reference (item 20), permissively
   licensed, with HOL Light proofs that double as a correctness oracle. Read the
   README's platform argument first. <https://github.com/awslabs/s2n-bignum>
10. **Abdulrahman, Becker, Kannwischer, Klein, "Fast and Clean" (SLOTHY),
    TCHES 2024(1).** Table 5 is the quantified case that scheduling alone is
    worth 1.90x on an X25519 kernel. <https://eprint.iacr.org/2022/1303>
11. **lib25519 speed table.** The scoreboard, and the source of the "batching is
    a vector-width win, not an algorithmic one" finding.
    <https://lib25519.cr.yp.to/speed.html>
12. **Bernstein & Schwabe, "NEON crypto", CHES 2012.** The
    radix-from-multiplier-width principle, which is why our 44-bit Poly1305
    limbs are wrong.
13. **Bernstein & Yang, safegcd, TCHES 2019(3) / ePrint 2019/266.** Item 15.
14. **Daniel Hu, OpenSSL PR #18522, `chacha-armv8-sve.pl`.** The only production
    vector-length-agnostic ChaCha20 and the direct template for task #13,
    including the `mixin` scalar-lane trick.
15. **tzakharko, `m4-sme-exploration`.** The prior art that bounds our SME claim:
    SVL = 512, one SME block per core cluster, SSVE vector arithmetic not
    full-rate. Read before writing the paper, not after.
    <https://github.com/tzakharko/m4-sme-exploration>
16. **Wei, Li, Shen, Yang, Zhao, "Optimized Implementation of ML-KEM on ARMv9-A
    with SVE2 and SME", ePrint 2026/093.** The nearest neighbour and the paper a
    reviewer will hold up first. <https://eprint.iacr.org/2026/093>
17. **Bernstein, Duif, Lange, Schwabe, Yang, "High-speed high-security
    signatures", CHES 2011.** The birational map behind item 1; §5 for batch
    verification; and the finding that ~33% of batched verification is point
    decompression, which is the argument for item 2's cached verifying key.
18. **Chalkias, Garillot, Nikolaenko, "Taming the many EdDSAs", SSR 2020 /
    ePrint 2020/1244.** Required *before* shipping batch verification:
    randomised batching is sound only against the cofactored equation, so our
    strict cofactorless `verify_strict` and a batch verifier would silently
    disagree. Pick one semantics repo-wide.
19. **Li, Krohn, Mazières, Shasha, "SUNDR", OSDI 2004**, then **Feldman, Zeller,
    Freedman, Felten, "SPORC", OSDI 2010.** The correct names and the correct
    prior art for what the manifest hash chain does and does not achieve.
20. **Albertini, Duong, Gueron, Kölbl, Luykx, Schmieg, "How to Abuse and Fix
    Authenticated Encryption Without Key Commitment", USENIX Security 2022.**
    The source of our key-commitment construction. Cite it; do not present the
    construction as ours.
21. **Lamba et al., "Cocoon", OOPSLA 2024.** What "structural enforcement of a
    security property in Rust" has to look like to be a contribution, and
    therefore why the dependency-graph check is not one.

---

## Appendix A: corrections

Recorded because several downstream conclusions depend on numbers that are no
longer true.

### A.1 Already fixed in the code — ignore the sweeps' recommendations

- *"GHASH performs a full reduction inside every multiply; 48 carry-less
  multiplies per 128 bytes against OpenSSL's 26; the single largest GHASH win
  available."* Not true at `f93d870`. `aes.rs` has `Unreduced`, `gf_mul_wide`
  and a separate `gf_reduce`; `absorb_eight_vectors` (`aes.rs:298`) sums eight
  unreduced products and reduces once. Our count is **27** carry-less multiplies
  per 128 bytes against OpenSSL's 26 — parity. Task #7 closed this.
- *"Delete the signature self-verification at the end of `seal()` — 1.50x on the
  whole record path."* Already done: `blindplane-core/src/lib.rs:805`
  `validate_own` skips signature verification unless the `fault-resistant`
  feature is enabled.
- *"Hardware SHA-512 unused inside Ed25519, ~15% of a seal."* Already done
  (task #8); `results/benchmarks.md` reports `sha512=hardware`.
- *"Niels-form tables for Ed25519 verify."* Already shipped (commit `771a81f`).
  Item 3 is the *coordinate model and NAF width*, not the tables.

### A.2 Stale measurements — the sweeps' conclusions built on these are wrong

- X25519 is **54,062 ops/s**, not 27,798. At 4.4 GHz that is ~81,400 cycles, not
  ~158,000. "We are 1.9–2.5x off the record" and "~2.2x is available inside the
  existing representation" do not survive; the real headroom inside 5×51 is
  ~1.5x.
- Ed25519 sign is **116,030 ops/s**, not 61,989 — ~37,900 cycles, better than the
  54,687 cycles lib25519 measures on a Cortex-A76. The "surprisingly weak signing
  number" and the urgency attached to the AffineNiels table (item 19) are both
  overstated. Item 19 remains worth doing, mainly for the 80 KB → 30 KB cache and
  DMP-surface reduction and because item 1 doubles the number of `mul_base` calls
  per seal.
- ChaCha20-Poly1305 is **1.43 GB/s**, not 0.95. The 0.95 figure predates the
  hand-written NEON ChaCha (task #6). The gap to ring is 1.37x, not 2.32x.

### A.3 Corrections to the project brief

| Brief says | Measured |
|---|---|
| ChaCha20-Poly1305 ~0.83x of ring | **0.73x** at 64 KiB, 0.77x at 1 KiB |
| X25519 1.4–1.6x faster than x25519-dalek | **1.18x** |
| AES-256-GCM ~0.95x | 0.93x at 64 KiB; **0.62x at 1 KiB**, which the brief omits |
| SHA-256 ~0.86x | 0.83x |
| SHA-512 ~parity | 0.95x — accurate |
| Ed25519 sign ~parity | 1.06x — accurate |
| Ed25519 verify ~0.75x | 0.75x — accurate |
| Argon2id ~0.9x | 0.88x — accurate |
| HPKE ~parity | 1.015x — accurate |

The 1 KiB AES-GCM figure is the omission that matters most: blindplane's records
are 4 KiB, so the short-message regime is the product's regime, and it is the one
place in the whole benchmark table where RustCrypto beats us.

### A.4 Sources the sweeps could not fully retrieve

eprint.iacr.org serves abstracts but puts a Cloudflare challenge in front of
PDFs from the sweep environment, so ePrint 2025/2171 (GHASH bit-reversal
elimination), 2019/842 (Improved SIMD Poly1305), 2026/1338 (Bitslicing the
AEGIS), 2021/185 (Montgomery multiplication on ARM64), 2019/266 (safegcd),
2020/1244 (Taming the many EdDSAs) and 2024/2060 (CT tool evaluation) are cited
from abstracts and secondary summaries. Any specific number quoted from them
here — safegcd's "<4000 Skylake cycles", 2025/2171's 0.33–0.34 cpb and
~1.7x-over-Karatsuba, 2026/1338's 2.5x — must be confirmed against the PDF
before it goes into a README or a paper. Gouvêa–López, Lenngren,
SLOTHY/TCHES 2024, the Ed25519 paper, the lib25519 table and all
OpenSSL/BoringSSL/s2n-bignum sources were read first-hand.
