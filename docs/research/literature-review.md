# Literature review: where we stand against the published state of the art

A survey of the academic and production literature on fast constant-time
cryptography, run to answer two questions: what techniques would make this crate
faster than its competitors, and is there anything here worth publishing.

Raw findings — 46 papers, 33 techniques with citations — are in
`literature-review.json`. This document is the verdict.

## 1. The publishability verdict: no

Every element of this project that looked like a contribution turns out to have
prior art, most of it well known:

| What looked novel | Prior art |
|---|---|
| "SME is a shared cluster coprocessor, not per-core" | tzakharko, [m4-sme-exploration](https://github.com/tzakharko/m4-sme-exploration), 2024–25 — already public |
| ChaCha20 on ARM scalable vectors | Dolbeau in SUPERCOP; OpenSSL [PR #18522](https://github.com/openssl/openssl/pull/18522), **merged 2022**, already uses XAR |
| Cryptography on SME | [ePrint 2026/093](https://eprint.iacr.org/2026/093), ML-KEM NTT on M4 Pro, up to 7.77x |
| Key-committing AEAD | Albertini, Duong, Gueron, Kölbl, Luykx, Schmieg, [ePrint 2020/1456](https://eprint.iacr.org/2020/1456), USENIX Security 2022 — now being standardised in CFRG |
| Signed hash chain for rollback detection | SUNDR, [OSDI 2004](https://www.usenix.org/conference/osdi-04/secure-untrusted-data-repository-sundr) — *fork consistency*, 22 years old |
| The whole server-blind architecture | SPORC, [OSDI 2010](https://www.cs.princeton.edu/~mfreed/docs/sporc-osdi10.pdf) — untrusted server orders and stores but cannot read; hash chains limit equivocation |

Two of these are worse than "already done":

- **Our rollback detection is weaker than SUNDR's.** A per-client persisted head
  detects rollback *for that client*. SUNDR gets fork consistency: a server that
  shows two clients divergent histories must fork them permanently and can never
  reconcile, which clients detect by comparing heads. We have no cross-client
  comparison, so a server can equivocate between devices indefinitely.
- **The SME co-scheduling framing is dead.** Once "SME is one shared unit per
  cluster, disjoint from the per-core NEON pipes" is public, a measured +57% from
  running two SME threads alongside eight NEON threads is a straightforward
  consequence, not a finding. And our own follow-up measurement showed the
  chip-wide SSVE ceiling (~7.4 GB/s) is *below* NEON at ten threads (7.81 GB/s),
  so adopting it would be a regression.

The honest description of this project is a solid engineering artifact with an
unusually rigorous test story, not a research contribution.

The only thread that is arguably unexplored: **SME as a cross-core side or covert
channel.** SME is shared per cluster, so a process on a sibling P-core can in
principle observe contention. That is an attack-side measurement nobody appears
to have published, and it cuts against our own library rather than for it.

## 2. Techniques that would actually make us fastest

Ranked by measured gain over effort. These are the concrete path from "behind
ring" to "ahead of ring".

### Tier 1 — quantified, high value

**Fuse ChaCha20 and Poly1305 into one lagged pass.**
Source: Krasnov, `chacha20_poly1305_armv8.pl` in BoringSSL/ring. ChaCha20 runs in
NEON while Poly1305 runs in *scalar general-purpose registers* on the previous
block group — two different execution resources, software-pipelined into one
loop. We currently run two full passes (`aead.rs` encrypts the whole buffer, then
MACs the whole buffer). **This is exactly what ring beats us with at 0.72x.**
Effort: high — it is a scheduling problem, not an algorithmic one.

**Poly1305 in base 2^64 with three limbs instead of 44-bit limbs.**
Exactly quantified: our `absorb` computes nine u64xu64→u128 products = 18
multiply instructions; the base-2^64 form needs 9. Low effort, self-contained to
one function plus limb packing. Constant-time by construction.

**Cut GHASH to 26 carry-less multiplies per 128 bytes.**
Source: Arm's AArch64cryptolib and OpenSSL `ghashv8-armx.pl`. We are at 48. Three
separate wins: precompute the *folded* Karatsuba key halves in the power table
(ours recomputes `a_lo ^ a_hi` at runtime through GPR round-trips), pre-twist the
H powers to delete the per-block `RBIT`, and software-pipeline so GHASH processes
the *previous* group while AES generates the current one.

**Reconsider Karatsuba on Apple cores.**
Gouvêa and López (CT-RSA 2015), the canonical ARMv8 GCM paper, *abandoned*
Karatsuba on AArch64 in favour of four straight PMULL/PMULL2 calls, because
extracting the upper half of a vector costs more than the multiply it saves. We
use Karatsuba. Low effort to test — the harness already exists in `lab/`.

### Tier 2 — quantified, larger effort

**Fix `Fe::mul` scheduling before changing anything else.** Our X25519 is roughly
2.2x above its own theoretical floor. SLOTHY (Abdulrahman, Becker, Kannwischer,
Klein, [TCHES 2024](https://eprint.iacr.org/2022/1303)) reports a **1.90x swing
from instruction scheduling and register allocation alone**, no algorithmic
change, on exactly this kind of code.

**Consider 4x64 radix-2^64 field arithmetic.** s2n-bignum's pure-scalar
`curve25519_x25519_alt` outperforms its own Lenngren-derived 5x51 hybrid on
contemporary ARM. Multiplier-throughput floor drops from 50 uops per field
multiply to 40.

**Bernstein–Yang safegcd inversion** ([ePrint 2019/266](https://eprint.iacr.org/2019/266))
instead of Fermat. Our Fermat chain is ~265 field operations, about 9–10% of
every X25519 and every point compression.

**Ed25519 verification**: width-8 NAF for the public basepoint scalar, T-free
projective doubling, and an affine-Niels constant-time basepoint table. Together
these are most of the 0.76x gap.

**Batch Ed25519 verification** (Bernstein et al., CHES 2011): 2.04x per signature
at batch 64, 2.4x asymptotically. **Security caveat, non-negotiable:** batch
verification is cofactored, and our `verify_strict` is cofactorless. They are not
interchangeable — see Chalkias, Garillot, Nikolaenko,
[ePrint 2020/1244](https://eprint.iacr.org/2020/1244).

**Montgomery's batch inversion** across independent records: n inversions become
1 inversion plus 3(n-1) multiplications. Classic trap: one zero element poisons
the whole batch.

### Tier 3 — assurance rather than speed

**Set `PSTATE.DIT`.** The M4 reports `FEAT_DIT=1`. Without it, "constant time" on
Apple Silicon is an assumption about undocumented microarchitecture; with it, it
is an architectural guarantee. Near-zero cost. **This is the cheapest credibility
improvement available and we do not do it.**

**A three-tier constant-time pipeline**: dudect natively on M4, TIMECOP on an
aarch64 Linux runner, and a fiat-crypto differential test for the field
arithmetic. Roughly a week for all three.

**Dougall Johnson's [Apple instruction tables](https://dougallj.github.io/applecpu/firestorm-simd.html)**
give per-instruction latency and throughput for Apple P-cores, which is what lets
us compute real floors instead of guessing at them.

### Explicitly refuted

- **SME ZA outer product (SMOPA) for Curve25519 or Poly1305 limb arithmetic**:
  5–7x *slower* per field multiply. The raw MAC rate is a trap; the fixed ZA
  drain cost dominates.
- **SVE2/SSVE Poly1305**: the one published data point (Graviton4, VL=128) is
  discouraging. Gate any attempt behind a microbenchmark.

## 3. Where we actually stand

| Primitive | vs. the competitor we benchmark | vs. the published state of the art |
|---|---|---|
| X25519 | 1.19x faster than `x25519-dalek` | **behind** — slower in cycles than s2n-bignum and lib25519 |
| Ed25519 sign | 1.06x faster than `ed25519-dalek` | competitive |
| Ed25519 verify | 0.76x | behind; the techniques to close it are known and listed above |
| AES-256-GCM | 0.94x of ring | behind: 48 PMULL per 128 B against a 26 PMULL target |
| ChaCha20-Poly1305 | 0.72x of ring | behind: we do two passes, the state of the art does one |
| SHA-256 | 0.84x of ring | near the single-stream latency bound; multi-buffer is the only real lever |
| SHA-512 | 0.95x of ring | competitive |
| Argon2id | 0.92x | competitive |
| HPKE | 1.02x | competitive |

Beating `x25519-dalek` is a low bar. The scoreboard that matters is
[lib25519's speed table](https://lib25519.cr.yp.to/speed.html), and against it we
are not close.

## 4. Reading list

1. **Gouvêa & López, "Implementing GCM on ARMv8"**, CT-RSA 2015 — the canonical
   ARMv8 GCM paper; read before touching `aes.rs` again.
2. **Krasnov, `chacha20_poly1305_armv8.pl`** (BoringSSL/ring source) — the fused
   AEAD kernel that is beating us.
3. **Abdulrahman et al., "Fast and Clean"**, TCHES 2024 — SLOTHY; the 1.90x from
   scheduling alone.
4. **Bernstein & Yang, safegcd**, TCHES 2019 — constant-time inversion.
5. **Albertini et al., "How to Abuse and Fix Authenticated Encryption"**,
   USENIX Security 2022 — the key-commitment construction we already use, and the
   correct citation for it.
6. **Li, Krohn, Mazières, Shasha, SUNDR**, OSDI 2004 — fork consistency; what our
   rollback detection should grow into.
7. **Feldman et al., SPORC**, OSDI 2010 — the closest published ancestor of this
   architecture.
8. **Chalkias, Garillot, Nikolaenko, "Taming the many EdDSAs"**, ePrint 2020/1244
   — required before shipping batch verification.
9. **Bernstein et al., Ed25519**, CHES 2011 — §5 is the batch verification
   construction.
10. **Dougall Johnson, Apple CPU instruction tables** — for computing floors.
