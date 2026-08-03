# Apple Silicon acceleration research

Raw material behind the "Which Apple hardware actually helps" section of the
top-level README. Everything here was **measured on the project's Apple M4**
(4 P + 6 E cores, macOS, rustc 1.96.1), not extrapolated from papers, and most
claims were then adversarially re-measured by an independent skeptic pass
(`skeptic*.swift`, `refute*.c` in `lab/`).

## Files

- `apple-acceleration-findings.json` — the complete structured findings from
  the research sweep: 29 result blocks across four dimensions (CPU ISA,
  GPU/Metal, NPU/matrix units, parallelism/batching), each acceleration path
  with its hardware, measured gain, evidence, feasibility and security cost,
  plus the adversarial verification verdicts.
- `lab/` — the actual measurement harnesses (C, Rust, Swift/Metal). These are
  research scratch code, not part of the build; kept so every number in the
  findings can be reproduced or challenged. Highlights:
  - `rsme_src_main.rs`, `sme*.c`, `sveprobe.c` — SME streaming-mode probes:
    prove SVL=512 bits, XAR/EOR3 availability in streaming mode, the
    smstart/smstop v8–v15 zeroing hazard, and the ~4x ChaCha round-function
    speedup over NEON.
  - `svl_xar_probe.rs` — minimal stable-Rust proof that `xar #(32-n)` is
    exactly a 32-bit lane `rotl(n)` after XOR, and that SVL is 16 u32 lanes.
  - `lab_src_sha512hw.rs` — the FEAT_SHA512 compression schedule later
    integrated into `blindplane-crypto/src/sha2.rs`, validated against NIST
    vectors and RustCrypto before integration.
  - `metal_*.swift`, `gpubench.swift`, `skeptic_gpu*.swift`,
    `clmulprobe.metal` — the GPU story: constant-time ChaCha20-Poly1305 at
    ~39.8 GB/s at 4 MiB, bitsliced AES losing to CPU hardware AES, GHASH on
    GPU losing catastrophically, and the ~150 µs kernel-launch floor that
    disqualifies per-record offload.
  - `ane_open*.c`, `fp16.c` — the Neural Engine dead end: no exact integer
    XOR, nothing to run.
  - `ladder_cpu.c` / `ladder_gpu.swift`, `fe_cpu.c` / `fe_gpu.swift` — field
    arithmetic and X25519 ladder comparisons.
  - `qos*.c`, `split_bench.rs`, `sweep.c` — P/E-core scheduling: the 4.25x
    scaling decomposition (7.02x heterogeneity ceiling × static-chunking loss
    × all-core clock droop) and the +17.6% dynamic work queue result.

## Verdict summary (details in the JSON)

| Unit | Verdict |
|---|---|
| CPU crypto extensions (AES/PMULL/SHA2/SHA512) | in use — the primary win |
| SME streaming vector unit (512-bit, XAR) | **real, unused: ~4x NEON on ChaCha; +57% running SME+NEON together** — top roadmap item |
| GPU (Metal) | bulk-only: fast above ~4 MiB, disqualified for records by launch latency; AES on GPU rejected (slower or timing-unsafe) |
| Neural Engine | closed — no integer XOR primitive |
| SME ZA / AMX matrix tiles | net loss for curve/Poly1305 limb math; relevant only for future lattice PQC |

A correctness postscript: the same research pass found a real bug in the then
in-flight NEON ChaCha20 (flat counter advance in the partial-tail path,
corrupting multi-call streams) that the existing test suite could not see. The
fix and the differential tests that now guard it are in
`blindplane-crypto/src/chacha.rs`.
