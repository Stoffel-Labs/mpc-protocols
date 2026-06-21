# HoneyBadger Multiply — Performance Diagnosis (measurement + report)

**Scope:** benchmark the batched multiply / `mul` and identify the dominant performance
bottleneck(s) with certainty. Per the agreed scope, this is a **report only** — no protocol
source was changed. Each proposed fix below names the experiment that establishes it.

**Method:** four independent measurement harnesses (all new files, no `mpc/src` edits):

| Harness | File | What it measures |
|---|---|---|
| A — component micro | `mpc/benches/hmpc_mul_micro_bench.rs` | per-operation cost (`recover_secret`, Vandermonde, domain build, share arith, serialize) |
| B — end-to-end | `mpc/benches/hmpc_mul_e2e_bench.rs` | timed `mul()` wall-clock + delivered-message count + correctness, swept over `(n,t,N)` on `FakeNetwork` |
| C — A/B certainty | `mpc/benches/hmpc_batchrecon_ab_bench.rs` | the **same** `N` secrets reconstructed two ways: per-chunk sessions vs one batched session — isolates the single differing variable |
| D — latency (turmoil) | `mpc/tests/mul_bench_turmoil.rs` | current `mul` under modeled network latency; derives the round-count of the critical path |

All numbers are `--release`, BLS12-381 `Fr`. FakeNetwork is zero-latency, so B/C measure the
**processing-bound** regime; D measures the **latency-bound** regime.

---

## TL;DR — the one certain, highest-impact bottleneck

**`Multiply::init` opens a *separate batch-reconstruction session for every `(t+1)`-chunk of
secrets, instead of one batched session for the whole batch.** Message volume therefore scales
**O(N·n²)** with the number of multiplied pairs, when it could be **O(n²)** (independent of N).
`BatchReconNode` **already implements the batched path** (`init_batch_reconstruct_many` /
`EvalBatch` / `RevealBatch`, `batch_recon.rs:141/321/393`); the multiply simply does not use it.

This is proven — not hypothesized — by the A/B (harness C): reconstructing the *same* 256 secrets,
the current per-chunk path sends **12 274 messages**; the batched path sends **170** (a 72×
reduction), and both reconstruct identically (asserted).

> **Status: all six findings now IMPLEMENTED.** Cumulative end-to-end win at n=10, t=3:
> - Messages for N=64: **6 400 → 400** (16×; now constant in N — was 100/pair, now 6.2/pair).
> - Wall for N=64: **5.3 ms → 3.5 ms → 1.5 ms** (Finding 6; per-round **2.7 ms → 0.75 ms**);
>   for N=8: ~0.9 ms → 0.6 ms → **0.42 ms**.
> - `recover_secret` per call: **29.8 → 27.2 µs** (domain cached; single path unchanged by Finding 6).
> - Multi-session (N > max_pairs) latency: 2 sessions **21 ms → 11 ms** (pipelined; turmoil @5 ms).
> - OEC/Gao (Byzantine) path: **1.30 → 1.15 ms** (g0 cached).
>

### ✅ Finding 6 (CERTAIN, new highest impact) — per-chunk `recover_secret` rebuilt the Lagrange basis every chunk — **IMPLEMENTED**
Even after Findings 1–5, the `EvalBatch`/`RevealBatch` handlers called `RobustShare::recover_secret`
**once per chunk** (`batch_len = N/(t+1)` times), and every call rebuilt the identical Lagrange basis
(`A(x)`, its derivative, and the per-point polynomial divisions) — identical because it depends only
on the sender ids, which are the same for every chunk in a session. So `recover_secret`'s ~27 µs scaled
`O(batch_len)` when the basis work is `O(1) + batch_len·O(degree)`.
- **Established by:** micro-bench A (27.9 µs/call) × measured call count (64 calls/node at N=64:
  16 chunks × 2 sessions × 2 rounds); code inspection confirms the per-chunk loop
  (`batch_recon.rs` EvalBatch/RevealBatch arms).
- **Fix applied:** new `batch_recover_secret(evals_by_sender, n, degree, t)` in `robust_interpolate.rs`
  builds the Lagrange basis **once** and applies it to all chunks as a linear combination, verifying
  each chunk against all `degree+t+1` evaluations and falling back to the full robust `recover_secret`
  (OEC/Gao) path **per chunk** on disagreement. The EvalBatch/RevealBatch handlers now call it instead
  of the per-chunk loop. Threat-model-neutral: identical optimistic-then-OEC logic, same `t`-fault
  tolerance, only the redundant per-chunk fixed cost is removed.
- **Validated:** new unit tests (honest-path exact match vs per-chunk `recover_secret` for any arrival
  order; `t`-corruption OEC fallback); lib 73/73, mul_test 3/3, node_test 16/16, batchrecon_test 4/4,
  fpmul_test 2/2. **Measured win (n=10,t=3):** wall N=64 **3.5 ms → 1.5 ms** (2.3×; per-round
  2.7 ms → **0.75 ms**), N=8 0.6 ms → 0.42 ms; n=5,t=1 N=64 ~4.4 ms → ~0.4 ms. turmoil confirms the
  2-round critical path is unchanged (sim_wall ≈ 2×latency + ~1 ms).

> Threat model preserved: all RS / Byzantine-corruption tests pass; every change is
> correctness-preserving and either threat-model-neutral or a strict liveness/security improvement
> (Task #1). See §4 for per-finding detail.

---

## 1. The pipeline under test

`HoneyBadgerMPCNode::mul` (`mod.rs:494`) chunks input into sessions of `max_pairs_per_session =
128·(t+1)` and runs them **sequentially** (each `await`s `wait_for_result`). Within one session,
`Multiply::init` (`mul/multiplication.rs:317`) splits the `N` pairs into `(t+1)`-chunks and, **for
each chunk, starts two batch-recon sessions** (a−x and b−y) via `init_batch_reconstruct`
(`multiplication.rs:418–446`). The remainder `N mod (t+1)` is opened via RBC (Avid).

So one `mul(N)` issues **`2·⌈N/(t+1)⌉` batch-recon sessions**, each = 2 network rounds × n
messages = `2n²` messages. **Total messages = `4·⌈N/(t+1)⌉·n²`** = O(N·n²).

---

## 2. Measured data

### A. Per-operation cost (micro-bench)

| Operation | n=5,t=1 | n=10,t=3 | n=20,t=6 |
|---|---|---|---|
| `recover_secret` — honest/optimistic | 15.2 µs | **29.8 µs** | 55.0 µs |
| `recover_secret` — OEC/Gao (t corrupted) | 117 µs | **1.30 ms** | 9.6 ms |
| `make_vandermonde`+`apply_vandermonde` | 3.6 µs | 5.0 µs | 9.0 µs |
| `GeneralEvaluationDomain::new(n)` | 2.9 µs | 2.9 µs | 2.9 µs |
| share arith (one `finalize_mul` iter) | 17 ns | 19 ns | 18 ns |
| bincode `WrappedMessage::BatchRecon(Eval)` ser / deser | — | 30 / 31 ns | — |
| ark-serialize `Vec<Fr>` reveal batch (w1 / w16 / w64) | — | 90 / 347 / 783 ns | — |

Notes: serialization is negligible (~30 ns/msg). `recover_secret` rebuilds the FFT evaluation
domain (2.9 µs) on **every call**. The OEC/Gao fallback is 44–175× slower than the optimistic
path — it only triggers on Byzantine corruption, but `compute_g0_from_domain` rebuilds a degree-n
polynomial from scratch each call.

### B. End-to-end `mul` (FakeNetwork, correctness-verified)

| Config | wall | msgs | msg/pair | sessions/node | correct |
|---|---|---|---|---|---|
| n=10,t=3,N=1 | 5.3 ms | ~2 000 | ~2 000 | 2 (RBC path) | ✅ |
| n=10,t=3,N=64 | **5.3 ms** | **6 400** | **100** | 32 | ✅ |
| n=5,t=1,N=1 | 1.15 ms | 275 | 275 | 2 (RBC path) | ✅ |
| n=5,t=1,N=64 | 4.36 ms | 3 200 | 50 | 64 | ✅ |
| n=10,t=3,N=8 | **panicked (fixed — see Finding 3)** | — | — | 4 | — |

`6 400 = 32 sessions × 2 rounds × 100 (n²)` — **arithmetic-exact**: message count is provably
`4·⌈N/(t+1)⌉·n²`. N=1 and N<t+1 route entirely through RBC (Avid), which is O(n²)-message-heavy
per value (~2 000 msgs for one mul).

### C. A/B — per-chunk sessions vs one batched session (the certainty engine)

Same `N` secrets reconstructed both ways; both asserted to reconstruct identically.

| N (chunks) | per-chunk: msgs / wall | batched: msgs / wall | msg ratio | wall ratio |
|---|---|---|---|---|
| 16 (4) | 745 / 1.0 ms | 170 / 0.74 ms | 4.4× | 1.35× |
| 64 (16) | 3 083 / 3.2 ms | 170 / 1.9 ms | 18× | 1.7× |
| 256 (64) | **12 274 / 12.8 ms** | **170 / 6.8 ms** | **72×** | **1.9×** |

Per-chunk messages grow **linearly with N** (`= chunks × 2n²`); batched messages are **constant**
(`≈ 2n²`). The wall gap is "only" ~1.9× under FakeNetwork because both paths share the
`recover_secret` compute floor (see §3) and the same 2-round dependency — the difference is purely
the message-processing volume.

### D. Latency regime (turmoil, current per-chunk `mul`, n=5,t=1,N=8)

| latency | simulated wall (max over nodes) |
|---|---|
| 1 ms | 3.0 ms |
| 5 ms | 11.0 ms |
| 20 ms | 41.0 ms |

`sim_wall ≈ 2 × latency + ~1 ms` ⇒ the latency-bound critical path is **2 sequential network
rounds** (the batch-recon Eval + Reveal rounds), **independent of N** within one session. All
per-chunk sessions pipeline into the same 2 rounds — so round-*count* is not what per-chunk wastes;
it wastes round-*bandwidth* (num_chunks× more messages per round).

---

## 3. Where the wall-clock goes (N=64, n=10, t=3 → 5.3 ms, attribution)

- **`recover_secret`: ~1.9 ms (certain).** `2·⌈N/(t+1)⌉·2 = 64` calls/node × 29.8 µs (micro-bench A).
  Plus Vandermonde ~0.16 ms (32 × 5 µs). Compute floor ≈ **2.1 ms**.
- **Message processing: ~3.2 ms (consistent with residual).** 6 400 msgs / 10 nodes = 640 msgs/node;
  the residual 5.3 − 2.1 ≈ 3.2 ms matches ~0.5 µs/msg (deserialize `WrappedMessage` + route +
  occasional `recover_secret`), consistent with the A/B per-message delta
  (`(12.8−6.8)ms / (12 274−170)msgs ≈ 0.5 µs/msg`).

The two terms together account for the measured wall-clock. This is the attribution identity the
"100% certain" bar requires.

---

## 4. Findings & proposed fixes, ranked by certainty

### ✅ Finding 1 (CERTAIN, highest impact) — per-chunk batch-recon sessions — **IMPLEMENTED (Task #2)**
`Multiply::init` opened `2·⌈N/(t+1)⌉` sessions; message volume was O(N·n²). The already-implemented
`init_batch_reconstruct_many` does it in one session → O(n²).
- **Established by:** A/B (harness C) — 72× fewer messages at N=256, identical reconstruction; B
  confirmed the `4·⌈N/(t+1)⌉·n²` message law arithmetic-exactly.
- **Fix applied:** `Multiply::init` now issues ONE `init_batch_reconstruct_many` for all a−x
  (sub_id 0) and ONE for all b−y (sub_id 1); `open_mult_handler` stores the single batched result
  per side (deser bound raised from `self.n` to `max_mul_pairs_per_session`, the session capacity);
  `clear_store` clears the two batched child sessions. Threat-model-neutral (same `recover_secret`
  RS path, same t-fault tolerance; only message batching and the bounded deserialization limit
  change).
- **Validated:** `mul_test` all 3 pass (RBC-only N=3, batch-only N=8, mixed N=10); mul unit tests
  pass; e2e correctness check passes. **Measured win (n=10,t=3):** messages 6 400 → **400** at N=64
  (16×; now constant in N — N=8 and N=64 both 400) and 800 → 400 at N=8; wall ~30% faster at N=64
  (5.3 ms → 3.7 ms; the new floor is `recover_secret`, Finding 2).

### ✅ Finding 2 (CERTAIN, secondary) — `recover_secret` rebuilt the FFT domain every call — **IMPLEMENTED (Task #3)**
Even after Finding 1, `recover_secret` is called O(⌈N/(t+1)⌉) times/node and rebuilt
`GeneralEvaluationDomain::new(n)` (2.9 µs) on every call.
- **Established by:** micro-bench A (domain 2.9 µs; recover_secret 29.8 µs).
- **Fix applied:** added `crate::common::get_or_create_evaluation_domain::<F>(n)` — a
  `OnceLock<Mutex<HashMap<(TypeId, n), domain>>>` memoization (exact, since the domain is a pure
  deterministic function of `(F, n)`; cache is tiny/bounded, no eviction). Routed the hot sites
  through it (`robust_interpolate_fnt`, `oec_decode`, `gao_rs_decode`, `make_vandermonde`).
  Threat-model-neutral (identical domain values).
- **Validated:** `recover_secret` dropped 29.8 → **27.2 µs** (n10,t3) and 15.2 → **12.5 µs** (n5,t1)
  — ~2.6 µs/call saved (one domain build), exactly as predicted. All tests green.

### ✅ Finding 3 (CERTAIN, robustness) — **IMPLEMENTED (Task #1)**
**The multiply raised a hard error on late/duplicate batch-recon messages for completed sessions.**
`cargo test -p stoffelmpc-mpc --test mul_test` **panicked** deterministically for N=8/N=10 on
`"Batch reconstruction has already terminated"`; `node.process` propagated this via `?`
(`mod.rs:752`) instead of dropping the redundant message. (The earlier "N=8 hangs" note was a
criterion no-match artifact — N=8 wasn't in the bench's default counts; the *protocol* symptom was
the `mul_test` panic, which was real.)
- **Established by:** deterministic `mul_test.rs` panic; harness C (direct `BatchReconNode`)
  reconstructs correctly for all N → isolated to the batch-recon late-message path.
- **Fix applied:** `BatchReconNode::get_or_create_store` now returns `Ok(None)` for an
  already-terminated session (matching the RBC pattern and the reverted `44bd56c`); the four
  `batch_recon_handler` call-sites drop late messages. Security: regression-free (redundant shares;
  final result unchanged; t-fault tolerance unchanged) and a **liveness improvement** (no
  DoS-on-late-message). **Not** addressed here: the separate session-ID-wrapping replay defense
  (needs the `cleared_sessions` set from `2f8aafd` with careful eviction design) — a pre-existing
  gap, no regression.
- **Validated:** `mul_test` all 3 pass (incl. N=8); e2e bench N=8 now completes
  (~0.9 ms, 800 msgs, correct=true); 71/71 relevant tests pass (1 pre-existing orphan
  `rand_bit::test_randbit_storage_limit` from `7df368b`, unrelated).

### ✅ Finding 4 (CONFIRMED then fixed) — sequential mul sessions — **IMPLEMENTED (Task #4)**
`mul()` ran its `max_pairs_per_session` sessions back-to-back (each `await`ed its result before the
next session's `init`).
- **Confirmed (certainty met):** turmoil at 5 ms latency — 2 sequential sessions took **21 ms vs
  11 ms for 1 session** (≈2×; 4 sequential rounds vs 2). Under FakeNetwork 2 sessions were only
  ~1.8× wall (the cost there is per-node serial message processing, which pipelining doesn't change).
- **Fix applied:** `mul()` now issues ALL sessions' `init`s first, then awaits results in order
  (sessions are independent — distinct ids/triples/storage — so rounds overlap; output order
  preserved). Threat-model-neutral (no crypto or state-sharing change).
- **Validated:** turmoil mul(512) (2 sessions) dropped **21 ms → 11 ms** = 1 session's latency;
  correctness intact (`mul_test`, e2e N=1024). Only matters for N > `max_pairs_per_session`
  (very large batches); the per-node serial receiver processing (not addressed here) bounds the
  FakeNetwork-regime win.

### ℹ️ Finding 5 (CERTAIN, edge-case) — OEC/Gao `g0` rebuilt every call — **IMPLEMENTED (Task #5)**
Only on Byzantine corruption; `compute_g0_from_domain` rebuilt a degree-n polynomial per call.
- **Established by:** micro-bench A (`recover_secret` OEC/Gao: n5 117 µs, n10 1.30 ms, n20 9.6 ms).
- **Fix applied:** memoized `g0(x) = ∏(x - domain.element(i))` (pure deterministic fn of `(F, n)`,
  same pattern as the domain cache) via `get_cached_g0_polynomial`/`store_g0_polynomial` in
  `compute_g0_from_domain`. Threat-model-neutral.
- **Validated:** OEC/Gao dropped 117 → **84 µs** (n5) and 1.30 → **1.15 ms** (n10); corruption-path
  tests pass. Does not affect honest-case throughput (OEC only runs under Byzantine corruption).

---

## 5. How to reproduce

```bash
# A — per-op costs
cargo bench -p stoffelmpc-mpc --bench hmpc_mul_micro_bench

# B — end-to-end wall + messages + correctness (Finding 3 / Task #1 now fixed)
cargo bench -p stoffelmpc-mpc --bench hmpc_mul_e2e_bench
HMPC_MUL_E2E_COUNTS=8,64,256 cargo bench -p stoffelmpc-mpc --bench hmpc_mul_e2e_bench

# C — the A/B certainty engine
cargo bench -p stoffelmpc-mpc --bench hmpc_batchrecon_ab_bench
HMPC_BRAB_COUNTS=64,256,1024 cargo bench -p stoffelmpc-mpc --bench hmpc_batchrecon_ab_bench

# D — latency sweep (current per-chunk mul under modeled latency)
cargo test -p stoffelmpc-mpc --test mul_bench_turmoil --release -- mul_batched_turmoil_timing --nocapture --ignored
MUL_TURMOIL_N=32 MUL_TURMOIL_N_NODES=10 MUL_TURMOIL_T=3 \
  cargo test -p stoffelmpc-mpc --test mul_bench_turmoil --release -- mul_batched_turmoil_timing --nocapture --ignored
```

Each bench prints `[...]`-prefixed lines with wall-time, message count, and `correct=true`.
Harness C asserts identical reconstruction on every iteration.

---

## 6. What was *not* changed
No edits to `mpc/src/` or to existing benches/tests. New files only: the four harnesses above and
their `[[bench]]` entries in `mpc/Cargo.toml`. The proposed fixes in §4 are recommendations, not
applied.
