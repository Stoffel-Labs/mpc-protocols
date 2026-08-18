---
name: sub-protocol-review
description: Review a new or modified MPC sub-protocol in this repo (mpc/src/honeybadger/*, mpc/src/avss_mpc/*, mpc/src/common/*) for the BFT-correctness and DoS-resilience issues that recur across this codebase - async message ordering, sender authentication, session admission caps, store cleanup, resource limits, RBC/batch-recon drain wiring, share-index consistency, channel backpressure, panic safety, statistical mask width, adversarial test coverage. Use when the user asks to review, audit, or check a new sub-protocol / protocol addition / preprocessing primitive for correctness or security issues.
---

# Sub-protocol review

Checklist for reviewing a new or modified MPC sub-protocol against failure modes that
have recurred repeatedly across this codebase (see AVID equivocation, AVID commit-quorum,
unsolicited-RBC-session-DoS, and state-corruption/DoS findings in project history — this
list exists because these bug classes keep coming back in new protocol code, not because
they're hypothetical).

## Scope

Applies to any new/changed module under `mpc/src/honeybadger/*`, `mpc/src/avss_mpc/*`,
or `mpc/src/common/*` that:
- defines its own session store and a `process`/`init`/handler entrypoint reachable from
  the network, and/or
- consumes `RBC` or `batch_recon` internally.

Identify the module(s) in scope first (new files/functions in the diff, or the directory
the user names), then walk every item below against them. Don't review unrelated
pre-existing code unless it's directly touched.

## Checklist

### 1. Async message ordering in handlers

Messages can arrive interleaved, delayed, duplicated, or before a session locally exists,
because the network is async BFT. A handler must not assume "round N before round N+1" or
"INIT before ECHO."

- State transitions should branch on explicit `ProtocolState` (e.g. `Initialized`/`Finished`
  in [triple_generation.rs](mpc/src/honeybadger/triple_gen/triple_generation.rs)), not on an
  implicit arrival order.
- Reprocessing the same message, or a message for an already-finished session, must be a
  silent no-op drop, not a wrong result or an error.
- A message for a session that doesn't exist yet locally must be handled by admission
  (item 3), not by panicking/unwrapping on a missing store entry.

### 2. Sender-ID re-authentication inside drain functions

RBC/batch-recon guarantee the delivered *bytes* were agreed by quorum — they do **not**
guarantee an identity field *embedded inside* those bytes is honest. Every
`drain_rbc_output` / `drain_batch_recon_output` must re-check
`msg.sender_id == id.sub_id()` before trusting that field downstream. Reference:
[input.rs:155-160](mpc/src/honeybadger/input/input.rs#L155-L160) (also `ran_dou_sha`,
`zero_share`, `share_gen`).

Red flag: a new `drain_*` that forwards an embedded sender/identity field straight into
handler logic with no `if msg.sender_id != authenticated_sender { drop }` guard.

### 3. Session admission via `get_or_admit`

Any `get_or_create_store`-style function must route through
`SessionStore::get_or_admit` ([session_store.rs:219](mpc/src/common/session_store.rs#L219)),
never a hand-rolled `if store.len() >= MAX { reject }`. A bare cap with no TTL-reclaim
silently becomes a permanent DoS once a peer fills it with abandoned sessions.

- Match the existing call shape:
  `store.get_or_admit(id, initiator_id, GLOBAL_CAP, GLOBAL_CAP / self.n, || ...)`.
- All three `Admission` variants must be handled distinctly: `Retired` → drop silently
  (harmless late straggler), `Rejected` → drop + `warn!` (capacity/DoS-relevant).
  Collapsing them loses the distinction the type was built for.
- `initiator_id` passed in must itself already be authenticated (item 2) — an
  unauthenticated initiator lets one party burn another party's per-peer quota by lying
  about who opened the session.

### 4. Store cleanup on every exit path, including errors

`clear_store`/`clear_session` must run on every session-ending path, not just the happy
one. An early `return Err(...)` after a session entered the store, with no cleanup, leaks
a slot that (combined with item 3's caps) is a slow-drip DoS until TTL eviction catches it.

- Check every `Err` return in `process`/`init`/`drain_*` after store admission.
- Multi-sub-session protocols must clear *all* sub-session IDs, not just the primary one
  (see the batched a·x/b·y cleanup in
  [multiplication.rs:200](mpc/src/honeybadger/mul/multiplication.rs#L200)).

### 5. Capacity limits at every boundary

Beyond session-count caps (item 3), check for the other limit types this codebase relies
on:
- A per-protocol `MAX_*_SESSIONS` constant passed as `global_cap` — every existing
  protocol has one (`MAX_MUL_SESSIONS`, `MAX_TRIPLE_GEN_SESSIONS`,
  `MAX_BATCH_RECON_SESSIONS`, ...). No such constant on a new protocol is a red flag.
- A per-peer cap (`global_cap / self.n`) — without it, one Byzantine party can exhaust the
  global cap alone.
- Deserialization of network-supplied bytes goes through `deser_bounded_vec` or a
  `.with_limit(MAX_MESSAGE_SIZE)` bincode config — never an unbounded
  length-prefixed `Vec`/allocation straight from attacker bytes.
- Limits are enforced *before* the expensive work (allocation, crypto verification), not
  after.

### 6. RBC/batch-recon drain wired into the process loop

RBC and batch-recon signal completion by pushing a `session_id` onto an internal
`output_sender` channel — nothing happens with it unless someone drains it. The consuming
protocol must (a) expose its own `drain_rbc_output`/`drain_batch_recon_output` pulling via
`try_recv()` (break on `Empty`, hard-error on `Disconnected` — see
[multiplication.rs:169](mpc/src/honeybadger/mul/multiplication.rs#L169)), and (b) that
drain must actually be called from the node's top-level dispatch loop
([mod.rs:843-951](mpc/src/honeybadger/mod.rs#L843-L951)), not merely defined.

Red flag: a new struct with a `batch_recon`/`rbc` field and no corresponding call site in
`mod.rs`'s message loop. Silent liveness bug — no crash, output just never arrives.

### 7. Share index consistency before interpolation

Distinct from item 2. Before feeding a received share into Lagrange
interpolation/reconstruction, check the share's own embedded index matches the
authenticated sender: `if share.id != sender_id { drop }` — see
[multiplication.rs:506](mpc/src/honeybadger/mul/multiplication.rs#L506),
[share_gen.rs:603](mpc/src/honeybadger/share_gen/share_gen.rs#L603),
[ran_dou_sha/mod.rs:573](mpc/src/honeybadger/ran_dou_sha/mod.rs#L573). Without this, a
party can send a share honestly attributed in the envelope but carrying a mismatched
internal index, corrupting interpolation for everyone.

### 8. Drain starvation → blocking send → node-wide stall

Output channels are bounded (`mpsc::channel(200)` / `(300)`, e.g.
[multiplication.rs:157](mpc/src/honeybadger/mul/multiplication.rs#L157)). If a drain
(item 6) is missing or not pumped often enough, the channel fills, and the next internal
`.send().await` from inside RBC/batch-recon's own processing blocks. Since that runs
inline on the node's single message-handling path, this stalls the *entire* node, not
just the one protocol. Check the drain is reachable often enough relative to expected
batch sizes for the channel capacity chosen.

### 9. No panics on network-attacker-controlled data

`.unwrap()` / `.expect()` / direct indexing on anything derived from a deserialized
message (share indices, vector lengths, enum variants) should propagate a typed error
(`MulError`, `TripleGenError`, ...) instead. A malformed message from one Byzantine party
must not panic the node's message loop. Not every `.unwrap()` is wrong — locking a mutex
or indexing internally-owned/bounded state is fine — flag only unwraps reachable from
message payloads.

### 10. Adversarial test coverage, not just happy-path

`BadFakeNetwork`/turmoil-style tests (currently only exercised in
[turmoil_test.rs](mpc/tests/turmoil_test.rs)) are what actually catch items 1, 2, 3, and 7
— most protocol tests use plain `FakeNetwork` happy-path runs only. A new sub-protocol
should have at least one test that drops/reorders/duplicates messages or injects a lying
dealer, not only a clean n-honest-parties run.

### 11. Mask width derived from the value, not configured beside it

Any protocol that hides a secret by opening `value + mask` (TruncPr, and everything built on
it — `mul_fixed`, `div_with_const_fixed`) is sound only while
`mask_bits >= value_bits + statistical_security`. Two rules:

- **Derive, don't configure.** The masked width must come from the value's own width. While `l`
  (value width) and `k` (security parameter) were separate config knobs, only their *sum* mattered,
  so passing a precision into the security slot read perfectly plausibly and silently delivered
  whatever margin happened to be left over — three shipped tests ran at 0, 4 and 16 bits of
  delivered security while declaring more. `HoneyBadgerMPCNodeOpts` now takes `precision` +
  `statistical_security` and derives `mask_bits()`. A new masking operation extends
  `max_masked_width`; it does not add a knob.
- **Check at point of use, against the value's own width.** `check_mask_security(value_bits)` runs
  before both current draws. It must read the *value's* precision, not `params` — a value can carry
  a different precision than the node was sized for, and that mismatch is the failure this catches.

Red flag: a new `take_prandint_shares` (or equivalent pool draw) with no preceding width check. The
draw API does not force one — nothing errors, the mask is just short, and the arithmetic stays
correct either way, which is why this class of bug survives testing. Also flag a new masking
consumer whose width isn't reflected in the pool-sizing function: the check then rejects it at first
use (correct) but the operation cannot be configured at all until sizing is updated.

## How to run the review

1. Identify the module(s) in scope (new/changed files, or what the user points at).
2. Read the module's `process`/`init`/`drain_*`/`get_or_create_store`/`clear_store`
   functions in full.
3. Walk items 1-11 against that code. For each, either confirm the pattern matches the
   referenced known-good example or record a finding.
4. Use grep to sanity-check adjacent evidence, e.g.:
   - `grep -n "get_or_admit\|get_or_create_store" <file>`
   - `grep -n "fn drain\|output_sender\|try_recv" <file>`
   - `grep -n "authenticated_sender\|sender_id !=" <file>`
   - `grep -n "clear_store\|clear_session" <file>`
   - `grep -n "MAX_.*SESSIONS\|deser_bounded_vec" <file>`
   - `grep -n "\.unwrap()\|\.expect(" <file>`
   - `grep -n "take_prandint_shares\|check_mask_security\|max_masked_width" <file>`
5. Report findings with the `ReportFindings` tool, most severe first (liveness/DoS/
   soundness breaks before style issues). Use the checklist item's topic as `category`
   (e.g. `session-admission`, `drain-wiring`, `sender-auth`, `panic-safety`,
   `test-coverage`, `mask-width`). Each finding needs a concrete `failure_scenario`: what a Byzantine
   party or adversarial network schedule does, and what breaks as a result — not just
   "this doesn't match the pattern."
6. If a checklist item doesn't apply to this module (e.g. it uses neither RBC nor
   batch-recon, so items 6/8 are moot), skip it silently rather than forcing a finding.
