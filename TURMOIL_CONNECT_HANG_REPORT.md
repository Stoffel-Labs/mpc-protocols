# TurmoilNetwork connect hang — investigation report

## Status

**Resolved** by a startup barrier inside `TurmoilNetwork::new`. The previously
flaky test `batch_reconstruction_with_partition_n_7_t_2_one_hold` now passes
30/30 runs. Existing freeze-start, delay, and hold tests across ransha,
preprocessing, and fpmul continue to pass.

The underlying Turmoil-layer bug (connect future never resolving when it
arrives after the peer's main task has moved past `TurmoilNetwork::new`)
is **not** fixed; the barrier sidesteps it by guaranteeing the temporal
pattern that triggers the bug never occurs.

## Symptom

A subset of Turmoil-based MPC tests intermittently hang. The Turmoil simulator
runs for its full configured `simulation_duration` (20 minutes simulated) and
exits with:

```
called `Result::unwrap()` on an `Err` value: "Ran for duration: 1200s steps: 1200002 without completing"
```

When this happens, exactly one node (which one varies across runs) never
participates in the protocol. The test driver waits for `n_parties` signals on
`tx_partition` and only ever receives `n_parties − 1`, blocking forever.

## Where the hang lives

The missing node enters `TurmoilNetwork::new` but never exits. Concretely, its
sequential dial loop (`network/src/turmoil_network.rs` ~line 118) reaches one
specific peer and gets stuck inside `TcpStream::connect(addr).await`. The
future never resolves — it neither succeeds nor fails — for the entire
remaining simulated runtime.

## Diagnostic evidence (run captured 2026-05-27)

Test: `batch_reconstruction_with_partition_n_7_t_2_one_hold`
Topology: 7 hosts, fully meshed, each host dials peers in id order
(skipping self).

| Node | Entered `TurmoilNetwork::new` | Exited `TurmoilNetwork::new` |
|------|-------------------------------|------------------------------|
| 0    | ✅                            | ✅                           |
| 1    | ✅                            | ✅                           |
| 2    | ✅                            | ✅                           |
| 3    | ✅                            | ✅                           |
| 4    | ✅                            | ❌ stuck dialing node 3      |
| 5    | ✅                            | ✅                           |
| 6    | ✅                            | ✅                           |

Timeline around the hang point:

```
t=26.667 — node 3: ENTER TurmoilNetwork::new
t=26.667 — node 3: spawn listener on 0.0.0.0:7003
t=26.668 — node 3: sleep 1ms done, start dial loop
t=26.667 — node 4: ENTER TurmoilNetwork::new
t=26.668 — node 4: sleep 1ms done, start dial loop
t=26.668 — node 4: dialing peer_id=0 (node0:7000)
…
t=26.760 — node 3's listener accepted connection (from node 0)
t=26.776 — node 3's listener accepted connection (from node 1)
t=26.781 — node 3's listener accepted connection (from node 6)
t=26.820 — node 3's listener accepted connection (from node 2)
t=26.909 — node 3's listener accepted connection (from node 5)
t=26.911 — node 3: EXIT TurmoilNetwork::new
t=26.977 — node 4: dial succeeded for peer_id=2
t=26.977 — node 4: dialing peer_id=3 (node3:7003)
                  *** TcpStream::connect future never resolves ***
                  *** node 3's listener never accepts a 6th connection ***
… simulation continues to t=1226.911 (1200 simulated seconds later) …
ERROR: Ran for duration: 1200s steps: 1200002 without completing
```

Five of the six expected inbound connections to node 3 arrived **before**
node 3 itself exited `TurmoilNetwork::new`. The sixth — from node 4 — arrived
**66 ms after** node 3's parent task had moved past `TurmoilNetwork::new`.
That sixth connection is the one that hangs.

The listener task on node 3 is a `tokio::spawn`'d task. It is logically still
alive — `accept().await` is reachable independently of whether the host's
main async block is still inside `TurmoilNetwork::new`. But the connect future
on the dialer side never resolves, so the listener never sees the connection
attempt.

## Likely root cause (hypothesis)

This appears to be a Turmoil-layer bug in how `TcpStream::connect` interacts
with the spawned-listener pattern. The pathology trigger seems to be:

- Host A spawns its listener task.
- Host A finishes its own `TurmoilNetwork::new` and the main task advances
  past the function (in our case, into a `sleep(50ms)` then
  `init_batch_reconstruct`).
- A peer host B attempts `TcpStream::connect(host_A_addr)` **after** that
  point.

When this temporal pattern occurs, the connect future on B never resolves.
Connect attempts from B that happen **before** A's main task leaves
`TurmoilNetwork::new` succeed normally — those are the 5 successful
connections in the table above.

We do not currently have a minimal Turmoil-only reproducer (no MPC code), but
the captured log strongly localises the problem to Turmoil's TCP simulation,
not to anything in the MPC layer.

## Fixes attempted

### 1. `yield_now()` → `sleep(Duration::from_millis(10))` in `connect_with_handshake` retry

Original code used `tokio::task::yield_now()` to back off after a failed
connect. In Turmoil, `yield_now` does not advance simulated time, so a node
losing the listener-ready race would livelock — the busy retry kept the ready
queue non-empty, preventing time advancement, and the world never changed so
retries kept failing identically.

Replacing with `tokio::time::sleep(Duration::from_millis(10))` fixed the
livelock cleanly. Pass rate went from ~0% to ~90%.

This change is **kept**.

### 2. `yield_now()` → `sleep(Duration::from_millis(1))` after spawning the listener (line 112)

A second `yield_now` existed right after `tokio::spawn(start_listener(...))`,
intended to give the spawned listener a chance to reach `accept()` before the
dialer loop started. Same yield_now issue: it does not advance simulated time,
so the listener may not actually progress through `bind` before the host
proceeds.

Replacing with `sleep(Duration::from_millis(1))` was kept. Effect on pass rate
was modest; the core hang described above persists.

This change is **kept**.

### 3. Timeout-wrapped `TcpStream::connect` + retry

Hypothesis: wrap `TcpStream::connect` in
`tokio::time::timeout(Duration::from_millis(100), ...)` so a hung connect
becomes a retryable failure, then sleep+retry.

Result: **made the flake rate worse, not better.** Pass rate dropped from
~90% to 60% (18/30). The diagnostic log on a failure showed node 4 made
**10,915 connect attempts** to node 3 (vs ~30 from any healthy node) — every
single retry timed out identically. This confirms that the pathology is
**persistent** for the affected (sender, address) pair, not transient. Once
Turmoil drops a connect on a given pair after the listener-parent moves on,
all subsequent connects on that pair from that sender also hang.

This change was **reverted**.

### 4. Startup barrier inside `TurmoilNetwork::new` ✅ **WORKING FIX**

The bug requires a specific temporal pattern: a `TcpStream::connect` future
needs to arrive at the peer's listener *after* the peer's main task has
already moved past `TurmoilNetwork::new`. If we can guarantee that no host
ever exits `TurmoilNetwork::new` while other hosts still have outstanding
dials to it, the pathology cannot trigger.

A `tokio::sync::Barrier` placed at the end of `TurmoilNetwork::new`,
synchronised across every participant (`n_nodes + n_clients`), achieves
exactly that. Every host:

1. Spawns its listener.
2. Sleeps briefly so its own `bind` completes.
3. Runs its dial loop, retrying on transient connect errors.
4. **Waits at the barrier.** Only when every host has finished step 3 does
   anyone proceed.

Because every peer is still inside `TurmoilNetwork::new` when our dials
fire, no dial can ever arrive "late." All connects happen during the window
where every listener-parent is still in scope. The pathology never triggers.

#### Implementation

Adds a single field to `TurmoilInnerNetwork`:

```rust
pub setup_barrier: Arc<Barrier>,
```

Initialised in `TurmoilInnerNetwork::new` with size `n_nodes + client_ids.len()`.
At the end of `TurmoilNetwork::new`:

```rust
inner.setup_barrier.wait().await;
```

That's the entire fix in `network/src/turmoil_network.rs`. No changes
required in any test file — `TurmoilInnerNetwork::new`'s public signature is
unchanged.

#### Validation

| Suite | Result |
|---|---|
| `batch_reconstruction_with_partition_n_7_t_2_one_hold` | 30/30 pass (was ~90%) |
| `ransha_e2e_turmoil_with_hold_minority_partition` (3 variants) | 3/3 pass |
| `preprocessing_e2e_with_delay` | pass |
| `preprocessing_e2e_with_freeze_start` | pass |
| `fpmul_e2e_with_preprocessing_freezing_start` | pass |
| `cargo test -p stoffelmpc-network` (unit tests) | 12/12 pass |

#### Compatibility with freeze-start tests

Tests that use `sim.hold` to freeze a node at startup (e.g.
`preprocessing_e2e_with_freeze_start`) continue to work. The held node's
dials block on the simulated network until released, which means the held
node sits in its dial loop until the driver issues `turmoil::release`. Only
then does it reach the barrier. Other hosts wait at the barrier in the
meantime. The semantics are identical to the user-level barriers those tests
already use after `TurmoilNetwork::new` — the new barrier just moves the
synchronisation point one step earlier and makes it automatic.

#### Why this is a workaround, not a fix

The underlying Turmoil bug remains. If any future test triggers the same
temporal pattern outside of the network-setup window (for example, if a
test were to lazily open additional `TcpStream` connections mid-protocol),
the barrier would not protect against it. A proper upstream fix would still
be worth pursuing — see "Long-term" recommendation below.

This change is **kept**.

## Current state of `network/src/turmoil_network.rs`

- Both `yield_now()` calls replaced with `tokio::time::sleep` (fixes #1, #2).
- **Startup barrier added** at the end of `TurmoilNetwork::new` (fix #4) —
  this is the actual fix that eliminates the hang.
- Diagnostic `info!` logs added throughout
  `TurmoilNetwork::new`, `start_listener`, and `connect_with_handshake`.
  These were useful for the investigation but **should be removed before
  the file is committed to a PR**.
- Timeout-wrapped connect was reverted.

## Recommended next steps

1. **Remove diagnostic logging from `turmoil_network.rs`.** The `info!`
   lines added during investigation are not needed in the final PR.
2. **Long-term: minimise and report upstream.**
   Build a 7-node Turmoil-only reproducer (no MPC code, no stoffelnet types)
   that exhibits the same hang. If it reproduces, file a bug against
   `turmoil 0.7.1`. If it does not reproduce in isolation, the bug is in our
   interaction pattern — likely in `start_listener` (e.g. listener task being
   logically dropped/starved in some scheduling order) — and needs a different
   structural fix. The barrier we added is a workaround, not a true fix; if
   the upstream bug is fixed the barrier could in principle be removed,
   though it remains a defensible piece of defensive infrastructure.

## Files referenced

- `network/src/turmoil_network.rs` — connection setup, listener, dial logic.
  - Line ~99: `TurmoilNetwork::new`
  - Line ~112: post-spawn sleep (was `yield_now`)
  - Line ~292: `start_listener`
  - Line ~333: `connect_with_handshake`
- `mpc/tests/turmoil_test.rs:2207` — `batch_reconstruction_with_partition`
  (the test family that surfaces the hang most reliably).
- `mpc/tests/utils/turmoil.rs:14` — `collect_results`, where the
  `Ran for duration` panic originates from `sim.run().unwrap()`.

## Why this test reveals the bug when others don't

Most existing Turmoil tests in the repo (ransha, fpmul, fpdiv) run protocols
that last hundreds of milliseconds to seconds of simulated time. The
batch_recon test family finishes in ~50–100 ms simulated, which means the
connection-setup phase is a much larger fraction of total runtime. With
shorter protocol runtime, the listener-startup race is the dominant timing
factor, and the temporal window where the hang triggers is wider.

This explains why no prior test author hit the bug, and why this test is the
right vehicle for documenting and fixing it.
