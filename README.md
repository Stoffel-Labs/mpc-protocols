# 🚀 Stoffel MPC Protocols

This repository provides a fully-asynchronous, robust collection of MPC (Multi-Party Computation) protocols designed to run inside the [**StoffelVM**](https://github.com/Stoffel-Labs/StoffelVM) runtime and the [**StoffelNet**](https://github.com/Stoffel-Labs/stoffel-networking) networking layer. However, it can also be used independently.

The repository is designed as a **general-purpose foundation for hosting multiple MPC protocol families** that share common networking, preprocessing, and arithmetic components.
This repository is intended to serve as a **collection of MPC protocols**, not a single fixed construction.

At present it contains two end-to-end protocol families:

- **HoneyBadgerMPC** — orchestrated by `HoneyBadgerMPCNode`
- **AVSS-based MPC** — orchestrated by `AvssMPCNode`, built on asynchronous verifiable secret sharing with Feldman shares.

The architecture is deliberately modular so that additional MPC protocols can be added over time without rewriting core components.

Key design goals:

- **Protocol-agnostic networking** via the `Network` trait
- **Reusable common sub-protocols** (RBC, secret sharing, etc.)
- **Shared arithmetic layers** (field, fixed-point, integer)
- **Explicit protocol routing** via compact `SessionId`s

## HoneyBadgerMPC 🦡
It includes implementations for **HoneyBadgerMPC** like random sharing protocols, preprocessing, Beaver triples, fixed-point arithmetic, integer arithmetic, and robust reconstruction procedures.

The core engine is built around the `HoneyBadgerMPCNode`, which orchestrates all subprotocols using an asynchronous message-passing model.

---

### ✨ Features

### Included Protocols
| Category | Protocol | Status |
|---------|----------|--------|
| Preprocessing | Shamir Random Share (RanSha) | ✔ Implemented |
| Preprocessing | Double Sharing / Random Double Sharing (DouSha / RanDouSha) | ✔ Implemented |
| Preprocessing | Beaver Triple Generation | ✔ Implemented |
| Preprocessing | Random Bit / PRandBit / PRandInt | ✔ Implemented |
| Arithmetic | Secure Beaver Multiplication | ✔ Implemented |
| Arithmetic | Fixed-Point Mul / DivWithConst / TruncPr | ✔ Implemented |
| I/O | Distributed Input / Output (via RBC) | ✔ Implemented |
| Reconstruction | Robust Interpolation | ✔ Implemented |
| Reconstruction | Batch Reconstruction | ✔ Implemented |
| Common | Reliable Broadcast (Bracha, AVID) | ✔ Implemented |
| Complete MPC | HoneyBadgerMPC Core | ✔ Implemented |
| Complete MPC | AVSS-based MPC (share gen, triples, mul, I/O) | ✔ Implemented |

Small-field arithmetic is also supported (GF(256) and the Goldilocks field) for preprocessing material over small fields.

---

### 📦 Workspace Structure

The workspace contains two crates: **`stoffelcrypto`** (the MPC protocols, in `mpc/`) and **`stoffelmpc-network`** (test network implementations, in `network/`).

```
mpc-protocols/
├── Cargo.toml                  # Workspace definition
├── mpc/                        # `stoffelcrypto` crate
│   ├── src/
│   │   ├── common/             # Protocol-agnostic building blocks
│   │   │   ├── rbc/            # Reliable broadcast (Bracha, AVID)
│   │   │   ├── share/          # Shamir, Feldman, and AVSS secret sharing
│   │   │   ├── acss/           # Pedersen polynomial commitments
│   │   │   ├── math/           # Extra fields (Goldilocks)
│   │   │   └── types/          # Fixed-point and integer types
│   │   ├── honeybadger/        # HoneyBadgerMPC protocol family
│   │   │   ├── robust_interpolate/ # RS-based robust interpolation (HBMPC Fig.1)
│   │   │   ├── batch_recon/    # Batch reconstruction (HBMPC Fig.2)
│   │   │   ├── ran_dou_sha/    # Random double sharing (HBMPC Fig.3)
│   │   │   ├── share_gen/      # Random Shamir share generation
│   │   │   ├── double_share/   # Basic double-share generation
│   │   │   ├── triple_gen/     # Beaver triple generator
│   │   │   ├── mul/            # Secure Beaver multiplication
│   │   │   ├── fpmul/          # Fixed-point mul, truncation, RandBit/PRandBitD, GF(256)
│   │   │   ├── fpdiv/          # Fixed-point division by a public constant
│   │   │   ├── input/, output/ # MPC I/O protocols via RBC
│   │   │   └── preprocessing.rs # Preprocessing material store
│   │   ├── avss_mpc/           # AVSS-based MPC protocol family
│   │   │   └── share_gen/, triple_gen/, mul/, input/, output/
│   │   └── ffi/                # C FFI bindings for the language SDKs
│   ├── tests/                  # End-to-end integration tests
│   └── benches/                # Criterion benchmarks
└── network/                    # `stoffelmpc-network` crate
    └── src/
        ├── fake_network.rs     # In-memory network for deterministic tests
        └── turmoil_network.rs  # turmoil-based network simulation
```

All HoneyBadger modules plug into:

#### `HoneyBadgerMPCNode<F, R>`
A node capable of:
- Running preprocessing (random shares, doubles, triples, PRandBit, PRandInt)
- Performing secure arithmetic operations
- Handling RBC-based input and output
- Routing messages using compact `SessionId` fields

The AVSS modules plug into the analogous `AvssMPCNode<F, R, G>`, which works over Feldman/AVSS shares on a curve group `G`.

### ⏱️ Offline Phase, Abort Semantics, and Timeouts

The **offline (preprocessing) phase** of HoneyBadgerMPC is intentionally designed to be **non-robust**. In line with the original HoneyBadgerMPC design, preprocessing protocols (e.g., random sharing, batch reconstruction, Beaver triple generation) are expected to **abort on failure** and be **restarted by the caller** until sufficient preprocessing material has been generated.

Typical failure conditions include:
- A node going offline
- Network message loss or delays
- RBC or subprotocols failing to terminate

Node-level operations wait for subprotocol results using the **configurable timeout** in `HoneyBadgerMPCNodeOpts` (see `timeout: Duration`, adjustable via `set_timeout`). If a required message or share never arrives, the operation fails with a timeout error instead of hanging indefinitely. **Retry and abort policy remains the responsibility of the caller** — the application decides whether to restart a failed preprocessing run.

---

### 🏃 How to Run

Running MPC requires:

1. **Start `N` HoneyBadgerMPCNode instances**
2. **Connect them with a StoffelNet‐compatible network (`Network` trait)**
3. **Spawn a processing loop for each node**
4. **Send messages into the network**
5. **Call MPC operations** like multiplication, fixed-point division, etc.

---

### ▶ Minimal Example: Running a 4-Party Secure Multiplication

Replace `FakeNetwork` with any `Network` implementation (FakeNetwork, StoffelNet, etc.). The helpers used below (`test_setup`, `create_global_nodes`, `construct_e2e_input_mul`, `receive`) live in [`mpc/tests/utils/test_utils.rs`](mpc/tests/utils/test_utils.rs).

```rust
use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_std::test_rng;
use std::time::Duration;
use stoffelcrypto::common::{rbc::rbc::Avid, MPCProtocol, SecretSharingScheme};
use stoffelcrypto::honeybadger::{
    robust_interpolate::robust_interpolate::RobustShare, SessionId,
};
use stoffelmpc_network::fake_network::FakeNetwork;

#[tokio::test]
async fn test_mul() {
    let n_parties = 4;
    let t = 1;
    let no_of_multiplications = 1;
    let mut rng = test_rng();

    // ---------------- Network (one handle per party) ----------------
    let (network, receivers, _, _) = test_setup(n_parties, vec![]);

    // ---------------- Preprocessing: Beaver triples ----------------
    let (_, triples) = construct_e2e_input_mul(n_parties, no_of_multiplications, t);

    // ---------------- Inputs ----------------
    let x = Fr::rand(&mut rng);
    let y = Fr::rand(&mut rng);
    let xs = RobustShare::compute_shares(x, n_parties, t, None, &mut rng).unwrap();
    let ys = RobustShare::compute_shares(y, n_parties, t, None, &mut rng).unwrap();

    // ---------------- Nodes ----------------
    let nodes = create_global_nodes::<Fr, Avid<SessionId>, RobustShare<Fr>, FakeNetwork>(
        n_parties,
        t,
        0,                       // n_triples (preprocessing target)
        0,                       // n_random_shares
        111,                     // instance id
        0,                       // n_prandbit
        0,                       // n_prandint
        0,                       // l: fixed-point bit size
        0,                       // k: security parameter
        Duration::from_secs(30), // per-operation timeout
        vec![],                  // client ids for input
    );

    // ---------------- Spawn message-processing loops ----------------
    receive::<Fr, Avid<SessionId>, RobustShare<Fr>, FakeNetwork>(
        receivers,
        nodes.clone(),
        network.clone(),
        None,
    );

    // ---------------- Load triples into each node's store ----------------
    for pid in 0..n_parties {
        nodes[pid].preprocessing_material.lock().await.add(
            Some(triples[pid].clone()),
            None,
            None,
            None,
            None,
            None,
        );
    }

    // ---------------- Run MPC ----------------
    let handles: Vec<_> = (0..n_parties)
        .map(|pid| {
            let mut node = nodes[pid].clone();
            let net = network[pid].clone();
            let x = vec![xs[pid].clone()];
            let y = vec![ys[pid].clone()];

            tokio::spawn(async move {
                let shares = node.mul(x, y, net).await.expect("mul failed");
                shares[0].clone()
            })
        })
        .collect();

    let shares: Vec<_> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|res| res.expect("task panicked"))
        .collect();

    // ---------------- Collect & Check ----------------
    let (_, z) = RobustShare::recover_secret(&shares[..=2 * t], n_parties, t).unwrap();
    assert_eq!(z, x * y);
}
```

For more examples check out the tests (e.g. [`mpc/tests/node_test.rs`](mpc/tests/node_test.rs) for node-level end-to-end flows, and [`mpc/tests/avss_mpc_test.rs`](mpc/tests/avss_mpc_test.rs) for the AVSS-based protocol).

---

### 🧪 Running Tests

### Run everything:
```bash
cargo test
```

### Run tests for the MPC crate only:
```bash
cargo test -p stoffelcrypto
```

### Run a specific test:
```bash
cargo test -p stoffelcrypto mul_e2e
```

### See logs:
```bash
RUST_LOG=info cargo test -- --nocapture
```

### Run benchmarks:
```bash
cargo bench -p stoffelcrypto
```

---

### 🔌 Running Preprocessing

```rust
let mut rng = StdRng::from_rng(OsRng).unwrap();
node.run_preprocessing(net.clone(), &mut rng).await?;
```

This fills the node's preprocessing store with:

- Random Shamir shares (optionally over a small field)
- Beaver triples (optionally over a small field)
- PRandBit outputs
- PRandInt outputs

Double shares and random double shares are generated and consumed internally during triple generation.

The amounts are controlled by `HoneyBadgerMPCNodeOpts` (`n_triples`, `n_random_shares`, `n_prandbit`, `n_prandint`).

---

### 📚 Reference Papers

- HoneyBadgerMPC — https://eprint.iacr.org/2019/883  
- Fixed-Point Secure Computation — https://ifca.ai/pub/fc10/31_47.pdf

## Learn More

To learn more about what you can build with Stoffel, visit 
[stoffelmpc.com](https://stoffelmpc.com?utm_source=github&utm_medium=readme&utm_campaign=mpc-protocols-repo&utm_term=mpc)
