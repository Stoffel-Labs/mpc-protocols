# 🚀 Stoffel MPC Protocols

This repository provides a fully-asynchronous, robust collection of MPC (Multi-Party Computation) protocols designed to run inside the [**StoffelVM**](https://github.com/Stoffel-Labs/StoffelVM) runtime and the[ **StoffelNet**](https://github.com/Stoffel-Labs/Stoffel) networking layer. However, it can also be used independently.

The repository is designed as a **general-purpose foundation for hosting multiple MPC protocol families** that share common networking, preprocessing, and arithmetic components.
This repository is intended to serve as a **collection of MPC protocols**, not a single fixed construction.

At present, **HoneyBadgerMPC** is the only fully integrated end-to-end MPC protocol. However, the architecture is deliberately modular so that additional MPC protocols can be added over time without rewriting core components.

Key design goals:

- **Protocol-agnostic networking** via the `Network` trait
- **Reusable common sub-protocols** (rbc,secret sharing,etc)
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
| Arithmetic | Fixed-Point Mul / DivWithConst / Trunc | ✔ Implemented |
| I/O | Distributed Input / Output (via RBC) | ✔ Implemented |
| Reconstruction | Robust Interpolation | ✔ Implemented |
| Reconstruction | Batch Reconstruction | ✔ Implemented |
| Complete MPC | HoneyBadgerMPC Core | ✔ Implemented |

---

### 📦 Crate Structure

`mod.rs` exposes the following modules:

```
robust_interpolate/       # RS-based robust interpolation (HBMPC Fig.1)
batch_recon/              # Batch reconstruction (HBMPC Fig.2)
ran_dou_sha/              # Random double sharing (HBMPC Fig.3)
share_gen/                # Random share generation
double_share/             # Basic double-share generation
triple_gen/               # Beaver triple generator
fpmul/                    # Fixed-point arithmetic protocols
input/, output/           # MPC I/O protocols via RBC
mul/                      # Secure Beaver multiplication
preprocessing/            # Preprocessing store management
share_gen/                # Random Shamir share generation
```

All modules plug into:

#### `HoneyBadgerMPCNode<F, R>`
A node capable of:
- Running preprocessing (random shares, doubles, triples, PRandBit, PRandInt)
- Performing secure arithmetic operations
- Handling RBC-based input and output
- Routing messages using compact `SessionId` fields

### ⏱️ Offline Phase, Abort Semantics, and Timeouts

The **offline (preprocessing) phase** of HoneyBadgerMPC is intentionally designed to be **non-robust**. In line with the original HoneyBadgerMPC design, preprocessing protocols (e.g., random sharing, batch reconstruction, Beaver triple generation) are expected to **abort on failure** and be **restarted by the caller** until sufficient preprocessing material has been generated.

Typical failure conditions include:
- A node going offline
- Network message loss or delays
- RBC or subprotocols failing to terminate

⚠️ **Important:**  
The preprocessing protocols **do not internally enforce timeouts**.  If a required message or share never arrives, the protocol may wait indefinitely. As a result, **timeout handling is the responsibility of the caller**. Preprocessing should always be wrapped in **external timeout logic**, with retry or abort behavior defined by the application.


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

Replace `FakeNetwork` with any `Network` implementation (FakeNetwork, StoffelNet, etc.):

```rust
#[tokio::test]
async fn test_mul() {
    let n = 4;
    let t = 1;
    let mut rng = test_rng();

    // ---------------- Network ----------------
    let config = FakeNetworkConfig::new(500);
    let (network, receivers, _) = FakeNetwork::new(n, Some(vec![]), config);
    let network: Arc<FakeNetwork> = Arc::new(network);

    // ---------------- Inputs ----------------
    let x = Fr::rand(&mut rng);
    let y = Fr::rand(&mut rng);

    let xs = RobustShare::compute_shares(x, n, t, None, &mut rng).unwrap();
    let ys = RobustShare::compute_shares(y, n, t, None, &mut rng).unwrap();

    // ---------------- Nodes ----------------
   let nodes = create_global_nodes::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(
        n, t, 2,   //No of beaver triples needed, 2 in this case for one multiplication
        111, //Instance-ID
    );

    // ---------------- Process messages ----------------
    receive::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(receivers, nodes.clone(), network.clone());

    // ---------------- Run MPC ----------------
    let handles: Vec<_> = (0..n)
        .map(|pid| {
            let mut node = nodes[pid].clone();
            let net = network.clone();
            let x = vec![xs[pid].clone()];
            let y = vec![ys[pid].clone()];

            tokio::spawn(async move {
                let shares = node.mul(x, y, net).await.expect("mul failed");
                return shares[0].clone();
            })
        })
        .collect();

    let shares: Vec<_> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|res| res.expect("task panicked"))
        .collect();

    // ---------------- Collect & Check ----------------

    let (_, z) = RobustShare::recover_secret(&shares[..=2 * t], n, t).unwrap();
    assert_eq!(z, x * y);
}


pub fn create_global_nodes<F: PrimeField, R: RBC + 'static, S, N>(
    n_parties: usize,
    t: usize,
    n_triples: usize,
    instance_id: u32,
) -> Vec<HoneyBadgerMPCNode<F, R>>
where
    N: Network + Send + Sync + 'static,
    S: SecretSharingScheme<F>,
    HoneyBadgerMPCNode<F, R>: MPCProtocol<F, S, N, MPCOpts = HoneyBadgerMPCNodeOpts>,
{
    let parameters =
        HoneyBadgerMPCNodeOpts::new(n_parties, t, n_triples, 0, instance_id, 0, 0, 0, 0).unwrap();
    (0..n_parties)
        .map(|id| HoneyBadgerMPCNode::setup(id, parameters.clone(), vec![]).unwrap())
        .collect()
}

pub fn receive<F, R, S, N>(
    mut receivers: Vec<Receiver<Vec<u8>>>,
    mut nodes: Vec<HoneyBadgerMPCNode<F, R>>,
    net: Arc<N>,
) where
    F: PrimeField,
    R: RBC + 'static,
    N: Network + Send + Sync + 'static,
    S: SecretSharingScheme<F>,
    HoneyBadgerMPCNode<F, R>: MPCProtocol<F, S, N>,
{
    assert_eq!(
        receivers.len(),
        nodes.len(),
        "Each node must have a receiver"
    );

    for i in 0..receivers.len() {
        let mut rx = receivers.remove(0);
        let mut node = nodes.remove(0);
        let net_clone = net.clone();

        tokio::spawn(async move {
            while let Some(raw_msg) = rx.recv().await {
                if let Err(e) = node.process(raw_msg, net_clone.clone()).await {
                    tracing::error!("Node {i} failed to process message: {e:?}");
                }
            }
            tracing::info!("Receiver task for node {i} ended");
        });
    }
}
```
For more examples check out the tests.

---

### 🧪 Running Tests

### Run everything:
```bash
cargo test
```

### Run a specific test:
```bash
cargo test test_session_id
```

### See logs:
```bash
RUST_LOG=info cargo test -- --nocapture
```

---

### 🔌 Running Preprocessing

```rust
let mut rng = StdRng::from_entropy();
node.run_preprocessing(net.clone(), &mut rng).await?;
```

This generates:

- Random Shamir shares  
- Double shares  
- Random double shares  
- Beaver triples  
- PRandBit outputs  
- PRandInt outputs  

---

### 📚 Reference Papers

- HoneyBadgerMPC — https://eprint.iacr.org/2019/883  
- Fixed-Point Secure Computation — https://ifca.ai/pub/fc10/31_47.pdf
