//! Turmoil-with-timing benchmark for the batched multiply (the current, per-chunk-session
//! implementation). Issues ONE `mul(N)` call per node under a modeled network latency, records
//! the simulated elapsed time seen by each node (≈ latency × sequential rounds + compute) and
//! the real wall-clock of `sim.run()`, and verifies correctness.
//!
//! Latency is read from env so the report can sweep it:
//!   MUL_TURMOIL_N=64 MUL_TURMOIL_LAT_MIN=1 MUL_TURMOIL_LAT_MAX=5 \
//!     cargo test -p stoffelmpc-mpc --test mul_bench_turmoil --release -- --nocapture --ignored
//!
//! Defaults (fast enough for CI): n=5, t=1, N=8, latency 1..5 ms.

pub mod utils;

use crate::utils::{
    test_utils::{construct_e2e_input_mul, create_global_nodes, setup_quiet_tracing},
    turmoil::turmoil_setup,
};
use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_std::test_rng;
use std::{sync::Arc, time::Instant};
use stoffelmpc_mpc::{
    common::{rbc::rbc::Avid, MPCProtocol, SecretSharingScheme},
    honeybadger::{robust_interpolate::robust_interpolate::RobustShare, SessionId},
};
use stoffelmpc_network::{fake_network::SenderId, turmoil_network::TurmoilNetwork};
use tokio::sync::Barrier;
use tracing::warn;

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Build per-node x/y input shares for `n_muls` random pairs plus the plaintext secrets.
fn make_inputs(
    n_parties: usize,
    t: usize,
    n_muls: usize,
) -> (
    Vec<Vec<RobustShare<Fr>>>,
    Vec<Vec<RobustShare<Fr>>>,
    Vec<Fr>,
    Vec<Fr>,
) {
    let mut rng = test_rng();
    let mut x_secret = Vec::with_capacity(n_muls);
    let mut y_secret = Vec::with_capacity(n_muls);
    let mut x_per_node = vec![Vec::with_capacity(n_muls); n_parties];
    let mut y_per_node = vec![Vec::with_capacity(n_muls); n_parties];
    for _ in 0..n_muls {
        let xv = Fr::rand(&mut rng);
        let yv = Fr::rand(&mut rng);
        x_secret.push(xv);
        y_secret.push(yv);
        let xs = RobustShare::compute_shares(xv, n_parties, t, None, &mut rng).unwrap();
        let ys = RobustShare::compute_shares(yv, n_parties, t, None, &mut rng).unwrap();
        for p in 0..n_parties {
            x_per_node[p].push(xs[p].clone());
            y_per_node[p].push(ys[p].clone());
        }
    }
    (x_per_node, y_per_node, x_secret, y_secret)
}

fn run_config(n: usize, t: usize, n_muls: usize, lat: Option<(u64, u64)>) {
    setup_quiet_tracing();

    let (x_per_node, y_per_node, x_secret, y_secret) = make_inputs(n, t, n_muls);
    let (_, triples) = construct_e2e_input_mul(n, n_muls, t);
    let nodes = create_global_nodes::<Fr, Avid<SessionId>, RobustShare<Fr>, TurmoilNetwork>(
        n,
        t,
        0,
        0,
        111,
        0,
        0,
        0,
        0,
        std::time::Duration::from_secs(120),
        vec![],
    );

    // Inject synthetic triples (mul() consumes them from the preprocessing store).
    {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            for pid in 0..n {
                nodes[pid]
                    .preprocessing_material
                    .lock()
                    .await
                    .add(Some(triples[pid].clone()), None, None, None, None, None);
            }
        });
    }

    let (mut sim, inner) = turmoil_setup(
        n,
        vec![],
        lat,
    );
    let latency_label = match lat {
        None => "none".to_string(),
        Some((a, b)) => format!("{a}..{b}ms"),
    };

    let (tx, rx_done) = std::sync::mpsc::channel::<
        Result<(usize, u128, Vec<RobustShare<Fr>>), String>,
    >();
    let (done_tx, mut done_rx) = tokio::sync::broadcast::channel::<()>(n);
    let barrier = Arc::new(Barrier::new(n));

    for id in 0..n {
        let inner = inner.clone();
        let node = nodes[id].clone();
        let tx = tx.clone();
        let done_tx = done_tx.clone();
        let barrier = barrier.clone();
        let x = x_per_node[id].clone();
        let y = y_per_node[id].clone();

        sim.host(format!("node{id}"), move || {
            let inner = inner.clone();
            let mut node = node.clone();
            let tx = tx.clone();
            let done_tx = done_tx.clone();
            let barrier = barrier.clone();
            let x = x.clone();
            let y = y.clone();
            async move {
                let (network, mut rx) = TurmoilNetwork::new(SenderId::Node(id), inner).await;
                let net = Arc::new(network);
                barrier.wait().await;

                let net2 = net.clone();
                let mut node2 = node.clone();
                let (mul_done_tx, mut mul_done_rx) = tokio::sync::oneshot::channel::<()>();
                let mul_handle = tokio::spawn(async move {
                    let t0 = tokio::time::Instant::now();
                    let out = node2.mul(x, y, net2).await?;
                    // Signal the drain loop that the result is in. (Receiver may be gone if the
                    // loop already exited — ignore the error.)
                    let _ = mul_done_tx.send(());
                    Ok::<_, stoffelmpc_mpc::honeybadger::HoneyBadgerError>((t0.elapsed(), out))
                });

                // Drain the network for this node until the mul finishes. Use select! on a done
                // signal rather than a polling timeout, so turmoil's simulated clock is not
                // advanced by elapsed timeouts (which would corrupt the timing measurement).
                loop {
                    tokio::select! {
                        biased;
                        _ = &mut mul_done_rx => break,
                        msg = rx.recv() => {
                            match msg {
                                Some((sender, m)) => {
                                    let sender_id = match sender {
                                        SenderId::Node(i) | SenderId::Client(i) => i,
                                    };
                                    // Tolerate benign late/duplicate batch-recon errors.
                                    if let Err(e) = node.process(sender_id, m, net.clone()).await {
                                        warn!(node = id, error = ?e, "tolerated message error");
                                    }
                                }
                                None => break,
                            }
                        }
                    }
                }

                match mul_handle.await {
                    Ok(Ok((elapsed, shares))) => {
                        let _ = tx.send(Ok((id, elapsed.as_micros(), shares)));
                    }
                    Ok(Err(e)) => {
                        let _ = tx.send(Err(format!("node {id} mul failed: {e:?}")));
                    }
                    Err(e) => {
                        let _ = tx.send(Err(format!("node {id} join error: {e:?}")));
                    }
                }
                let _ = done_tx.send(());
                Ok(())
            }
        });
    }

    drop(tx);
    drop(done_tx);

    sim.client("driver", async move {
        let mut count = 0;
        while count < n {
            if done_rx.recv().await.is_ok() {
                count += 1;
            } else {
                break;
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    });

    let real_start = Instant::now();
    sim.run().unwrap();
    let real_wall = real_start.elapsed();

    let mut results = Vec::new();
    for r in std::iter::from_fn(|| rx_done.try_recv().ok()) {
        match r {
            Ok(t) => results.push(t),
            Err(e) => panic!("{e}"),
        }
    }
    assert_eq!(results.len(), n, "not all nodes reported");

    // Correctness: every multiplication reconstructs to x*y across (2t+1) parties.
    let mut by_node = std::collections::HashMap::new();
    let mut max_sim_us: u128 = 0;
    for (id, sim_us, shares) in &results {
        by_node.insert(*id, shares.clone());
        max_sim_us = max_sim_us.max(*sim_us);
        assert_eq!(shares.len(), n_muls, "node {id} wrong share count");
    }
    for i in 0..n_muls {
        let shares: Vec<RobustShare<Fr>> = (0..n).map(|pid| by_node[&pid][i].clone()).collect();
        let (_, z) = RobustShare::recover_secret(&shares[0..=(2 * t)], n, t).unwrap();
        assert_eq!(z, x_secret[i] * y_secret[i], "mul mismatch at index {i}");
    }

    eprintln!(
        "[mul_turmoil] n={n} t={t} N={N} latency={lat}: sim_wall={sw} us (max over nodes) | \
         real_sim_run={rw} ms | correct=true",
        n = n,
        t = t,
        N = n_muls,
        lat = latency_label,
        sw = max_sim_us,
        rw = real_wall.as_secs_f64() * 1e3,
    );
}

#[test]
#[ignore = "timing bench: enable with --ignored; tunable via MUL_TURMOIL_* env"]
fn mul_batched_turmoil_timing() {
    let n = env_u64("MUL_TURMOIL_N_NODES", 5) as usize;
    let t = env_u64("MUL_TURMOIL_T", 1) as usize;
    let n_muls = env_u64("MUL_TURMOIL_N", 8) as usize;
    let lat_min = env_u64("MUL_TURMOIL_LAT_MIN", 1);
    let lat_max = env_u64("MUL_TURMOIL_LAT_MAX", 5);

    // Sweep fixed latencies (min == max) so the report can derive rounds ≈ sim_wall / latency.
    // Turmoil's `None` uses an unspecified default, so we pass explicit values instead.
    for lat in [Some((1, 1)), Some((5, 5)), Some((20, 20)), Some((lat_min, lat_max))] {
        run_config(n, t, n_muls, lat);
    }
}
