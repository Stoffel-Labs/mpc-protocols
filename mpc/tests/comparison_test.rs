pub mod utils;

use crate::utils::test_utils::{fan_in_inboxes, setup_tracing, test_setup};
use ark_bls12_381::Fr;
use ark_ff::{Field, UniformRand};
use ark_std::rand::Rng;
use ark_std::test_rng;
use std::sync::Arc;
use stoffelmpc_mpc::common::RBC;
use stoffelmpc_mpc::common::{rbc::rbc::Avid, ProtocolSessionId, SecretSharingScheme};
use stoffelmpc_mpc::honeybadger::comparison::mod2::Mod2Node;
use stoffelmpc_mpc::honeybadger::{
    comparison::pre_mulc::PreMulCNode, robust_interpolate::robust_interpolate::RobustShare,
    triple_gen::ShamirBeaverTriple, ProtocolType, SessionId, WrappedMessage,
};
use stoffelmpc_network::fake_network::{FakeNetwork, SenderId};
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinSet;
use tracing::warn;

fn spawn_premulc_receiver_tasks(
    num_parties: usize,
    mut receivers: Vec<Vec<Receiver<Vec<u8>>>>,
    nodes: Vec<PreMulCNode<Fr, Avid<SessionId>>>,
    network: Vec<Arc<FakeNetwork>>,
) -> JoinSet<()> {
    let mut set = JoinSet::new();
    for i in 0..num_parties {
        let mut node = nodes[i].clone();
        let receiver = receivers.remove(0);
        let net = network[i].clone();
        let inbox: Vec<(SenderId, Receiver<Vec<u8>>)> = receiver
            .into_iter()
            .enumerate()
            .map(|(j, r)| (SenderId::Node(j), r))
            .collect();
        let mut merge_rx = fan_in_inboxes(inbox);

        set.spawn(async move {
            while let Some((_, bytes)) = merge_rx.recv().await {
                let wrapped: WrappedMessage = match bincode::deserialize(&bytes) {
                    Ok(m) => m,
                    Err(_) => {
                        warn!("deserialize failed");
                        continue;
                    }
                };
                match wrapped {
                    WrappedMessage::BatchRecon(msg) => {
                        let round = msg.session_id.round_id();
                        if round == 0 {
                            node.batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("batch_recon process failed");
                            node.drain_batch_recon_output()
                                .await
                                .expect("drain_batch_recon_output failed");
                        } else if round == 1 {
                            node.mul
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("mul.batch_recon process failed");
                            node.mul
                                .drain_batch_recon_output()
                                .await
                                .expect("mul.drain_batch_recon_output failed");
                        } else {
                            warn!("unexpected round_id {round}");
                        }
                    }
                    WrappedMessage::Rbc(msg) => {
                        node.mul
                            .rbc
                            .process(msg, net.clone())
                            .await
                            .expect("rbc process failed");
                        node.mul
                            .drain_rbc_output()
                            .await
                            .expect("drain_rbc_output failed");
                    }
                    _ => warn!("unexpected message type"),
                }
            }
        });
    }
    set
}

// ── helpers ────────────────────────────────────────────────────────────────────

fn make_triples(n: usize, t: usize, k: usize) -> Vec<Vec<ShamirBeaverTriple<Fr>>> {
    let mut rng = test_rng();
    let mut per_party: Vec<Vec<ShamirBeaverTriple<Fr>>> = vec![vec![]; n];
    for _ in 0..k {
        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);
        let c = a * b;
        let sa = RobustShare::compute_shares(a, n, t, None, &mut rng).unwrap();
        let sb = RobustShare::compute_shares(b, n, t, None, &mut rng).unwrap();
        let sc = RobustShare::compute_shares(c, n, t, None, &mut rng).unwrap();
        for p in 0..n {
            per_party[p].push(ShamirBeaverTriple {
                a: sa[p].clone(),
                b: sb[p].clone(),
                mult: sc[p].clone(),
            });
        }
    }
    per_party
}

fn share_value(v: Fr, n: usize, t: usize) -> Vec<RobustShare<Fr>> {
    let mut rng = test_rng();
    RobustShare::compute_shares(v, n, t, None, &mut rng).unwrap()
}

// ── offline e2e ────────────────────────────────────────────────────────────────
//
// Runs generate_preprocessing on k=4 random (r, s) pairs.
// Verifies the invariant: prefix_product(w)[j] * z[j] == 1 for all j.
//
// Derivation:
//   w[0]=r[0], w[i]=r[i]/r[i-1]  ⟹  prefix(w)[j] = r[j]
//   z[i] = 1/r[i]
//   ⟹  prefix(w)[j] * z[j] = r[j] * (1/r[j]) = 1

#[tokio::test]
async fn premulc_offline_e2e() {
    setup_tracing();
    let n = 5;
    let t = 1;
    let k = 4; // must be a multiple of t+1 = 2
    let duration = std::time::Duration::from_secs(10);
    let session = SessionId::new(
        ProtocolType::PreMulCOff,
        SessionId::pack_slot24(1, 0, 0),
        42,
    );

    let mut rng = test_rng();
    let r_vals: Vec<Fr> = (0..k).map(|_| Fr::rand(&mut rng)).collect();
    let s_vals: Vec<Fr> = (0..k).map(|_| Fr::rand(&mut rng)).collect();

    let mut r_per_party: Vec<Vec<RobustShare<Fr>>> = vec![vec![]; n];
    let mut s_per_party: Vec<Vec<RobustShare<Fr>>> = vec![vec![]; n];
    for i in 0..k {
        let rs = share_value(r_vals[i], n, t);
        let ss = share_value(s_vals[i], n, t);
        for p in 0..n {
            r_per_party[p].push(rs[p].clone());
            s_per_party[p].push(ss[p].clone());
        }
    }

    let triples = make_triples(n, t, k);
    let (network, receivers, _, _) = test_setup(n, vec![]);
    let nodes: Vec<PreMulCNode<Fr, Avid<SessionId>>> = (0..n)
        .map(|id| PreMulCNode::new(id, n, t).unwrap())
        .collect();
    let _recv = spawn_premulc_receiver_tasks(n, receivers, nodes.clone(), network.clone());

    let mut init_set = JoinSet::new();
    for i in 0..n {
        let mut node = nodes[i].clone();
        let (r, s, tri, net) = (
            r_per_party[i].clone(),
            s_per_party[i].clone(),
            triples[i].clone(),
            network[i].clone(),
        );
        init_set.spawn(async move {
            node.generate_preprocessing(r, s, tri, session, net, duration)
                .await
                .unwrap()
        });
    }
    while let Some(r) = init_set.join_next().await {
        r.unwrap();
    }

    // Recover (w, z) secrets and verify prefix_product(w)[j] * z[j] = 1.
    let mut w_shares: Vec<Vec<RobustShare<Fr>>> = vec![vec![]; k];
    let mut z_shares: Vec<Vec<RobustShare<Fr>>> = vec![vec![]; k];
    for i in 0..n {
        let (w, z) = nodes[i]
            .wait_for_preprocessing(session, duration)
            .await
            .unwrap();
        for j in 0..k {
            w_shares[j].push(w[j].clone());
            z_shares[j].push(z[j].clone());
        }
    }

    let mut prefix = Fr::from(1u64);
    for j in 0..k {
        let (_, w_j) = RobustShare::recover_secret(&w_shares[j], n, t).unwrap();
        let (_, z_j) = RobustShare::recover_secret(&z_shares[j], n, t).unwrap();
        prefix *= w_j;
        assert_eq!(
            prefix * z_j,
            Fr::from(1u64),
            "invariant failed at index {j}"
        );
    }
}

// ── online e2e ─────────────────────────────────────────────────────────────────
//
// Tests the online prefix-product computation with synthetic preprocessing.
//
// Synthetic (w, z):
//   r[i] random nonzero
//   w[0]=r[0],  w[i]=r[i]/r[i-1]
//   z[i]=1/r[i]
//
// These satisfy the invariant so the protocol outputs p[j] = a[0]*…*a[j].

#[tokio::test]
async fn premulc_online_e2e() {
    setup_tracing();
    let n = 5;
    let t = 1;
    let k = 4;
    let duration = std::time::Duration::from_secs(10);
    let session = SessionId::new(ProtocolType::BitLTC1, SessionId::pack_slot24(2, 0, 0), 42);

    let mut rng = test_rng();
    let a_vals: Vec<Fr> = (0..k).map(|_| Fr::rand(&mut rng)).collect();
    let r_vals: Vec<Fr> = (0..k)
        .map(|_| loop {
            let v = Fr::rand(&mut rng);
            if v != Fr::from(0u64) {
                break v;
            }
        })
        .collect();

    let w_vals: Vec<Fr> = (0..k)
        .map(|i| {
            if i == 0 {
                r_vals[0]
            } else {
                r_vals[i] * r_vals[i - 1].inverse().unwrap()
            }
        })
        .collect();
    let z_vals: Vec<Fr> = r_vals.iter().map(|r| r.inverse().unwrap()).collect();

    let mut a_pp: Vec<Vec<RobustShare<Fr>>> = vec![vec![]; n];
    let mut w_pp: Vec<Vec<RobustShare<Fr>>> = vec![vec![]; n];
    let mut z_pp: Vec<Vec<RobustShare<Fr>>> = vec![vec![]; n];
    for i in 0..k {
        let sa = share_value(a_vals[i], n, t);
        let sw = share_value(w_vals[i], n, t);
        let sz = share_value(z_vals[i], n, t);
        for p in 0..n {
            a_pp[p].push(sa[p].clone());
            w_pp[p].push(sw[p].clone());
            z_pp[p].push(sz[p].clone());
        }
    }

    let triples = make_triples(n, t, k);
    let (network, receivers, _, _) = test_setup(n, vec![]);
    let nodes: Vec<PreMulCNode<Fr, Avid<SessionId>>> = (0..n)
        .map(|id| PreMulCNode::new(id, n, t).unwrap())
        .collect();
    let _recv = spawn_premulc_receiver_tasks(n, receivers, nodes.clone(), network.clone());

    let mut init_set = JoinSet::new();
    for i in 0..n {
        let mut node = nodes[i].clone();
        let (a, w, z, tri, net) = (
            a_pp[i].clone(),
            w_pp[i].clone(),
            z_pp[i].clone(),
            triples[i].clone(),
            network[i].clone(),
        );
        init_set.spawn(async move {
            node.init(a, w, z, tri, session, net, duration)
                .await
                .unwrap()
        });
    }
    while let Some(r) = init_set.join_next().await {
        r.unwrap();
    }

    // Collect prefix-product shares, recover secrets, verify p[j] = a[0]*…*a[j].
    let mut p_shares: Vec<Vec<RobustShare<Fr>>> = vec![vec![]; k];
    for i in 0..n {
        let ps = nodes[i].wait_for_result(session, duration).await.unwrap();
        assert_eq!(ps.len(), k);
        for j in 0..k {
            p_shares[j].push(ps[j].clone());
        }
    }

    let mut expected = Fr::from(1u64);
    for j in 0..k {
        expected *= a_vals[j];
        let (_, p_j) = RobustShare::recover_secret(&p_shares[j], n, t).unwrap();
        assert_eq!(p_j, expected, "prefix product mismatch at index {j}");
    }
}
// ── Mod2 receiver ──────────────────────────────────────────────────────────────
// All RBC messages go to mod2.rbc; after each message drain_rbc_output.

fn spawn_mod2_receiver_tasks(
    num_parties: usize,
    mut receivers: Vec<Vec<Receiver<Vec<u8>>>>,
    nodes: Vec<Mod2Node<Fr, Avid<SessionId>>>,
    network: Vec<Arc<FakeNetwork>>,
) -> JoinSet<()> {
    let mut set = JoinSet::new();
    for i in 0..num_parties {
        let mut node = nodes[i].clone();
        let receiver = receivers.remove(0);
        let net = network[i].clone();
        let inbox: Vec<(SenderId, Receiver<Vec<u8>>)> = receiver
            .into_iter()
            .enumerate()
            .map(|(j, r)| (SenderId::Node(j), r))
            .collect();
        let mut merge_rx = fan_in_inboxes(inbox);

        set.spawn(async move {
            while let Some((_, bytes)) = merge_rx.recv().await {
                let wrapped: WrappedMessage = match bincode::deserialize(&bytes) {
                    Ok(m) => m,
                    Err(_) => {
                        warn!("deserialize failed");
                        continue;
                    }
                };
                match wrapped {
                    WrappedMessage::Rbc(msg) => {
                        node.rbc
                            .process(msg, net.clone())
                            .await
                            .expect("mod2 rbc process failed");
                        node.drain_rbc_output()
                            .await
                            .expect("mod2 drain_rbc_output failed");
                    }
                    _ => warn!("unexpected message type"),
                }
            }
        });
    }
    set
}

// ── Mod2 e2e ───────────────────────────────────────────────────────────────────
//
// Protocol 3.4: computes [a mod 2] from [a] and PRandM(k, 1) preprocessing.
//
// Preprocessing values:
//   r_double_prime  — any random field element (blinding; cancels in the open)
//   r_zero_prime    — a random *bit* share (0 or 1)
//
// The protocol opens c = 2^{k-1} + a + 2*r'' + r0' and computes
//   [a0] = XOR(c mod 2, [r0'])
// so the result is a mod 2 regardless of the blinding.

async fn mod2_run(a_val: u64, k: usize) {
    let n = 5;
    let t = 1;
    let duration = std::time::Duration::from_secs(10);
    let session = SessionId::new(ProtocolType::Mod2, SessionId::pack_slot24(1, 0, 0), 42);

    let mut rng = test_rng();

    // Share a.
    let a = Fr::from(a_val);
    let a_shares = share_value(a, n, t);

    // PRandM(k, 1) preprocessing: r'' is any field element, r0' is a bit.
    let r_dp_val = Fr::from(rng.gen::<u64>() % (1u64 << (k as u64 - 1)));
    let r_zp_val = Fr::from(rng.gen::<u64>() & 1); // 0 or 1

    let r_dp_shares = share_value(r_dp_val, n, t);
    let r_zp_shares = share_value(r_zp_val, n, t);

    let (network, receivers, _, _) = test_setup(n, vec![]);
    let nodes: Vec<Mod2Node<Fr, Avid<SessionId>>> = (0..n)
        .map(|id| Mod2Node::<Fr, Avid<SessionId>>::new(id, n, t).unwrap())
        .collect();

    let _recv = spawn_mod2_receiver_tasks(n, receivers, nodes.clone(), network.clone());

    // Each party calls init.
    let mut init_set = JoinSet::new();
    for i in 0..n {
        let mut node = nodes[i].clone();
        let (a_s, r_dp, r_zp, net) = (
            a_shares[i].clone(),
            r_dp_shares[i].clone(),
            r_zp_shares[i].clone(),
            network[i].clone(),
        );
        init_set.spawn(async move { node.init(a_s, k, r_dp, r_zp, session, net).await.unwrap() });
    }
    while let Some(r) = init_set.join_next().await {
        r.unwrap();
    }

    // Collect result shares and recover secret.
    let mut result_shares = vec![];
    for i in 0..n {
        result_shares.push(nodes[i].wait_for_result(session, duration).await.unwrap());
    }

    let (_, a0) = RobustShare::recover_secret(&result_shares, n, t).unwrap();
    let expected = Fr::from(a_val & 1);
    assert_eq!(
        a0,
        expected,
        "mod2({a_val}) expected {}, got {a0}",
        a_val & 1
    );
}

#[tokio::test]
async fn mod2_even() {
    setup_tracing();
    mod2_run(42, 8).await; // even → 0
}

#[tokio::test]
async fn mod2_odd() {
    setup_tracing();
    mod2_run(77, 8).await; // odd → 1
}

#[tokio::test]
async fn mod2_zero() {
    setup_tracing();
    mod2_run(0, 8).await; // zero → 0
}

#[tokio::test]
async fn mod2_one() {
    setup_tracing();
    mod2_run(1, 8).await; // one → 1
}
