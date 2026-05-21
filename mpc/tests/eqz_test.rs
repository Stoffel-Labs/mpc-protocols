pub mod utils;

use crate::utils::comparison_utils::{
    collect_result_shares, make_kor_cs_prep, make_prandm_prep, make_triples, share_value,
};
use crate::utils::test_utils::{fan_in_inboxes, setup_tracing, test_setup};
use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_std::test_rng;
use std::sync::Arc;
use stoffelmpc_mpc::common::RBC;
use stoffelmpc_mpc::common::{rbc::rbc::Avid, ProtocolSessionId, SecretSharingScheme};
use stoffelmpc_mpc::honeybadger::comparison::eqz::EQZNode;
use stoffelmpc_mpc::honeybadger::comparison::kor_cl::KOrCLNode;
use stoffelmpc_mpc::honeybadger::comparison::kor_cs::KOrCSNode;
use stoffelmpc_mpc::honeybadger::comparison::rand_inv_pair::{RandInvPairNode, RandInvPairPrep};
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::{ProtocolType, SessionId, WrappedMessage};
use stoffelmpc_network::fake_network::{FakeNetwork, SenderId};
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinSet;
use tracing::warn;

// ── RandInvPair helper ─────────────────────────────────────────────────────────

fn make_rand_inv_pair_prep(k: usize, n: usize, t: usize) -> Vec<RandInvPairPrep<Fr>> {
    let mut rng = test_rng();
    let mut r_pp: Vec<Vec<RobustShare<Fr>>> = vec![vec![]; n];
    let mut r_prime_pp: Vec<Vec<RobustShare<Fr>>> = vec![vec![]; n];
    for _ in 0..k {
        let r = loop {
            let v = Fr::rand(&mut rng);
            if v != Fr::from(0u64) {
                break v;
            }
        };
        let rp = loop {
            let v = Fr::rand(&mut rng);
            if v != Fr::from(0u64) {
                break v;
            }
        };
        let sr = share_value(r, n, t);
        let srp = share_value(rp, n, t);
        for p in 0..n {
            r_pp[p].push(sr[p].clone());
            r_prime_pp[p].push(srp[p].clone());
        }
    }
    let triples = make_triples(n, t, k);
    (0..n)
        .map(|i| RandInvPairPrep {
            r_shares: r_pp[i].clone(),
            r_prime_shares: r_prime_pp[i].clone(),
            triples: triples[i].clone(),
        })
        .collect()
}

// ── RandInvPair receiver ───────────────────────────────────────────────────────
//
// Session routing:
//   BatchRecon round_id=0 → batch_recon      (product openings)
//   BatchRecon round_id=1 → mul.batch_recon  (Multiply internals)
//   Rbc                   → mul.rbc          (round_id=2 from Multiply)

fn spawn_rand_inv_pair_receiver_tasks(
    num_parties: usize,
    mut receivers: Vec<Vec<Receiver<Vec<u8>>>>,
    nodes: Vec<RandInvPairNode<Fr, Avid<SessionId>>>,
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
                    WrappedMessage::BatchRecon(msg) => match msg.session_id.round_id() {
                        0 => {
                            node.batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("rand_inv_pair batch_recon failed");
                            node.drain_batch_recon_output()
                                .await
                                .expect("rand_inv_pair drain_batch_recon failed");
                        }
                        1 => {
                            node.mul
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("rand_inv_pair mul batch_recon failed");
                            node.mul
                                .drain_batch_recon_output()
                                .await
                                .expect("rand_inv_pair mul drain_batch_recon failed");
                        }
                        r => warn!("unexpected BatchRecon round_id {r}"),
                    },
                    WrappedMessage::Rbc(msg) => {
                        node.mul
                            .rbc
                            .process(msg, net.clone())
                            .await
                            .expect("rand_inv_pair mul rbc failed");
                        node.mul
                            .drain_rbc_output()
                            .await
                            .expect("rand_inv_pair mul drain_rbc failed");
                    }
                    _ => warn!("unexpected message type"),
                }
            }
        });
    }
    set
}

// ── RandInvPair e2e ────────────────────────────────────────────────────────────
//
// Generates k ([r_j], [r_j^{-1}]) pairs. Reconstructs both and verifies r * r_inv = 1.

async fn rand_inv_pair_run(k: usize) {
    let n = 5;
    let t = 1;
    let duration = std::time::Duration::from_secs(10);
    let session = SessionId::new(ProtocolType::EQZ, SessionId::pack_slot24(1, 0, 0), 42);

    let prep = make_rand_inv_pair_prep(k, n, t);
    let (network, receivers, _, _) = test_setup(n, vec![]);
    let nodes: Vec<RandInvPairNode<Fr, Avid<SessionId>>> = (0..n)
        .map(|id| RandInvPairNode::new(id, n, t).unwrap())
        .collect();
    let _recv = spawn_rand_inv_pair_receiver_tasks(n, receivers, nodes.clone(), network.clone());

    let mut run_set = JoinSet::new();
    for i in 0..n {
        let mut node = nodes[i].clone();
        let net = network[i].clone();
        let pp = prep[i].clone();
        run_set.spawn(async move { node.run(pp, session, net, duration).await.unwrap() });
    }
    while let Some(r) = run_set.join_next().await {
        r.unwrap();
    }

    // Collect per-party pair shares, reconstruct r and r_inv, verify r * r_inv = 1.
    let mut all_pairs: Vec<Vec<(RobustShare<Fr>, RobustShare<Fr>)>> = Vec::new();
    for i in 0..n {
        let pairs = nodes[i].wait_for_result(session, duration).await.unwrap();
        assert_eq!(pairs.len(), k);
        all_pairs.push(pairs);
    }
    let one = Fr::from(1u64);
    for j in 0..k {
        let r_shares: Vec<RobustShare<Fr>> = all_pairs.iter().map(|p| p[j].0.clone()).collect();
        let r_inv_shares: Vec<RobustShare<Fr>> = all_pairs.iter().map(|p| p[j].1.clone()).collect();
        let (_, r_j) = RobustShare::recover_secret(&r_shares, n, t).unwrap();
        let (_, r_inv_j) = RobustShare::recover_secret(&r_inv_shares, n, t).unwrap();
        assert_eq!(r_j * r_inv_j, one, "pair {j}: r * r_inv != 1");
    }
}

#[tokio::test]
async fn rand_inv_pair_single() {
    setup_tracing();
    rand_inv_pair_run(1).await;
}

#[tokio::test]
async fn rand_inv_pair_multiple() {
    setup_tracing();
    rand_inv_pair_run(4).await;
}

// ── KOrCS receiver ─────────────────────────────────────────────────────────────
//
// Session routing:
//   BatchRecon calling_proto KOr1/KOr2 → mul.batch_recon 
//   BatchRecon otherwise               → batch_recon       (d_j openings)
//   Rbc        calling_proto KOr1/KOr2 → mul.rbc

fn spawn_kor_cs_receiver_tasks(
    num_parties: usize,
    mut receivers: Vec<Vec<Receiver<Vec<u8>>>>,
    nodes: Vec<KOrCSNode<Fr, Avid<SessionId>>>,
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
                    WrappedMessage::BatchRecon(msg) => match msg.session_id.calling_protocol() {
                        Some(ProtocolType::KOr1) | Some(ProtocolType::KOr2) => {
                            node.mul
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("kor_cs mul batch_recon failed");
                            node.mul
                                .drain_batch_recon_output()
                                .await
                                .expect("kor_cs mul drain_batch_recon failed");
                        }
                        _ => {
                            node.batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("kor_cs batch_recon failed");
                            node.drain_batch_recon_output()
                                .await
                                .expect("kor_cs drain_batch_recon failed");
                        }
                    },
                    WrappedMessage::Rbc(msg) => {
                        node.mul
                            .rbc
                            .process(msg, net.clone())
                            .await
                            .expect("kor_cs mul rbc failed");
                        node.mul
                            .drain_rbc_output()
                            .await
                            .expect("kor_cs mul drain_rbc failed");
                    }
                    _ => warn!("unexpected message type"),
                }
            }
        });
    }
    set
}

// ── KOrCS e2e ──────────────────────────────────────────────────────────────────
//
// Computes [OR(b_1,...,b_k)] for secret bit shares. Returns 1 if any bit is 1, else 0.

async fn kor_cs_run(bit_values: &[u64]) {
    let k = bit_values.len();
    let n = 5;
    let t = 1;
    let duration = std::time::Duration::from_secs(10);
    let session = SessionId::new(ProtocolType::EQZ, SessionId::pack_slot24(1, 0, 0), 42);

    let mut bits_per_party: Vec<Vec<RobustShare<Fr>>> = vec![vec![]; n];
    for &bv in bit_values {
        let s = share_value(Fr::from(bv), n, t);
        for p in 0..n {
            bits_per_party[p].push(s[p].clone());
        }
    }
    let prep = make_kor_cs_prep(k, n, t);

    let (network, receivers, _, _) = test_setup(n, vec![]);
    let nodes: Vec<KOrCSNode<Fr, Avid<SessionId>>> =
        (0..n).map(|id| KOrCSNode::new(id, n, t).unwrap()).collect();
    let _recv = spawn_kor_cs_receiver_tasks(n, receivers, nodes.clone(), network.clone());

    let mut run_set = JoinSet::new();
    for i in 0..n {
        let mut node = nodes[i].clone();
        let net = network[i].clone();
        let bits = bits_per_party[i].clone();
        let pp = prep[i].clone();
        run_set.spawn(async move { node.run(bits, pp, session, net, duration).await.unwrap() });
    }
    while let Some(r) = run_set.join_next().await {
        r.unwrap();
    }

    let mut result_shares = vec![];
    for i in 0..n {
        result_shares.push(nodes[i].wait_for_result(session, duration).await.unwrap());
    }
    let (_, result) = RobustShare::recover_secret(&result_shares, n, t).unwrap();
    let expected = Fr::from(if bit_values.iter().any(|&b| b == 1) {
        1u64
    } else {
        0u64
    });
    assert_eq!(
        result, expected,
        "kor_cs expected {expected:?}, got {result:?}"
    );
}

#[tokio::test]
async fn kor_cs_all_zero() {
    setup_tracing();
    kor_cs_run(&[0, 0, 0, 0]).await; // OR(0,0,0,0) = 0
}

#[tokio::test]
async fn kor_cs_all_one() {
    setup_tracing();
    kor_cs_run(&[1, 1, 1, 1]).await; // OR(1,1,1,1) = 1
}

#[tokio::test]
async fn kor_cs_single_one() {
    setup_tracing();
    kor_cs_run(&[0, 0, 1, 0]).await; // OR(0,0,1,0) = 1
}

#[tokio::test]
async fn kor_cs_mixed() {
    setup_tracing();
    kor_cs_run(&[1, 0, 0, 1]).await; // OR(1,0,0,1) = 1
}

// ── KOrCL receiver ─────────────────────────────────────────────────────────────
//
// Session routing:
//   BatchRecon calling_proto KOr1/KOr2 → kor_cs.mul.batch_recon
//   BatchRecon otherwise               → kor_cs.batch_recon
//   Rbc        calling_proto KOr1/KOr2 → kor_cs.mul.rbc
//   Rbc        otherwise (round_id=1)  → rbc

fn spawn_kor_cl_receiver_tasks(
    num_parties: usize,
    mut receivers: Vec<Vec<Receiver<Vec<u8>>>>,
    nodes: Vec<KOrCLNode<Fr, Avid<SessionId>>>,
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
                    WrappedMessage::BatchRecon(msg) => match msg.session_id.calling_protocol() {
                        Some(ProtocolType::KOr1) | Some(ProtocolType::KOr2) => {
                            node.kor_cs
                                .mul
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("kor_cs mul batch_recon failed");
                            node.kor_cs
                                .mul
                                .drain_batch_recon_output()
                                .await
                                .expect("kor_cs mul drain_batch_recon failed");
                        }
                        _ => {
                            node.kor_cs
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("kor_cs batch_recon failed");
                            node.kor_cs
                                .drain_batch_recon_output()
                                .await
                                .expect("kor_cs drain_batch_recon failed");
                        }
                    },
                    WrappedMessage::Rbc(msg) => match msg.session_id.calling_protocol() {
                        Some(ProtocolType::KOr1) | Some(ProtocolType::KOr2) => {
                            node.kor_cs
                                .mul
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("kor_cs mul rbc failed");
                            node.kor_cs
                                .mul
                                .drain_rbc_output()
                                .await
                                .expect("kor_cs mul drain_rbc failed");
                        }
                        _ => {
                            node.rbc
                                .process(msg, net.clone())
                                .await
                                .expect("kor_cl rbc failed");
                            node.drain_rbc_output()
                                .await
                                .expect("kor_cl drain_rbc failed");
                        }
                    },
                    _ => warn!("unexpected message type"),
                }
            }
        });
    }
    set
}

// ── KOrCL e2e ──────────────────────────────────────────────────────────────────
//
// Protocol 4.3: k-ary OR with log-round reduction. Returns 1 if any bit is 1, else 0.

async fn kor_cl_run(bit_values: &[u64]) {
    let k = bit_values.len();
    let n = 5;
    let t = 1;
    let m = (k as u32).ilog2() as usize + 1;
    let duration = std::time::Duration::from_secs(10);
    let session = SessionId::new(ProtocolType::EQZ, SessionId::pack_slot24(1, 0, 0), 42);

    let mut bits_per_party: Vec<Vec<RobustShare<Fr>>> = vec![vec![]; n];
    for &bv in bit_values {
        let s = share_value(Fr::from(bv), n, t);
        for p in 0..n {
            bits_per_party[p].push(s[p].clone());
        }
    }
    let prandm_prep = make_prandm_prep(k, m, n, t);
    let kor_cs_prep = make_kor_cs_prep(m, n, t);

    let (network, receivers, _, _) = test_setup(n, vec![]);
    let nodes: Vec<KOrCLNode<Fr, Avid<SessionId>>> =
        (0..n).map(|id| KOrCLNode::new(id, n, t).unwrap()).collect();
    let _recv = spawn_kor_cl_receiver_tasks(n, receivers, nodes.clone(), network.clone());

    let mut run_set = JoinSet::new();
    for i in 0..n {
        let mut node = nodes[i].clone();
        let net = network[i].clone();
        let bits = bits_per_party[i].clone();
        let pp = prandm_prep[i].clone();
        let ks_pp = kor_cs_prep[i].clone();
        run_set.spawn(async move {
            node.run(bits, pp, ks_pp, session, net, duration)
                .await
                .unwrap()
        });
    }

    let result_shares = collect_result_shares(run_set).await;
    let (_, result) = RobustShare::recover_secret(&result_shares, n, t).unwrap();
    let expected = Fr::from(if bit_values.iter().any(|&b| b == 1) {
        1u64
    } else {
        0u64
    });
    assert_eq!(
        result, expected,
        "kor_cl expected {expected:?}, got {result:?}"
    );
}

#[tokio::test]
async fn kor_cl_all_zero() {
    setup_tracing();
    kor_cl_run(&[0, 0, 0, 0, 0, 0, 0, 0]).await; // OR of 8 zeros = 0
}

#[tokio::test]
async fn kor_cl_all_one() {
    setup_tracing();
    kor_cl_run(&[1, 1, 1, 1, 1, 1, 1, 1]).await; // OR of 8 ones = 1
}

#[tokio::test]
async fn kor_cl_single_one() {
    setup_tracing();
    kor_cl_run(&[0, 0, 0, 1, 0, 0, 0, 0]).await; // single 1 among 8 zeros = 1
}

// ── EQZ receiver ───────────────────────────────────────────────────────────────
//
// Session routing:
//   BatchRecon calling_proto KOr1/KOr2 → kor_cl.kor_cs.mul.batch_recon
//   BatchRecon otherwise               → kor_cl.kor_cs.batch_recon
//   Rbc        calling_proto KOr1/KOr2 → kor_cl.kor_cs.mul.rbc
//   Rbc        otherwise round_id=0    → rbc        (EQZ masking broadcast)
//   Rbc        otherwise round_id=1    → kor_cl.rbc (KOrCL masking broadcast)

fn spawn_eqz_receiver_tasks(
    num_parties: usize,
    mut receivers: Vec<Vec<Receiver<Vec<u8>>>>,
    nodes: Vec<EQZNode<Fr, Avid<SessionId>>>,
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
                    WrappedMessage::BatchRecon(msg) => match msg.session_id.calling_protocol() {
                        Some(ProtocolType::KOr1) | Some(ProtocolType::KOr2) => {
                            node.kor_cl
                                .kor_cs
                                .mul
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("kor_cs mul batch_recon failed");
                            node.kor_cl
                                .kor_cs
                                .mul
                                .drain_batch_recon_output()
                                .await
                                .expect("kor_cs mul drain_batch_recon failed");
                        }
                        _ => {
                            node.kor_cl
                                .kor_cs
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("kor_cs batch_recon failed");
                            node.kor_cl
                                .kor_cs
                                .drain_batch_recon_output()
                                .await
                                .expect("kor_cs drain_batch_recon failed");
                        }
                    },
                    WrappedMessage::Rbc(msg) => match msg.session_id.calling_protocol() {
                        Some(ProtocolType::KOr1) | Some(ProtocolType::KOr2) => {
                            node.kor_cl
                                .kor_cs
                                .mul
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("kor_cs mul rbc failed");
                            node.kor_cl
                                .kor_cs
                                .mul
                                .drain_rbc_output()
                                .await
                                .expect("kor_cs mul drain_rbc failed");
                        }
                        _ => match msg.session_id.round_id() {
                            0 => {
                                node.rbc
                                    .process(msg, net.clone())
                                    .await
                                    .expect("eqz rbc failed");
                                node.drain_rbc_output().await.expect("eqz drain_rbc failed");
                            }
                            1 => {
                                node.kor_cl
                                    .rbc
                                    .process(msg, net.clone())
                                    .await
                                    .expect("kor_cl rbc failed");
                                node.kor_cl
                                    .drain_rbc_output()
                                    .await
                                    .expect("kor_cl drain_rbc failed");
                            }
                            r => warn!("unexpected Rbc round_id {r}"),
                        },
                    },
                    _ => warn!("unexpected message type"),
                }
            }
        });
    }
    set
}

// ── EQZ e2e ────────────────────────────────────────────────────────────────────
//
// Protocol 3.7: computes [a = 0] for a k-bit value a.
// Returns 1 if a = 0, 0 otherwise.

async fn eqz_run(a_val: u64, k: usize) {
    let n = 5;
    let t = 1;
    let m = (k as u32).ilog2() as usize + 1;
    let duration = std::time::Duration::from_secs(10);
    let session = SessionId::new(ProtocolType::EQZ, SessionId::pack_slot24(1, 0, 0), 42);

    let a_shares = share_value(Fr::from(a_val), n, t);
    let prandm_prep = make_prandm_prep(k, k, n, t);
    let kor_cl_prandm = make_prandm_prep(k, m, n, t);
    let kor_cs_prep = make_kor_cs_prep(m, n, t);

    let (network, receivers, _, _) = test_setup(n, vec![]);
    let nodes: Vec<EQZNode<Fr, Avid<SessionId>>> =
        (0..n).map(|id| EQZNode::new(id, n, t).unwrap()).collect();
    let _recv = spawn_eqz_receiver_tasks(n, receivers, nodes.clone(), network.clone());

    let mut run_set = JoinSet::new();
    for i in 0..n {
        let mut node = nodes[i].clone();
        let net = network[i].clone();
        let a_s = a_shares[i].clone();
        let pp = prandm_prep[i].clone();
        let kl_pp = kor_cl_prandm[i].clone();
        let ks_pp = kor_cs_prep[i].clone();
        run_set.spawn(async move {
            node.run(a_s, k, pp, kl_pp, ks_pp, session, net, duration)
                .await
                .unwrap()
        });
    }

    let result_shares = collect_result_shares(run_set).await;
    let (_, result) = RobustShare::recover_secret(&result_shares, n, t).unwrap();
    let expected = Fr::from(if a_val == 0 { 1u64 } else { 0u64 });
    assert_eq!(
        result, expected,
        "eqz({a_val}, k={k}) expected {expected:?}, got {result:?}"
    );
}

#[tokio::test]
async fn eqz_zero() {
    setup_tracing();
    eqz_run(0, 8).await; // 0 = 0 → 1
}

#[tokio::test]
async fn eqz_nonzero() {
    setup_tracing();
    eqz_run(42, 8).await; // 42 ≠ 0 → 0
}

#[tokio::test]
async fn eqz_one() {
    setup_tracing();
    eqz_run(1, 8).await; // 1 ≠ 0 → 0
}

#[tokio::test]
async fn eqz_max() {
    setup_tracing();
    eqz_run(255, 8).await; // max 8-bit ≠ 0 → 0
}

#[tokio::test]
async fn eqz_all_but_lsb() {
    setup_tracing();
    eqz_run(254, 8).await; // 11111110 ≠ 0 → 0
}
