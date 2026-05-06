pub mod utils;

use crate::utils::test_utils::{fan_in_inboxes, setup_tracing, test_setup};
use ark_bls12_381::Fr;
use ark_ff::{Field, UniformRand};
use ark_std::rand::Rng;
use ark_std::test_rng;
use std::sync::Arc;
use stoffelmpc_mpc::common::RBC;
use stoffelmpc_mpc::common::{rbc::rbc::Avid, ProtocolSessionId, SecretSharingScheme};
use stoffelmpc_mpc::honeybadger::comparison::bit_ltc1::BitLTC1Node;
use stoffelmpc_mpc::honeybadger::comparison::ltz::LTZNode;
use stoffelmpc_mpc::honeybadger::comparison::mod2::Mod2Node;
use stoffelmpc_mpc::honeybadger::comparison::mod2m::Mod2mNode;
use stoffelmpc_mpc::honeybadger::comparison::trunc::TruncNode;
use stoffelmpc_mpc::honeybadger::comparison::{PRandMPrep, PreMulCPrep};
use stoffelmpc_mpc::honeybadger::{
    comparison::pre_mulc::PreMulCNode, robust_interpolate::robust_interpolate::RobustShare,
    triple_gen::ShamirBeaverTriple, ProtocolType, SessionId, WrappedMessage,
};
use stoffelmpc_network::fake_network::{FakeNetwork, SenderId};
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinSet;
use tracing::warn;

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

fn share_bits_of(v: u64, k: usize, n: usize, t: usize) -> Vec<Vec<RobustShare<Fr>>> {
    let mut per_party: Vec<Vec<RobustShare<Fr>>> = vec![vec![]; n];
    for i in 0..k {
        let bit = Fr::from((v >> i) & 1);
        let shares = share_value(bit, n, t);
        for p in 0..n {
            per_party[p].push(shares[p].clone());
        }
    }
    per_party
}

/// Synthetic PreMulC preprocessing: r[i] nonzero random, w[0]=r[0], w[i]=r[i]/r[i-1], z[i]=1/r[i].
/// Satisfies prefix_product(w)[j] * z[j] = 1 for all j.
fn make_premulc_prep(pk: usize, n: usize, t: usize) -> Vec<PreMulCPrep<Fr>> {
    let mut rng = test_rng();
    let r_vals: Vec<Fr> = (0..pk)
        .map(|_| loop {
            let v = Fr::rand(&mut rng);
            if v != Fr::from(0u64) {
                break v;
            }
        })
        .collect();
    let w_vals: Vec<Fr> = (0..pk)
        .map(|i| {
            if i == 0 {
                r_vals[0]
            } else {
                r_vals[i] * r_vals[i - 1].inverse().unwrap()
            }
        })
        .collect();
    let z_vals: Vec<Fr> = r_vals.iter().map(|r| r.inverse().unwrap()).collect();
    let triples = make_triples(n, t, pk);
    let mut w_pp = vec![vec![]; n];
    let mut z_pp = vec![vec![]; n];
    for i in 0..pk {
        let sw = share_value(w_vals[i], n, t);
        let sz = share_value(z_vals[i], n, t);
        for p in 0..n {
            w_pp[p].push(sw[p].clone());
            z_pp[p].push(sz[p].clone());
        }
    }
    (0..n)
        .map(|i| PreMulCPrep {
            w: w_pp[i].clone(),
            z: z_pp[i].clone(),
            triples: triples[i].clone(),
        })
        .collect()
}

/// PRandM(dp_bits, m): r'' is dp_bits-wide, r' is m-bit with full bit decomposition.
fn make_prandm_prep(dp_bits: usize, m: usize, n: usize, t: usize) -> Vec<PRandMPrep<Fr>> {
    let mut rng = test_rng();
    let r_dp = Fr::from(rng.gen::<u64>() % (1u64 << dp_bits as u64));
    let r_prime_int = rng.gen::<u64>() % (1u64 << m as u64);
    let r_dp_shares = share_value(r_dp, n, t);
    let r_prime_shares = share_value(Fr::from(r_prime_int), n, t);
    let r_prime_bits_pp = share_bits_of(r_prime_int, m, n, t);
    (0..n)
        .map(|i| PRandMPrep {
            r_double_prime: r_dp_shares[i].clone(),
            r_prime: r_prime_shares[i].clone(),
            r_prime_bits: r_prime_bits_pp[i].clone(),
        })
        .collect()
}

/// Mod2 preprocessing: r'' is (k-1)-bit, r' is a random bit, no bit decomposition.
fn make_mod2_prep(k: usize, n: usize, t: usize) -> Vec<PRandMPrep<Fr>> {
    let mut rng = test_rng();
    let r_dp = Fr::from(rng.gen::<u64>() % (1u64 << (k as u64 - 1)));
    let r_zp = Fr::from(rng.gen::<u64>() & 1);
    let r_dp_shares = share_value(r_dp, n, t);
    let r_zp_shares = share_value(r_zp, n, t);
    (0..n)
        .map(|i| PRandMPrep {
            r_double_prime: r_dp_shares[i].clone(),
            r_prime: r_zp_shares[i].clone(),
            r_prime_bits: vec![],
        })
        .collect()
}

async fn collect_result_shares(mut set: JoinSet<RobustShare<Fr>>) -> Vec<RobustShare<Fr>> {
    let mut shares = vec![];
    while let Some(r) = set.join_next().await {
        shares.push(r.unwrap());
    }
    shares
}

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
// Verifies p[j] = a[0] * … * a[j].

#[tokio::test]
async fn premulc_online_e2e() {
    setup_tracing();
    let n = 5;
    let t = 1;
    let k = 4;
    let duration = std::time::Duration::from_secs(10);
    let session = SessionId::new(ProtocolType::LTZ, SessionId::pack_slot24(2, 0, 0), 42);

    let mut rng = test_rng();
    let a_vals: Vec<Fr> = (0..k).map(|_| Fr::rand(&mut rng)).collect();

    let mut a_pp: Vec<Vec<RobustShare<Fr>>> = vec![vec![]; n];
    for i in 0..k {
        let sa = share_value(a_vals[i], n, t);
        for p in 0..n {
            a_pp[p].push(sa[p].clone());
        }
    }

    let premulc_prep = make_premulc_prep(k, n, t);
    let (network, receivers, _, _) = test_setup(n, vec![]);
    let nodes: Vec<PreMulCNode<Fr, Avid<SessionId>>> = (0..n)
        .map(|id| PreMulCNode::new(id, n, t).unwrap())
        .collect();
    let _recv = spawn_premulc_receiver_tasks(n, receivers, nodes.clone(), network.clone());

    let mut init_set = JoinSet::new();
    for i in 0..n {
        let mut node = nodes[i].clone();
        let net = network[i].clone();
        let a = a_pp[i].clone();
        let prep = premulc_prep[i].clone();
        init_set.spawn(async move { node.init(a, prep, session, net, duration).await.unwrap() });
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
// Opens c = 2^{k-1} + a + 2*r'' + r0' and computes [a0] = XOR(c mod 2, [r0']).

async fn mod2_run(a_val: u64, k: usize) {
    let n = 5;
    let t = 1;
    let duration = std::time::Duration::from_secs(10);
    let session = SessionId::new(ProtocolType::LTZ, SessionId::pack_slot24(1, 0, 0), 42);

    let a_shares = share_value(Fr::from(a_val), n, t);
    let prep_per_party = make_mod2_prep(k, n, t);

    let (network, receivers, _, _) = test_setup(n, vec![]);
    let nodes: Vec<Mod2Node<Fr, Avid<SessionId>>> = (0..n)
        .map(|id| Mod2Node::<Fr, Avid<SessionId>>::new(id, n, t).unwrap())
        .collect();

    let _recv = spawn_mod2_receiver_tasks(n, receivers, nodes.clone(), network.clone());

    // Each party calls init.
    let mut init_set = JoinSet::new();
    for i in 0..n {
        let mut node = nodes[i].clone();
        let (a_s, net, prep) = (
            a_shares[i].clone(),
            network[i].clone(),
            prep_per_party[i].clone(),
        );
        init_set.spawn(async move { node.init(a_s, k, prep, session, net).await.unwrap() });
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
    assert_eq!(
        a0,
        Fr::from(a_val & 1),
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

// ── BitLTC1 receiver ───────────────────────────────────────────────────────────
//
// Round routing for WrappedMessage::BatchRecon:
//   round_id=0  →  pre_mul_c.batch_recon
//   round_id=1  →  pre_mul_c.mul.batch_recon
// Round routing for WrappedMessage::Rbc:
//   round_id=2  →  pre_mul_c.mul.rbc
//   round_id=0  →  mod2.rbc

fn spawn_bitltc1_receiver_tasks(
    num_parties: usize,
    mut receivers: Vec<Vec<Receiver<Vec<u8>>>>,
    nodes: Vec<BitLTC1Node<Fr, Avid<SessionId>>>,
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
                            node.pre_mul_c
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("premulc batch_recon failed");
                            node.pre_mul_c
                                .drain_batch_recon_output()
                                .await
                                .expect("premulc drain failed");
                        }
                        1 => {
                            node.pre_mul_c
                                .mul
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("mul batch_recon failed");
                            node.pre_mul_c
                                .mul
                                .drain_batch_recon_output()
                                .await
                                .expect("mul drain failed");
                        }
                        _ => warn!("unexpected BatchRecon round_id"),
                    },
                    WrappedMessage::Rbc(msg) => match msg.session_id.round_id() {
                        2 => {
                            node.pre_mul_c
                                .mul
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("mul rbc failed");
                            node.pre_mul_c
                                .mul
                                .drain_rbc_output()
                                .await
                                .expect("mul drain_rbc failed");
                        }
                        0 => {
                            node.mod2
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("mod2 rbc failed");
                            node.mod2
                                .drain_rbc_output()
                                .await
                                .expect("mod2 drain_rbc failed");
                        }
                        _ => warn!("unexpected Rbc round_id"),
                    },
                    _ => warn!("unexpected message type"),
                }
            }
        });
    }
    set
}

// ── BitLTC1 e2e ────────────────────────────────────────────────────────────────
//
// Computes [a <_k b] where a is a clear k-bit value and b is secret-shared.

async fn bit_ltc1_run(a_val: u64, b_val: u64, k: usize) {
    let n = 5;
    let t = 1;
    let duration = std::time::Duration::from_secs(10);
    let session = SessionId::new(ProtocolType::LTZ, SessionId::pack_slot24(1, 0, 0), 42);

    let pk = BitLTC1Node::<Fr, Avid<SessionId>>::premulc_k(k, t);
    let b_bits_per_party = share_bits_of(b_val, k, n, t);
    let premulc_prep = make_premulc_prep(pk, n, t);
    let mod2_prep = make_mod2_prep(k, n, t);

    let (network, receivers, _, _) = test_setup(n, vec![]);
    let nodes: Vec<BitLTC1Node<Fr, Avid<SessionId>>> = (0..n)
        .map(|id| BitLTC1Node::new(id, n, t).unwrap())
        .collect();
    let _recv = spawn_bitltc1_receiver_tasks(n, receivers, nodes.clone(), network.clone());

    let mut run_set = JoinSet::new();
    for i in 0..n {
        let mut node = nodes[i].clone();
        let net = network[i].clone();
        let b_bits = b_bits_per_party[i].clone();
        let pp = premulc_prep[i].clone();
        let m2p = mod2_prep[i].clone();
        run_set.spawn(async move {
            node.run(Fr::from(a_val), b_bits, pp, m2p, session, net, duration)
                .await
                .unwrap()
        });
    }

    let result_shares = collect_result_shares(run_set).await;
    let (_, result) = RobustShare::recover_secret(&result_shares, n, t).unwrap();
    let expected = Fr::from(if a_val < b_val { 1u64 } else { 0u64 });
    assert_eq!(
        result, expected,
        "bit_ltc1({a_val} < {b_val}) expected {expected:?}, got {result:?}"
    );
}

#[tokio::test]
async fn bit_ltc1_a_less_than_b() {
    setup_tracing();
    bit_ltc1_run(3, 7, 4).await;
}

#[tokio::test]
async fn bit_ltc1_a_greater_than_b() {
    setup_tracing();
    bit_ltc1_run(10, 4, 4).await;
}

#[tokio::test]
async fn bit_ltc1_a_equal_b() {
    setup_tracing();
    bit_ltc1_run(7, 7, 4).await;
}

fn spawn_mod2m_receiver_tasks(
    num_parties: usize,
    mut receivers: Vec<Vec<Receiver<Vec<u8>>>>,
    nodes: Vec<Mod2mNode<Fr, Avid<SessionId>>>,
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
                            node.bit_ltc1
                                .pre_mul_c
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("premulc batch_recon failed");
                            node.bit_ltc1
                                .pre_mul_c
                                .drain_batch_recon_output()
                                .await
                                .expect("premulc drain failed");
                        }
                        1 => {
                            node.bit_ltc1
                                .pre_mul_c
                                .mul
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("mul batch_recon failed");
                            node.bit_ltc1
                                .pre_mul_c
                                .mul
                                .drain_batch_recon_output()
                                .await
                                .expect("mul drain failed");
                        }
                        _ => warn!("unexpected BatchRecon round_id"),
                    },
                    WrappedMessage::Rbc(msg) => match msg.session_id.round_id() {
                        1 => {
                            node.rbc
                                .process(msg, net.clone())
                                .await
                                .expect("mod2m rbc failed");
                            node.drain_rbc_output()
                                .await
                                .expect("mod2m drain_rbc failed");
                        }
                        2 => {
                            node.bit_ltc1
                                .pre_mul_c
                                .mul
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("mul rbc failed");
                            node.bit_ltc1
                                .pre_mul_c
                                .mul
                                .drain_rbc_output()
                                .await
                                .expect("mul drain_rbc failed");
                        }
                        0 => {
                            node.bit_ltc1
                                .mod2
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("mod2 rbc failed");
                            node.bit_ltc1
                                .mod2
                                .drain_rbc_output()
                                .await
                                .expect("mod2 drain_rbc failed");
                        }
                        _ => warn!("unexpected Rbc round_id"),
                    },
                    _ => warn!("unexpected message type"),
                }
            }
        });
    }
    set
}

async fn mod2m_run(a_val: u64, k: usize, m: usize) {
    let n = 5;
    let t = 1;
    let duration = std::time::Duration::from_secs(10);
    let session = SessionId::new(ProtocolType::LTZ, SessionId::pack_slot24(1, 0, 0), 42);

    let pk = BitLTC1Node::<Fr, Avid<SessionId>>::premulc_k(m, t);
    let a_shares = share_value(Fr::from(a_val), n, t);
    let prandm_prep = make_prandm_prep(k - m, m, n, t);
    let premulc_prep = make_premulc_prep(pk, n, t);
    let mod2_prep = make_mod2_prep(k, n, t);

    let (network, receivers, _, _) = test_setup(n, vec![]);
    let nodes: Vec<Mod2mNode<Fr, Avid<SessionId>>> =
        (0..n).map(|id| Mod2mNode::new(id, n, t).unwrap()).collect();
    let _recv = spawn_mod2m_receiver_tasks(n, receivers, nodes.clone(), network.clone());

    let mut run_set = JoinSet::new();
    for i in 0..n {
        let mut node = nodes[i].clone();
        let net = network[i].clone();
        let a_s = a_shares[i].clone();
        let pp = prandm_prep[i].clone();
        let pmc = premulc_prep[i].clone();
        let m2p = mod2_prep[i].clone();
        run_set.spawn(async move {
            node.run(a_s, k, m, pp, pmc, m2p, session, net, duration)
                .await
                .unwrap()
        });
    }

    let result_shares = collect_result_shares(run_set).await;
    let (_, a_mod) = RobustShare::recover_secret(&result_shares, n, t).unwrap();
    let expected = Fr::from(a_val % (1u64 << m as u64));
    assert_eq!(
        a_mod, expected,
        "mod2m({a_val}, {m}) expected {expected:?}, got {a_mod:?}"
    );
}

#[tokio::test]
async fn mod2m_basic() {
    setup_tracing();
    mod2m_run(42, 8, 4).await; // 42 mod 16 = 10
}

#[tokio::test]
async fn mod2m_zero() {
    setup_tracing();
    mod2m_run(0, 8, 4).await;
}

#[tokio::test]
async fn mod2m_boundary() {
    setup_tracing();
    mod2m_run(16, 8, 4).await; // 16 mod 16 = 0
}

#[tokio::test]
async fn mod2m_max_low_bits() {
    setup_tracing();
    mod2m_run(15, 8, 4).await; // 15 mod 16 = 15
}

// ── Trunc receiver ─────────────────────────────────────────────────────────────

fn spawn_trunc_receiver_tasks(
    num_parties: usize,
    mut receivers: Vec<Vec<Receiver<Vec<u8>>>>,
    nodes: Vec<TruncNode<Fr, Avid<SessionId>>>,
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
                            node.mod2m
                                .bit_ltc1
                                .pre_mul_c
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("premulc batch_recon failed");
                            node.mod2m
                                .bit_ltc1
                                .pre_mul_c
                                .drain_batch_recon_output()
                                .await
                                .expect("premulc drain failed");
                        }
                        1 => {
                            node.mod2m
                                .bit_ltc1
                                .pre_mul_c
                                .mul
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("mul batch_recon failed");
                            node.mod2m
                                .bit_ltc1
                                .pre_mul_c
                                .mul
                                .drain_batch_recon_output()
                                .await
                                .expect("mul drain failed");
                        }
                        _ => warn!("unexpected BatchRecon round_id"),
                    },
                    WrappedMessage::Rbc(msg) => match msg.session_id.round_id() {
                        1 => {
                            node.mod2m
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("mod2m rbc failed");
                            node.mod2m
                                .drain_rbc_output()
                                .await
                                .expect("mod2m drain_rbc failed");
                        }
                        2 => {
                            node.mod2m
                                .bit_ltc1
                                .pre_mul_c
                                .mul
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("mul rbc failed");
                            node.mod2m
                                .bit_ltc1
                                .pre_mul_c
                                .mul
                                .drain_rbc_output()
                                .await
                                .expect("mul drain_rbc failed");
                        }
                        0 => {
                            node.mod2m
                                .bit_ltc1
                                .mod2
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("mod2 rbc failed");
                            node.mod2m
                                .bit_ltc1
                                .mod2
                                .drain_rbc_output()
                                .await
                                .expect("mod2 drain_rbc failed");
                        }
                        _ => warn!("unexpected Rbc round_id"),
                    },
                    _ => warn!("unexpected message type"),
                }
            }
        });
    }
    set
}

// ── Trunc e2e ──────────────────────────────────────────────────────────────────
//
// Protocol 3.3: computes [floor(a / 2^m)] from [a] and PRandM(k, m) preprocessing.

async fn trunc_run(a_val: u64, k: usize, m: usize) {
    let n = 5;
    let t = 1;
    let duration = std::time::Duration::from_secs(10);
    let session = SessionId::new(ProtocolType::LTZ, SessionId::pack_slot24(1, 0, 0), 42);

    let pk = BitLTC1Node::<Fr, Avid<SessionId>>::premulc_k(m, t);
    let a_shares = share_value(Fr::from(a_val), n, t);
    let prandm_prep = make_prandm_prep(k - m, m, n, t);
    let premulc_prep = make_premulc_prep(pk, n, t);
    let mod2_prep = make_mod2_prep(k, n, t);

    let (network, receivers, _, _) = test_setup(n, vec![]);
    let nodes: Vec<TruncNode<Fr, Avid<SessionId>>> =
        (0..n).map(|id| TruncNode::new(id, n, t).unwrap()).collect();
    let _recv = spawn_trunc_receiver_tasks(n, receivers, nodes.clone(), network.clone());

    let mut run_set = JoinSet::new();
    for i in 0..n {
        let mut node = nodes[i].clone();
        let net = network[i].clone();
        let a_s = a_shares[i].clone();
        let pp = prandm_prep[i].clone();
        let pmc = premulc_prep[i].clone();
        let m2p = mod2_prep[i].clone();
        run_set.spawn(async move {
            node.run(a_s, k, m, pp, pmc, m2p, session, net, duration)
                .await
                .unwrap()
        });
    }

    let result_shares = collect_result_shares(run_set).await;
    let (_, truncated) = RobustShare::recover_secret(&result_shares, n, t).unwrap();
    let expected = Fr::from(a_val >> m as u64);
    assert_eq!(
        truncated, expected,
        "trunc({a_val}, {m}) expected {expected:?}, got {truncated:?}"
    );
}

#[tokio::test]
async fn trunc_basic() {
    setup_tracing();
    trunc_run(42, 8, 3).await; // floor(42 / 8) = 5
}

#[tokio::test]
async fn trunc_zero() {
    setup_tracing();
    trunc_run(0, 8, 4).await;
}

#[tokio::test]
async fn trunc_exact_power_of_two() {
    setup_tracing();
    trunc_run(16, 8, 4).await; // floor(16 / 16) = 1
}

#[tokio::test]
async fn trunc_below_divisor() {
    setup_tracing();
    trunc_run(15, 8, 4).await; // floor(15 / 16) = 0
}

#[tokio::test]
async fn trunc_max_value() {
    setup_tracing();
    trunc_run(255, 8, 4).await; // floor(255 / 16) = 15
}

#[tokio::test]
async fn trunc_small_shift() {
    setup_tracing();
    trunc_run(100, 8, 2).await; // floor(100 / 4) = 25
}

// ── LTZ receiver ───────────────────────────────────────────────────────────────

fn spawn_ltz_receiver_tasks(
    num_parties: usize,
    mut receivers: Vec<Vec<Receiver<Vec<u8>>>>,
    nodes: Vec<LTZNode<Fr, Avid<SessionId>>>,
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
                            node.trunc
                                .mod2m
                                .bit_ltc1
                                .pre_mul_c
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("premulc batch_recon failed");
                            node.trunc
                                .mod2m
                                .bit_ltc1
                                .pre_mul_c
                                .drain_batch_recon_output()
                                .await
                                .expect("premulc drain failed");
                        }
                        1 => {
                            node.trunc
                                .mod2m
                                .bit_ltc1
                                .pre_mul_c
                                .mul
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("mul batch_recon failed");
                            node.trunc
                                .mod2m
                                .bit_ltc1
                                .pre_mul_c
                                .mul
                                .drain_batch_recon_output()
                                .await
                                .expect("mul drain failed");
                        }
                        _ => warn!("unexpected BatchRecon round_id"),
                    },
                    WrappedMessage::Rbc(msg) => match msg.session_id.round_id() {
                        1 => {
                            node.trunc
                                .mod2m
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("mod2m rbc failed");
                            node.trunc
                                .mod2m
                                .drain_rbc_output()
                                .await
                                .expect("mod2m drain_rbc failed");
                        }
                        2 => {
                            node.trunc
                                .mod2m
                                .bit_ltc1
                                .pre_mul_c
                                .mul
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("mul rbc failed");
                            node.trunc
                                .mod2m
                                .bit_ltc1
                                .pre_mul_c
                                .mul
                                .drain_rbc_output()
                                .await
                                .expect("mul drain_rbc failed");
                        }
                        0 => {
                            node.trunc
                                .mod2m
                                .bit_ltc1
                                .mod2
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("mod2 rbc failed");
                            node.trunc
                                .mod2m
                                .bit_ltc1
                                .mod2
                                .drain_rbc_output()
                                .await
                                .expect("mod2 drain_rbc failed");
                        }
                        _ => warn!("unexpected Rbc round_id"),
                    },
                    _ => warn!("unexpected message type"),
                }
            }
        });
    }
    set
}

// ── LTZ e2e ────────────────────────────────────────────────────────────────────
//
// Protocol 3.6: computes [a < 0] for a k-bit signed value.
// Internally calls Trunc([a], k, k-1), so m = k-1.

async fn ltz_run(a_signed: i64, k: usize) {
    let n = 5;
    let t = 1;
    let m = k - 1;
    let duration = std::time::Duration::from_secs(10);
    let session = SessionId::new(ProtocolType::LTZ, SessionId::pack_slot24(1, 0, 0), 42);

    let pk = BitLTC1Node::<Fr, Avid<SessionId>>::premulc_k(m, t);
    let a_field = if a_signed < 0 {
        -Fr::from((-a_signed) as u64)
    } else {
        Fr::from(a_signed as u64)
    };
    let a_shares = share_value(a_field, n, t);
    let prandm_prep = make_prandm_prep(1, m, n, t);
    let premulc_prep = make_premulc_prep(pk, n, t);
    let mod2_prep = make_mod2_prep(k, n, t);

    let (network, receivers, _, _) = test_setup(n, vec![]);
    let nodes: Vec<LTZNode<Fr, Avid<SessionId>>> =
        (0..n).map(|id| LTZNode::new(id, n, t).unwrap()).collect();
    let _recv = spawn_ltz_receiver_tasks(n, receivers, nodes.clone(), network.clone());

    let mut run_set = JoinSet::new();
    for i in 0..n {
        let mut node = nodes[i].clone();
        let net = network[i].clone();
        let a_s = a_shares[i].clone();
        let pp = prandm_prep[i].clone();
        let pmc = premulc_prep[i].clone();
        let m2p = mod2_prep[i].clone();
        run_set.spawn(async move {
            node.run(a_s, k, pp, pmc, m2p, session, net, duration)
                .await
                .unwrap()
        });
    }

    let result_shares = collect_result_shares(run_set).await;
    let (_, result) = RobustShare::recover_secret(&result_shares, n, t).unwrap();
    let expected = Fr::from(if a_signed < 0 { 1u64 } else { 0u64 });
    assert_eq!(
        result, expected,
        "ltz({a_signed}) expected {expected:?}, got {result:?}"
    );
}

#[tokio::test]
async fn ltz_negative() {
    setup_tracing();
    ltz_run(-7, 8).await;
}

#[tokio::test]
async fn ltz_positive() {
    setup_tracing();
    ltz_run(42, 8).await;
}

#[tokio::test]
async fn ltz_zero() {
    setup_tracing();
    ltz_run(0, 8).await;
}

#[tokio::test]
async fn ltz_minus_one() {
    setup_tracing();
    ltz_run(-1, 8).await;
}

#[tokio::test]
async fn ltz_most_negative() {
    setup_tracing();
    ltz_run(-128, 8).await;
}

#[tokio::test]
async fn ltz_max_positive() {
    setup_tracing();
    ltz_run(127, 8).await;
}
