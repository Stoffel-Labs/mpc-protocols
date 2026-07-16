pub mod utils;

use crate::utils::comparison_utils::{
    field_to_signed_real, make_apprec_prep, make_fpdiv_prep, make_mod2_prep, make_prebitlt_prep,
    make_premod2m_prep, make_premulc_prep, make_triples, make_zero_shares, share_signed_fixed,
    share_value,
};
use crate::utils::test_utils::{fan_in_inboxes, setup_tracing, test_setup};
use ark_bls12_381::Fr;
use ark_ff::{BigInteger, Field, PrimeField, UniformRand};
use ark_std::test_rng;
use std::sync::Arc;
use stoffelcrypto::common::RBC;
use stoffelcrypto::common::{rbc::rbc::Avid, ProtocolSessionId, SecretSharingScheme};
use stoffelcrypto::honeybadger::bitwise::app_rec::AppRecNode;
use stoffelcrypto::honeybadger::bitwise::bit_dec::BitDecNode;
use stoffelcrypto::honeybadger::bitwise::mod2::Mod2Node;
use stoffelcrypto::honeybadger::bitwise::pre_bitlt::PreBitLTNode;
use stoffelcrypto::honeybadger::bitwise::pre_mod2m::PreMod2mNode;
use stoffelcrypto::honeybadger::bitwise::pre_mulc::{PreMulCOfflineNode, PreMulCOnlineNode};
use stoffelcrypto::honeybadger::bitwise::suf_mul_inv::SufMulInvNode;
use stoffelcrypto::honeybadger::bitwise::suf_or::SufOrNode;
use stoffelcrypto::honeybadger::fpdiv::fpdiv::FpDivNode;
use stoffelcrypto::honeybadger::{
    robust_interpolate::robust_interpolate::RobustShare, ProtocolType, SessionId, WrappedMessage,
};
use stoffelmpc_network::fake_network::{FakeNetwork, SenderId};
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinSet;
use tracing::warn;

fn spawn_premulc_receiver_tasks(
    num_parties: usize,
    mut receivers: Vec<Vec<Receiver<Vec<u8>>>>,
    nodes: Vec<PreMulCOnlineNode<Fr, Avid<SessionId>>>,
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

fn spawn_premulcoff_receiver_tasks(
    num_parties: usize,
    mut receivers: Vec<Vec<Receiver<Vec<u8>>>>,
    nodes: Vec<PreMulCOfflineNode<Fr, Avid<SessionId>>>,
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
                            node.mul_pub
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("batch_recon process failed");
                            node.mul_pub
                                .drain_batch_recon_output()
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
    let session = SessionId::new(ProtocolType::PreMulCOff, SessionId::pack_slot(1, 0, 0), 42);

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

    let u_zero = make_zero_shares(n, t, k);
    let v_triples = make_triples(n, t, k - 1);
    let (network, receivers, _, _) = test_setup(n, vec![]);
    let nodes: Vec<PreMulCOfflineNode<Fr, Avid<SessionId>>> = (0..n)
        .map(|id| PreMulCOfflineNode::new(id, n, t).unwrap())
        .collect();
    let _recv = spawn_premulcoff_receiver_tasks(n, receivers, nodes.clone(), network.clone());

    let mut init_set = JoinSet::new();
    for i in 0..n {
        let mut node = nodes[i].clone();
        let (r, s, uz, vtri, net) = (
            r_per_party[i].clone(),
            s_per_party[i].clone(),
            u_zero[i].clone(),
            v_triples[i].clone(),
            network[i].clone(),
        );
        init_set.spawn(async move {
            node.generate_preprocessing(r, s, uz, vtri, session, net, duration)
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
        let (w, z, _) = nodes[i]
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
    let session = SessionId::new(ProtocolType::FpDiv, SessionId::pack_slot(2, 0, 0), 42);

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
    let nodes: Vec<PreMulCOnlineNode<Fr, Avid<SessionId>>> = (0..n)
        .map(|id| PreMulCOnlineNode::new(id, n, t).unwrap())
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
        let (ps, _) = nodes[i].wait_for_result(session, duration).await.unwrap();
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
    let session = SessionId::new(ProtocolType::FpDiv, SessionId::pack_slot(1, 0, 0), 42);

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

// ── SufOr receiver ─────────────────────────────────────────────────────────────
// SufOrNode wraps a PreMulCOnlineNode as `inner`; routing is identical to
// spawn_premulc_receiver_tasks, just reached through `node.inner`.

fn spawn_sufor_receiver_tasks(
    num_parties: usize,
    mut receivers: Vec<Vec<Receiver<Vec<u8>>>>,
    nodes: Vec<SufOrNode<Fr, Avid<SessionId>>>,
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
                            node.inner
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("batch_recon process failed");
                            node.inner
                                .drain_batch_recon_output()
                                .await
                                .expect("drain_batch_recon_output failed");
                        } else if round == 1 {
                            node.inner
                                .mul
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("mul.batch_recon process failed");
                            node.inner
                                .mul
                                .drain_batch_recon_output()
                                .await
                                .expect("mul.drain_batch_recon_output failed");
                        } else {
                            warn!("unexpected round_id {round}");
                        }
                    }
                    WrappedMessage::Rbc(msg) => {
                        node.inner
                            .mul
                            .rbc
                            .process(msg, net.clone())
                            .await
                            .expect("rbc process failed");
                        node.inner
                            .mul
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

// ── SufOr e2e ──────────────────────────────────────────────────────────────────
//
// Computes SufOr_j = OR(b_j, ..., b_{k-1}) for each j (0-indexed), and checks
// against the suffix-OR of the plaintext bit pattern.

async fn suf_or_run(bit_vals: Vec<u64>) {
    let n = 5;
    let t = 1;
    let k = bit_vals.len();
    let mul_duration = std::time::Duration::from_secs(10);
    let duration = std::time::Duration::from_secs(10);
    let session = SessionId::new(ProtocolType::FpDiv, SessionId::pack_slot(3, 0, 0), 42);

    let mut b_pp: Vec<Vec<RobustShare<Fr>>> = vec![vec![]; n];
    for &v in &bit_vals {
        let sb = share_value(Fr::from(v), n, t);
        for p in 0..n {
            b_pp[p].push(sb[p].clone());
        }
    }

    let prep = make_premulc_prep(k, n, t);
    let (network, receivers, _, _) = test_setup(n, vec![]);
    let nodes: Vec<SufOrNode<Fr, Avid<SessionId>>> = (0..n)
        .map(|id| SufOrNode::new(id, n, t).unwrap())
        .collect();
    let _recv = spawn_sufor_receiver_tasks(n, receivers, nodes.clone(), network.clone());

    let mut init_set = JoinSet::new();
    for i in 0..n {
        let mut node = nodes[i].clone();
        let net = network[i].clone();
        let bits = b_pp[i].clone();
        let p = prep[i].clone();
        init_set.spawn(async move {
            node.init(bits, p, session, net, mul_duration, duration)
                .await
                .unwrap()
        });
    }
    let mut result_shares: Vec<Vec<RobustShare<Fr>>> = vec![vec![]; k];
    while let Some(r) = init_set.join_next().await {
        let result = r.unwrap();
        assert_eq!(result.len(), k);
        for j in 0..k {
            result_shares[j].push(result[j].clone());
        }
    }

    // Expected suffix OR over plaintext bits.
    let mut expected = vec![0u64; k];
    let mut acc = 0u64;
    for j in (0..k).rev() {
        acc |= bit_vals[j];
        expected[j] = acc;
    }

    for j in 0..k {
        let (_, s_j) = RobustShare::recover_secret(&result_shares[j], n, t).unwrap();
        assert_eq!(
            s_j,
            Fr::from(expected[j]),
            "suf_or mismatch at index {j}: bits={bit_vals:?}"
        );
    }
}

#[tokio::test]
async fn suf_or_mixed() {
    setup_tracing();
    suf_or_run(vec![0, 1, 0, 0]).await;
}

#[tokio::test]
async fn suf_or_all_zero() {
    setup_tracing();
    suf_or_run(vec![0, 0, 0, 0]).await;
}

#[tokio::test]
async fn suf_or_all_one() {
    setup_tracing();
    suf_or_run(vec![1, 1, 1, 1]).await;
}

#[tokio::test]
async fn suf_or_leading_one() {
    setup_tracing();
    suf_or_run(vec![1, 0, 0, 0]).await;
}

// ── SufMulInv receiver ────────────────────────────────────────────────────────
// SufMulInvNode also wraps a PreMulCOnlineNode as `inner`; same routing as
// spawn_sufor_receiver_tasks.

fn spawn_sufmulinv_receiver_tasks(
    num_parties: usize,
    mut receivers: Vec<Vec<Receiver<Vec<u8>>>>,
    nodes: Vec<SufMulInvNode<Fr, Avid<SessionId>>>,
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
                            node.inner
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("batch_recon process failed");
                            node.inner
                                .drain_batch_recon_output()
                                .await
                                .expect("drain_batch_recon_output failed");
                        } else if round == 1 {
                            node.inner
                                .mul
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("mul.batch_recon process failed");
                            node.inner
                                .mul
                                .drain_batch_recon_output()
                                .await
                                .expect("mul.drain_batch_recon_output failed");
                        } else {
                            warn!("unexpected round_id {round}");
                        }
                    }
                    WrappedMessage::Rbc(msg) => {
                        node.inner
                            .mul
                            .rbc
                            .process(msg, net.clone())
                            .await
                            .expect("rbc process failed");
                        node.inner
                            .mul
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

// ── SufMulInv e2e ────────────────────────────────────────────────────────────
//
// For non-zero inputs [a_0, ..., a_{k-1}], computes suffix products
// S_j = a_j * ... * a_{k-1} and their inverses S_j^{-1}.

#[tokio::test]
async fn suf_mul_inv_e2e() {
    setup_tracing();
    let n = 5;
    let t = 1;
    let k = 4;
    let mul_duration = std::time::Duration::from_secs(10);
    let duration = std::time::Duration::from_secs(10);
    let session = SessionId::new(ProtocolType::FpDiv, SessionId::pack_slot(4, 0, 0), 42);

    let mut rng = test_rng();
    let a_vals: Vec<Fr> = (0..k)
        .map(|_| loop {
            let v = Fr::rand(&mut rng);
            if v != Fr::from(0u64) {
                break v;
            }
        })
        .collect();

    let mut a_pp: Vec<Vec<RobustShare<Fr>>> = vec![vec![]; n];
    for &v in &a_vals {
        let sa = share_value(v, n, t);
        for p in 0..n {
            a_pp[p].push(sa[p].clone());
        }
    }

    let prep = make_premulc_prep(k, n, t);
    let (network, receivers, _, _) = test_setup(n, vec![]);
    let nodes: Vec<SufMulInvNode<Fr, Avid<SessionId>>> = (0..n)
        .map(|id| SufMulInvNode::new(id, n, t).unwrap())
        .collect();
    let _recv = spawn_sufmulinv_receiver_tasks(n, receivers, nodes.clone(), network.clone());

    let mut init_set = JoinSet::new();
    for i in 0..n {
        let mut node = nodes[i].clone();
        let net = network[i].clone();
        let a = a_pp[i].clone();
        let p = prep[i].clone();
        init_set.spawn(async move {
            node.init(a, p, session, net, mul_duration, duration)
                .await
                .unwrap()
        });
    }
    let mut s_shares: Vec<Vec<RobustShare<Fr>>> = vec![vec![]; k];
    let mut s_inv_shares: Vec<Vec<RobustShare<Fr>>> = vec![vec![]; k];
    while let Some(r) = init_set.join_next().await {
        let (s, s_inv) = r.unwrap();
        assert_eq!(s.len(), k);
        assert_eq!(s_inv.len(), k);
        for j in 0..k {
            s_shares[j].push(s[j].clone());
            s_inv_shares[j].push(s_inv[j].clone());
        }
    }

    // Expected suffix products, computed right-to-left over plaintext values.
    let mut expected = vec![Fr::from(1u64); k];
    let mut acc = Fr::from(1u64);
    for j in (0..k).rev() {
        acc *= a_vals[j];
        expected[j] = acc;
    }

    for j in 0..k {
        let (_, s_j) = RobustShare::recover_secret(&s_shares[j], n, t).unwrap();
        let (_, s_inv_j) = RobustShare::recover_secret(&s_inv_shares[j], n, t).unwrap();
        assert_eq!(s_j, expected[j], "suffix product mismatch at index {j}");
        assert_eq!(
            s_inv_j,
            expected[j].inverse().unwrap(),
            "suffix product inverse mismatch at index {j}"
        );
        assert_eq!(
            s_j * s_inv_j,
            Fr::from(1u64),
            "S_j * S_j^-1 != 1 at index {j}"
        );
    }
}

// ── PreBitLT receiver ────────────────────────────────────────────────────────
//
// PreBitLTNode composes three sub-protocols. Under the caller's own
// calling_protocol (e.g. FpDiv): suf_mul_inv's inner PreMulCOnlineNode
// (BatchRecon round 0 = its own reveal, round 1 + Rbc round 2 = its embedded
// Mul) and mod2 (Rbc round 0, one instance per bit). Under
// ProtocolType::PreBitMul: the standalone phase-4 Multiply.

fn spawn_prebitlt_receiver_tasks(
    num_parties: usize,
    mut receivers: Vec<Vec<Receiver<Vec<u8>>>>,
    nodes: Vec<PreBitLTNode<Fr, Avid<SessionId>>>,
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
                        let proto = msg.session_id.calling_protocol();
                        let round = msg.session_id.round_id();
                        if proto == Some(ProtocolType::PreBitMul) {
                            node.mul
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("mul.batch_recon process failed");
                            node.mul
                                .drain_batch_recon_output()
                                .await
                                .expect("mul.drain_batch_recon_output failed");
                        } else if round == 0 {
                            node.suf_mul_inv
                                .inner
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("suf_mul_inv batch_recon process failed");
                            node.suf_mul_inv
                                .inner
                                .drain_batch_recon_output()
                                .await
                                .expect("suf_mul_inv drain_batch_recon_output failed");
                        } else if round == 1 {
                            node.suf_mul_inv
                                .inner
                                .mul
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("suf_mul_inv.mul batch_recon process failed");
                            node.suf_mul_inv
                                .inner
                                .mul
                                .drain_batch_recon_output()
                                .await
                                .expect("suf_mul_inv.mul drain_batch_recon_output failed");
                        } else {
                            warn!("unexpected round_id {round}");
                        }
                    }
                    WrappedMessage::Rbc(msg) => {
                        let proto = msg.session_id.calling_protocol();
                        let round = msg.session_id.round_id();
                        if proto == Some(ProtocolType::PreBitMul) {
                            node.mul
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("mul.rbc process failed");
                            node.mul
                                .drain_rbc_output()
                                .await
                                .expect("mul.drain_rbc_output failed");
                        } else if round == 2 {
                            node.suf_mul_inv
                                .inner
                                .mul
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("suf_mul_inv.mul rbc process failed");
                            node.suf_mul_inv
                                .inner
                                .mul
                                .drain_rbc_output()
                                .await
                                .expect("suf_mul_inv.mul drain_rbc_output failed");
                        } else if round == 0 || round == 1 {
                            // round 0 = single-value Mod2 session, round 1 =
                            // batched (used by PreBitLT's phase 5).
                            node.mod2
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("mod2 rbc process failed");
                            node.mod2
                                .drain_rbc_output()
                                .await
                                .expect("mod2 drain_rbc_output failed");
                        } else {
                            warn!("unexpected round_id {round}");
                        }
                    }
                    _ => warn!("unexpected message type"),
                }
            }
        });
    }
    set
}

// ── PreBitLT e2e ─────────────────────────────────────────────────────────────
//
// Reference oracle: evaluates the same algebraic steps as PreBitLTNode::init
// in the clear, so the test validates that the distributed computation
// matches its own specified algebra — mirroring how premulc_*_e2e checks
// algebraic invariants rather than an independently-derived semantics.

fn prebitlt_reference(a_bits: &[Fr], b_vals: &[Fr]) -> Vec<Fr> {
    let k = a_bits.len();
    let one = Fr::from(1u64);
    let two = Fr::from(2u64);

    // d_i = XOR(a_i, b_i) = b_i*(1-2a_i) + a_i
    let d: Vec<Fr> = a_bits
        .iter()
        .zip(b_vals.iter())
        .map(|(&a_i, &b_i)| b_i * (one - two * a_i) + a_i)
        .collect();
    let d_plus_1: Vec<Fr> = d.iter().map(|&d_i| d_i + one).collect();

    // Suffix products p_j = prod_{i=j}^{k-1} d_plus_1[i], and their inverses.
    let mut p = vec![one; k];
    let mut acc = one;
    for j in (0..k).rev() {
        acc *= d_plus_1[j];
        p[j] = acc;
    }
    let p_inv: Vec<Fr> = p.iter().map(|x| x.inverse().unwrap()).collect();

    // s[0] = (1-a0)*(p0-p1); s[i] = s[i-1] + (1-ai)*(pi-p{i+1}); s[k-1] uses d[k-1].
    let mut s = vec![Fr::from(0u64); k];
    s[0] = (p[0] - p[1]) * (one - a_bits[0]);
    for i in 1..k - 1 {
        s[i] = s[i - 1] + (p[i] - p[i + 1]) * (one - a_bits[i]);
    }
    s[k - 1] = s[k - 2] + d[k - 1] * (one - a_bits[k - 1]);

    // m_i = s_i * p_inv_{i+1} for i=0..k-2; m_{k-1} = s_{k-1} directly.
    let mut m: Vec<Fr> = (0..k - 1).map(|i| s[i] * p_inv[i + 1]).collect();
    m.push(s[k - 1]);

    // u_i = m_i mod 2 (LSB of canonical integer representative).
    m.iter()
        .map(|x| {
            if x.into_bigint().get_bit(0) {
                Fr::from(1u64)
            } else {
                Fr::from(0u64)
            }
        })
        .collect()
}

async fn pre_bitlt_run(a_vals: Vec<u64>, b_vals: Vec<u64>) {
    let n = 5;
    let t = 1;
    let k = a_vals.len();
    assert_eq!(b_vals.len(), k);
    let duration = std::time::Duration::from_secs(10);
    let session = SessionId::new(ProtocolType::FpDiv, SessionId::pack_slot(5, 0, 0), 42);

    let a_bits: Vec<Fr> = a_vals.iter().map(|&v| Fr::from(v)).collect();
    let b_field: Vec<Fr> = b_vals.iter().map(|&v| Fr::from(v)).collect();

    let mut b_pp: Vec<Vec<RobustShare<Fr>>> = vec![vec![]; n];
    for &v in &b_field {
        let sb = share_value(v, n, t);
        for p in 0..n {
            b_pp[p].push(sb[p].clone());
        }
    }

    let prep = make_prebitlt_prep(k, n, t);
    let (network, receivers, _, _) = test_setup(n, vec![]);
    let nodes: Vec<PreBitLTNode<Fr, Avid<SessionId>>> = (0..n)
        .map(|id| PreBitLTNode::new(id, n, t).unwrap())
        .collect();
    let _recv = spawn_prebitlt_receiver_tasks(n, receivers, nodes.clone(), network.clone());

    let mut init_set = JoinSet::new();
    for (i, p) in prep.into_iter().enumerate() {
        let mut node = nodes[i].clone();
        let net = network[i].clone();
        let bits = a_bits.clone();
        let b_shares = b_pp[i].clone();
        init_set.spawn(async move {
            node.init(bits, b_shares, p, session, net, duration)
                .await
                .unwrap()
        });
    }
    let mut u_shares: Vec<Vec<RobustShare<Fr>>> = vec![vec![]; k];
    while let Some(r) = init_set.join_next().await {
        let result = r.unwrap();
        assert_eq!(result.len(), k);
        for j in 0..k {
            u_shares[j].push(result[j].clone());
        }
    }

    let expected = prebitlt_reference(&a_bits, &b_field);
    for j in 0..k {
        let (_, u_j) = RobustShare::recover_secret(&u_shares[j], n, t).unwrap();
        assert_eq!(
            u_j, expected[j],
            "pre_bitlt mismatch at index {j}: a={a_vals:?} b={b_vals:?}"
        );
    }
}

#[tokio::test]
async fn pre_bitlt_e2e() {
    setup_tracing();
    pre_bitlt_run(vec![0, 1, 0, 1], vec![1, 0, 1, 0]).await;
}

#[tokio::test]
async fn pre_bitlt_all_zero_vs_all_one() {
    setup_tracing();
    pre_bitlt_run(vec![0, 0, 0, 0], vec![1, 1, 1, 1]).await;
}

#[tokio::test]
async fn pre_bitlt_all_one_vs_all_zero() {
    setup_tracing();
    pre_bitlt_run(vec![1, 1, 1, 1], vec![0, 0, 0, 0]).await;
}

#[tokio::test]
async fn pre_bitlt_equal() {
    setup_tracing();
    pre_bitlt_run(vec![1, 0, 1, 0], vec![1, 0, 1, 0]).await;
}

// ── PreMod2m receiver ────────────────────────────────────────────────────────
//
// PreMod2mNode::drain_rbc_output can itself block for a full pre_bitlt
// round-trip (see pre_mod2m.rs docs) — unlike every other drain_*_output in
// this codebase. So unlike the other receiver tasks in this file, the round=4
// reveal branch below spawns each drain attempt as its own detached task
// instead of awaiting it inline: if it blocks, this receiver loop must stay
// free to keep feeding node.pre_bitlt's own sub-protocol messages (routed the
// same way as spawn_prebitlt_receiver_tasks, just reached through
// `node.pre_bitlt`), since pre_bitlt's completion depends on them.

fn spawn_premod2m_receiver_tasks(
    num_parties: usize,
    mut receivers: Vec<Vec<Receiver<Vec<u8>>>>,
    nodes: Vec<PreMod2mNode<Fr, Avid<SessionId>>>,
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
                        let round = msg.session_id.round_id();
                        let proto = msg.session_id.calling_protocol();
                        if round == 4 {
                            // PreMod2m's own reveal (round=4 is unique to it;
                            // pre_bitlt's Rbc traffic uses rounds 0-2). Purely
                            // local now — no longer needs a detached task.
                            node.rbc
                                .process(msg, net.clone())
                                .await
                                .expect("pre_mod2m rbc process failed");
                            node.drain_rbc_output()
                                .await
                                .expect("pre_mod2m drain_rbc_output failed");
                        } else if proto == Some(ProtocolType::PreBitMul) {
                            node.pre_bitlt
                                .mul
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("mul.rbc process failed");
                            node.pre_bitlt
                                .mul
                                .drain_rbc_output()
                                .await
                                .expect("mul.drain_rbc_output failed");
                        } else if round == 2 {
                            node.pre_bitlt
                                .suf_mul_inv
                                .inner
                                .mul
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("suf_mul_inv.mul rbc process failed");
                            node.pre_bitlt
                                .suf_mul_inv
                                .inner
                                .mul
                                .drain_rbc_output()
                                .await
                                .expect("suf_mul_inv.mul drain_rbc_output failed");
                        } else if round == 0 || round == 1 {
                            node.pre_bitlt
                                .mod2
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("mod2 rbc process failed");
                            node.pre_bitlt
                                .mod2
                                .drain_rbc_output()
                                .await
                                .expect("mod2 drain_rbc_output failed");
                        } else {
                            warn!("unexpected Rbc round_id {round}");
                        }
                    }
                    WrappedMessage::BatchRecon(msg) => {
                        let proto = msg.session_id.calling_protocol();
                        let round = msg.session_id.round_id();
                        if proto == Some(ProtocolType::PreBitMul) {
                            node.pre_bitlt
                                .mul
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("mul.batch_recon process failed");
                            node.pre_bitlt
                                .mul
                                .drain_batch_recon_output()
                                .await
                                .expect("mul.drain_batch_recon_output failed");
                        } else if round == 0 {
                            node.pre_bitlt
                                .suf_mul_inv
                                .inner
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("suf_mul_inv batch_recon process failed");
                            node.pre_bitlt
                                .suf_mul_inv
                                .inner
                                .drain_batch_recon_output()
                                .await
                                .expect("suf_mul_inv drain_batch_recon_output failed");
                        } else if round == 1 {
                            node.pre_bitlt
                                .suf_mul_inv
                                .inner
                                .mul
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("suf_mul_inv.mul batch_recon process failed");
                            node.pre_bitlt
                                .suf_mul_inv
                                .inner
                                .mul
                                .drain_batch_recon_output()
                                .await
                                .expect("suf_mul_inv.mul drain_batch_recon_output failed");
                        } else {
                            warn!("unexpected BatchRecon round_id {round}");
                        }
                    }
                    _ => warn!("unexpected message type"),
                }
            }
        });
    }
    set
}

// ── PreMod2m e2e ─────────────────────────────────────────────────────────────
//
// Computes [a mod 2], [a mod 4], ..., [a mod 2^m] and checks against plain
// integer arithmetic on a_val.

async fn pre_mod2m_run(a_val: u64, k: usize, m: usize, dp_bits: usize) {
    let n = 5;
    let t = 1;
    let duration = std::time::Duration::from_secs(10);
    let session = SessionId::new(ProtocolType::FpDiv, SessionId::pack_slot(6, 0, 0), 42);

    let a_shares = share_value(Fr::from(a_val), n, t);
    let prep = make_premod2m_prep(dp_bits, m, n, t);

    let (network, receivers, _, _) = test_setup(n, vec![]);
    let nodes: Vec<PreMod2mNode<Fr, Avid<SessionId>>> = (0..n)
        .map(|id| PreMod2mNode::new(id, n, t).unwrap())
        .collect();
    let _recv =
        spawn_premod2m_receiver_tasks(n, receivers, nodes.clone(), network.clone());

    let mut init_set = JoinSet::new();
    for (i, p) in prep.into_iter().enumerate() {
        let mut node = nodes[i].clone();
        let net = network[i].clone();
        let a = a_shares[i].clone();
        init_set.spawn(async move { node.init(a, k, m, p, session, net, duration).await.unwrap() });
    }
    let mut result_shares: Vec<Vec<RobustShare<Fr>>> = vec![vec![]; m];
    while let Some(r) = init_set.join_next().await {
        let res = r.unwrap();
        assert_eq!(res.len(), m);
        for j in 0..m {
            result_shares[j].push(res[j].clone());
        }
    }

    for j in 0..m {
        let (_, val) = RobustShare::recover_secret(&result_shares[j], n, t).unwrap();
        let expected = a_val % (1u64 << (j + 1));
        assert_eq!(
            val,
            Fr::from(expected),
            "pre_mod2m mismatch at j={j} (mod 2^{}): a={a_val}",
            j + 1
        );
    }
}

#[tokio::test]
async fn pre_mod2m_e2e() {
    setup_tracing();
    pre_mod2m_run(173, 8, 4, 40).await;
}

#[tokio::test]
async fn pre_mod2m_zero() {
    setup_tracing();
    pre_mod2m_run(0, 8, 4, 40).await;
}

#[tokio::test]
async fn pre_mod2m_max() {
    setup_tracing();
    pre_mod2m_run(255, 8, 4, 40).await;
}

// ── BitDec receiver ──────────────────────────────────────────────────────────
// BitDecNode wraps a PreMod2mNode as `pre_mod2m`; routing is identical to
// spawn_premod2m_receiver_tasks, just reached through `node.pre_mod2m` —
// including the detached-task spawn for the round=4 reveal drain (see that
// receiver's comment for why it must not be awaited inline).

fn spawn_bitdec_receiver_tasks(
    num_parties: usize,
    mut receivers: Vec<Vec<Receiver<Vec<u8>>>>,
    nodes: Vec<BitDecNode<Fr, Avid<SessionId>>>,
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
                        let round = msg.session_id.round_id();
                        let proto = msg.session_id.calling_protocol();
                        if round == 4 {
                            node.pre_mod2m
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("pre_mod2m rbc process failed");
                            node.pre_mod2m
                                .drain_rbc_output()
                                .await
                                .expect("pre_mod2m drain_rbc_output failed");
                        } else if proto == Some(ProtocolType::PreBitMul) {
                            node.pre_mod2m
                                .pre_bitlt
                                .mul
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("mul.rbc process failed");
                            node.pre_mod2m
                                .pre_bitlt
                                .mul
                                .drain_rbc_output()
                                .await
                                .expect("mul.drain_rbc_output failed");
                        } else if round == 2 {
                            node.pre_mod2m
                                .pre_bitlt
                                .suf_mul_inv
                                .inner
                                .mul
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("suf_mul_inv.mul rbc process failed");
                            node.pre_mod2m
                                .pre_bitlt
                                .suf_mul_inv
                                .inner
                                .mul
                                .drain_rbc_output()
                                .await
                                .expect("suf_mul_inv.mul drain_rbc_output failed");
                        } else if round == 0 || round == 1 {
                            node.pre_mod2m
                                .pre_bitlt
                                .mod2
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("mod2 rbc process failed");
                            node.pre_mod2m
                                .pre_bitlt
                                .mod2
                                .drain_rbc_output()
                                .await
                                .expect("mod2 drain_rbc_output failed");
                        } else {
                            warn!("unexpected Rbc round_id {round}");
                        }
                    }
                    WrappedMessage::BatchRecon(msg) => {
                        let proto = msg.session_id.calling_protocol();
                        let round = msg.session_id.round_id();
                        if proto == Some(ProtocolType::PreBitMul) {
                            node.pre_mod2m
                                .pre_bitlt
                                .mul
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("mul.batch_recon process failed");
                            node.pre_mod2m
                                .pre_bitlt
                                .mul
                                .drain_batch_recon_output()
                                .await
                                .expect("mul.drain_batch_recon_output failed");
                        } else if round == 0 {
                            node.pre_mod2m
                                .pre_bitlt
                                .suf_mul_inv
                                .inner
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("suf_mul_inv batch_recon process failed");
                            node.pre_mod2m
                                .pre_bitlt
                                .suf_mul_inv
                                .inner
                                .drain_batch_recon_output()
                                .await
                                .expect("suf_mul_inv drain_batch_recon_output failed");
                        } else if round == 1 {
                            node.pre_mod2m
                                .pre_bitlt
                                .suf_mul_inv
                                .inner
                                .mul
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("suf_mul_inv.mul batch_recon process failed");
                            node.pre_mod2m
                                .pre_bitlt
                                .suf_mul_inv
                                .inner
                                .mul
                                .drain_batch_recon_output()
                                .await
                                .expect("suf_mul_inv.mul drain_batch_recon_output failed");
                        } else {
                            warn!("unexpected BatchRecon round_id {round}");
                        }
                    }
                    _ => warn!("unexpected message type"),
                }
            }
        });
    }
    set
}

// ── BitDec e2e ───────────────────────────────────────────────────────────────
//
// Full bit decomposition: recovers each [a_j] and checks it against the j-th
// bit of a_val.

// u_bar must lie in Z⟨k⟩ = [-2^{k-1}, 2^{k-1}-1] (signed) — BitDec's actual
// precondition (Protocol 10). The expected bit pattern is u_bar's canonical
// non-negative representative mod 2^k, i.e. its two's-complement encoding.
async fn bit_dec_run(u_bar: i128, k: usize, dp_bits: usize) {
    let n = 5;
    let t = 1;
    let duration = std::time::Duration::from_secs(10);
    let session = SessionId::new(ProtocolType::FpDiv, SessionId::pack_slot(7, 0, 0), 42);

    let expected = u_bar.rem_euclid(1i128 << k) as u64;
    let a_shares = share_signed_fixed(u_bar, n, t);
    // BitDec runs PreMod2m with m = k-1 (m < k, per the paper).
    let prep = make_premod2m_prep(dp_bits, k - 1, n, t);

    let (network, receivers, _, _) = test_setup(n, vec![]);
    let nodes: Vec<BitDecNode<Fr, Avid<SessionId>>> = (0..n)
        .map(|id| BitDecNode::new(id, n, t).unwrap())
        .collect();
    let _recv =
        spawn_bitdec_receiver_tasks(n, receivers, nodes.clone(), network.clone());

    let mut init_set = JoinSet::new();
    for (i, p) in prep.into_iter().enumerate() {
        let mut node = nodes[i].clone();
        let net = network[i].clone();
        let a = a_shares[i].clone();
        init_set.spawn(async move { node.init(a, k, p, session, net, duration).await.unwrap() });
    }
    let mut bit_shares: Vec<Vec<RobustShare<Fr>>> = vec![vec![]; k];
    while let Some(r) = init_set.join_next().await {
        let bits = r.unwrap();
        assert_eq!(bits.len(), k);
        for j in 0..k {
            bit_shares[j].push(bits[j].clone());
        }
    }

    for j in 0..k {
        let (_, bit) = RobustShare::recover_secret(&bit_shares[j], n, t).unwrap();
        assert_eq!(
            bit,
            Fr::from((expected >> j) & 1),
            "bit_dec mismatch at bit {j}: u_bar={u_bar} (expected pattern {expected:#07b})"
        );
    }
}

// k = 5 so m = k-1 = 4 is a multiple of (t+1) = 2, as PreBitLT's internal
// PreMulC requires.

#[tokio::test]
async fn bit_dec_e2e() {
    setup_tracing();
    bit_dec_run(13, 5, 40).await; // 13 = 0b01101, in Z⟨5⟩ = [-16,15]
}

#[tokio::test]
async fn bit_dec_zero() {
    setup_tracing();
    bit_dec_run(0, 5, 40).await;
}

#[tokio::test]
async fn bit_dec_all_ones() {
    setup_tracing();
    bit_dec_run(-1, 5, 40).await; // -1 = 0b11111 in 5-bit two's complement
}

#[tokio::test]
async fn bit_dec_most_negative() {
    setup_tracing();
    bit_dec_run(-16, 5, 40).await; // boundary of Z⟨5⟩ = [-16,15]
}

// ── AppRec receiver ──────────────────────────────────────────────────────────
//
// AppRecNode composes BitDec (session reused as-is), SufOr (tag=SufOr, same
// exec_id), and 3 sequential Multiply rounds (tags PreBitMul/PreBitMul1/
// PreBitMul2, same exec_id) — see app_rec.rs's module docs for the exact
// session-routing scheme. The only ambiguity is BitDec's nested PreBitLT,
// which also tags its own Multiply `PreBitMul` but always at exec_id=0
// (PreMod2m hardcodes exec_id=0 for its nested PreBitLT call), so it's
// disambiguated from AppRec's own PreBitMul-tagged round by exec_id alone.
// TruncPr's RBC reveal always lands at round=0, which nothing else uses
// (BitDec's nested batched Mod2 only ever uses round=1 via init_batch).

fn spawn_apprec_receiver_tasks(
    num_parties: usize,
    mut receivers: Vec<Vec<Receiver<Vec<u8>>>>,
    nodes: Vec<AppRecNode<Fr, Avid<SessionId>>>,
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
                        let round = msg.session_id.round_id();
                        let proto = msg.session_id.calling_protocol();
                        let exec_id = msg.session_id.exec_id();
                        if round == 4 {
                            // BitDec's own PreMod2m reveal.
                            node.bit_dec
                                .pre_mod2m
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("bitdec pre_mod2m rbc process failed");
                            node.bit_dec
                                .pre_mod2m
                                .drain_rbc_output()
                                .await
                                .expect("bitdec pre_mod2m drain_rbc_output failed");
                        } else if round == 0 {
                            // AppRec's own final TruncPr reveal.
                            node.trunc
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("trunc rbc process failed");
                            node.trunc
                                .drain_rbc_output()
                                .await
                                .expect("trunc drain_rbc_output failed");
                        } else if proto == Some(ProtocolType::PreBitMul) && exec_id == 0 {
                            // BitDec's nested PreBitLT's own Multiply (phase 4).
                            node.bit_dec
                                .pre_mod2m
                                .pre_bitlt
                                .mul
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("nested pre_bitlt.mul rbc process failed");
                            node.bit_dec
                                .pre_mod2m
                                .pre_bitlt
                                .mul
                                .drain_rbc_output()
                                .await
                                .expect("nested pre_bitlt.mul drain_rbc_output failed");
                        } else if matches!(
                            proto,
                            Some(ProtocolType::PreBitMul)
                                | Some(ProtocolType::PreBitMul1)
                                | Some(ProtocolType::PreBitMul2)
                        ) {
                            // AppRec's own 3 Multiply rounds (steps 3, 6/7, 8).
                            node.mul
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("apprec mul rbc process failed");
                            node.mul
                                .drain_rbc_output()
                                .await
                                .expect("apprec mul drain_rbc_output failed");
                        } else if proto == Some(ProtocolType::SufOr) {
                            // AppRec's own SufOr call's embedded Multiply.
                            node.suf_or
                                .inner
                                .mul
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("sufor mul rbc process failed");
                            node.suf_or
                                .inner
                                .mul
                                .drain_rbc_output()
                                .await
                                .expect("sufor mul drain_rbc_output failed");
                        } else if round == 2 {
                            // BitDec's nested SufMulInv's embedded Multiply.
                            node.bit_dec
                                .pre_mod2m
                                .pre_bitlt
                                .suf_mul_inv
                                .inner
                                .mul
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("nested suf_mul_inv.mul rbc process failed");
                            node.bit_dec
                                .pre_mod2m
                                .pre_bitlt
                                .suf_mul_inv
                                .inner
                                .mul
                                .drain_rbc_output()
                                .await
                                .expect("nested suf_mul_inv.mul drain_rbc_output failed");
                        } else if round == 1 {
                            // BitDec's nested batched Mod2.
                            node.bit_dec
                                .pre_mod2m
                                .pre_bitlt
                                .mod2
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("nested mod2 rbc process failed");
                            node.bit_dec
                                .pre_mod2m
                                .pre_bitlt
                                .mod2
                                .drain_rbc_output()
                                .await
                                .expect("nested mod2 drain_rbc_output failed");
                        } else {
                            warn!("unexpected Rbc round_id {round}");
                        }
                    }
                    WrappedMessage::BatchRecon(msg) => {
                        let proto = msg.session_id.calling_protocol();
                        let round = msg.session_id.round_id();
                        let exec_id = msg.session_id.exec_id();
                        if proto == Some(ProtocolType::PreBitMul) && exec_id == 0 {
                            node.bit_dec
                                .pre_mod2m
                                .pre_bitlt
                                .mul
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("nested pre_bitlt.mul batch_recon process failed");
                            node.bit_dec
                                .pre_mod2m
                                .pre_bitlt
                                .mul
                                .drain_batch_recon_output()
                                .await
                                .expect("nested pre_bitlt.mul drain_batch_recon_output failed");
                        } else if matches!(
                            proto,
                            Some(ProtocolType::PreBitMul)
                                | Some(ProtocolType::PreBitMul1)
                                | Some(ProtocolType::PreBitMul2)
                        ) {
                            node.mul
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("apprec mul batch_recon process failed");
                            node.mul
                                .drain_batch_recon_output()
                                .await
                                .expect("apprec mul drain_batch_recon_output failed");
                        } else if proto == Some(ProtocolType::SufOr) {
                            if round == 0 {
                                node.suf_or
                                    .inner
                                    .batch_recon
                                    .process(msg, net.clone())
                                    .await
                                    .expect("sufor batch_recon process failed");
                                node.suf_or
                                    .inner
                                    .drain_batch_recon_output()
                                    .await
                                    .expect("sufor drain_batch_recon_output failed");
                            } else {
                                node.suf_or
                                    .inner
                                    .mul
                                    .batch_recon
                                    .process(msg, net.clone())
                                    .await
                                    .expect("sufor mul batch_recon process failed");
                                node.suf_or
                                    .inner
                                    .mul
                                    .drain_batch_recon_output()
                                    .await
                                    .expect("sufor mul drain_batch_recon_output failed");
                            }
                        } else if round == 0 {
                            node.bit_dec
                                .pre_mod2m
                                .pre_bitlt
                                .suf_mul_inv
                                .inner
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("nested suf_mul_inv batch_recon process failed");
                            node.bit_dec
                                .pre_mod2m
                                .pre_bitlt
                                .suf_mul_inv
                                .inner
                                .drain_batch_recon_output()
                                .await
                                .expect("nested suf_mul_inv drain_batch_recon_output failed");
                        } else if round == 1 {
                            node.bit_dec
                                .pre_mod2m
                                .pre_bitlt
                                .suf_mul_inv
                                .inner
                                .mul
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("nested suf_mul_inv.mul batch_recon process failed");
                            node.bit_dec
                                .pre_mod2m
                                .pre_bitlt
                                .suf_mul_inv
                                .inner
                                .mul
                                .drain_batch_recon_output()
                                .await
                                .expect("nested suf_mul_inv.mul drain_batch_recon_output failed");
                        } else {
                            warn!("unexpected BatchRecon round_id {round}");
                        }
                    }
                    _ => warn!("unexpected message type"),
                }
            }
        });
    }
    set
}

// ── AppRec e2e ───────────────────────────────────────────────────────────────
//
// Checks w ≈ 1/b within the paper's own linear-approximation error bound
// (relative error < 0.08578), plus slack for fixed-point quantization at the
// small k,f used here. z must be 0 for b≠0 and 1 for b=0.

async fn app_rec_run(u_bar: i128, k: usize, f: usize) {
    let n = 5;
    let t = 1;
    let dp_bits = 40;
    let duration = std::time::Duration::from_secs(10);
    // exec_id must be nonzero: PreMod2m hardcodes exec_id=0 for BitDec's
    // nested PreBitLT call, and AppRec's own PreBitMul-tagged round would
    // collide with it at exec_id=0 (see app_rec.rs's session routing docs).
    let session = SessionId::new(ProtocolType::FpDiv, SessionId::pack_slot(9, 0, 0), 42);

    let b_shares = share_signed_fixed(u_bar, n, t);
    let prep = make_apprec_prep(dp_bits, k, f, n, t);

    let (network, receivers, _, _) = test_setup(n, vec![]);
    let nodes: Vec<AppRecNode<Fr, Avid<SessionId>>> = (0..n)
        .map(|id| AppRecNode::new(id, n, t).unwrap())
        .collect();
    let _recv =
        spawn_apprec_receiver_tasks(n, receivers, nodes.clone(), network.clone());

    let mut init_set = JoinSet::new();
    for (i, p) in prep.into_iter().enumerate() {
        let mut node = nodes[i].clone();
        let net = network[i].clone();
        let b = b_shares[i].clone();
        init_set.spawn(async move {
            node.init(b, k, f, p, session, net, duration)
                .await
                .unwrap()
        });
    }
    let mut w_shares = Vec::with_capacity(n);
    let mut z_shares = Vec::with_capacity(n);
    while let Some(r) = init_set.join_next().await {
        let (w, z) = r.unwrap();
        w_shares.push(w);
        z_shares.push(z);
    }

    let (_, w_val) = RobustShare::recover_secret(&w_shares, n, t).unwrap();
    let (_, z_val) = RobustShare::recover_secret(&z_shares, n, t).unwrap();

    let b_real = u_bar as f64 / (1u128 << f) as f64;

    if u_bar == 0 {
        assert_eq!(z_val, Fr::from(1u64), "z must be 1 for b=0");
        return;
    }

    assert_eq!(z_val, Fr::from(0u64), "z must be 0 for b={b_real}");
    let w_real = field_to_signed_real(w_val, f);
    let rel_err = (w_real * b_real - 1.0).abs();
    assert!(
        rel_err < 0.2,
        "AppRec(1/{b_real}) = {w_real}, relative error {rel_err} exceeds tolerance"
    );
}

// k=15, f=6: at f=3 a single probabilistic-rounding miss in TruncPr shifts
// the result by 1/8 = 12.5%, which combined with the paper's own ~8.6%
// approximation bound occasionally exceeded the tolerance below (observed
// flaky at k=9,f=3). At f=6 one rounding unit is only 1/64 ≈ 1.6%.

#[tokio::test]
async fn app_rec_positive() {
    setup_tracing();
    app_rec_run(128, 15, 6).await; // b = 2.0
}

#[tokio::test]
async fn app_rec_negative() {
    setup_tracing();
    app_rec_run(-128, 15, 6).await; // b = -2.0
}

#[tokio::test]
async fn app_rec_non_power_of_two() {
    setup_tracing();
    app_rec_run(192, 15, 6).await; // b = 3.0
}

#[tokio::test]
async fn app_rec_zero() {
    setup_tracing();
    app_rec_run(0, 15, 6).await; // b = 0 → z = 1
}

// ── FXDiv e2e ────────────────────────────────────────────────────────────────
//
// Routes every message one level deeper than `spawn_apprec_receiver_tasks`
// (through `node.app_rec.*`), and adds two new branches ahead of it for
// FpDivNode's own dedicated tags (FpDivTrunc, FpDivMulA/FpDivMulB), which
// never collide with AppRec's internal FpDiv/PreBitMul*/SufOr-tagged
// traffic since they're checked first, by tag, before falling through to
// the round-based dispatch AppRec's own internals rely on.

fn spawn_fpdiv_receiver_tasks(
    num_parties: usize,
    mut receivers: Vec<Vec<Receiver<Vec<u8>>>>,
    nodes: Vec<FpDivNode<Fr, Avid<SessionId>>>,
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
                        let round = msg.session_id.round_id();
                        let proto = msg.session_id.calling_protocol();
                        let exec_id = msg.session_id.exec_id();
                        if proto == Some(ProtocolType::FpDivTrunc) {
                            // FpDivNode's own Trunc calls (step 3, steps 6/7/8
                            // per iteration), isolated from each other by round_id.
                            node.trunc
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("fpdiv trunc rbc process failed");
                            node.trunc
                                .drain_rbc_output()
                                .await
                                .expect("fpdiv trunc drain_rbc_output failed");
                        } else if matches!(
                            proto,
                            Some(ProtocolType::FpDivMulA) | Some(ProtocolType::FpDivMulB)
                        ) {
                            // FpDivNode's own Multiply rounds (step 3/4 batch,
                            // and each iteration's Round A / Round B).
                            node.mul
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("fpdiv mul rbc process failed");
                            node.mul
                                .drain_rbc_output()
                                .await
                                .expect("fpdiv mul drain_rbc_output failed");
                        } else if round == 4 {
                            // AppRec's BitDec's own PreMod2m reveal.
                            node.app_rec
                                .bit_dec
                                .pre_mod2m
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("bitdec pre_mod2m rbc process failed");
                            node.app_rec
                                .bit_dec
                                .pre_mod2m
                                .drain_rbc_output()
                                .await
                                .expect("bitdec pre_mod2m drain_rbc_output failed");
                        } else if round == 0 {
                            // AppRec's own final TruncPr reveal.
                            node.app_rec
                                .trunc
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("apprec trunc rbc process failed");
                            node.app_rec
                                .trunc
                                .drain_rbc_output()
                                .await
                                .expect("apprec trunc drain_rbc_output failed");
                        } else if proto == Some(ProtocolType::PreBitMul) && exec_id == 0 {
                            // BitDec's nested PreBitLT's own Multiply (phase 4).
                            node.app_rec
                                .bit_dec
                                .pre_mod2m
                                .pre_bitlt
                                .mul
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("nested pre_bitlt.mul rbc process failed");
                            node.app_rec
                                .bit_dec
                                .pre_mod2m
                                .pre_bitlt
                                .mul
                                .drain_rbc_output()
                                .await
                                .expect("nested pre_bitlt.mul drain_rbc_output failed");
                        } else if matches!(
                            proto,
                            Some(ProtocolType::PreBitMul)
                                | Some(ProtocolType::PreBitMul1)
                                | Some(ProtocolType::PreBitMul2)
                        ) {
                            // AppRec's own 3 Multiply rounds (steps 3, 6/7, 8).
                            node.app_rec
                                .mul
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("apprec mul rbc process failed");
                            node.app_rec
                                .mul
                                .drain_rbc_output()
                                .await
                                .expect("apprec mul drain_rbc_output failed");
                        } else if proto == Some(ProtocolType::SufOr) {
                            // AppRec's own SufOr call's embedded Multiply.
                            node.app_rec
                                .suf_or
                                .inner
                                .mul
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("sufor mul rbc process failed");
                            node.app_rec
                                .suf_or
                                .inner
                                .mul
                                .drain_rbc_output()
                                .await
                                .expect("sufor mul drain_rbc_output failed");
                        } else if round == 2 {
                            // BitDec's nested SufMulInv's embedded Multiply.
                            node.app_rec
                                .bit_dec
                                .pre_mod2m
                                .pre_bitlt
                                .suf_mul_inv
                                .inner
                                .mul
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("nested suf_mul_inv.mul rbc process failed");
                            node.app_rec
                                .bit_dec
                                .pre_mod2m
                                .pre_bitlt
                                .suf_mul_inv
                                .inner
                                .mul
                                .drain_rbc_output()
                                .await
                                .expect("nested suf_mul_inv.mul drain_rbc_output failed");
                        } else if round == 1 {
                            // BitDec's nested batched Mod2.
                            node.app_rec
                                .bit_dec
                                .pre_mod2m
                                .pre_bitlt
                                .mod2
                                .rbc
                                .process(msg, net.clone())
                                .await
                                .expect("nested mod2 rbc process failed");
                            node.app_rec
                                .bit_dec
                                .pre_mod2m
                                .pre_bitlt
                                .mod2
                                .drain_rbc_output()
                                .await
                                .expect("nested mod2 drain_rbc_output failed");
                        } else {
                            warn!("unexpected Rbc round_id {round}");
                        }
                    }
                    WrappedMessage::BatchRecon(msg) => {
                        let proto = msg.session_id.calling_protocol();
                        let round = msg.session_id.round_id();
                        let exec_id = msg.session_id.exec_id();
                        if matches!(
                            proto,
                            Some(ProtocolType::FpDivMulA) | Some(ProtocolType::FpDivMulB)
                        ) {
                            node.mul
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("fpdiv mul batch_recon process failed");
                            node.mul
                                .drain_batch_recon_output()
                                .await
                                .expect("fpdiv mul drain_batch_recon_output failed");
                        } else if proto == Some(ProtocolType::PreBitMul) && exec_id == 0 {
                            node.app_rec
                                .bit_dec
                                .pre_mod2m
                                .pre_bitlt
                                .mul
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("nested pre_bitlt.mul batch_recon process failed");
                            node.app_rec
                                .bit_dec
                                .pre_mod2m
                                .pre_bitlt
                                .mul
                                .drain_batch_recon_output()
                                .await
                                .expect("nested pre_bitlt.mul drain_batch_recon_output failed");
                        } else if matches!(
                            proto,
                            Some(ProtocolType::PreBitMul)
                                | Some(ProtocolType::PreBitMul1)
                                | Some(ProtocolType::PreBitMul2)
                        ) {
                            node.app_rec
                                .mul
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("apprec mul batch_recon process failed");
                            node.app_rec
                                .mul
                                .drain_batch_recon_output()
                                .await
                                .expect("apprec mul drain_batch_recon_output failed");
                        } else if proto == Some(ProtocolType::SufOr) {
                            if round == 0 {
                                node.app_rec
                                    .suf_or
                                    .inner
                                    .batch_recon
                                    .process(msg, net.clone())
                                    .await
                                    .expect("sufor batch_recon process failed");
                                node.app_rec
                                    .suf_or
                                    .inner
                                    .drain_batch_recon_output()
                                    .await
                                    .expect("sufor drain_batch_recon_output failed");
                            } else {
                                node.app_rec
                                    .suf_or
                                    .inner
                                    .mul
                                    .batch_recon
                                    .process(msg, net.clone())
                                    .await
                                    .expect("sufor mul batch_recon process failed");
                                node.app_rec
                                    .suf_or
                                    .inner
                                    .mul
                                    .drain_batch_recon_output()
                                    .await
                                    .expect("sufor mul drain_batch_recon_output failed");
                            }
                        } else if round == 0 {
                            node.app_rec
                                .bit_dec
                                .pre_mod2m
                                .pre_bitlt
                                .suf_mul_inv
                                .inner
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("nested suf_mul_inv batch_recon process failed");
                            node.app_rec
                                .bit_dec
                                .pre_mod2m
                                .pre_bitlt
                                .suf_mul_inv
                                .inner
                                .drain_batch_recon_output()
                                .await
                                .expect("nested suf_mul_inv drain_batch_recon_output failed");
                        } else if round == 1 {
                            node.app_rec
                                .bit_dec
                                .pre_mod2m
                                .pre_bitlt
                                .suf_mul_inv
                                .inner
                                .mul
                                .batch_recon
                                .process(msg, net.clone())
                                .await
                                .expect("nested suf_mul_inv.mul batch_recon process failed");
                            node.app_rec
                                .bit_dec
                                .pre_mod2m
                                .pre_bitlt
                                .suf_mul_inv
                                .inner
                                .mul
                                .drain_batch_recon_output()
                                .await
                                .expect("nested suf_mul_inv.mul drain_batch_recon_output failed");
                        } else {
                            warn!("unexpected BatchRecon round_id {round}");
                        }
                    }
                    _ => warn!("unexpected message type"),
                }
            }
        });
    }
    set
}

// Checks c ≈ a/b within a tolerance accounting for the paper's own linear-
// approximation bound (inherited via AppRec) plus probabilistic-rounding
// slack accumulated across FXDiv's extra truncations.

async fn fpdiv_run(a_bar: i128, b_bar: i128, k: usize, f: usize) {
    let n = 5;
    let t = 1;
    let dp_bits = 40;
    let duration = std::time::Duration::from_secs(10);
    // Must be tagged FpDiv: PreMod2m (nested under AppRec's BitDec) hardcodes
    // ProtocolType::FpDiv for its parent-session lookup key.
    let session = SessionId::new(ProtocolType::FpDiv, SessionId::pack_slot(9, 0, 0), 42);

    let a_shares = share_signed_fixed(a_bar, n, t);
    let b_shares = share_signed_fixed(b_bar, n, t);
    let prep = make_fpdiv_prep(dp_bits, k, f, n, t);

    let (network, receivers, _, _) = test_setup(n, vec![]);
    let nodes: Vec<FpDivNode<Fr, Avid<SessionId>>> = (0..n)
        .map(|id| FpDivNode::new(id, n, t).unwrap())
        .collect();
    let _recv = spawn_fpdiv_receiver_tasks(n, receivers, nodes.clone(), network.clone());

    let mut init_set = JoinSet::new();
    for (i, p) in prep.into_iter().enumerate() {
        let mut node = nodes[i].clone();
        let net = network[i].clone();
        let a = a_shares[i].clone();
        let b = b_shares[i].clone();
        init_set.spawn(async move {
            node.init(a, b, k, f, p, session, net, duration)
                .await
                .unwrap()
        });
    }
    let mut c_shares = Vec::with_capacity(n);
    let mut z_shares = Vec::with_capacity(n);
    while let Some(r) = init_set.join_next().await {
        let (c, z) = r.unwrap();
        c_shares.push(c);
        z_shares.push(z);
    }

    let (_, c_val) = RobustShare::recover_secret(&c_shares, n, t).unwrap();
    let (_, z_val) = RobustShare::recover_secret(&z_shares, n, t).unwrap();

    let a_real = a_bar as f64 / (1u128 << f) as f64;
    let b_real = b_bar as f64 / (1u128 << f) as f64;

    if b_bar == 0 {
        assert_eq!(z_val, Fr::from(1u64), "z must be 1 for b=0");
        return;
    }

    assert_eq!(z_val, Fr::from(0u64), "z must be 0 for b={b_real}");
    let c_real = field_to_signed_real(c_val, f);
    let expected = a_real / b_real;
    let rel_err = if expected.abs() < 1e-9 {
        c_real.abs()
    } else {
        ((c_real - expected) / expected).abs()
    };
    assert!(
        rel_err < 0.2,
        "FXDiv({a_real}/{b_real}) = {c_real}, expected ≈{expected}, relative error {rel_err} exceeds tolerance"
    );
}

#[tokio::test]
async fn fpdiv_exact() {
    setup_tracing();
    fpdiv_run(384, 128, 15, 6).await; // 6.0 / 2.0 = 3.0
}

#[tokio::test]
async fn fpdiv_sign_permutations() {
    setup_tracing();
    fpdiv_run(-384, 128, 15, 6).await; // -6.0 / 2.0 = -3.0
    fpdiv_run(384, -128, 15, 6).await; // 6.0 / -2.0 = -3.0
    fpdiv_run(-384, -128, 15, 6).await; // -6.0 / -2.0 = 3.0
}

#[tokio::test]
async fn fpdiv_non_exact_quotient() {
    setup_tracing();
    fpdiv_run(64, 192, 15, 6).await; // 1.0 / 3.0 ≈ 0.333
}

#[tokio::test]
async fn fpdiv_by_zero() {
    setup_tracing();
    fpdiv_run(64, 0, 15, 6).await; // z = 1, c is don't-care
}
