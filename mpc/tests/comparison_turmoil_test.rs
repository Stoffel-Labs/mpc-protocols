//! Turmoil-driven tests for the comparison operations (LTZ, EQZ — Catrina &
//! de Hoogh 2010, Protocols 3.6/3.7) and their dependency chain (PreMod2m,
//! PreBitLT, KOrCL, KOrCS).
//!
//! Scoped out (see `fpdiv_turmoil_test.rs` for the class of bug this rules
//! out): `fpdiv.rs`'s refinement loop reused one `Multiply` `SessionId`
//! across a variable number of sequential logical calls (steps 3/4 plus
//! every iteration's Round A), which is exactly the shape `Multiply`/
//! `BatchReconNode` mishandle under late delivery (see that file's header).
//! Nothing in the comparison stack has that shape: LTZ, EQZ, PreMod2m,
//! PreBitLT, and KOrCS are all fixed constant-round pipelines with no
//! "repeat until converged" loop — every `Multiply`/`BatchReconNode` session
//! anywhere in this call graph (KOrCS's `KOr1`/`KOr2`, PreBitLT's
//! `PreBitMul3`/`LTZBitMul`, SufMulInv's inner Multiply) is used exactly
//! once per top-level `ltz_int`/`eqz_int` call, each phase tagged with its
//! own distinct `ProtocolType`. (Verified by reading every `SessionId::new`
//! call site under `honeybadger::{comparison,bitwise}` — none reuse a base
//! session across a loop the way `fpdiv.rs` did.)
//!
//! These tests exist to confirm that structural read empirically under real
//! turmoil networking (variable latency, an adversarial slow node), not to
//! reproduce a known bug — this protocol family had no turmoil coverage at
//! all before (only FakeNetwork, which delivers close to synchronously).

mod utils;

use crate::utils::{
    comparison_utils::{
        make_kor_cs_prep, make_prandm_prep, make_premod2m_prep, share_signed_fixed, share_value,
    },
    test_utils::setup_tracing,
    turmoil::{add_driver, turmoil_setup},
};
use ark_bls12_381::Fr;
use std::sync::Arc;
use stoffelcrypto::{
    common::{ProtocolSessionId, SecretSharingScheme},
    honeybadger::{
        comparison::{eqz::EQZNode, ltz::LTZNode},
        robust_interpolate::robust_interpolate::RobustShare,
        ProtocolType, SessionId, WrappedMessage,
    },
};
use stoffelmpc_network::{fake_network::SenderId, turmoil_network::TurmoilNetwork};
use tokio::sync::mpsc::Receiver;
use tokio::time::Duration;
use tracing::warn;

// ── LTZ ──────────────────────────────────────────────────────────────────

// Mirrors `spawn_ltz_receiver_tasks` in `comparison_test.rs` exactly (same
// dispatch table, already validated by that file's FakeNetwork-based
// correctness tests), adapted to TurmoilNetwork's single pre-fanned-in
// receiver instead of FakeNetwork's per-peer inboxes.
async fn run_ltz_receiver(mut rx: Receiver<(SenderId, Vec<u8>)>, mut node: LTZNode<Fr>, net: Arc<TurmoilNetwork>) {
    while let Some((_sender, bytes)) = rx.recv().await {
        let wrapped: WrappedMessage = match bincode::deserialize(&bytes) {
            Ok(m) => m,
            Err(_) => {
                warn!("ltz turmoil: deserialize failed");
                continue;
            }
        };
        match wrapped {
            WrappedMessage::PreMod2m(msg) => {
                node.pre_mod2m.process(msg).await.expect("pre_mod2m process failed");
            }
            WrappedMessage::Mod2(msg) => {
                node.pre_mod2m
                    .pre_bitlt
                    .mod2
                    .process(msg)
                    .await
                    .expect("mod2 process failed");
            }
            WrappedMessage::Mult(msg) => match msg.session_id.calling_protocol() {
                Some(ProtocolType::LTZBitMul) => {
                    node.pre_mod2m
                        .pre_bitlt
                        .mul
                        .process(msg.sender, msg.session_id, msg.payload)
                        .await
                        .expect("mul process failed");
                }
                _ => {
                    node.pre_mod2m
                        .pre_bitlt
                        .suf_mul_inv
                        .inner
                        .mul
                        .process(msg.sender, msg.session_id, msg.payload)
                        .await
                        .expect("suf_mul_inv.mul process failed");
                }
            },
            WrappedMessage::BatchRecon(msg) => {
                let proto = msg.session_id.calling_protocol();
                let round = msg.session_id.round_id();
                if proto == Some(ProtocolType::LTZBitMul) {
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
                    warn!("ltz turmoil: unexpected BatchRecon round_id {round}");
                }
            }
            _ => warn!("ltz turmoil: unexpected message type"),
        }
    }
}

fn ltz_e2e_turmoil(u_bar: i128, k: usize, dp_bits: usize, latency: Option<(u64, u64)>, slow_node: Option<(usize, Duration)>) {
    setup_tracing();
    let n = 5;
    let t = 1;
    let duration = Duration::from_secs(30);
    let session = SessionId::new(ProtocolType::LTZ, SessionId::pack_slot(0, 0, 0), 42);

    let a_shares = share_signed_fixed(u_bar, n, t);
    let prep = make_premod2m_prep(dp_bits, k - 1, n, t);

    let (mut sim, inner) = turmoil_setup(n, vec![], latency);
    let (tx, rx_done) = std::sync::mpsc::channel::<Result<RobustShare<Fr>, String>>();

    for (id, p) in prep.into_iter().enumerate() {
        let inner = inner.clone();
        let node = LTZNode::<Fr>::new(id, n, t).unwrap();
        let a = a_shares[id].clone();
        let tx = tx.clone();

        sim.host(format!("node{}", id), move || {
            let inner = inner.clone();
            let mut node = node.clone();
            let a = a.clone();
            let p = p.clone();
            let tx = tx.clone();

            async move {
                let (network, rx) = TurmoilNetwork::new(SenderId::Node(id), inner).await;
                let network = Arc::new(network);

                let recv_node = node.clone();
                let recv_net = network.clone();
                tokio::spawn(async move {
                    run_ltz_receiver(rx, recv_node, recv_net).await;
                });

                match node.run(a, k, p, session, network, duration).await {
                    Ok(s) => {
                        let _ = tx.send(Ok(s));
                    }
                    Err(e) => {
                        let _ = tx.send(Err(format!("node {id} ltz error: {e:?}")));
                    }
                }
                Ok(())
            }
        });
    }
    drop(tx);

    if let Some((slow_id, delay)) = slow_node {
        for other in 0..n {
            if other != slow_id {
                sim.set_link_latency(format!("node{}", slow_id), format!("node{}", other), delay);
            }
        }
    }

    add_driver(&mut sim, 60);
    sim.run().unwrap();

    let results: Vec<_> = std::iter::from_fn(|| rx_done.try_recv().ok()).collect();
    assert_eq!(results.len(), n, "not all nodes reported a result/error");

    let mut s_shares = Vec::with_capacity(n);
    for r in results {
        match r {
            Ok(s) => s_shares.push(s),
            Err(e) => panic!("{e}"),
        }
    }

    let (_, s) = RobustShare::recover_secret(&s_shares, n, t).unwrap();
    let expected = if u_bar < 0 { Fr::from(1u64) } else { Fr::from(0u64) };
    assert_eq!(s, expected, "ltz mismatch: u_bar={u_bar}, k={k}");
}

#[test]
fn ltz_e2e_turmoil_negative() {
    ltz_e2e_turmoil(-5, 8, 40, Some((10, 2000)), None);
}

#[test]
fn ltz_e2e_turmoil_positive() {
    ltz_e2e_turmoil(5, 8, 40, Some((10, 2000)), None);
}

#[test]
fn ltz_e2e_turmoil_zero() {
    ltz_e2e_turmoil(0, 8, 40, Some((10, 2000)), None);
}

#[test]
fn ltz_e2e_turmoil_boundaries() {
    ltz_e2e_turmoil(-128, 8, 40, Some((10, 2000)), None); // most negative
    ltz_e2e_turmoil(127, 8, 40, Some((10, 2000)), None); // max positive
    ltz_e2e_turmoil(-1, 8, 40, Some((10, 2000)), None);
}

#[test]
fn ltz_e2e_turmoil_with_slow_node() {
    ltz_e2e_turmoil(-5, 8, 40, Some((10, 50)), Some((4, Duration::from_secs(3))));
}

// ── EQZ ──────────────────────────────────────────────────────────────────

// Mirrors `spawn_eqz_receiver_tasks` in `comparison_test.rs` exactly.
async fn run_eqz_receiver(mut rx: Receiver<(SenderId, Vec<u8>)>, mut node: EQZNode<Fr>, net: Arc<TurmoilNetwork>) {
    while let Some((_sender, bytes)) = rx.recv().await {
        let wrapped: WrappedMessage = match bincode::deserialize(&bytes) {
            Ok(m) => m,
            Err(_) => {
                warn!("eqz turmoil: deserialize failed");
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
            WrappedMessage::Mult(msg) => match msg.session_id.calling_protocol() {
                Some(ProtocolType::KOr1) | Some(ProtocolType::KOr2) => {
                    node.kor_cl
                        .kor_cs
                        .mul
                        .process(msg.sender, msg.session_id, msg.payload)
                        .await
                        .expect("kor_cs mul process failed");
                }
                _ => panic!("eqz turmoil: unexpected calling protocol for Mult: {:?}", msg.session_id),
            },
            WrappedMessage::Eqz(msg) => {
                node.process(msg).await.expect("eqz process failed");
            }
            WrappedMessage::KOrCl(msg) => {
                node.kor_cl.process(msg).await.expect("kor_cl process failed");
            }
            _ => warn!("eqz turmoil: unexpected message type"),
        }
    }
}

fn eqz_e2e_turmoil(a_val: u64, k: usize, latency: Option<(u64, u64)>, slow_node: Option<(usize, Duration)>) {
    setup_tracing();
    let n = 5;
    let t = 1;
    let m = (k as u32).ilog2() as usize + 1;
    let duration = Duration::from_secs(30);
    let session = SessionId::new(ProtocolType::EQZ, SessionId::pack_slot(1, 0, 0), 42);

    let a_shares = share_value(Fr::from(a_val), n, t);
    let prandm_prep = make_prandm_prep(k, k, n, t);
    let kor_cl_prandm = make_prandm_prep(k, m, n, t);
    let kor_cs_prep = make_kor_cs_prep(m, n, t);

    let (mut sim, inner) = turmoil_setup(n, vec![], latency);
    let (tx, rx_done) = std::sync::mpsc::channel::<Result<RobustShare<Fr>, String>>();

    for id in 0..n {
        let inner = inner.clone();
        let node = EQZNode::<Fr>::new(id, n, t).unwrap();
        let a_s = a_shares[id].clone();
        let pp = prandm_prep[id].clone();
        let kl_pp = kor_cl_prandm[id].clone();
        let ks_pp = kor_cs_prep[id].clone();
        let tx = tx.clone();

        sim.host(format!("node{}", id), move || {
            let inner = inner.clone();
            let mut node = node.clone();
            let a_s = a_s.clone();
            let pp = pp.clone();
            let kl_pp = kl_pp.clone();
            let ks_pp = ks_pp.clone();
            let tx = tx.clone();

            async move {
                let (network, rx) = TurmoilNetwork::new(SenderId::Node(id), inner).await;
                let network = Arc::new(network);

                let recv_node = node.clone();
                let recv_net = network.clone();
                tokio::spawn(async move {
                    run_eqz_receiver(rx, recv_node, recv_net).await;
                });

                match node.run(a_s, k, pp, kl_pp, ks_pp, session, network, duration).await {
                    Ok(s) => {
                        let _ = tx.send(Ok(s));
                    }
                    Err(e) => {
                        let _ = tx.send(Err(format!("node {id} eqz error: {e:?}")));
                    }
                }
                Ok(())
            }
        });
    }
    drop(tx);

    if let Some((slow_id, delay)) = slow_node {
        for other in 0..n {
            if other != slow_id {
                sim.set_link_latency(format!("node{}", slow_id), format!("node{}", other), delay);
            }
        }
    }

    add_driver(&mut sim, 60);
    sim.run().unwrap();

    let results: Vec<_> = std::iter::from_fn(|| rx_done.try_recv().ok()).collect();
    assert_eq!(results.len(), n, "not all nodes reported a result/error");

    let mut result_shares = Vec::with_capacity(n);
    for r in results {
        match r {
            Ok(s) => result_shares.push(s),
            Err(e) => panic!("{e}"),
        }
    }

    let (_, result) = RobustShare::recover_secret(&result_shares, n, t).unwrap();
    let expected = Fr::from(if a_val == 0 { 1u64 } else { 0u64 });
    assert_eq!(result, expected, "eqz({a_val}, k={k}) expected {expected:?}, got {result:?}");
}

#[test]
fn eqz_e2e_turmoil_zero() {
    eqz_e2e_turmoil(0, 8, Some((10, 2000)), None);
}

#[test]
fn eqz_e2e_turmoil_nonzero() {
    eqz_e2e_turmoil(42, 8, Some((10, 2000)), None);
    eqz_e2e_turmoil(1, 8, Some((10, 2000)), None);
    eqz_e2e_turmoil(255, 8, Some((10, 2000)), None);
    eqz_e2e_turmoil(254, 8, Some((10, 2000)), None);
}

#[test]
fn eqz_e2e_turmoil_with_slow_node() {
    eqz_e2e_turmoil(0, 8, Some((10, 50)), Some((4, Duration::from_secs(3))));
}
