//! Turmoil-driven tests for FXDiv (secret/secret fixed-point division,
//! `FpDivNode` in `honeybadger/fpdiv/fpdiv.rs`).
//!
//! `FpDivNode::init` composes AppRec (single-shot) with a `theta - 1`
//! iteration Newton/Goldschmidt refinement loop. Steps 3/4 and every loop
//! iteration's Round A share one *base* `SessionId` (`mul_a_session`).
//!
//! `Multiply`'s own storage (and its nested `BatchReconNode` storage) is
//! keyed purely by `(calling_protocol, exec_id, instance_id)` — there was no
//! notion of "which logical call". `BatchReconNode::get_or_create_store` and
//! `Multiply::process` both explicitly tolerate a late message arriving for
//! an already-cleared session by silently recreating/reusing the store
//! ("Wrapping/ID-reuse replay is a separate concern" — see
//! `batch_recon.rs`'s `get_or_create_store`). That's fine for a session used
//! exactly once. It was not fine for `mul_a_session`'s reuse across steps
//! 3/4 and every refinement-loop iteration.
//!
//! CONFIRMED this was a real, easily-reproduced hazard, not just a
//! theoretical one: before the fix, every `fpdiv_e2e_turmoil_*` test below
//! failed reproducibly on every run — including with *no* deliberately
//! adversarial timing at all (turmoil's own default latency was enough) —
//! with nodes aborting mid-computation on `InterpolateError(DecodingError(
//! "Online Error Correction failed to find a valid polynomial"))`: a
//! slightly-slow-but-honest peer's stale opening from a finished call got
//! folded into the next call's (identically-keyed) reconstruction, and the
//! mismatched point made robust decoding fail outright. The existing
//! FakeNetwork-based tests in `bitwise_test.rs`/`node_test.rs` never saw
//! this because that harness delivers messages effectively synchronously,
//! never letting one call finish before the next starts.
//!
//! Fix: `SessionId` bits 120..128 were unused/reserved (see `mod.rs`'s
//! `SessionId::new` — always 0). `mul_a_session_for(call_index)` in
//! `fpdiv.rs` now sets those bits via `with_extra_bits` to a distinct value
//! per logical call (0 for steps 3/4, `iteration_index + 1` for each loop
//! iteration), and `Multiply` propagates `extra_bits` through its own
//! internal session derivations (nested `BatchReconNode` sessions, the
//! direct-open session, and `process()`'s canonical storage key) so each
//! call's storage stays separate. `exec_id`/`instance_id` (the caller's own
//! identity) and `round_id`/`sub_id` (already meaningful to `Multiply`'s own
//! wire protocol) are untouched; every other caller of `Multiply` never sets
//! `extra_bits` and is unaffected (defaults to 0, matching prior behavior).
//!
//! Tests:
//!  - `fpdiv_e2e_turmoil_*`: the full `FpDivNode::init` composition under
//!    turmoil networking — this protocol had no turmoil coverage at all
//!    before (only `FpDivConst`, a different/simpler protocol, did). All
//!    pass now, including the ones that failed on every run pre-fix.
//!  - `fpdiv_mul_session_reuse_without_extra_bits_still_corrupts_turmoil`:
//!    deterministic proof of the raw hazard — a caller that reuses the
//!    literal same `SessionId` (pre-fix `fpdiv.rs` behavior) is still
//!    exposed, since avoiding that is the caller's responsibility.
//!  - `fpdiv_mul_session_reuse_extra_bits_prevents_corruption_turmoil`:
//!    the identical scenario with `extra_bits` varied per call (what
//!    `fpdiv.rs` now does), confirming it prevents the corruption.

mod utils;

use crate::utils::{
    comparison_utils::{field_to_signed_real, make_fpdiv_prep, share_signed_fixed},
    test_utils::setup_tracing,
    turmoil::{add_driver, turmoil_setup},
};
use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_serialize::CanonicalSerialize;
use ark_std::test_rng;
use std::sync::Arc;
use stoffelcrypto::{
    common::{ProtocolSessionId, SecretSharingScheme},
    honeybadger::{
        fpdiv::fpdiv::FpDivNode,
        mul::{multiplication::Multiply, MulError},
        robust_interpolate::robust_interpolate::RobustShare,
        ProtocolType, SessionId, WrappedMessage,
    },
};
use stoffelmpc_network::{fake_network::SenderId, turmoil_network::TurmoilNetwork};
use tokio::sync::mpsc::Receiver;
use tokio::time::Duration;
use tracing::warn;

// ── Shared FpDivNode message dispatcher (TurmoilNetwork) ────────────────────
//
// Mirrors `spawn_fpdiv_receiver_tasks` in `bitwise_test.rs` exactly (same
// dispatch table, already validated by the existing FakeNetwork-based
// correctness tests), adapted to TurmoilNetwork's single pre-fanned-in
// receiver instead of FakeNetwork's per-peer inboxes.
async fn run_fpdiv_receiver(
    mut rx: Receiver<(SenderId, Vec<u8>)>,
    mut node: FpDivNode<Fr>,
    net: Arc<TurmoilNetwork>,
) {
    while let Some((_sender, bytes)) = rx.recv().await {
        let wrapped: WrappedMessage = match bincode::deserialize(&bytes) {
            Ok(m) => m,
            Err(_) => {
                warn!("fpdiv turmoil: deserialize failed");
                continue;
            }
        };
        match wrapped {
            WrappedMessage::Trunc(msg) => {
                let proto = msg.session_id.calling_protocol();
                if proto == Some(ProtocolType::FpDivTrunc) {
                    node.trunc
                        .process(msg)
                        .await
                        .expect("fpdiv trunc process failed");
                } else {
                    node.app_rec
                        .trunc
                        .process(msg)
                        .await
                        .expect("apprec trunc process failed");
                }
            }
            WrappedMessage::PreMod2m(msg) => {
                node.app_rec
                    .bit_dec
                    .pre_mod2m
                    .process(msg)
                    .await
                    .expect("bitdec pre_mod2m process failed");
            }
            WrappedMessage::Mod2(msg) => {
                node.app_rec
                    .bit_dec
                    .pre_mod2m
                    .pre_bitlt
                    .mod2
                    .process(msg)
                    .await
                    .expect("nested mod2 process failed");
            }
            WrappedMessage::Mult(msg) => {
                let proto = msg.session_id.calling_protocol();
                if matches!(
                    proto,
                    Some(ProtocolType::FpDivMulA) | Some(ProtocolType::FpDivMulB)
                ) {
                    node.mul
                        .process(msg.sender, msg.session_id, msg.payload)
                        .await
                        .expect("fpdiv mul process failed");
                } else if proto == Some(ProtocolType::PreBitMul3) {
                    node.app_rec
                        .bit_dec
                        .pre_mod2m
                        .pre_bitlt
                        .mul
                        .process(msg.sender, msg.session_id, msg.payload)
                        .await
                        .expect("nested pre_bitlt.mul process failed");
                } else if matches!(
                    proto,
                    Some(ProtocolType::PreBitMul)
                        | Some(ProtocolType::PreBitMul1)
                        | Some(ProtocolType::PreBitMul2)
                ) {
                    node.app_rec
                        .mul
                        .process(msg.sender, msg.session_id, msg.payload)
                        .await
                        .expect("apprec mul process failed");
                } else if proto == Some(ProtocolType::SufOr) {
                    node.app_rec
                        .suf_or
                        .inner
                        .mul
                        .process(msg.sender, msg.session_id, msg.payload)
                        .await
                        .expect("sufor mul process failed");
                } else {
                    node.app_rec
                        .bit_dec
                        .pre_mod2m
                        .pre_bitlt
                        .suf_mul_inv
                        .inner
                        .mul
                        .process(msg.sender, msg.session_id, msg.payload)
                        .await
                        .expect("nested suf_mul_inv.mul process failed");
                }
            }
            WrappedMessage::BatchRecon(msg) => {
                let proto = msg.session_id.calling_protocol();
                let round = msg.session_id.round_id();
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
                        .expect("fpdiv mul drain failed");
                } else if proto == Some(ProtocolType::PreBitMul3) {
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
                        .expect("nested pre_bitlt.mul drain failed");
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
                        .expect("apprec mul drain failed");
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
                            .expect("sufor drain failed");
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
                            .expect("sufor mul drain failed");
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
                        .expect("nested suf_mul_inv drain failed");
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
                        .expect("nested suf_mul_inv.mul drain failed");
                } else {
                    warn!("fpdiv turmoil: unexpected BatchRecon round_id {round}");
                }
            }
            _ => warn!("fpdiv turmoil: unexpected message type"),
        }
    }
}

// ── Test A/C: full FpDivNode::init end-to-end under turmoil networking ─────

fn fpdiv_e2e_turmoil(
    a_bar: i128,
    b_bar: i128,
    k: usize,
    f: usize,
    latency: Option<(u64, u64)>,
    slow_node: Option<(usize, Duration)>,
) {
    setup_tracing();
    let n = 5;
    let t = 1;
    let dp_bits = 40;
    let duration = Duration::from_secs(30);
    let session = SessionId::new(ProtocolType::FpDiv, SessionId::pack_slot(1, 0, 0), 42);

    let a_shares = share_signed_fixed(a_bar, n, t);
    let b_shares = share_signed_fixed(b_bar, n, t);
    let prep = make_fpdiv_prep(dp_bits, k, f, n, t);

    let (mut sim, inner) = turmoil_setup(n, vec![], latency);
    let (tx, rx_done) =
        std::sync::mpsc::channel::<Result<(RobustShare<Fr>, RobustShare<Fr>), String>>();

    for (id, p) in prep.into_iter().enumerate() {
        let inner = inner.clone();
        let node = FpDivNode::<Fr>::new(id, n, t).unwrap();
        let a = a_shares[id].clone();
        let b = b_shares[id].clone();
        let tx = tx.clone();

        sim.host(format!("node{}", id), move || {
            let inner = inner.clone();
            let mut node = node.clone();
            let a = a.clone();
            let b = b.clone();
            let p = p.clone();
            let tx = tx.clone();

            async move {
                let (network, rx) = TurmoilNetwork::new(SenderId::Node(id), inner).await;
                let network = Arc::new(network);

                let recv_node = node.clone();
                let recv_net = network.clone();
                tokio::spawn(async move {
                    run_fpdiv_receiver(rx, recv_node, recv_net).await;
                });

                match node.init(a, b, k, f, p, session, network, duration).await {
                    Ok((c, z)) => {
                        let _ = tx.send(Ok((c.value().clone(), z)));
                    }
                    Err(e) => {
                        let _ = tx.send(Err(format!("node {id} fpdiv error: {e:?}")));
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

    let mut c_shares = Vec::with_capacity(n);
    let mut z_shares = Vec::with_capacity(n);
    for r in results {
        match r {
            Ok((c, z)) => {
                c_shares.push(c);
                z_shares.push(z);
            }
            Err(e) => panic!("{e}"),
        }
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

/// Baseline correctness + liveness for the full FXDiv composition
/// (AppRec + theta-1 refinement iterations) under realistic jittery
/// latency. `FpDivConst` already had turmoil coverage; the secret/secret
/// `FpDivNode` (this file's subject) previously had none.
#[test]
fn fpdiv_e2e_turmoil_variable_latency() {
    // k=15,f=6 -> theta=3, so 2 refinement-loop iterations run: this
    // exercises the `mul_a_session`/`mul_b_session` reuse boundary at least
    // once under real network jitter, not just a single-iteration case.
    fpdiv_e2e_turmoil(384, 128, 15, 6, Some((10, 2000)), None); // 6.0 / 2.0 = 3.0
}

/// Control: no explicit extra latency configured at all (turmoil's own
/// baseline default timing only). Kept separate from the variable-latency
/// test above to show the reuse hazard doesn't need deliberately wide
/// jitter to reproduce — turmoil's default message timing is already
/// enough to split iterations across the fast/slow quorum boundary.
#[test]
fn fpdiv_e2e_turmoil_control_no_extra_latency() {
    fpdiv_e2e_turmoil(384, 128, 15, 6, None, None);
}

#[test]
fn fpdiv_e2e_turmoil_sign_permutations() {
    fpdiv_e2e_turmoil(-384, 128, 15, 6, Some((10, 2000)), None);
    fpdiv_e2e_turmoil(384, -128, 15, 6, Some((10, 2000)), None);
    fpdiv_e2e_turmoil(-384, -128, 15, 6, Some((10, 2000)), None);
}

#[test]
fn fpdiv_e2e_turmoil_by_zero() {
    fpdiv_e2e_turmoil(64, 0, 15, 6, Some((10, 2000)), None);
}

/// Adversarial-timing regression guard: one node is consistently much
/// slower than the rest, maximizing the odds that the fast quorum races
/// through a refinement-loop iteration boundary (reusing `mul_a_session`/
/// `mul_b_session`) while the slow node's prior-iteration messages are
/// still in flight. If the session-reuse hazard described at the top of
/// this file is reachable at full end-to-end scale, this is the test most
/// likely to surface it (as a wrong result, a hang, or a node-side error).
#[test]
fn fpdiv_e2e_turmoil_with_slow_node() {
    fpdiv_e2e_turmoil(
        384,
        128,
        15,
        6,
        Some((10, 50)),
        Some((4, Duration::from_secs(3))),
    );
}

async fn deliver_direct_open_share(
    node: &Multiply<Fr>,
    session_id: SessionId,
    dealer: usize,
    a_share: RobustShare<Fr>,
    b_share: RobustShare<Fr>,
) -> Result<(), MulError> {
    let sid = SessionId::new(
        ProtocolType::FpDivMulA,
        SessionId::pack_slot(session_id.exec_id(), dealer as u8, 2),
        session_id.instance_id(),
    )
    .with_extra_bits(session_id.extra_bits());
    let mut payload = Vec::new();
    vec![a_share].serialize_compressed(&mut payload).unwrap();
    vec![b_share].serialize_compressed(&mut payload).unwrap();
    node.process(dealer, sid, payload).await
}

// ── Test B: deterministic proof of the mul_a_session reuse hazard, and of
// its fix ────────────────────────────────────────────────────────────────
//
// Isolates exactly the pattern `fpdiv.rs` relies on: one base `Multiply`
// session, reused across two sequential logical calls with *different*
// secret inputs (iteration 0 and iteration 1 of FpDiv's refinement loop).
// One peer ("dealer 4") is slow: its iteration-0 direct-open share arrives
// only after iteration 1 has already started reusing the base session.
// Runs over a real TurmoilNetwork (single host), driving `Multiply::process`
// directly with hand-built messages so the sequencing is exact and
// reproducible — no timing race to win, unlike a full e2e hold.
//
// `fpdiv_mul_session_reuse_without_extra_bits_still_corrupts_turmoil` shows
// the raw hazard: a caller that reuses the literal same `SessionId` (the
// pre-fix behavior) still gets corruption/failure, since `Multiply` itself
// has no opinion on reuse — that's the caller's responsibility.
// `fpdiv_mul_session_reuse_extra_bits_prevents_corruption_turmoil` shows the
// fix: tagging each call with a distinct `extra_bits` value (exactly what
// `fpdiv.rs`'s `mul_a_session_for` now does) keeps the two calls' storage
// separate, so the stale delivery lands in an abandoned bucket instead of
// iteration 1's live one, and iteration 1 completes correctly once dealer
// 4's real share arrives.
async fn run_session_reuse_scenario(
    node_id: usize,
    n: usize,
    t: usize,
    iter0_session: SessionId,
    iter1_session: SessionId,
) -> Result<(), String> {
    let node = Multiply::<Fr>::new(node_id, n, t).unwrap();
    let mut rng = test_rng();

    // ---- Iteration 0: single-value multiply, direct-open path ----
    // (no_of_mul=1, t+1=2 -> no_of_batch=0 -> everything opens via direct
    // point-to-point `Mult` messages, matching a Round-B-shaped call;
    // Round A's own 2-value shape would take the batched path instead, but
    // the session-reuse hazard being demonstrated lives in
    // `Multiply::process` itself and applies identically to both paths.)
    let x1 = Fr::rand(&mut rng);
    let y1 = Fr::rand(&mut rng);
    let a1 = Fr::rand(&mut rng); // the value that will be "opened" as triple.a - x1
    let b1 = Fr::rand(&mut rng);
    let triple1_mult = RobustShare::new((a1 + x1) * (b1 + y1), node_id, t);
    {
        let storage_bind = node
            .get_or_create_mult_storage(iter0_session, node_id)
            .await
            .unwrap();
        let mut storage = storage_bind.lock().await;
        storage.no_of_mul = Some(1);
        storage.inputs = (
            vec![RobustShare::new(x1, node_id, t)],
            vec![RobustShare::new(y1, node_id, t)],
        );
        storage.share_mult_from_triple = vec![triple1_mult];
    }

    // Genuine degree-t shares of the true masked values a1, b1, as the
    // other 2t+1=3 dealers (here: 1, 2, 4) would open them.
    let a1_shares = RobustShare::compute_shares(a1, n, t, None, &mut rng).unwrap();
    let b1_shares = RobustShare::compute_shares(b1, n, t, None, &mut rng).unwrap();

    // Dealers 1 and 2 deliver promptly; dealer 4 ("slow") does not deliver
    // its iteration-0 share yet.
    deliver_direct_open_share(
        &node,
        iter0_session,
        1,
        a1_shares[1].clone(),
        b1_shares[1].clone(),
    )
    .await
    .unwrap();
    deliver_direct_open_share(
        &node,
        iter0_session,
        2,
        a1_shares[2].clone(),
        b1_shares[2].clone(),
    )
    .await
    .unwrap();

    // Only 2 of the 2t+1=3 dealers needed have delivered: iteration 0 is
    // legitimately still pending at this node.

    // ---- Dealer 4's iteration-0 share finally arrives, LATE ----
    let iter0_late = deliver_direct_open_share(
        &node,
        iter0_session,
        4,
        a1_shares[4].clone(),
        b1_shares[4].clone(),
    )
    .await;
    let iter0_result = match iter0_late {
        Ok(()) => node
            .wait_for_result(iter0_session, Duration::from_secs(2))
            .await
            .expect("iteration 0 should complete once its 3rd dealer share lands"),
        Err(e) => {
            return Err(format!(
                "iteration 0's own delivery unexpectedly failed: {e:?}"
            ))
        }
    };
    if iter0_result.len() != 1 {
        return Err("iteration 0 returned the wrong number of results".to_string());
    }
    node.clear_store(iter0_session).await.unwrap();

    // ---- Iteration 1: reuses (all or part of) iter0_session, brand-new
    // secret inputs ----
    let x2 = Fr::rand(&mut rng);
    let y2 = Fr::rand(&mut rng);
    let a2 = Fr::rand(&mut rng);
    let b2 = Fr::rand(&mut rng);
    let triple2_mult = RobustShare::new((a2 + x2) * (b2 + y2), node_id, t);
    {
        let storage_bind = node
            .get_or_create_mult_storage(iter1_session, node_id)
            .await
            .unwrap();
        let mut storage = storage_bind.lock().await;
        storage.no_of_mul = Some(1);
        storage.inputs = (
            vec![RobustShare::new(x2, node_id, t)],
            vec![RobustShare::new(y2, node_id, t)],
        );
        storage.share_mult_from_triple = vec![triple2_mult];
    }

    let a2_shares = RobustShare::compute_shares(a2, n, t, None, &mut rng).unwrap();
    let b2_shares = RobustShare::compute_shares(b2, n, t, None, &mut rng).unwrap();

    // Dealers 1 and 2 deliver their genuine iteration-1 shares. That's only
    // 2 of the 3 needed -- legitimately incomplete.
    deliver_direct_open_share(
        &node,
        iter1_session,
        1,
        a2_shares[1].clone(),
        b2_shares[1].clone(),
    )
    .await
    .unwrap();
    deliver_direct_open_share(
        &node,
        iter1_session,
        2,
        a2_shares[2].clone(),
        b2_shares[2].clone(),
    )
    .await
    .unwrap();

    // Dealer 4 has NOT sent an iteration-1 share yet. But dealer 4's stale
    // iteration-0 direct-open message was already fully absorbed above
    // (into iteration 0's now-cleared storage) -- that instance is done and
    // gone. This is a *fresh*, separate stale-arrival scenario: suppose
    // dealer 4's iteration-0 message had instead been delayed long enough
    // to arrive only now, after iteration 1 already started reusing
    // `iter0_session`'s key. Simulate that directly by delivering an
    // iteration-0-shaped share (dealer 4, values a1/b1) tagged with
    // `iter0_session` again.
    let stale_delivery = deliver_direct_open_share(
        &node,
        iter0_session,
        4,
        a1_shares[4].clone(),
        b1_shares[4].clone(),
    )
    .await;
    if let Err(e) = stale_delivery {
        // When `iter0_session == iter1_session` (no `extra_bits`), this
        // stale delivery IS iteration 1's 3rd dealer share as far as
        // Multiply's storage is concerned -- mixing dealer 4's stale
        // iteration-0 opening with dealers 1/2's genuine iteration-1 ones
        // makes robust decoding fail outright. That's the bug, observed
        // here rather than at the final `wait_for_result` below.
        return Err(format!(
            "BUG: the stale iteration-0 delivery got folded into iteration 1's reconstruction \
             attempt and made it fail for an honest node: {e:?}"
        ));
    }

    // Dealer 4's genuine iteration-1 share, finally.
    deliver_direct_open_share(
        &node,
        iter1_session,
        4,
        a2_shares[4].clone(),
        b2_shares[4].clone(),
    )
    .await
    .unwrap();

    match node
        .wait_for_result(iter1_session, Duration::from_secs(2))
        .await
    {
        Ok(shares) => {
            let expected = x2 * y2;
            if shares[0].share[0] == expected {
                Ok(())
            } else {
                Err(format!(
                    "BUG: iteration 1 completed with the WRONG value (cross-iteration \
                     corruption): got {:?}, expected x2*y2 = {:?}",
                    shares[0].share[0], expected
                ))
            }
        }
        Err(e) => Err(format!(
            "BUG: iteration 1 never completed even after dealer 4's genuine share arrived -- \
             the stale iteration-0 delivery must have corrupted or wedged its storage: {e:?}"
        )),
    }
}

fn run_session_reuse_test(iter0_session: SessionId, iter1_session: SessionId, expect_ok: bool) {
    setup_tracing();
    let n = 5;
    let t = 1;
    let node_id = 0;

    let (mut sim, inner) = turmoil_setup(1, vec![], Some((10, 50)));
    let (tx, rx_done) = std::sync::mpsc::channel::<Result<(), String>>();

    sim.host("node0", move || {
        let inner = inner.clone();
        let tx = tx.clone();
        async move {
            let (_network, _rx) = TurmoilNetwork::new(SenderId::Node(node_id), inner).await;
            let outcome =
                run_session_reuse_scenario(node_id, n, t, iter0_session, iter1_session).await;
            let _ = tx.send(outcome);
            Ok(())
        }
    });

    add_driver(&mut sim, 10);
    sim.run().unwrap();

    let results: Vec<_> = std::iter::from_fn(|| rx_done.try_recv().ok()).collect();
    assert_eq!(results.len(), 1);
    match (&results[0], expect_ok) {
        (Ok(()), true) => {}
        (Err(e), false) => {
            // Documents the raw hazard: confirm it's the expected failure
            // mode, not something unrelated.
            assert!(
                e.contains("BUG:"),
                "expected the documented cross-iteration corruption/hang, got a different failure: {e}"
            );
        }
        (Ok(()), false) => panic!(
            "expected the raw session-reuse hazard to still manifest (no extra_bits used), but \
             iteration 1 completed correctly -- did Multiply's default behavior change?"
        ),
        (Err(e), true) => panic!("{e}"),
    }
}

/// Raw hazard: both iterations tagged with the literal same SessionId (no
/// `extra_bits`) -- the pre-fix `fpdiv.rs` behavior. `Multiply` has no
/// opinion on session reuse by itself; avoiding this is the caller's job.
#[test]
fn fpdiv_mul_session_reuse_without_extra_bits_still_corrupts_turmoil() {
    let session_id = SessionId::new(ProtocolType::FpDivMulA, SessionId::pack_slot(9, 0, 0), 42);
    run_session_reuse_test(session_id, session_id, false);
}

/// The fix: each call tagged with a distinct `extra_bits` value, exactly as
/// `fpdiv.rs`'s `mul_a_session_for` now does (call_index 0 for steps 3/4,
/// call_index >= 1 for each refinement-loop iteration). The stale
/// iteration-0 delivery now lands in an abandoned bucket instead of
/// iteration 1's live one.
#[test]
fn fpdiv_mul_session_reuse_extra_bits_prevents_corruption_turmoil() {
    let base = SessionId::new(ProtocolType::FpDivMulA, SessionId::pack_slot(9, 0, 0), 42);
    run_session_reuse_test(base.with_extra_bits(0), base.with_extra_bits(1), true);
}
