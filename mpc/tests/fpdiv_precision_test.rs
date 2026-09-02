//! Regression guard for the "Round B (step 8) repeated per refinement-loop
//! iteration" bug in FXDiv (Catrina COMM 2018, Protocol 7).
//!
//! Protocol 7 runs step 8 (the final `Div2mPD(c*(α+d), 2k, 2f)`) exactly
//! *once*, after the θ-1-rep loop over steps 6-7 — not once per iteration.
//! Each loop trip is a plain Goldschmidt step (`c_n = c_{n-1}(1+d_{n-1})`,
//! `d_n = d_{n-1}^2`), which telescopes to `c_n = (a/b)(1-ϵ0^{2^n})` for
//! initial relative error ϵ0. The one extra step-8 half-step reuses the
//! *last* `d` (already squared θ-1 times) without squaring it again,
//! buying one more doubling of accuracy for the cost of a single multiply.
//!
//! Repeating that half-step on every iteration instead (using that
//! iteration's own freshly squared `d`) does not converge to `a/b`: the
//! recursion `c_n = c_{n-1}(1+d_{n-1})(1+d_n)` telescopes to
//! `c_n → (a/b)/(1-ϵ0^2)` as `n → ∞` — a fixed, wrong value with a
//! permanent relative bias that does not shrink with more iterations.
//! Empirically, for the (a,b) pair used below, the buggy variant measured
//! a steady ~0.2% relative error (vs. the correct variant's <1e-9).
//!
//! This lives in its own file/process (not alongside `bitwise_test.rs`'s
//! other FpDiv tests) because `SecretFixedPoint::new_with_precision` locks
//! a process-global `(k, f)` on first use (`GLOBAL_FIXED_PRECISION`); this
//! test deliberately uses a different `(k, f)` than the k=15,f=6 the other
//! FpDiv tests share, to run enough iterations (θ-1 = 3) to make the bug's
//! fixed bias trivially separable from a correct implementation's residual
//! (sub-ULP) truncation-rounding noise.

mod utils;

use crate::utils::{
    comparison_utils::{field_to_signed_real, make_fpdiv_prep, share_signed_fixed},
    test_utils::{fan_in_inboxes, setup_tracing, test_setup},
};
use ark_bls12_381::Fr;
use std::sync::Arc;
use stoffelcrypto::{
    common::{types::fixed::FixedPointPrecision, ProtocolSessionId, SecretSharingScheme},
    honeybadger::{
        fpdiv::fpdiv::FpDivNode, robust_interpolate::robust_interpolate::RobustShare, ProtocolType,
        SessionId, WrappedMessage,
    },
};
use stoffelmpc_network::fake_network::{FakeNetwork, SenderId};
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinSet;
use tracing::warn;

// Mirrors `spawn_fpdiv_receiver_tasks` in `bitwise_test.rs` (same dispatch
// table, already validated by that file's correctness tests).
fn spawn_fpdiv_receiver_tasks(
    num_parties: usize,
    mut receivers: Vec<Vec<Receiver<Vec<u8>>>>,
    nodes: Vec<FpDivNode<Fr>>,
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
                                .expect("fpdiv mul drain_batch_recon_output failed");
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

#[tokio::test]
async fn fpdiv_high_precision_tight_tolerance() {
    setup_tracing();
    let n = 5;
    let t = 1;
    let dp_bits = 40;
    let k = 32;
    let f = 20;
    let duration = std::time::Duration::from_secs(10);
    let session = SessionId::new(ProtocolType::FpDiv, SessionId::pack_slot(1, 0, 0), 42);

    // 6.0 / 2.0 = 3.0, at f=10 fractional bits.
    let scale = 1i128 << f;
    let a_bar = 6 * scale;
    let b_bar = 2 * scale;

    let a_shares = share_signed_fixed(a_bar, n, t);
    let b_shares = share_signed_fixed(b_bar, n, t);
    let prep = make_fpdiv_prep(dp_bits, k, f, n, t);

    let (network, receivers, _, _) = test_setup(n, vec![]);
    let nodes: Vec<FpDivNode<Fr>> = (0..n).map(|id| FpDivNode::new(id, n, t).unwrap()).collect();
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
        assert_eq!(*c.precision(), FixedPointPrecision::new(k, f));
        c_shares.push(c.value().clone());
        z_shares.push(z);
    }

    let (_, c_val) = RobustShare::recover_secret(&c_shares, n, t).unwrap();
    let (_, z_val) = RobustShare::recover_secret(&z_shares, n, t).unwrap();
    assert_eq!(z_val, Fr::from(0u64), "z must be 0 for b != 0");

    let c_real = field_to_signed_real(c_val, f);
    let expected = 3.0f64;
    let rel_err = ((c_real - expected) / expected).abs();
    assert!(
        rel_err < 1e-4,
        "FXDiv(6/2) = {c_real}, expected {expected}, relative error {rel_err} exceeds tolerance \
         -- if this regresses, check whether fpdiv.rs's step-8 (Round B) half-step got moved back \
         inside the refinement loop instead of running once after it"
    );
}
