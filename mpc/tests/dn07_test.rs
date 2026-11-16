//! End-to-end tests for the DN07 preprocessing multiplication and exact-zero check, over `F` and
//! over `Gf256`, driven by double sharings the test deals.
//!
//! **Every session here carries a preprocessing tag.** That is not decoration: `Dn07MulNode` opens
//! at degree `2t`, which is unreconstructible on the asynchronous robust online path at
//! `n = 3t+1`, and `PreprocessingSessionId` is the only session type its `init_*` accepts. The
//! test that an online tag is refused lives here too, at the bottom.

mod utils;

use crate::utils::test_utils::{fan_in_inboxes, setup_tracing, test_setup};
use ark_bls12_381::Fr;
use std::sync::Arc;
use std::time::Duration;
use stoffelcrypto::common::gf2k::field::Gf256;
use stoffelcrypto::common::gf2k::share::GfShare;
use stoffelcrypto::common::share::shamir::NonRobustShare;
use stoffelcrypto::common::{ProtocolSessionId, SecretSharingScheme};
use stoffelcrypto::honeybadger::dn07::dn07::Dn07MulNode;
use stoffelcrypto::honeybadger::dn07::gf_dn07::GfDn07MulNode;
use stoffelcrypto::honeybadger::dn07::{Dn07Error, PreprocessingSessionId};
use stoffelcrypto::honeybadger::double_share::DoubleShamirShare;
use stoffelcrypto::honeybadger::gf_double_share::GfDoubleShamirShare;
use stoffelcrypto::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelcrypto::honeybadger::{ProtocolType, SessionId, WrappedMessage};
use stoffelmpc_network::fake_network::{FakeNetwork, SenderId};
use tokio::sync::mpsc::Receiver;
use tokio::sync::Mutex;

/// `n = 10, t = 3` throughout: the smallest party count in the plan's tables at which `t >= 2`,
/// which is where a one-coefficient PRZS would start leaking. At `t = 1` the correct and the
/// broken mask coincide, so a suite run only at `n = 4` proves nothing about either.
const N: usize = 10;
const T: usize = 3;

// ---------------------------------------------------------------------------------------------
// double sharings
// ---------------------------------------------------------------------------------------------

/// `count` double sharings `([r]_t, [r]_2t)` of independent uniform `r`, one list per party.
/// Dealt by the test: in production these come from `RanDouSha`, which has its own tests.
fn f_doubles(count: usize, n: usize, t: usize) -> Vec<Vec<DoubleShamirShare<Fr>>> {
    use ark_ff::UniformRand;
    let mut rng = ark_std::test_rng();
    let mut per_party = vec![Vec::with_capacity(count); n];
    for _ in 0..count {
        let r = Fr::rand(&mut rng);
        let low = NonRobustShare::compute_shares(r, n, t, None, &mut rng).unwrap();
        let high = NonRobustShare::compute_shares(r, n, 2 * t, None, &mut rng).unwrap();
        for (party, (l, h)) in low.into_iter().zip(high).enumerate() {
            per_party[party].push(DoubleShamirShare::new(l, h));
        }
    }
    per_party
}

fn gf_doubles(count: usize, n: usize, t: usize) -> Vec<Vec<GfDoubleShamirShare<Gf256>>> {
    use stoffelcrypto::common::gf2k::field::BinaryField;
    let mut rng = ark_std::test_rng();
    let mut per_party = vec![Vec::with_capacity(count); n];
    for _ in 0..count {
        let r = Gf256::random(&mut rng);
        let low = GfShare::compute_shares(r, n, t, &mut rng).unwrap();
        let high = GfShare::compute_shares(r, n, 2 * t, &mut rng).unwrap();
        for (party, (l, h)) in low.into_iter().zip(high).enumerate() {
            per_party[party].push(GfDoubleShamirShare::new(l, h));
        }
    }
    per_party
}

fn pre_sid(tag: ProtocolType, exec: u64) -> PreprocessingSessionId {
    PreprocessingSessionId::new(SessionId::new(tag, SessionId::pack_slot(exec, 0, 0), 111)).unwrap()
}

// ---------------------------------------------------------------------------------------------
// message pumps
// ---------------------------------------------------------------------------------------------

/// Routes `WrappedMessage::BatchRecon` into each node's DN07 child and drains completions.
///
/// Batch-reconstruction errors are *collected* rather than unwrapped: a degree-`2t` opening is
/// detect-and-abort, and the adversarial test below needs to assert that the abort happened.
fn spawn_f_pumps(
    nodes: &[Arc<Mutex<Dn07MulNode<Fr>>>],
    mut receivers: Vec<Vec<Receiver<Vec<u8>>>>,
    network: Vec<Arc<FakeNetwork>>,
    errors: Arc<Mutex<Vec<String>>>,
) {
    for (i, node) in nodes.iter().enumerate() {
        let node = Arc::clone(node);
        let inbox: Vec<(SenderId, Receiver<Vec<u8>>)> = receivers
            .remove(0)
            .into_iter()
            .enumerate()
            .map(|(j, r)| (SenderId::Node(j), r))
            .collect();
        let mut merged = fan_in_inboxes(inbox);
        let net = network[i].clone();
        let errors = Arc::clone(&errors);
        tokio::spawn(async move {
            while let Some((_, bytes)) = merged.recv().await {
                let Ok(wrapped) = bincode::deserialize::<WrappedMessage>(&bytes) else {
                    continue;
                };
                if let WrappedMessage::BatchRecon(msg) = wrapped {
                    let mut bind = node.lock().await;
                    if let Err(e) = bind.batch_recon.process(msg, net.clone()).await {
                        errors.lock().await.push(format!("{e:?}"));
                        continue;
                    }
                    if let Err(e) = bind.drain_batch_recon_output().await {
                        errors.lock().await.push(format!("{e:?}"));
                    }
                }
            }
        });
    }
}

fn spawn_gf_pumps(
    nodes: &[Arc<Mutex<GfDn07MulNode<Gf256>>>],
    mut receivers: Vec<Vec<Receiver<Vec<u8>>>>,
    network: Vec<Arc<FakeNetwork>>,
    errors: Arc<Mutex<Vec<String>>>,
) {
    for (i, node) in nodes.iter().enumerate() {
        let node = Arc::clone(node);
        let inbox: Vec<(SenderId, Receiver<Vec<u8>>)> = receivers
            .remove(0)
            .into_iter()
            .enumerate()
            .map(|(j, r)| (SenderId::Node(j), r))
            .collect();
        let mut merged = fan_in_inboxes(inbox);
        let net = network[i].clone();
        let errors = Arc::clone(&errors);
        tokio::spawn(async move {
            while let Some((_, bytes)) = merged.recv().await {
                let Ok(wrapped) = bincode::deserialize::<WrappedMessage>(&bytes) else {
                    continue;
                };
                if let WrappedMessage::GfBatchRecon(msg) = wrapped {
                    let mut bind = node.lock().await;
                    if let Err(e) = bind.batch_recon.process(msg, net.clone()).await {
                        errors.lock().await.push(format!("{e:?}"));
                        continue;
                    }
                    if let Err(e) = bind.drain_batch_recon_output().await {
                        errors.lock().await.push(format!("{e:?}"));
                    }
                }
            }
        });
    }
}

// ---------------------------------------------------------------------------------------------
// `F` side
// ---------------------------------------------------------------------------------------------

/// Degree-`t` sharings of `secrets`, laid out per party.
fn f_share_all(secrets: &[Fr], n: usize, t: usize) -> Vec<Vec<RobustShare<Fr>>> {
    let mut rng = ark_std::test_rng();
    let mut out = vec![Vec::new(); n];
    for s in secrets {
        let shares = RobustShare::compute_shares(*s, n, t, None, &mut rng).unwrap();
        for (p, item) in out.iter_mut().enumerate() {
            item.push(shares[p].clone());
        }
    }
    out
}

#[tokio::test]
async fn f_dn07_multiplies_without_a_beaver_triple() {
    setup_tracing();
    let sid = pre_sid(ProtocolType::Dn07, 1);
    let k = 2 * T + 1; // exactly one degree-2t batch-reconstruction group

    let xs: Vec<Fr> = (0..k).map(|i| Fr::from(i as u64 + 3)).collect();
    let ys: Vec<Fr> = (0..k).map(|i| Fr::from(i as u64 * 7 + 11)).collect();
    let x_shares = f_share_all(&xs, N, T);
    let y_shares = f_share_all(&ys, N, T);
    let sources = f_doubles(k, N, T);

    let (network, receivers, _, _) = test_setup(N, vec![]);
    let nodes: Vec<Arc<Mutex<Dn07MulNode<Fr>>>> = (0..N)
        .map(|id| Arc::new(Mutex::new(Dn07MulNode::<Fr>::new(id, N, T).unwrap())))
        .collect();
    let errors = Arc::new(Mutex::new(Vec::new()));
    spawn_f_pumps(&nodes, receivers, network.clone(), Arc::clone(&errors));

    for (id, node) in nodes.iter().enumerate() {
        let doubles = sources[id].clone();
        node.lock()
            .await
            .init_mul(
                sid,
                x_shares[id].clone(),
                y_shares[id].clone(),
                doubles,
                network[id].clone(),
            )
            .await
            .unwrap();
    }

    let mut products: Vec<Vec<RobustShare<Fr>>> = vec![Vec::new(); k];
    for node in nodes.iter() {
        let handle = node.lock().await.clone();
        let out = handle
            .wait_for_products(sid.get(), Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(out.len(), k);
        for (i, share) in out.into_iter().enumerate() {
            // The product must come back labelled degree `t`: the whole point of DN07 is that the
            // degree-`2t` object never leaves the protocol.
            assert_eq!(share.degree, T);
            products[i].push(share);
        }
    }

    assert!(errors.lock().await.is_empty(), "{:?}", errors.lock().await);
    for i in 0..k {
        let (_, xy) = RobustShare::recover_secret(&products[i], N, T).unwrap();
        assert_eq!(xy, xs[i] * ys[i], "DN07 product {i} is wrong");
    }
}

#[tokio::test]
async fn f_exact_zero_check_passes_on_bits_and_aborts_on_a_non_bit() {
    setup_tracing();
    let k = 2 * T + 1;

    // Case 1: every `u` is a bit, so `u(u-1) = 0` and the check passes.
    // Case 2: one `u` is 5, so `u(u-1) = 20 != 0` and the check must abort with the index.
    for (exec, values, expected_violation) in [
        (10u64, vec![0u64, 1, 1, 0, 1, 0, 1], None),
        (11u64, vec![0u64, 1, 5, 0, 1, 0, 1], Some(2usize)),
    ] {
        let sid = pre_sid(ProtocolType::Dn07, exec);
        let us: Vec<Fr> = values.iter().map(|v| Fr::from(*v)).collect();
        let u_shares = f_share_all(&us, N, T);
        let sources = f_doubles(k, N, T);

        let (network, receivers, _, _) = test_setup(N, vec![]);
        let nodes: Vec<Arc<Mutex<Dn07MulNode<Fr>>>> = (0..N)
            .map(|id| Arc::new(Mutex::new(Dn07MulNode::<Fr>::new(id, N, T).unwrap())))
            .collect();
        let errors = Arc::new(Mutex::new(Vec::new()));
        spawn_f_pumps(&nodes, receivers, network.clone(), Arc::clone(&errors));

        for (id, node) in nodes.iter().enumerate() {
            let doubles = sources[id].clone();
            // v = u - 1, so the product is u(u-1), zero exactly on {0, 1}.
            let v: Vec<RobustShare<Fr>> = u_shares[id]
                .iter()
                .map(|s| (s.clone() - Fr::from(1_u64)).unwrap())
                .collect();
            node.lock()
                .await
                .init_zero_check(sid, u_shares[id].clone(), v, doubles, network[id].clone())
                .await
                .unwrap();
        }

        for node in nodes.iter() {
            let handle = node.lock().await.clone();
            let outcome = handle
                .wait_for_zero_check(sid.get(), Duration::from_secs(5))
                .await;
            match expected_violation {
                None => assert!(outcome.is_ok(), "all-bit batch must pass, got {outcome:?}"),
                Some(i) => assert!(
                    matches!(outcome, Err(Dn07Error::ZeroCheckFailed { index }) if index == i),
                    "expected an abort naming index {i}, got {outcome:?}"
                ),
            }
        }
        assert!(errors.lock().await.is_empty(), "{:?}", errors.lock().await);
    }
}

/// The detect-with-probability-1 property, exercised rather than asserted in prose.
///
/// One party contributes a corrupted degree-`2t` share. At `n = 3t+1` the degree-`2t` evaluation
/// code is `[3t+1, 2t+1]` with minimum distance `n - 2t = t+1 > t`, so a single deviation is a
/// **non-codeword** and reconstruction must fail rather than return a wrong value. This is what
/// licenses DN07's use in preprocessing without a sacrifice, a MAC or a cut-and-choose — and it is
/// also why DN07 must never reach the online path, where an abort is not permitted.
#[tokio::test]
async fn f_a_corrupted_share_aborts_rather_than_yielding_a_wrong_product() {
    setup_tracing();
    let sid = pre_sid(ProtocolType::Dn07, 20);
    let k = 2 * T + 1;

    let xs: Vec<Fr> = (0..k).map(|i| Fr::from(i as u64 + 2)).collect();
    let x_shares = f_share_all(&xs, N, T);
    let sources = f_doubles(k, N, T);

    let (network, receivers, _, _) = test_setup(N, vec![]);
    let nodes: Vec<Arc<Mutex<Dn07MulNode<Fr>>>> = (0..N)
        .map(|id| Arc::new(Mutex::new(Dn07MulNode::<Fr>::new(id, N, T).unwrap())))
        .collect();
    let errors = Arc::new(Mutex::new(Vec::new()));
    spawn_f_pumps(&nodes, receivers, network.clone(), Arc::clone(&errors));

    for (id, node) in nodes.iter().enumerate() {
        let mut doubles = sources[id].clone();
        if id == 0 {
            // Party 0 deviates: it masks with a `[r]_2t` that is off by a constant, so its
            // contribution to the opening lies on no common degree-2t polynomial with the rest.
            for d in doubles.iter_mut() {
                *d = stoffelcrypto::honeybadger::double_share::DoubleShamirShare::new(
                    d.degree_t.clone(),
                    NonRobustShare::new(
                        d.degree_2t.share[0] + Fr::from(12345_u64),
                        d.degree_2t.id,
                        d.degree_2t.degree,
                    ),
                );
            }
        }
        node.lock()
            .await
            .init_mul(
                sid,
                x_shares[id].clone(),
                x_shares[id].clone(),
                doubles,
                network[id].clone(),
            )
            .await
            .unwrap();
    }

    // Give the pumps time to attempt reconstruction and fail.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let collected = errors.lock().await.clone();
    assert!(
        !collected.is_empty(),
        "a single corrupted degree-2t share must be DETECTED; nothing was reported"
    );
    // Specifically a *decoding* failure, not incidental plumbing noise: the corrupted evaluation
    // vector is a non-codeword of the `[3t+1, 2t+1]` code, and that is what must be reported.
    assert!(
        collected.iter().any(|e| e.contains("Decoding")
            || e.contains("Interpolate")
            || e.contains("NotEnoughShares")),
        "expected a reconstruction failure, got: {collected:?}"
    );

    // And no honest party may have accepted a product.
    for node in nodes.iter().skip(1) {
        let handle = node.lock().await.clone();
        let out = handle
            .wait_for_products(sid.get(), Duration::from_millis(200))
            .await;
        assert!(
            out.is_err(),
            "an honest party accepted a product from a corrupted opening"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// `Gf2k` side
// ---------------------------------------------------------------------------------------------

fn gf_share_all(secrets: &[Gf256], n: usize, t: usize) -> Vec<Vec<GfShare<Gf256>>> {
    let mut rng = ark_std::test_rng();
    let mut out = vec![Vec::new(); n];
    for s in secrets {
        let shares = GfShare::compute_shares(*s, n, t, &mut rng).unwrap();
        for (p, item) in out.iter_mut().enumerate() {
            item.push(shares[p].clone());
        }
    }
    out
}

#[tokio::test]
async fn gf_dn07_multiplies_without_a_beaver_triple() {
    setup_tracing();
    let sid = pre_sid(ProtocolType::GfDn07, 30);
    let k = 2 * T + 1;

    let xs: Vec<Gf256> = (0..k).map(|i| Gf256::from(i as u8 + 3)).collect();
    let ys: Vec<Gf256> = (0..k).map(|i| Gf256::from(i as u8 * 7 + 11)).collect();
    let x_shares = gf_share_all(&xs, N, T);
    let y_shares = gf_share_all(&ys, N, T);
    let sources = gf_doubles(k, N, T);

    let (network, receivers, _, _) = test_setup(N, vec![]);
    let nodes: Vec<Arc<Mutex<GfDn07MulNode<Gf256>>>> = (0..N)
        .map(|id| Arc::new(Mutex::new(GfDn07MulNode::<Gf256>::new(id, N, T).unwrap())))
        .collect();
    let errors = Arc::new(Mutex::new(Vec::new()));
    spawn_gf_pumps(&nodes, receivers, network.clone(), Arc::clone(&errors));

    for (id, node) in nodes.iter().enumerate() {
        let doubles = sources[id].clone();
        node.lock()
            .await
            .init_mul(
                sid,
                x_shares[id].clone(),
                y_shares[id].clone(),
                doubles,
                network[id].clone(),
            )
            .await
            .unwrap();
    }

    let mut products: Vec<Vec<GfShare<Gf256>>> = vec![Vec::new(); k];
    for node in nodes.iter() {
        let handle = node.lock().await.clone();
        let out = handle
            .wait_for_products(sid.get(), Duration::from_secs(5))
            .await
            .unwrap();
        for (i, share) in out.into_iter().enumerate() {
            assert_eq!(share.degree, T);
            products[i].push(share);
        }
    }

    assert!(errors.lock().await.is_empty(), "{:?}", errors.lock().await);
    for i in 0..k {
        let (_, xy) = GfShare::recover_secret(&products[i], N, T).unwrap();
        assert_eq!(xy, xs[i] * ys[i], "GF DN07 product {i} is wrong");
    }
}

/// `W(W+1) = 0` exactly on `GF(2) ⊂ GF(2^k)`, so this is bit-ness certification with soundness
/// error 0 and no random linear combination — which is why `Gf256`'s `2^-8` challenge space is
/// irrelevant to it.
#[tokio::test]
async fn gf_exact_zero_check_certifies_bitness_and_aborts_on_a_non_bit() {
    setup_tracing();
    let k = 2 * T + 1;

    for (exec, values, expected_violation) in [
        (40u64, vec![0u8, 1, 1, 0, 1, 0, 1], None),
        (41u64, vec![0u8, 1, 1, 0, 9, 0, 1], Some(4usize)),
    ] {
        let sid = pre_sid(ProtocolType::GfDn07, exec);
        let ws: Vec<Gf256> = values.iter().map(|v| Gf256::from(*v)).collect();
        let w_shares = gf_share_all(&ws, N, T);
        let sources = gf_doubles(k, N, T);

        let (network, receivers, _, _) = test_setup(N, vec![]);
        let nodes: Vec<Arc<Mutex<GfDn07MulNode<Gf256>>>> = (0..N)
            .map(|id| Arc::new(Mutex::new(GfDn07MulNode::<Gf256>::new(id, N, T).unwrap())))
            .collect();
        let errors = Arc::new(Mutex::new(Vec::new()));
        spawn_gf_pumps(&nodes, receivers, network.clone(), Arc::clone(&errors));

        for (id, node) in nodes.iter().enumerate() {
            let doubles = sources[id].clone();
            let v: Vec<GfShare<Gf256>> = w_shares[id]
                .iter()
                .map(|s| (s.clone() + Gf256::from(1_u8)).unwrap())
                .collect();
            node.lock()
                .await
                .init_zero_check(sid, w_shares[id].clone(), v, doubles, network[id].clone())
                .await
                .unwrap();
        }

        for node in nodes.iter() {
            let handle = node.lock().await.clone();
            let outcome = handle
                .wait_for_zero_check(sid.get(), Duration::from_secs(5))
                .await;
            match expected_violation {
                None => assert!(outcome.is_ok(), "all-bit batch must pass, got {outcome:?}"),
                Some(i) => assert!(
                    matches!(outcome, Err(Dn07Error::ZeroCheckFailed { index }) if index == i),
                    "expected an abort naming index {i}, got {outcome:?}"
                ),
            }
        }
        assert!(errors.lock().await.is_empty(), "{:?}", errors.lock().await);
    }
}

// ---------------------------------------------------------------------------------------------
// phase discipline
// ---------------------------------------------------------------------------------------------

/// The barrier that matters. `init_mul` and `init_zero_check` take a [`PreprocessingSessionId`],
/// so an online session cannot be passed to them at all — it cannot be *constructed*.
#[test]
fn online_sessions_cannot_be_handed_to_dn07() {
    for tag in [
        ProtocolType::Mul,
        ProtocolType::GfMul,
        ProtocolType::A2B,
        ProtocolType::A2BGfMul,
        ProtocolType::B2A,
        ProtocolType::Input,
        ProtocolType::FpMul,
        ProtocolType::Trunc,
        ProtocolType::FpDivConst,
    ] {
        let sid = SessionId::new(tag, SessionId::pack_slot(1, 0, 0), 111);
        assert!(
            matches!(
                PreprocessingSessionId::new(sid),
                Err(Dn07Error::OnlinePhaseForbidden { .. })
            ),
            "{tag:?} must not be usable as a DN07 session"
        );
    }
}
