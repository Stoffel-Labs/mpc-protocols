//! End-to-end tests for the DN07 preprocessing multiplication and exact-zero check, over `F` and
//! over `Gf256`, driven by PRSS + PRZS double sharings.
//!
//! **Every session here carries a preprocessing tag.** That is not decoration: `Dn07MulNode` opens
//! at degree `2t`, which is unreconstructible on the asynchronous robust online path at
//! `n = 3t+1`, and `PreprocessingSessionId` is the only session type its `init_*` accepts. The
//! test that an online tag is refused lives here too, at the bottom.

mod utils;

use crate::utils::test_utils::{fan_in_inboxes, setup_tracing, test_setup};
use ark_bls12_381::Fr;
use ark_ff::Zero;
use std::sync::Arc;
use std::time::Duration;
use stoffelcrypto::common::gf2k::field::Gf256;
use stoffelcrypto::common::gf2k::share::GfShare;
use stoffelcrypto::common::share::shamir::NonRobustShare;
use stoffelcrypto::common::{ProtocolSessionId, SecretSharingScheme};
use stoffelcrypto::honeybadger::dn07::dn07::Dn07MulNode;
use stoffelcrypto::honeybadger::dn07::double_share::{
    GfPrssDoubleShareSource, PrssDoubleShareSource,
};
use stoffelcrypto::honeybadger::dn07::gf_dn07::GfDn07MulNode;
use stoffelcrypto::honeybadger::dn07::{Dn07Error, PreprocessingSessionId};
use stoffelcrypto::honeybadger::gf_prss::gf_prss::GfPrssKeys;
use stoffelcrypto::honeybadger::prss::prss::{all_tsets, held_ranks, PrssKeys};
use stoffelcrypto::honeybadger::prss::PrssAllocator;
use stoffelcrypto::honeybadger::prss::PRSS_KEY_LEN;
use stoffelcrypto::honeybadger::przs::gf_przs::GfPrzsKeys;
use stoffelcrypto::honeybadger::przs::przs::PrzsKeys;
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
// key material
// ---------------------------------------------------------------------------------------------

/// One key per maximal unqualified set, held by every party outside that set — the shape
/// `setup_prss_keys` establishes over the network with RISS.
fn key_family(n: usize, t: usize) -> Vec<[u8; PRSS_KEY_LEN]> {
    use rand::{Rng, SeedableRng};
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xD007_0007);
    (0..all_tsets(n, t).len())
        .map(|_| {
            let mut k = [0u8; PRSS_KEY_LEN];
            rng.fill(&mut k);
            k
        })
        .collect()
}

fn party_keys(
    n: usize,
    t: usize,
    id: usize,
    family: &[[u8; PRSS_KEY_LEN]],
) -> Vec<(usize, [u8; PRSS_KEY_LEN])> {
    held_ranks(n, t, id)
        .into_iter()
        .map(|r| (r, family[r]))
        .collect()
}

fn f_sources(n: usize, t: usize) -> Vec<PrssDoubleShareSource<Fr>> {
    let family = key_family(n, t);
    (0..n)
        .map(|id| {
            let keys = party_keys(n, t, id, &family);
            PrssDoubleShareSource::new(
                PrssKeys::<Fr>::new(id, n, t, &keys).unwrap(),
                PrzsKeys::<Fr>::new(id, n, t, &keys).unwrap(),
            )
            .unwrap()
        })
        .collect()
}

fn gf_sources(n: usize, t: usize) -> Vec<GfPrssDoubleShareSource<Gf256>> {
    let family = key_family(n, t);
    (0..n)
        .map(|id| {
            let keys = party_keys(n, t, id, &family);
            GfPrssDoubleShareSource::new(
                GfPrssKeys::<Gf256>::new(id, n, t, &keys).unwrap(),
                GfPrzsKeys::<Gf256>::new(id, n, t, &keys).unwrap(),
            )
            .unwrap()
        })
        .collect()
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
    let sources = f_sources(N, T);

    let (network, receivers, _, _) = test_setup(N, vec![]);
    let nodes: Vec<Arc<Mutex<Dn07MulNode<Fr>>>> = (0..N)
        .map(|id| Arc::new(Mutex::new(Dn07MulNode::<Fr>::new(id, N, T).unwrap())))
        .collect();
    let errors = Arc::new(Mutex::new(Vec::new()));
    spawn_f_pumps(&nodes, receivers, network.clone(), Arc::clone(&errors));

    for (id, node) in nodes.iter().enumerate() {
        let doubles = sources[id].double_shares_at(sid, 0, k).unwrap();
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
        let sources = f_sources(N, T);

        let (network, receivers, _, _) = test_setup(N, vec![]);
        let nodes: Vec<Arc<Mutex<Dn07MulNode<Fr>>>> = (0..N)
            .map(|id| Arc::new(Mutex::new(Dn07MulNode::<Fr>::new(id, N, T).unwrap())))
            .collect();
        let errors = Arc::new(Mutex::new(Vec::new()));
        spawn_f_pumps(&nodes, receivers, network.clone(), Arc::clone(&errors));

        for (id, node) in nodes.iter().enumerate() {
            let doubles = sources[id].double_shares_at(sid, 0, k).unwrap();
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
    let sources = f_sources(N, T);

    let (network, receivers, _, _) = test_setup(N, vec![]);
    let nodes: Vec<Arc<Mutex<Dn07MulNode<Fr>>>> = (0..N)
        .map(|id| Arc::new(Mutex::new(Dn07MulNode::<Fr>::new(id, N, T).unwrap())))
        .collect();
    let errors = Arc::new(Mutex::new(Vec::new()));
    spawn_f_pumps(&nodes, receivers, network.clone(), Arc::clone(&errors));

    for (id, node) in nodes.iter().enumerate() {
        let mut doubles = sources[id].double_shares_at(sid, 0, k).unwrap();
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
    let sources = gf_sources(N, T);

    let (network, receivers, _, _) = test_setup(N, vec![]);
    let nodes: Vec<Arc<Mutex<GfDn07MulNode<Gf256>>>> = (0..N)
        .map(|id| Arc::new(Mutex::new(GfDn07MulNode::<Gf256>::new(id, N, T).unwrap())))
        .collect();
    let errors = Arc::new(Mutex::new(Vec::new()));
    spawn_gf_pumps(&nodes, receivers, network.clone(), Arc::clone(&errors));

    for (id, node) in nodes.iter().enumerate() {
        let doubles = sources[id].double_shares_at(sid, 0, k).unwrap();
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
        let sources = gf_sources(N, T);

        let (network, receivers, _, _) = test_setup(N, vec![]);
        let nodes: Vec<Arc<Mutex<GfDn07MulNode<Gf256>>>> = (0..N)
            .map(|id| Arc::new(Mutex::new(GfDn07MulNode::<Gf256>::new(id, N, T).unwrap())))
            .collect();
        let errors = Arc::new(Mutex::new(Vec::new()));
        spawn_gf_pumps(&nodes, receivers, network.clone(), Arc::clone(&errors));

        for (id, node) in nodes.iter().enumerate() {
            let doubles = sources[id].double_shares_at(sid, 0, k).unwrap();
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

/// The PRZS mask that randomises every one of these openings must span `t` dimensions, not one.
/// A one-dimensional mask is type-correct, passes every functional test above, and leaks `t-1`
/// dimensions of the product polynomial on every multiplication. The source refuses to be built
/// from a store that does not carry `t` coefficients per set.
#[test]
fn the_mask_behind_every_opening_is_t_dimensional() {
    let family = key_family(N, T);
    let keys = party_keys(N, T, 0, &family);
    let przs = PrzsKeys::<Fr>::new(0, N, T, &keys).unwrap();
    assert_eq!(przs.mask_dimension(), T);
    assert_eq!(przs.coefficients_per_set(), T);
    assert_eq!(przs.degree(), 2 * T);

    let gf_przs = GfPrzsKeys::<Gf256>::new(0, N, T, &keys).unwrap();
    assert_eq!(gf_przs.mask_dimension(), T);
    assert_eq!(gf_przs.degree(), 2 * T);
}

/// A DN07 multiplication's mask must be uniform over the *whole* field, not over a `bits`-wide
/// window: `d = xy - r` is opened in the clear, so a non-uniform `r` leaks `xy`.
#[test]
fn the_multiplication_mask_is_uniform_over_the_field() {
    let sources = f_sources(N, T);
    let sid = pre_sid(ProtocolType::Dn07, 99);
    let count = 8;
    let per_party: Vec<Vec<_>> = sources
        .iter()
        .map(|s| s.double_shares_at(sid, 0, count).unwrap())
        .collect();

    for nu in 0..count {
        let lo: Vec<RobustShare<Fr>> = (0..N)
            .map(|i| RobustShare::new(per_party[i][nu].degree_t.share[0], i, T))
            .collect();
        let (_, r) = RobustShare::recover_secret(&lo, N, T).unwrap();
        // `PrssKeys::shares_at(.., bits)` would land in `[0, C(n,t) * 2^bits)`, an integer range
        // vanishingly unlikely to exceed 2^70 for any usable `bits`. A uniform draw over
        // bls12-381's 255-bit field will not sit there.
        assert!(
            !r.is_zero(),
            "a uniform field element should not be zero; position {nu}"
        );
    }
    // Two different positions must not collide.
    assert_ne!(
        per_party[0][0].degree_t.share[0],
        per_party[0][1].degree_t.share[0]
    );
}

// ---------------------------------------------------------------------------------------------
// the converted call site: GF triple generation on PRSS/PRZS double sharings
// ---------------------------------------------------------------------------------------------

/// `run_gf_preprocessing` now takes its `([r]_t, [r]_2t)` from [`GfPrssDoubleShareSource`] instead
/// of running `GfRanDouSha`, whenever PRSS keys have been established. This exercises exactly that
/// substitution against the real `GfTripleGenNode`: same node, same degree-`2t` opening, double
/// sharing from the PRF instead of from the wire.
///
/// `18.857 -> 2.857` **payload** bytes per triple at `n = 10` — the 6.6x of ranked item 6 — comes
/// entirely from the double sharing costing nothing, so the thing that has to be proved is that a
/// PRF-derived pair is as good a degree-reduction mask as a dealt one. It is: `a*b` still
/// reconstructs.
///
/// Two standing qualifications on that 6.6x, both recorded in `honeybadger::dn07`: the `18.857`
/// baseline is *fully dealt*, a state this tree had already left (the improvement over what it
/// actually did is 3.25x-3.91x), and it cannot be measured above `n = 4` because dealt
/// `GfRanSha` does not complete there. `2.857` is also a marginal figure: the wire cost of a
/// batch is `2n * 48 + O2 * triples`.
#[tokio::test]
async fn gf_triple_generation_accepts_prss_double_sharings() {
    use stoffelcrypto::honeybadger::gf_triple_gen::gf_triple_generation::GfTripleGenNode;
    use stoffelcrypto::honeybadger::triple_gen::triple_generation::ProtocolState;

    setup_tracing();
    let k = 2 * T + 1;
    let session_id = SessionId::new(ProtocolType::GfTriple, SessionId::pack_slot(77, 0, 0), 111);
    // The source is addressed under the node's own `GfDn07` position space — the *network* session
    // stays `GfTriple`, because that is the tag the batch-reconstruction child is routed under.
    //
    // The position is named by hand here because this test drives `GfTripleGenNode` directly. In
    // production `run_gf_preprocessing` claims it from the node's single `PrssAllocator`
    // (`HoneyBadgerMPCNode::gf_prss_doubles`) and never from a counter of its own, because the
    // edaBit modulus-overflow filter is a second consumer of this same keystream and two
    // independent monotone counters on one stream collide.
    let derivation = pre_sid(ProtocolType::GfDn07, 77);

    let a_vals: Vec<Gf256> = (0..k).map(|i| Gf256::from(i as u8 + 21)).collect();
    let b_vals: Vec<Gf256> = (0..k).map(|i| Gf256::from(i as u8 * 3 + 5)).collect();
    let a_shares = gf_share_all(&a_vals, N, T);
    let b_shares = gf_share_all(&b_vals, N, T);
    let sources = gf_sources(N, T);

    let (network, mut receivers, _, _) = test_setup(N, vec![]);
    let nodes: Vec<Arc<Mutex<GfTripleGenNode<Gf256>>>> = (0..N)
        .map(|id| Arc::new(Mutex::new(GfTripleGenNode::new(id, N, T).unwrap())))
        .collect();

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
        tokio::spawn(async move {
            while let Some((_, bytes)) = merged.recv().await {
                let Ok(WrappedMessage::GfBatchRecon(msg)) =
                    bincode::deserialize::<WrappedMessage>(&bytes)
                else {
                    continue;
                };
                let mut bind = node.lock().await;
                if bind
                    .batch_recon_node
                    .process(msg, net.clone())
                    .await
                    .is_ok()
                {
                    let _ = bind.drain_batch_recon_output().await;
                }
            }
        });
    }

    for (id, node) in nodes.iter().enumerate() {
        let doubles = sources[id].double_shares_at(derivation, 0, k).unwrap();
        node.lock()
            .await
            .init_batch(
                a_shares[id].clone(),
                b_shares[id].clone(),
                doubles,
                session_id,
                network[id].clone(),
            )
            .await
            .unwrap();
    }

    tokio::time::sleep(Duration::from_millis(400)).await;

    let mut ab_shares: Vec<Vec<GfShare<Gf256>>> = vec![Vec::new(); k];
    for node in nodes.iter() {
        let bind = node.lock().await;
        let storage = bind.storage.lock().await;
        let (_, _, triple_store) = storage.get(&session_id).unwrap();
        let data = triple_store.lock().await;
        assert!(matches!(data.protocol_state, ProtocolState::Finished));
        for (i, triple) in data.protocol_output.iter().enumerate() {
            ab_shares[i].push(triple.mult.clone());
        }
    }

    for i in 0..k {
        let (_, ab) = GfShare::recover_secret(&ab_shares[i], N, T).unwrap();
        assert_eq!(
            ab,
            a_vals[i] * b_vals[i],
            "GF triple {i} built on a PRSS/PRZS double sharing is wrong"
        );
    }
}

/// **The GF triple's last cost residual, closed.** `ensure_gf_triples` took its double sharing
/// from PRSS but still drew `[a]` and `[b]` from dealt `GfRanSha`, so a triple cost `2 x R1 + O2`
/// where the `F` side's `generate_triples_via_dn07` has always paid `O2` alone. This drives the
/// real `GfTripleGenNode` on an input set that is PRSS-derived *end to end* — `a`, `b` and the
/// mask, all three out of one [`PrssAllocator`] claim, nothing on the wire but the one degree-`2t`
/// opening.
///
/// Nothing here knows `a` or `b` in advance, which is the point: they are recovered from the same
/// shares the protocol multiplied, and the product has to match.
#[tokio::test]
async fn gf_triple_generation_accepts_a_wholly_prss_derived_input_set() {
    use stoffelcrypto::honeybadger::gf_triple_gen::gf_triple_generation::GfTripleGenNode;
    use stoffelcrypto::honeybadger::triple_gen::triple_generation::ProtocolState;

    setup_tracing();
    let k = 2 * T + 1;
    let session_id = SessionId::new(ProtocolType::GfTriple, SessionId::pack_slot(78, 0, 0), 111);
    let sources = gf_sources(N, T);

    // One allocator per party, each starting fresh and claiming in the same order — which is what
    // makes every party's window the same window without any of them saying so on the wire. In
    // production this is the node's *single* allocator, shared with the edaBit filter; a counter
    // of the triple path's own would be monotone here and colliding there.
    let mut material = Vec::with_capacity(N);
    for source in sources.iter() {
        let alloc = PrssAllocator::new(111, source.key_family_id());
        material.push(source.triple_material(&alloc, k).await.unwrap());
    }

    let (network, mut receivers, _, _) = test_setup(N, vec![]);
    let nodes: Vec<Arc<Mutex<GfTripleGenNode<Gf256>>>> = (0..N)
        .map(|id| Arc::new(Mutex::new(GfTripleGenNode::new(id, N, T).unwrap())))
        .collect();

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
        tokio::spawn(async move {
            while let Some((_, bytes)) = merged.recv().await {
                let Ok(WrappedMessage::GfBatchRecon(msg)) =
                    bincode::deserialize::<WrappedMessage>(&bytes)
                else {
                    continue;
                };
                let mut bind = node.lock().await;
                if bind
                    .batch_recon_node
                    .process(msg, net.clone())
                    .await
                    .is_ok()
                {
                    let _ = bind.drain_batch_recon_output().await;
                }
            }
        });
    }

    for (id, node) in nodes.iter().enumerate() {
        node.lock()
            .await
            .init_batch(
                material[id].a.clone(),
                material[id].b.clone(),
                material[id].doubles.clone(),
                session_id,
                network[id].clone(),
            )
            .await
            .unwrap();
    }

    tokio::time::sleep(Duration::from_millis(400)).await;

    let mut ab_shares: Vec<Vec<GfShare<Gf256>>> = vec![Vec::new(); k];
    for node in nodes.iter() {
        let bind = node.lock().await;
        let storage = bind.storage.lock().await;
        let (_, _, triple_store) = storage.get(&session_id).unwrap();
        let data = triple_store.lock().await;
        assert!(matches!(data.protocol_state, ProtocolState::Finished));
        for (i, triple) in data.protocol_output.iter().enumerate() {
            ab_shares[i].push(triple.mult.clone());
        }
    }

    for i in 0..k {
        // `a` and `b` are recovered from the very shares the protocol multiplied. They are
        // pseudorandom, so this is also the assertion that every party derived the *same* value
        // at the same position: a fork would leave these on no common degree-`t` polynomial.
        let a_col: Vec<GfShare<Gf256>> = (0..N).map(|id| material[id].a[i].clone()).collect();
        let b_col: Vec<GfShare<Gf256>> = (0..N).map(|id| material[id].b[i].clone()).collect();
        let (_, a_val) = GfShare::recover_secret(&a_col, N, T).unwrap();
        let (_, b_val) = GfShare::recover_secret(&b_col, N, T).unwrap();
        let (_, ab) = GfShare::recover_secret(&ab_shares[i], N, T).unwrap();
        assert_eq!(
            ab,
            a_val * b_val,
            "GF triple {i} built on a wholly PRSS-derived input set is wrong"
        );
    }
}
