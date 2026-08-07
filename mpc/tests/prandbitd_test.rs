use crate::utils::prandbitd_utils::{generate_small_field_bits, spawn_receiver_tasks};
use crate::utils::test_utils::{setup_tracing, test_setup};
use ark_bls12_381::Fr;
use ark_ff::{BigInteger, One, PrimeField, Zero};
use num_integer::binomial;
use std::time::Duration;
use stoffelcrypto::common::math::goldilocks::GoldilocksField;
use stoffelcrypto::common::{ProtocolSessionId, SecretSharingScheme};
use stoffelcrypto::honeybadger::fpmul::f256::{lagrange_interpolate_f2_8, Gf256Domain};
use stoffelcrypto::honeybadger::fpmul::prandbitd::PRandBitDNode;
use stoffelcrypto::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelcrypto::honeybadger::{ProtocolType, SessionId};
use tokio::task::JoinSet;
use tracing::info;

mod utils;

#[tokio::test]
async fn prandbitd_correctness_e2e() {
    setup_tracing();

    let num_parties = 5;
    let threshold = 1;
    let batch_size = threshold + 1;
    let k = 16;
    let kappa = 20;
    let nu = f64::log2(binomial(num_parties, threshold) as f64).ceil() as usize;
    let l = k + kappa + nu;

    info!("l value: {}, Bits big field: {}", l, Fr::MODULUS_BIT_SIZE);

    let session_id = SessionId::new(ProtocolType::PRandBit, SessionId::pack_slot(123, 0, 0), 111);

    // Build a fake network.
    let (network, receivers, _, _) = test_setup(num_parties, vec![]);

    // Create nodes for the protocol.
    let mut nodes: Vec<PRandBitDNode<GoldilocksField, Fr>> = (0..num_parties)
        .map(|i| PRandBitDNode::new(i, num_parties, threshold).unwrap())
        .collect();

    // Spawn receiver tasks.
    let _set = spawn_receiver_tasks(num_parties, receivers, nodes.clone(), network.clone()).await;

    // Generate inputs for the protocol.
    let small_field_bits = generate_small_field_bits(num_parties, threshold, batch_size);

    // Initialize nodes.
    let mut set = JoinSet::new();
    for node in &nodes {
        let id = node.id;
        set.spawn({
            let session_id = session_id.clone();
            let small_field_bits = small_field_bits[id].clone();
            let network = network[id].clone();
            let mut node = node.clone();
            async move {
                node.generate_riss(session_id, small_field_bits, l, k, batch_size, network)
                    .await
                    .unwrap()
            }
        });
    }

    while let Some(result) = set.join_next().await {
        result.unwrap();
    }

    // Wait for all the protocols to finish.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut all_outputs_bit = Vec::new();
    let mut all_outputs_int = Vec::new();
    let mut evaluation_points = Vec::new();
    let binary_domain = Gf256Domain::new(num_parties).unwrap();
    for node in &mut nodes {
        let store = node
            .get_or_create_store(session_id.clone(), node.id)
            .await
            .unwrap();
        let node_id = node.id;
        let store_guard = store.lock().await;

        let shares_bit = store_guard.share_b_2.clone();
        let shares_int = store_guard.share_b_p.clone();

        assert_eq!(shares_bit.len(), batch_size);
        assert_eq!(shares_int.len(), batch_size);

        // Reconstruct the outputs and check that they are bits.
        all_outputs_int.push(shares_int);
        all_outputs_bit.push(shares_bit);
        evaluation_points.push(binary_domain.element(node_id));
    }

    for idx_share in 0..batch_size {
        let mut shares_int = Vec::new();
        let mut shares_bit = Vec::new();
        for node in &nodes {
            shares_int.push(all_outputs_int[node.id][idx_share].clone());
            shares_bit.push(all_outputs_bit[node.id][idx_share].clone());
        }
        let (_, value_int) =
            RobustShare::recover_secret(&shares_int, num_parties, threshold).unwrap();
        assert!(value_int.is_zero() || value_int.is_one());

        let bin_poly = lagrange_interpolate_f2_8(&evaluation_points, &shares_bit);
        let value_bit = bin_poly.coeffs[0];
        assert!(value_bit.is_zero() || value_bit.is_one());

        assert!(
            (value_int.is_zero() && value_bit.is_zero())
                || (value_int.is_one() && value_bit.is_one())
        );
    }
}

/// PRandInt masks must actually carry the width they are declared to have.
///
/// `HoneyBadgerMPCNode::mul_fixed`/`div_with_const_fixed` reject a *declared* `l` narrower than
/// `2k - f`, but that is a config check — it says nothing about the randomness preprocessing
/// really produces. TruncPr broadcasts `b + 2^m*r_int + r'` in the clear and `r_int` is the only
/// thing hiding `b` above bit `m`, so if generation silently produced a small value the declared
/// bound would be satisfied while the mask leaked. This exercises the same `generate_riss` /
/// `wait_for_int_result` path `ensure_prandint_shares` uses, and checks the reconstructed masks
/// are actually large.
#[tokio::test]
async fn prandint_masks_have_their_declared_width() {
    setup_tracing();

    let num_parties = 5;
    let threshold = 1;
    let batch_size = threshold + 1;
    let k = 16;
    let kappa = 20;
    let nu = f64::log2(binomial(num_parties, threshold) as f64).ceil() as usize;
    let l = k + kappa + nu;

    let session_id = SessionId::new(ProtocolType::PRandInt, SessionId::pack_slot(77, 0, 0), 111);
    let (network, receivers, _, _) = test_setup(num_parties, vec![]);

    let nodes: Vec<PRandBitDNode<GoldilocksField, Fr>> = (0..num_parties)
        .map(|i| PRandBitDNode::new(i, num_parties, threshold).unwrap())
        .collect();
    let _set = spawn_receiver_tasks(num_parties, receivers, nodes.clone(), network.clone()).await;

    // PRandInt is PRandBitD driven with no small-field bits — exactly how
    // `ensure_prandint_shares` invokes it.
    let mut set = JoinSet::new();
    for node in &nodes {
        let id = node.id;
        set.spawn({
            let network = network[id].clone();
            let mut node = node.clone();
            async move {
                node.generate_riss(session_id, vec![], l, k, batch_size, network)
                    .await
                    .unwrap();
                node.wait_for_int_result(session_id, Duration::from_secs(30))
                    .await
                    .unwrap()
            }
        });
    }

    let mut per_party = vec![Vec::new(); num_parties];
    let mut collected = Vec::new();
    while let Some(result) = set.join_next().await {
        collected.push(result.unwrap());
    }
    for shares in collected {
        for share in shares {
            per_party[share.id].push(share);
        }
    }

    // Reconstruct each mask and confirm it is genuinely wide, not a small or constant value.
    // A degenerate generator (the failure mode this guards) yields tiny reconstructions.
    let produced = per_party[0].len();
    assert!(produced > 0, "no PRandInt masks were produced");

    // Deliberately loose. RISS sums C(n,t) contributions of l bits each, so a mask lands
    // around l + log2(C(n,t)) bits (~59 observed for l = 39 here) but is near-uniform below
    // that — asserting `>= l` would fail whenever a draw happens to land low, roughly one time
    // in eight. `k` is far under the distribution while still orders of magnitude above the
    // degenerate values this exists to catch (a constant mask is a handful of bits), giving a
    // false-failure probability around 2^-26.
    let min_acceptable_bits = k as u32;
    for idx in 0..produced {
        let shares: Vec<_> = (0..num_parties)
            .map(|p| per_party[p][idx].clone())
            .collect();
        let (_, mask) = RobustShare::recover_secret(&shares, num_parties, threshold).unwrap();

        assert!(!mask.is_zero(), "PRandInt mask {idx} reconstructed to zero");
        // Bit width = index of the highest set byte, refined to the highest set bit.
        let bytes = mask.into_bigint().to_bytes_le();
        let bits = bytes
            .iter()
            .rposition(|b| *b != 0)
            .map(|i| (i as u32) * 8 + (8 - bytes[i].leading_zeros()))
            .unwrap_or(0);
        assert!(
            bits >= min_acceptable_bits,
            "PRandInt mask {idx} is {bits} bits, far below the declared l = {l}; \
             a mask this narrow cannot hide a 2k-bit TruncPr intermediate"
        );
    }
}
