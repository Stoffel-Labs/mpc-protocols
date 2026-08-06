use crate::utils::prandint_utils::spawn_receiver_tasks;
use crate::utils::test_utils::{setup_tracing, test_setup};
use ark_bls12_381::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use num_integer::binomial;
use std::time::Duration;
use stoffelcrypto::common::{ProtocolSessionId, SecretSharingScheme};
use stoffelcrypto::honeybadger::fpmul::prandint::PRandIntNode;
use stoffelcrypto::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelcrypto::honeybadger::{ProtocolType, SessionId};
use tokio::task::JoinSet;

mod utils;

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

    let nodes: Vec<PRandIntNode<Fr>> = (0..num_parties)
        .map(|i| PRandIntNode::new(i, num_parties, threshold).unwrap())
        .collect();
    let _set = spawn_receiver_tasks(num_parties, receivers, nodes.clone(), network.clone()).await;

    let mut set = JoinSet::new();
    for node in &nodes {
        let id = node.id;
        set.spawn({
            let network = network[id].clone();
            let mut node = node.clone();
            async move {
                node.generate_riss(session_id, l, k, batch_size, network)
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
