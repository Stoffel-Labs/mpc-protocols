//! The randomness extraction of `RanDouSha` against a coalition that deals inconsistently.
//!
//! Every party deals a double sharing, an `n x n` matrix is applied to the `n` dealings, the first
//! `t + 1` results are kept and the rest are opened to the parties `t + 1 ..` to be checked. The
//! check is sound only if a set of bad dealings cannot cancel in every *honest* check — a property
//! of the matrix, not of the protocol.
//!
//! The coalition here is `{0, 4, 8, 12}` at `n = 13`, `t = 4`. Each of the four deals a degree-`2t`
//! sharing whose secret is off by the same `delta`; checkers 8 and 12 are in the coalition and
//! simply say OK.
//!
//! This is a regression test. The matrix used to be the Vandermonde matrix `alpha_j^k` over a
//! radix-2 domain of size 16, with which the four errors cancel at every honest checker
//! (`sum_m i^(j*m) = 0` unless `4 | j`): every honest party finished, and kept outputs 0 and 4
//! were not double sharings. The matrix is now hyper-invertible
//! (`common::share::make_hyper_invertible`), and `formal/extraction` checks the two rank
//! conditions for every corrupt set.

pub mod utils;

use crate::utils::test_utils::{fan_in_inboxes, setup_tracing, test_setup};
use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_std::test_rng;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use stoffelcrypto::common::rbc::rbc::Avid;
use stoffelcrypto::common::share::shamir::NonRobustShare;
use stoffelcrypto::common::{ProtocolSessionId, SecretSharingScheme, RBC};
use stoffelcrypto::honeybadger::ran_dou_sha::messages::{RanDouShaMessage, RanDouShaPayload};
use stoffelcrypto::honeybadger::ran_dou_sha::{RanDouShaNode, RanDouShaState};
use stoffelcrypto::honeybadger::{ProtocolType, SessionId, WrappedMessage};
use stoffelmpc_network::fake_network::SenderId;
use tokio::sync::Mutex;

type Node = Arc<Mutex<RanDouShaNode<Fr, Avid<SessionId>>>>;

/// Runs one `RanDouSha` in which `coalition` deals degree-`2t` sharings off by `delta` and its
/// members among the checkers broadcast OK without checking. Returns, for every kept output on
/// which all honest parties finished, the difference between the degree-`2t` and the degree-`t`
/// secret — zero for a valid double sharing — or `None` if some honest party did not finish.
async fn run_with_coalition(n: usize, t: usize, coalition: &[usize]) -> Option<Vec<Fr>> {
    let session_id = SessionId::new(ProtocolType::Randousha, SessionId::pack_slot(7, 0, 0), 4242);
    let corrupt: HashSet<usize> = coalition.iter().copied().collect();
    let mut rng = test_rng();
    let delta = Fr::from(5u64);

    // The dealings: `shares_*[party][dealer]`.
    let mut shares_t = vec![Vec::with_capacity(n); n];
    let mut shares_2t = vec![Vec::with_capacity(n); n];
    for dealer in 0..n {
        let secret = Fr::rand(&mut rng);
        let off = if corrupt.contains(&dealer) {
            delta
        } else {
            Fr::from(0u64)
        };
        let deg_t = NonRobustShare::compute_shares(secret, n, t, None, &mut rng).unwrap();
        let deg_2t =
            NonRobustShare::compute_shares(secret + off, n, 2 * t, None, &mut rng).unwrap();
        for party in 0..n {
            shares_t[party].push(deg_t[party].clone());
            shares_2t[party].push(deg_2t[party].clone());
        }
    }

    let (network, mut receivers, _, _) = test_setup(n, vec![]);
    let nodes: Vec<Node> = (0..n)
        .map(|id| Arc::new(Mutex::new(RanDouShaNode::new(id, n, t, t + 1).unwrap())))
        .collect();

    for (id, node) in nodes.iter().enumerate() {
        let node = node.clone();
        let net = network[id].clone();
        let lying_checker = corrupt.contains(&id) && id > t;
        let inbox: Vec<_> = receivers
            .remove(0)
            .into_iter()
            .enumerate()
            .map(|(from, rx)| (SenderId::Node(from), rx))
            .collect();
        let mut merged = fan_in_inboxes(inbox);
        tokio::spawn(async move {
            let mut said_ok = false;
            while let Some((_, bytes)) = merged.recv().await {
                let Ok(wrapped) = bincode::deserialize::<WrappedMessage>(&bytes) else {
                    continue;
                };
                match wrapped {
                    // A corrupt checker does not check: it broadcasts OK, exactly as an honest
                    // checker would after a successful reconstruction.
                    WrappedMessage::RanDouSha(_) if lying_checker => {
                        if !said_ok {
                            said_ok = true;
                            let verdict = RanDouShaMessage::new(
                                id,
                                session_id,
                                RanDouShaPayload::Output(true),
                            );
                            let rbc_session = SessionId::new(
                                ProtocolType::Randousha,
                                SessionId::pack_slot(7, id as u8, 0),
                                4242,
                            );
                            let guard = node.lock().await;
                            let _ = guard
                                .rbc
                                .init(
                                    bincode::serialize(&verdict).unwrap(),
                                    rbc_session,
                                    net.clone(),
                                )
                                .await;
                        }
                    }
                    WrappedMessage::RanDouSha(msg) => {
                        let _ = node.lock().await.process(msg, net.clone()).await;
                    }
                    WrappedMessage::Rbc(msg) => {
                        let mut guard = node.lock().await;
                        let _ = guard.rbc.process(msg, net.clone()).await;
                        let _ = guard.drain_rbc_output().await;
                    }
                    _ => {}
                }
            }
        });
    }

    for (id, node) in nodes.iter().enumerate() {
        let _ = node
            .lock()
            .await
            .init(
                shares_t[id].clone(),
                shares_2t[id].clone(),
                session_id,
                network[id].clone(),
            )
            .await;
    }
    tokio::time::sleep(Duration::from_millis(3000)).await;

    // The honest parties' outputs.
    let mut outputs = Vec::new();
    for (id, node) in nodes.iter().enumerate() {
        if corrupt.contains(&id) {
            continue;
        }
        let mut guard = node.lock().await;
        let store = guard.get_or_create_store(session_id, id).await.unwrap();
        let store = store.lock().await;
        if store.state != RanDouShaState::Finished {
            return None;
        }
        outputs.push(store.protocol_output.clone());
    }

    let mut differences = Vec::new();
    for kept in 0..=t {
        let deg_t: Vec<_> = outputs.iter().map(|o| o[kept].degree_t.clone()).collect();
        let deg_2t: Vec<_> = outputs.iter().map(|o| o[kept].degree_2t.clone()).collect();
        let (_, secret_t) = NonRobustShare::recover_secret(&deg_t[..t + 1], n, t).unwrap();
        let (_, secret_2t) = NonRobustShare::recover_secret(&deg_2t[..2 * t + 1], n, t).unwrap();
        differences.push(secret_2t - secret_t);
    }
    Some(differences)
}

/// A coalition of `t` dealers must not be able to get an inconsistent double sharing accepted:
/// either some honest party refuses to finish, or every kept output is a valid double sharing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_coalition_cannot_slip_an_inconsistent_double_sharing_past_the_check() {
    setup_tracing();
    let outcome = run_with_coalition(13, 4, &[0, 4, 8, 12]).await;
    if let Some(differences) = outcome {
        let zero = Fr::from(0u64);
        let broken: Vec<usize> = differences
            .iter()
            .enumerate()
            .filter(|(_, d)| **d != zero)
            .map(|(i, _)| i)
            .collect();
        assert!(
            broken.is_empty(),
            "every honest party finished, yet kept outputs {broken:?} are not double sharings: \
             their degree-2t and degree-t secrets differ"
        );
    }
}

/// The matrix is what it claims to be: it carries the values of any polynomial of degree below
/// `n` at `1..=n` to its values at `n+1..=2n`. Hyper-invertibility is a consequence of exactly
/// this — a square submatrix with a kernel vector would give a non-zero polynomial of degree
/// below `n` with `n` roots.
#[test]
fn the_extraction_matrix_moves_evaluations_from_alpha_to_beta() {
    use stoffelcrypto::common::share::make_hyper_invertible;
    let mut rng = test_rng();
    for n in [4usize, 7, 10, 13, 16] {
        let matrix = make_hyper_invertible::<Fr>(n).unwrap();
        let coefficients: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let eval = |x: u64| {
            let x = Fr::from(x);
            coefficients
                .iter()
                .rev()
                .fold(Fr::from(0u64), |acc, c| acc * x + c)
        };
        for (i, row) in matrix.iter().enumerate() {
            let combined: Fr = row
                .iter()
                .enumerate()
                .map(|(j, m)| *m * eval(j as u64 + 1))
                .sum();
            assert_eq!(combined, eval((n + i) as u64 + 1), "n = {n}, row {i}");
        }
    }
}

/// The same over `GF(2^8)`, where the points are consecutive powers of the generator.
#[test]
fn the_binary_extraction_matrix_moves_evaluations_from_alpha_to_beta() {
    use stoffelcrypto::common::gf2k::field::{BinaryField, Gf256};
    use stoffelcrypto::common::gf2k::{get_or_create_gf2k_domain, make_hyper_invertible};
    for n in [4usize, 7, 10, 13, 16] {
        let matrix = make_hyper_invertible::<Gf256>(n).unwrap();
        let domain = get_or_create_gf2k_domain::<Gf256>(2 * n).unwrap();
        let coefficients: Vec<Gf256> = (0..n).map(|k| Gf256((17 * k + 3) as u8)).collect();
        let eval = |x: Gf256| {
            coefficients
                .iter()
                .rev()
                .fold(Gf256::zero(), |acc, c| acc * x + *c)
        };
        for (i, row) in matrix.iter().enumerate() {
            let mut combined = Gf256::zero();
            for (j, m) in row.iter().enumerate() {
                combined = combined + *m * eval(domain.element(j));
            }
            assert_eq!(combined, eval(domain.element(n + i)), "n = {n}, row {i}");
        }
    }
}
