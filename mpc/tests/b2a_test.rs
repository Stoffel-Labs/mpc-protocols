//! Tier-A end-to-end tests for binary-to-arithmetic conversion, driven against a standalone
//! [`B2ANode`] over a `FakeNetwork` (the `gf_mul_test.rs` shape: one receiver task per party,
//! every `process` followed by its matching drain).
//!
//! What is pinned here, and why it is not already pinned elsewhere:
//!
//! * `conv_node_test.rs` drives `b2a` through `HoneyBadgerMPCNode::process` at `n = 4, t = 1`,
//!   which is the *wiring*: dispatch arms, drains, session allocation and material accounting.
//! * The in-file `#[cfg(test)]` suite in `b2a.rs` covers the parameter, session-id and material
//!   guards, also at `n = 4, t = 1`.
//! * This file covers the blueprint's Tier-A parameters — `n = 10, t = 3` and `n = 13, t = 4` —
//!   and the *arithmetic* the conversion is supposed to implement: round-trip correctness over
//!   random values, the boundary values on both sides of the width bound, the `ell <= 63`
//!   rejection path, and `b2a_checked`.
//!
//! The daBits are supplied by a trusted dealer. That is deliberate and is not a weakening of the
//! test: what B2A owes its caller, *given* well-formed daBits, is this file's subject, and
//! dealing them in the clear is what makes a failure here land on B2A rather than on whatever
//! produced its input. daBit generation is `prss_dabit_test.rs`'s subject.
//!
//! The older justification — that a real batch could not be smaller than the dealt protocol's
//! 1024-output bucketing soundness floor — no longer applies. PRSS daBits have soundness error 0
//! and no floor; only the isolation argument remains.
//!
//! Every reconstruction below deliberately uses only `2t + 1` shares. B2A opens at degree `t`, a
//! code with `d = 2t + 1`, so a quorum suffices and no individual party is depended upon — the
//! degree-`2t` openings elsewhere in the crate would need all `n` here.

pub mod utils;

#[path = "utils/conv_width_utils.rs"]
mod conv_width_utils;

#[cfg(test)]
mod tests {
    use crate::conv_width_utils::{
        fixed_point_corpus, fixed_point_precision, fixed_point_width, shift_to_unsigned,
    };
    use crate::utils::test_utils::{fan_in_inboxes, setup_tracing};
    use std::sync::Arc;
    use std::time::Duration;

    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::{Rng, SeedableRng};
    use stoffelcrypto::{
        common::{
            convert::{bit_to_binary, bit_to_field, canonical_bits, field_bit_width},
            gf2k::{
                field::{BinaryField, Gf256},
                share::GfShare,
            },
            math::goldilocks::GoldilocksField,
            ProtocolSessionId, SecretSharingScheme,
        },
        honeybadger::{
            b2a::{
                b2a::{max_width, B2ANode, MAX_B2A_BITS},
                B2AError,
            },
            dabit::DaBit,
            gf_triple_gen::GfBeaverTriple,
            robust_interpolate::robust_interpolate::RobustShare,
            ProtocolType, SessionId, WrappedMessage,
        },
    };
    use stoffelmpc_network::fake_network::{
        FakeInnerNetwork, FakeNetwork, FakeNetworkConfig, SenderId,
    };
    use tokio::sync::mpsc::Receiver;
    use tokio::task::JoinSet;
    use tracing::warn;

    type F = GoldilocksField;
    type K = Gf256;
    type Node = B2ANode<F, K>;

    /// `p = 2^64 - 2^32 + 1`, the Goldilocks modulus.
    const P: u128 = 0xFFFF_FFFF_0000_0001;

    const TIMEOUT: Duration = Duration::from_secs(60);

    /// A parent B2A session id: `round_id == 0` and `sub_id == 0`, which is what separates a
    /// parent from the children the node mints for its own openings.
    fn parent(exec: u64, instance: u32) -> SessionId {
        SessionId::new(
            ProtocolType::B2A,
            SessionId::pack_slot(exec, 0, 0),
            instance,
        )
    }

    /// Little-endian bits of `value` at `width`.
    fn bits_of(value: u128, width: usize) -> Vec<bool> {
        (0..width).map(|i| (value >> i) & 1 == 1).collect()
    }

    /// The integer a little-endian bit vector encodes.
    fn as_integer(bits: &[bool]) -> u128 {
        bits.iter()
            .enumerate()
            .filter(|(_, b)| **b)
            .map(|(i, _)| 1u128 << i)
            .sum()
    }

    /// Trusted-dealer stand-in for the daBit pool: `count` daBits on uniformly random bits, each
    /// dealt at degree `t` in both domains under the same party index.
    fn deal_dabits(n: usize, t: usize, count: usize, rng: &mut StdRng) -> Vec<Vec<DaBit<F, K>>> {
        let mut per_party: Vec<Vec<DaBit<F, K>>> = vec![Vec::with_capacity(count); n];
        for _ in 0..count {
            let bit: bool = rng.gen();
            let arith =
                RobustShare::compute_shares(bit_to_field::<F>(bit), n, t, None, rng).unwrap();
            let bin = GfShare::compute_shares(bit_to_binary::<K>(bit), n, t, rng).unwrap();
            for party in 0..n {
                per_party[party]
                    .push(DaBit::new(arith[party].clone(), bin[party].clone(), t).unwrap());
            }
        }
        per_party
    }

    /// Deals the input bits, LSB first, one degree-`t` `GfShare` per bit.
    ///
    /// `tamper` replaces one bit's *secret* with an arbitrary `K` element. That is the only way to
    /// build a non-bit input: a `GfShare` carries no bit-ness guarantee, which is exactly the
    /// condition B2A has to survive without panicking.
    fn deal_bit_shares(
        n: usize,
        t: usize,
        values: &[Vec<bool>],
        tamper: Option<(usize, usize, K)>,
        rng: &mut StdRng,
    ) -> Vec<Vec<Vec<GfShare<K>>>> {
        let mut per_party: Vec<Vec<Vec<GfShare<K>>>> = vec![Vec::with_capacity(values.len()); n];
        for (v, value) in values.iter().enumerate() {
            for party in per_party.iter_mut() {
                party.push(Vec::with_capacity(value.len()));
            }
            for (i, bit) in value.iter().enumerate() {
                let secret = match tamper {
                    Some((tv, ti, k)) if tv == v && ti == i => k,
                    _ => bit_to_binary::<K>(*bit),
                };
                let shares = GfShare::compute_shares(secret, n, t, rng).unwrap();
                for (party, share) in shares.into_iter().enumerate() {
                    per_party[party][v].push(share);
                }
            }
        }
        per_party
    }

    fn deal_gf_triples(
        n: usize,
        t: usize,
        count: usize,
        rng: &mut StdRng,
    ) -> Vec<Vec<GfBeaverTriple<K>>> {
        let mut per_party: Vec<Vec<GfBeaverTriple<K>>> = vec![Vec::with_capacity(count); n];
        for _ in 0..count {
            let a = K::random(rng);
            let b = K::random(rng);
            let a_shares = GfShare::compute_shares(a, n, t, rng).unwrap();
            let b_shares = GfShare::compute_shares(b, n, t, rng).unwrap();
            let c_shares = GfShare::compute_shares(a * b, n, t, rng).unwrap();
            for party in 0..n {
                per_party[party].push(GfBeaverTriple::new(
                    a_shares[party].clone(),
                    b_shares[party].clone(),
                    c_shares[party].clone(),
                ));
            }
        }
        per_party
    }

    #[derive(Clone, Copy, PartialEq)]
    enum Variant {
        /// [`B2ANode::b2a`] — the default, width bound `max_width::<F>()`.
        Unchecked,
        /// [`B2ANode::b2a_checked`] — one exact-zero AND layer certifying the inputs.
        Checked,
        /// [`B2ANode::b2a_full_width_unchecked`] — width bound `field_bit_width::<F>()`.
        FullWidth,
    }

    /// Runs one conversion across all `n` parties and returns each party's result in party order.
    ///
    /// The receiver tasks demux exactly as the node dispatcher does. B2A owns no message type of
    /// its own, so every arm is `GfBatchRecon` routed on `calling_protocol()` alone, the id
    /// claimed inside the payload is checked against the authenticated envelope sender, and every
    /// `process` is immediately followed by its drain (C10) — nothing else moves a finished
    /// reconstruction out of the batch-recon store and the opening driver would park forever.
    async fn b2a_e2e(
        n: usize,
        t: usize,
        values: &[Vec<bool>],
        variant: Variant,
        tamper: Option<(usize, usize, K)>,
        seed: u64,
    ) -> Vec<Result<Vec<RobustShare<F>>, B2AError>> {
        setup_tracing();

        let mut rng = StdRng::seed_from_u64(seed);
        let total: usize = values.iter().map(Vec::len).sum();
        let bits = deal_bit_shares(n, t, values, tamper, &mut rng);
        let dabits = deal_dabits(n, t, total, &mut rng);
        let triples = match variant {
            Variant::Checked => Some(deal_gf_triples(n, t, total, &mut rng)),
            _ => None,
        };

        let config = FakeNetworkConfig::new(4096);
        let (inner, mut receivers, _) = FakeInnerNetwork::new(n, None, config);
        let networks: Vec<Arc<FakeNetwork>> = (0..n)
            .map(|id| Arc::new(FakeNetwork::new(id, inner.clone())))
            .collect();
        let nodes: Vec<Node> = (0..n).map(|id| Node::new(id, n, t).unwrap()).collect();

        let mut receiver_tasks = JoinSet::new();
        for node in &nodes {
            let mut node = node.clone();
            let net = Arc::clone(&networks[node.id]);
            let inbox: Vec<(SenderId, Receiver<Vec<u8>>)> = std::mem::take(&mut receivers[node.id])
                .into_iter()
                .enumerate()
                .map(|(i, r)| (SenderId::Node(i), r))
                .collect();
            let mut merged = fan_in_inboxes(inbox);
            receiver_tasks.spawn(async move {
                while let Some((sender, bytes)) = merged.recv().await {
                    let wrapped: WrappedMessage = match bincode::deserialize(&bytes) {
                        Ok(m) => m,
                        Err(e) => {
                            warn!("undecodable message: {e:?}");
                            continue;
                        }
                    };
                    match wrapped {
                        WrappedMessage::GfBatchRecon(msg) => {
                            // C1/C3: the id inside the payload is the sender's own claim and is
                            // never trusted; only the authenticated envelope id is.
                            if SenderId::Node(msg.sender_id) != sender {
                                warn!("forged sender id, dropping");
                                continue;
                            }
                            assert_eq!(msg.session_id.calling_protocol(), Some(ProtocolType::B2A));
                            if let Err(e) = node.gf_open.process(msg, Arc::clone(&net)).await {
                                warn!("gf batch recon processing error: {e:?}");
                            }
                            if let Err(e) = node.drain_gf_open_output().await {
                                warn!("drain failed: {e:?}");
                            }
                        }
                        other => panic!("unexpected message {other:?}"),
                    }
                }
            });
        }

        let session_id = parent(seed, 77);
        let mut set = JoinSet::new();
        for (index, node) in nodes.iter().enumerate() {
            let mut node = node.clone();
            let net = Arc::clone(&networks[index]);
            let bits = bits[index].clone();
            let dabits = dabits[index].clone();
            let triples = triples.as_ref().map(|t| t[index].clone());
            set.spawn(async move {
                let started = match variant {
                    Variant::Checked => {
                        node.b2a_checked(
                            session_id,
                            bits,
                            dabits,
                            triples.expect("checked variant deals triples"),
                            TIMEOUT,
                            net,
                        )
                        .await
                    }
                    Variant::FullWidth => {
                        node.b2a_full_width_unchecked(session_id, bits, dabits, TIMEOUT, net)
                            .await
                    }
                    Variant::Unchecked => node.b2a(session_id, bits, dabits, TIMEOUT, net).await,
                };
                let result = match started {
                    Ok(()) => node.wait_for_result(session_id, TIMEOUT).await,
                    Err(e) => Err(e),
                };
                // Cleanup happens on the failure path too, not only the happy one (C7).
                node.clear_store(session_id).await;
                assert_eq!(
                    node.store_len().await,
                    0,
                    "party {} leaked a session",
                    node.id
                );
                assert_eq!(
                    node.gf_open.store_len().await,
                    0,
                    "party {} leaked a child opening session",
                    node.id
                );
                (node.id, result)
            });
        }

        let mut by_party: Vec<Option<Result<Vec<RobustShare<F>>, B2AError>>> =
            (0..n).map(|_| None).collect();
        while let Some(joined) = set.join_next().await {
            let (id, result) = joined.expect("party task panicked");
            by_party[id] = Some(result);
        }
        receiver_tasks.abort_all();
        by_party
            .into_iter()
            .map(|r| r.expect("every party reported"))
            .collect()
    }

    /// Reconstructs value `v` from a deliberately minimal quorum of `2t + 1` degree-`t` shares.
    fn recover(
        results: &[Result<Vec<RobustShare<F>>, B2AError>],
        v: usize,
        n: usize,
        t: usize,
    ) -> F {
        let shares: Vec<RobustShare<F>> = results
            .iter()
            .take(2 * t + 1)
            .map(|r| r.as_ref().expect("party failed")[v].clone())
            .collect();
        RobustShare::recover_secret(&shares, n, t).unwrap().1
    }

    /// Every party returned a share of its own, at degree `t`, one per input value.
    fn assert_share_shape(
        results: &[Result<Vec<RobustShare<F>>, B2AError>],
        values: usize,
        t: usize,
    ) {
        for (party, result) in results.iter().enumerate() {
            let shares = result.as_ref().expect("party failed");
            assert_eq!(
                shares.len(),
                values,
                "party {party} returned the wrong count"
            );
            for share in shares {
                assert_eq!(
                    share.id, party,
                    "party {party} returned someone else's index"
                );
                assert_eq!(share.degree, t, "party {party} returned the wrong degree");
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // Round-trip correctness
    // ---------------------------------------------------------------------------------------

    /// `[x_0..x_{l-1}]_K -> [sum 2^i x_i]_F` over uniformly random values at several widths.
    ///
    /// Random bit patterns are the case a hand-picked one cannot cover: a wrong weight, a
    /// reversed endianness or a mis-indexed daBit all survive `0` and `2^w - 1` and die here.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn b2a_round_trips_random_values_at_n10_t3() {
        let (n, t) = (10usize, 3usize);
        let mut rng = StdRng::seed_from_u64(0xB2A0);
        let values: Vec<Vec<bool>> = [1usize, 8, 32, 63, 63, 17]
            .iter()
            .map(|width| (0..*width).map(|_| rng.gen()).collect())
            .collect();

        let results = b2a_e2e(n, t, &values, Variant::Unchecked, None, 1).await;
        assert_share_shape(&results, values.len(), t);
        for (v, value) in values.iter().enumerate() {
            assert_eq!(
                recover(&results, v, n, t),
                F::from(as_integer(value)),
                "value {v} (width {})",
                value.len()
            );
        }
    }

    /// The same at `n = 13, t = 4`, the blueprint's second Tier-A shape: a different quorum size,
    /// a different per-peer batch-reconstruction quota, and a different chunk size.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn b2a_round_trips_random_values_at_n13_t4() {
        let (n, t) = (13usize, 4usize);
        let mut rng = StdRng::seed_from_u64(0xB2A1);
        let values: Vec<Vec<bool>> = [1usize, 32, 63]
            .iter()
            .map(|width| (0..*width).map(|_| rng.gen()).collect())
            .collect();

        let results = b2a_e2e(n, t, &values, Variant::Unchecked, None, 2).await;
        assert_share_shape(&results, values.len(), t);
        for (v, value) in values.iter().enumerate() {
            assert_eq!(
                recover(&results, v, n, t),
                F::from(as_integer(value)),
                "value {v} (width {})",
                value.len()
            );
        }
    }

    /// Boundary values at and below the width bound.
    ///
    /// `0` and `1` catch a weighting that starts at the wrong power; `2^62` and `2^62 + 1` catch
    /// a truncated accumulator; `2^63 - 1` is the largest value `ell = 63` can carry and is the
    /// one an off-by-one in the bound would get wrong.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn b2a_converts_the_boundary_values_of_the_width_bound() {
        let (n, t) = (10usize, 3usize);
        let w = MAX_B2A_BITS;
        let payloads: Vec<u128> = vec![
            0,
            1,
            1 << 62,
            (1u128 << 62) + 1,
            (1u128 << 63) - 1,
            0x5555_5555_5555_5555,
        ];
        let values: Vec<Vec<bool>> = payloads.iter().map(|v| bits_of(*v, w)).collect();

        let results = b2a_e2e(n, t, &values, Variant::Unchecked, None, 3).await;
        assert_share_shape(&results, values.len(), t);
        for (v, payload) in payloads.iter().enumerate() {
            // Every payload here is below `2^63 - 1 < p`, so the recomposition is an *integer*
            // identity and not merely a congruence: `F::from` of the integer is the answer.
            assert!(*payload < P, "payload {v} is not below the modulus");
            assert_eq!(recover(&results, v, n, t), F::from(*payload), "payload {v}");
        }
    }

    /// The full-width entry point on the values that only it can carry.
    ///
    /// `p - 1 = 0xFFFF_FFFF_0000_0000` is exactly what A2B emits for `-1`, so this is the half of
    /// the A2B round trip that lives on this side of the boundary; `p - (2^32 - 1)` is the other
    /// side of the `2^64 - p` identity the conversion's reduction turns on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn b2a_full_width_unchecked_is_exact_up_to_the_modulus() {
        let (n, t) = (10usize, 3usize);
        let w = field_bit_width::<F>();
        let payloads: Vec<u128> = vec![
            0,
            1u128 << 63,
            P - 1,                 // 0xFFFF_FFFF_0000_0000, what A2B emits for -1
            P - (1u128 << 32) + 1, // p - (2^32 - 1)
            P - 2,
        ];
        let values: Vec<Vec<bool>> = payloads.iter().map(|v| bits_of(*v, w)).collect();

        let results = b2a_e2e(n, t, &values, Variant::FullWidth, None, 4).await;
        assert_share_shape(&results, values.len(), t);
        for (v, payload) in payloads.iter().enumerate() {
            assert!(*payload < P, "payload {v} is not below the modulus");
            assert_eq!(recover(&results, v, n, t), F::from(*payload), "payload {v}");
            // And the canonical decomposition of the answer is the bit vector we fed in — the
            // property an A2B round trip relies on.
            assert_eq!(
                canonical_bits::<F>(F::from(*payload), w).unwrap(),
                values[v],
                "payload {v} is not its own canonical decomposition"
            );
        }
    }

    // ---------------------------------------------------------------------------------------
    // The `ell <= 63` rejection path
    // ---------------------------------------------------------------------------------------

    /// Width 64 on the default entry point is a hard error, not a silent `x mod p`.
    ///
    /// `2^64 - 1 > p`, so at width 64 the `2^32 - 1` payloads in `[p, 2^64)` would come back
    /// reduced — and the payload is the adversary's to choose. The rejection must also be
    /// unanimous: it is a function of the local shape alone, so every party reaches it
    /// identically without a round of communication.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn b2a_rejects_a_width_above_the_bound_rather_than_wrapping() {
        let (n, t) = (10usize, 3usize);
        assert_eq!(max_width::<F>(), MAX_B2A_BITS);
        assert_eq!(field_bit_width::<F>(), MAX_B2A_BITS + 1);

        // `p - 1` needs all 64 bits and is the value that would *appear* to work: it is below the
        // modulus, so a silent acceptance would return the right answer here and the wrong one
        // for `p` itself.
        let values = vec![bits_of(P - 1, field_bit_width::<F>())];
        let results = b2a_e2e(n, t, &values, Variant::Unchecked, None, 5).await;
        for (party, result) in results.iter().enumerate() {
            match result {
                Err(B2AError::WidthTooLarge { value, width, max }) => {
                    assert_eq!(
                        (*value, *width, *max),
                        (0, 64, MAX_B2A_BITS),
                        "party {party}"
                    );
                }
                other => panic!("party {party} accepted a 64-bit value: {other:?}"),
            }
        }
    }

    /// Width 63 is accepted and width 64 refused *by the same entry point*, and the full-width
    /// entry point moves the line by exactly one — the bound is a property of the entry point,
    /// not a global constant.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_width_bound_sits_exactly_between_63_and_64() {
        let (n, t) = (10usize, 3usize);

        let at_bound = vec![bits_of((1u128 << 63) - 1, MAX_B2A_BITS)];
        let accepted = b2a_e2e(n, t, &at_bound, Variant::Unchecked, None, 6).await;
        assert_eq!(
            recover(&accepted, 0, n, t),
            F::from((1u128 << 63) - 1),
            "the largest value the bound admits must convert"
        );

        // One bit wider on the same entry point: refused.
        let over = vec![bits_of((1u128 << 63) - 1, MAX_B2A_BITS + 1)];
        let refused = b2a_e2e(n, t, &over, Variant::Unchecked, None, 7).await;
        for result in &refused {
            assert!(matches!(result, Err(B2AError::WidthTooLarge { .. })));
        }

        // The *same* over-wide input on the explicitly named full-width entry point: accepted,
        // because the caller has taken on the `sum 2^i x_i < p` precondition by naming it.
        let full = b2a_e2e(n, t, &over, Variant::FullWidth, None, 8).await;
        assert_eq!(recover(&full, 0, n, t), F::from((1u128 << 63) - 1));

        // And one bit past *that* is refused everywhere: there is no entry point above 64.
        let beyond = vec![bits_of(1, field_bit_width::<F>() + 1)];
        let refused = b2a_e2e(n, t, &beyond, Variant::FullWidth, None, 9).await;
        for result in &refused {
            match result {
                Err(B2AError::WidthTooLarge { width, max, .. }) => {
                    assert_eq!((*width, *max), (65, field_bit_width::<F>()));
                }
                other => panic!("a 65-bit value was not refused: {other:?}"),
            }
        }
    }

    /// A non-bit input share is a typed error at every party, never a panic and never a silently
    /// wrong arithmetic result.
    ///
    /// `Gf256(3)` is outside the `GF(2)` subfield, so the opened `c = x XOR r` falls outside it
    /// too. Because `c` was robustly opened, the verdict is *agreed* — every honest party rejects
    /// with the same index, with no extra round.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn b2a_rejects_a_non_bit_input_identically_at_every_party() {
        let (n, t) = (10usize, 3usize);
        let values = vec![bits_of(0b1011, 4), bits_of(0b0110, 4)];
        let results = b2a_e2e(
            n,
            t,
            &values,
            Variant::Unchecked,
            Some((1, 2, Gf256(3))),
            10,
        )
        .await;
        for (party, result) in results.iter().enumerate() {
            match result {
                Err(B2AError::NonBooleanInput { value, index }) => {
                    assert_eq!((*value, *index), (1, 2), "party {party}");
                }
                other => panic!("party {party} did not reject the non-bit: {other:?}"),
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // The checked variant
    // ---------------------------------------------------------------------------------------

    /// `b2a_checked` returns the same arithmetic as `b2a` on honest input — the certification
    /// layer is a proof obligation discharged, not a different conversion.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn b2a_checked_agrees_with_the_unchecked_path() {
        let (n, t) = (10usize, 3usize);
        let mut rng = StdRng::seed_from_u64(0xB2A2);
        let values: Vec<Vec<bool>> = [1usize, 16, 63]
            .iter()
            .map(|width| (0..*width).map(|_| rng.gen()).collect())
            .collect();

        let checked = b2a_e2e(n, t, &values, Variant::Checked, None, 11).await;
        let unchecked = b2a_e2e(n, t, &values, Variant::Unchecked, None, 12).await;
        assert_share_shape(&checked, values.len(), t);
        for (v, value) in values.iter().enumerate() {
            let expected = F::from(as_integer(value));
            assert_eq!(recover(&checked, v, n, t), expected, "checked, value {v}");
            assert_eq!(
                recover(&unchecked, v, n, t),
                expected,
                "unchecked, value {v}"
            );
        }
    }

    /// The certification layer *proves* a non-bit input rather than inferring it.
    ///
    /// `x(x + 1)` is identically zero for a bit and depends on nothing but the input, so unlike
    /// the `c_i.is_bit()` inference it does not lean on the daBit's binary half being well
    /// formed. Exact zero, so soundness error is 0 and the offending index comes for free.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn b2a_checked_proves_a_non_bit_input() {
        let (n, t) = (10usize, 3usize);
        let values = vec![bits_of(0b1101, 4)];
        let results = b2a_e2e(n, t, &values, Variant::Checked, Some((0, 2, Gf256(7))), 13).await;
        for (party, result) in results.iter().enumerate() {
            match result {
                Err(B2AError::CertificationFailed { value, index }) => {
                    assert_eq!((*value, *index), (0, 2), "party {party}");
                }
                other => panic!("party {party} did not certify-reject: {other:?}"),
            }
        }
    }

    /// A tampered bit that happens to stay inside `GF(2)` is invisible to the unchecked path and
    /// caught by the checked one — the exact difference the extra AND layer buys.
    ///
    /// Flipping bit 0 of a value from 1 to 0 is a perfectly well-formed input, so `b2a` converts
    /// it faithfully to the *wrong* value and `b2a_checked` also accepts it: certification proves
    /// bit-ness, not provenance. This pins that the checked variant does not over-claim.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn certification_proves_bit_ness_and_not_provenance() {
        let (n, t) = (10usize, 3usize);
        let values = vec![bits_of(0b1011, 4)];
        // `Gf256(0)` is a legitimate bit, so neither path can object; the conversion is of the
        // value the *shares* encode, which is now 0b1010.
        let results = b2a_e2e(n, t, &values, Variant::Checked, Some((0, 0, Gf256(0))), 14).await;
        assert_eq!(recover(&results, 0, n, t), F::from(0b1010u128));
    }

    /// A GF triple count that does not match the bit count is a hard, exact-length error.
    ///
    /// `==`, never `>=`: a surplus triple would mean the caller believes preprocessing it has
    /// already spent is still unspent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn b2a_checked_refuses_a_material_length_that_is_not_exactly_right() {
        setup_tracing();
        let (n, t) = (10usize, 3usize);
        let mut rng = StdRng::seed_from_u64(0xB2A3);
        let values = vec![bits_of(0b1011, 4)];
        let total = 4usize;

        let config = FakeNetworkConfig::new(64);
        let (inner, _receivers, _) = FakeInnerNetwork::new(n, None, config);
        let network = Arc::new(FakeNetwork::new(0, inner));
        let mut node = Node::new(0, n, t).unwrap();

        let bits = deal_bit_shares(n, t, &values, None, &mut rng);
        let dabits = deal_dabits(n, t, total, &mut rng);
        // One triple short of the one-per-bit the certification layer needs.
        let triples = deal_gf_triples(n, t, total - 1, &mut rng);

        let err = node
            .b2a_checked(
                parent(20, 77),
                bits[0].clone(),
                dabits[0].clone(),
                triples[0].clone(),
                TIMEOUT,
                network,
            )
            .await
            .expect_err("a short triple vector must be refused");
        match err {
            B2AError::MaterialLengthMismatch {
                what,
                expected,
                got,
            } => {
                assert_eq!((what, expected, got), ("gf triples", total, total - 1));
            }
            other => panic!("unexpected error: {other:?}"),
        }
        // The shape check runs before the session is admitted, so nothing was left behind.
        assert_eq!(node.store_len().await, 0);
    }

    // ---------------------------------------------------------------------------------------
    // The fixed-point width, `ell = 33`
    // ---------------------------------------------------------------------------------------

    /// The whole fixed-point corpus at `ell = 33`.
    ///
    /// `FixedPointPrecision::new(32, 16)` is the repo default and the plan's §2.4 attaches
    /// `ell = k + 1 = 33` to it. The `+1` is not slack: `truncpr.rs:192` shifts a signed `k`-bit
    /// value into the *closed* interval `[0, 2^k]`, whose upper endpoint needs bit `k`, and an
    /// unrescaled sum of two shifted operands sets that bit outright. A conversion sized at `k`
    /// bits is right on every value anyone would hand-check and wrong on the carry, so `2^32`,
    /// `2^32 + 1` and `2^33 - 1` are all in the corpus.
    ///
    /// `33 <= max_width::<F>()`, so this is the default entry point and not the full-width one —
    /// a fixed-point caller never needs the unchecked variant.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn b2a_converts_the_fixed_point_width() {
        let (n, t) = (10usize, 3usize);
        let precision = fixed_point_precision();
        let ell = fixed_point_width();
        assert_eq!((precision.k(), precision.f()), (32, 16), "the repo default");
        assert_eq!(ell, 33);
        assert!(
            ell <= max_width::<F>(),
            "ell = 33 is inside the width bound"
        );

        let corpus = fixed_point_corpus();
        let values: Vec<Vec<bool>> = corpus
            .iter()
            .map(|(_, payload)| bits_of(*payload as u128, ell))
            .collect();

        let results = b2a_e2e(n, t, &values, Variant::Unchecked, None, 30).await;
        assert_share_shape(&results, values.len(), t);
        for (v, (label, payload)) in corpus.iter().enumerate() {
            // Every payload is below `2^33 < p`, so this is an integer identity, not a congruence.
            assert!((*payload as u128) < P);
            assert_eq!(
                recover(&results, v, n, t),
                F::from(*payload as u128),
                "{label}"
            );
            // And the bit vector we fed in is the canonical decomposition of the answer, which is
            // what makes the A2B half of the round trip exact.
            assert_eq!(
                canonical_bits::<F>(F::from(*payload as u128), ell).unwrap(),
                values[v],
                "{label} is not its own canonical decomposition at width {ell}"
            );
        }
    }

    /// The same corpus at `n = 13, t = 4`: a different quorum, chunk size and per-peer quota.
    ///
    /// Worth repeating rather than folding into the `n = 10` run, because `ell = 33` is not a
    /// multiple of any of those and the padding a short final chunk needs is `n`-dependent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn b2a_converts_the_fixed_point_width_at_n13_t4() {
        let (n, t) = (13usize, 4usize);
        let ell = fixed_point_width();

        // The signed values a fixed-point caller actually holds, carried through the same
        // `+2^(k-1)` shift `truncpr` applies. `-2^31` and `2^31 - 1` are the two extremes.
        let signed: Vec<i64> = vec![-(1i64 << 31), -1, 0, 1, 1 << 16, (1i64 << 31) - 1];
        let payloads: Vec<u64> = signed.iter().map(|v| shift_to_unsigned(*v)).collect();
        let values: Vec<Vec<bool>> = payloads.iter().map(|p| bits_of(*p as u128, ell)).collect();

        let results = b2a_e2e(n, t, &values, Variant::Unchecked, None, 31).await;
        assert_share_shape(&results, values.len(), t);
        for (v, value) in signed.iter().enumerate() {
            assert_eq!(
                recover(&results, v, n, t),
                F::from(payloads[v] as u128),
                "shift({value})"
            );
        }
    }

    /// B2A's preprocessing is exactly `ell` daBits per value, so its cost falls linearly with the
    /// conversion width — the one thing that *does* get cheaper at `ell = 33` (plan §2.4).
    ///
    /// A2B's does not, and that asymmetry is the standing negative result: A2B's mask has to be
    /// uniform on `[0, p)` whatever the payload width, so its edaBit stays 64 daBits wide. B2A has
    /// no such constraint — it masks each input bit independently — so two 33-bit values need 66
    /// daBits where two 63-bit values need 126.
    ///
    /// Pinned through the exact-length check rather than by counting a successful run, because
    /// `==` (not `>=`) is itself the property: a surplus daBit is one the caller believes is still
    /// unspent, and spending it twice turns two openings into `c XOR c' = x XOR x'`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn b2a_spends_exactly_one_dabit_per_bit_of_the_width() {
        setup_tracing();
        let (n, t) = (10usize, 3usize);
        let ell = fixed_point_width();
        let mut rng = StdRng::seed_from_u64(0xB2A4);

        let config = FakeNetworkConfig::new(64);
        let (inner, _receivers, _) = FakeInnerNetwork::new(n, None, config);
        let network = Arc::new(FakeNetwork::new(0, inner));

        // `(width, values)` pairs and the daBit count each one owes.
        for (exec, (width, count)) in [(ell, 2usize), (max_width::<F>(), 2usize)]
            .into_iter()
            .enumerate()
        {
            let expected = width * count;
            let values: Vec<Vec<bool>> = (0..count)
                .map(|_| (0..width).map(|_| rng.gen()).collect())
                .collect();
            let bits = deal_bit_shares(n, t, &values, None, &mut rng);
            // One short of what the width owes.
            let dabits = deal_dabits(n, t, expected - 1, &mut rng);

            let mut node = Node::new(0, n, t).unwrap();
            let err = node
                .b2a(
                    parent(40 + exec as u64, 77),
                    bits[0].clone(),
                    dabits[0].clone(),
                    TIMEOUT,
                    Arc::clone(&network),
                )
                .await
                .expect_err("a short daBit vector must be refused");
            match err {
                B2AError::MaterialLengthMismatch {
                    what,
                    expected: want,
                    got,
                } => {
                    assert_eq!(
                        (what, want, got),
                        ("dabits", expected, expected - 1),
                        "width {width}: the daBit bill is not {count} * {width}"
                    );
                }
                other => panic!("width {width}: unexpected error {other:?}"),
            }
            // The shape check runs before admission, so nothing was left behind on the way out.
            assert_eq!(node.store_len().await, 0, "width {width} leaked a session");
        }

        // Linearity, stated as the ratio the two bills above establish.
        assert_eq!(
            max_width::<F>() * 2 - ell * 2,
            60,
            "60 daBits per pair is what narrowing from 63 bits to 33 saves"
        );
    }
}
