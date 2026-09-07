use crate::common::session_store::{Admission, SessionStore};
use crate::{
    avss_mpc::{
        mul::{multiplication::verify_share_against_commitments, ReconstructionMessage},
        triple_gen::{BeaverTriple, TripleCheckMessage, TripleGenError, TripleGenStore},
        AvssSessionId, AvssWrappedMessage, ProtocolType,
    },
    common::{
        share::{
            avss::{AvssNode, MAX_PENDING_SESSIONS},
            feldman::FeldmanShamirShare,
        },
        ProtocolSessionId, SecretSharingScheme, RBC,
    },
};
use ark_ec::CurveGroup;
use ark_ff::{FftField, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::{
    mpsc::{self},
    Mutex,
};
use tracing::{info, warn};

#[derive(Clone, Debug)]
pub struct TripleGenNode<F: FftField, R: RBC, C: CurveGroup<ScalarField = F>> {
    pub id: usize,
    pub n_parties: usize,
    pub threshold: usize,
    pub avss: AvssNode<F, R, C, AvssSessionId>,
    pub avss_output: Arc<Mutex<mpsc::Receiver<AvssSessionId>>>,
    pub store:
        Arc<Mutex<SessionStore<AvssSessionId, (usize, Instant, Arc<Mutex<TripleGenStore<F, C>>>)>>>,
    pub rbc: R,
    pub rbc_output: Arc<Mutex<mpsc::Receiver<AvssSessionId>>>,
}

const MAX_AVSS_TRIPLE_GEN_SESSIONS: usize = 256;

impl<F, R, C> TripleGenNode<F, R, C>
where
    F: PrimeField,
    R: RBC<Id = AvssSessionId>,
    C: CurveGroup<ScalarField = F> + Send + Sync,
{
    pub fn new(
        id: PartyId,
        n_parties: usize,
        threshold: usize,
        sk_i: F,
        pk_map: Arc<Vec<C>>,
    ) -> Result<Self, TripleGenError> {
        // Must be >= MAX_PENDING_SESSIONS: AvssNode::process uses try_send and drops
        // notifications on a full channel rather than blocking, so a smaller capacity here
        // would silently lose notifications well before the session cache itself is full.
        let (tx, rx) = mpsc::channel(MAX_PENDING_SESSIONS);
        let avss = AvssNode::new(
            id,
            n_parties,
            (1..=n_parties).collect(),
            threshold,
            sk_i,
            pk_map,
            tx,
            Arc::new(AvssWrappedMessage::rbc_wrap),
            Arc::new(AvssWrappedMessage::avss_wrap),
        )?;

        let (rbc_sender, rbc_receiver) = mpsc::channel(MAX_PENDING_SESSIONS);
        let rbc = R::new(
            id,
            n_parties,
            threshold,
            threshold + 1,
            rbc_sender,
            Arc::new(AvssWrappedMessage::rbc_wrap),
        )?;

        Ok(Self {
            id,
            n_parties,
            threshold,
            avss,
            avss_output: Arc::new(Mutex::new(rx)),
            store: Arc::new(Mutex::new(SessionStore::with_default_cap())),
            rbc,
            rbc_output: Arc::new(Mutex::new(rbc_receiver)),
        })
    }

    async fn get_or_create_store(
        &mut self,
        sid: AvssSessionId,
        initiator_id: usize,
    ) -> Option<Arc<Mutex<TripleGenStore<F, C>>>> {
        match self.store.lock().await.get_or_admit(
            sid,
            initiator_id,
            MAX_AVSS_TRIPLE_GEN_SESSIONS,
            MAX_AVSS_TRIPLE_GEN_SESSIONS / self.n_parties,
            || Arc::new(Mutex::new(TripleGenStore::empty(2 * self.threshold + 1))),
        ) {
            Admission::Got(arc) => Some(arc),
            Admission::Retired => None,
            Admission::Rejected => {
                warn!("AVSS TripleGen session limit reached");
                None
            }
        }
    }

    /// Retires this session and clears every per-dealer AVSS sub-session plus the two
    /// sacrifice-check opening rounds it created.
    pub async fn clear_store(&self, session_id: AvssSessionId) -> bool {
        let m = 2 * self.threshold + 1;
        for dealer in 0..m {
            let avss_sid = AvssSessionId::new(
                session_id.calling_protocol().unwrap(),
                AvssSessionId::pack_slot(session_id.exec_id(), dealer as u8, session_id.round_id()),
                session_id.instance_id(),
            );
            self.avss.clear_session(avss_sid).await;
        }

        for party in 0..self.n_parties {
            for round in 0..2u8 {
                let check_sid = AvssSessionId::new(
                    ProtocolType::TripleCheck,
                    AvssSessionId::pack_slot(session_id.exec_id(), party as u8, round),
                    session_id.instance_id(),
                );
                self.rbc.clear_session(check_sid).await;
            }
        }

        let mut store = self.store.lock().await;
        store.retire(session_id)
    }

    /// Derives the Fiat-Shamir challenge for the sacrifice check from the public
    /// commitment transcript of every triple generated this call (the `batch` real
    /// candidates plus the sacrifice). Every honest party computes the identical value
    /// locally, with no extra network round: the hash input is fixed the moment AVSS
    /// dealing finishes, before any party could know what challenge it will produce, so
    /// a cheating dealer cannot pick their forged value to cancel out against it.
    fn fiat_shamir_challenge(triples: &[BeaverTriple<F, C>]) -> F {
        let mut buf = Vec::new();
        for triple in triples {
            for share in [&triple.a, &triple.b, &triple.c] {
                for c in &share.commitments {
                    c.serialize_compressed(&mut buf).unwrap();
                }
            }
        }
        let hash = Sha256::digest(&buf);
        F::from_le_bytes_mod_order(&hash)
    }

    /// rho = candidate.a * t_pub - sacrifice.a, sigma = candidate.b - sacrifice.b.
    /// Pure and local (degree t) — each party computes its own point on these using
    /// only shares it already holds and trusts.
    fn compute_rho_sigma(
        candidate: &BeaverTriple<F, C>,
        sacrifice: &BeaverTriple<F, C>,
        t_pub: F,
    ) -> Result<(FeldmanShamirShare<F, C>, FeldmanShamirShare<F, C>), TripleGenError> {
        let scaled_a = (candidate.a.clone() * t_pub)?;
        let rho = (scaled_a - sacrifice.a.clone())?;
        let sigma = (candidate.b.clone() - sacrifice.b.clone())?;
        Ok((rho, sigma))
    }

    /// check = candidate.c * t_pub - sacrifice.c - sacrifice.a*sigma_pub - sacrifice.b*rho_pub
    ///         - rho_pub*sigma_pub.
    /// Pure and local (degree t) once rho_pub/sigma_pub are public. Reconstructing check
    /// to zero for every candidate proves candidate.c == candidate.a * candidate.b,
    /// given a correct sacrifice (h == f*g) — see the derivation referenced above
    /// `fiat_shamir_challenge`.
    fn compute_check(
        candidate: &BeaverTriple<F, C>,
        sacrifice: &BeaverTriple<F, C>,
        t_pub: F,
        rho_pub: F,
        sigma_pub: F,
    ) -> Result<FeldmanShamirShare<F, C>, TripleGenError> {
        let scaled_c = (candidate.c.clone() * t_pub)?;
        let term1 = (scaled_c - sacrifice.c.clone())?;
        let term2 = (sacrifice.a.clone() * sigma_pub)?;
        let term3 = (sacrifice.b.clone() * rho_pub)?;
        let const_term = rho_pub * sigma_pub;
        let check = (term1 - term2)?;
        let check = (check - term3)?;
        let check = (check - const_term)?;
        Ok(check)
    }

    pub async fn gen_triple<N, G>(
        &mut self,
        session_id: AvssSessionId,
        a: Vec<FeldmanShamirShare<F, C>>,
        b: Vec<FeldmanShamirShare<F, C>>,
        rng: &mut G,
        network: Arc<N>,
    ) -> Result<Vec<BeaverTriple<F, C>>, TripleGenError>
    where
        N: Network + Send + Sync,
        G: Rng + Send,
    {
        info!("party {} starting triple gen", self.id);

        if a.len() != b.len() {
            return Err(TripleGenError::InvalidShareLength);
        }
        // The vector is [real candidates || their dedicated sacrifices], equal-length
        // halves — every candidate gets its own single-use sacrifice (see Step 4).
        if a.len() < 2 || a.len() % 2 != 0 {
            return Err(TripleGenError::InvalidBatchSize);
        }
        let t = self.threshold;
        let m = 2 * t + 1;

        let full_batch = a.len();
        let batch = full_batch / 2;

        // === Step 1: local products (vector), including the sacrifice half ===
        // c_i_prime[j] = a_i[j] * b_i[j]
        let c_i_prime: Vec<F> = a
            .iter()
            .zip(b.iter())
            .map(|(s1, s2)| s1.feldmanshare.share[0] * s2.feldmanshare.share[0])
            .collect();
        // === Step 2: dealers AVSS-share the batch vector ===
        let is_dealer = self.id < m;
        if is_dealer {
            let avss_sid = AvssSessionId::new(
                session_id.calling_protocol().unwrap(),
                AvssSessionId::pack_slot(
                    session_id.exec_id(),
                    self.id as u8,
                    session_id.round_id(),
                ),
                session_id.instance_id(),
            );
            self.avss
                .init(c_i_prime, avss_sid, rng, network.clone())
                .await?;
        }

        // Create store once
        let store_ref = match self.get_or_create_store(session_id, self.id).await {
            Some(s) => s,
            None => return Ok(vec![]),
        };
        let xs: Vec<F> = (0..m).map(|i| F::from((i + 1) as u64)).collect();

        // === Step 3: collect dealer outputs, then lagrange-combine component-wise ===
        // This produces `full_batch` triples: the first `batch` are the real candidates,
        // the second `batch` are their dedicated sacrifices (candidate i <-> sacrifice
        // `batch + i`).
        let triples: Vec<BeaverTriple<F, C>> = 'dealing: loop {
            let done = {
                let mut rx = self.avss_output.lock().await;
                match rx.recv().await {
                    Some(d) => d,
                    None => unreachable!(),
                }
            };

            let same = done.calling_protocol().unwrap() == session_id.calling_protocol().unwrap()
                && done.exec_id() == session_id.exec_id()
                && done.round_id() == session_id.round_id()
                && done.instance_id() == session_id.instance_id();

            if !same {
                continue 'dealing;
            }

            let dealer = done.sub_id() as usize;
            if dealer >= m {
                self.avss.take_share(done).await;
                continue 'dealing;
            }

            let pieces = self
                .avss
                .take_share(done)
                .await
                .and_then(|x| x)
                .ok_or(TripleGenError::MissingDealer(dealer))?;
            if pieces.len() != full_batch {
                return Err(TripleGenError::InvalidShareLength);
            }

            let mut st = store_ref.lock().await;
            st.received.insert(dealer, pieces);
            st.reception_tracker[dealer] = true;

            if st.reception_tracker.iter().all(|&x| x) {
                // === Lagrange combine for each batch index j ===
                let mut c_out: Vec<FeldmanShamirShare<F, C>> = Vec::with_capacity(full_batch);

                for j in 0..full_batch {
                    let mut c_val_j = F::zero();
                    let mut c_comms_j = vec![C::zero(); t + 1];

                    for dealer_id in 0..m {
                        let x_i = xs[dealer_id];
                        let lambda = Self::lagrange_at_zero(x_i, &xs);

                        let share = st
                            .received
                            .get(&dealer_id)
                            .ok_or(TripleGenError::MissingDealer(dealer_id))?;
                        let s = &share[j];

                        // share value
                        c_val_j += lambda * s.feldmanshare.share[0];

                        // commitments (degree t)
                        if s.commitments.len() != t + 1 {
                            return Err(TripleGenError::CommitmentLengthMismatch);
                        }
                        for k in 0..=t {
                            c_comms_j[k] += s.commitments[k].mul(lambda);
                        }
                    }

                    // Shamir evaluation points are 1-based throughout the AVSS
                    // stack, while network party identifiers are 0-based.
                    c_out.push(FeldmanShamirShare::new(c_val_j, self.id + 1, t, c_comms_j)?);
                }
                let out: Vec<BeaverTriple<F, C>> = c_out
                    .iter()
                    .enumerate()
                    .map(|(i, c)| BeaverTriple {
                        a: a[i].clone(),
                        b: b[i].clone(),
                        c: c.clone(),
                    })
                    .collect();
                st.output = Some(out.clone());
                break 'dealing out;
            }
        };

        // === Step 4: sacrifice check, entirely at degree t ===
        //
        // For candidate i (a,b,c) and its own dedicated sacrifice (f,g,h):
        //   rho_i   = a_i*t_pub - f_i
        //   sigma_i = b_i - g_i
        //   check_i = c_i*t_pub - h_i - f_i*sigma_i - g_i*rho_i - rho_i*sigma_i
        // check_i == 0 for every i iff every candidate satisfies c == a*b (given its
        // sacrifice is correct; if a sacrifice is wrong, that candidate's check comes out
        // as a nonzero constant, so it's caught too). See conversation/plan for the full
        // derivation.
        //
        // Each candidate MUST get its own independent sacrifice, never one shared across
        // the batch: with a shared (f,g), revealing rho_i = t_pub*a_i - f for every i
        // lets anyone compute rho_i - rho_j = t_pub*(a_i - a_j), collapsing every
        // candidate's `a` (and `b`) in the batch to a single residual unknown (the
        // shared f). If that unknown is ever pinned down by any unrelated leak of one
        // triple, every other triple in the batch becomes recoverable too — breaking the
        // independence Beaver triples require. An independent sacrifice per candidate
        // keeps each one's mask information-theoretically separate from every other's.
        let candidates = &triples[0..batch];
        let sacrifices = &triples[batch..full_batch];

        let t_pub = Self::fiat_shamir_challenge(&triples);

        let mut rho_shares = Vec::with_capacity(batch);
        let mut sigma_shares = Vec::with_capacity(batch);
        for (triple, sacrifice) in candidates.iter().zip(sacrifices.iter()) {
            let (rho, sigma) = Self::compute_rho_sigma(triple, sacrifice, t_pub)?;
            rho_shares.push(rho);
            sigma_shares.push(sigma);
        }
        let expected_rho_commitments: Vec<Vec<C>> =
            rho_shares.iter().map(|s| s.commitments.clone()).collect();
        let expected_sigma_commitments: Vec<Vec<C>> =
            sigma_shares.iter().map(|s| s.commitments.clone()).collect();

        let reconst_message = ReconstructionMessage::new(rho_shares, sigma_shares);
        let mut bytes_rec_message = Vec::new();
        reconst_message.serialize_compressed(&mut bytes_rec_message)?;
        let round0_sid = AvssSessionId::new(
            ProtocolType::TripleCheck,
            AvssSessionId::pack_slot(session_id.exec_id(), self.id as u8, 0),
            session_id.instance_id(),
        );
        let round0_msg = TripleCheckMessage::new(self.id, session_id, bytes_rec_message);
        self.rbc
            .init(
                bincode::serialize(&round0_msg)?,
                round0_sid,
                network.clone(),
            )
            .await?;

        let mut round0_received: HashMap<
            usize,
            (Vec<FeldmanShamirShare<F, C>>, Vec<FeldmanShamirShare<F, C>>),
        > = HashMap::new();
        // Round-1 (check) messages can arrive before we've finished round 0 — buffer
        // them raw and (re-)validate once we know the expected commitments, which
        // depend on our own check shares and are only computable after round 0
        // completes.
        let mut round1_pending: HashMap<usize, Vec<FeldmanShamirShare<F, C>>> = HashMap::new();
        let mut expected_check_commitments: Option<Vec<Vec<C>>> = None;

        let check_pub: Vec<F> = 'check: loop {
            let id = {
                let mut rx = self.rbc_output.lock().await;
                match rx.recv().await {
                    Some(id) => id,
                    None => unreachable!(),
                }
            };
            if id.exec_id() != session_id.exec_id() || id.instance_id() != session_id.instance_id()
            {
                continue 'check;
            }
            let sender = id.sub_id() as usize;
            if sender >= self.n_parties {
                continue 'check;
            }
            let round = id.round_id();
            let output = self.rbc.get_store(id).await?;
            let msg: TripleCheckMessage = match bincode::deserialize(&output) {
                Ok(m) => m,
                Err(_) => continue 'check,
            };
            if msg.sender != sender {
                warn!("dropping triple-check message with mismatched sender claim from {sender}");
                continue 'check;
            }

            match round {
                0 => {
                    if round0_received.contains_key(&sender) {
                        continue 'check;
                    }
                    let rec: ReconstructionMessage<F, C> =
                        match CanonicalDeserialize::deserialize_compressed(msg.payload.as_slice()) {
                            Ok(r) => r,
                            Err(_) => continue 'check,
                        };
                    if rec.a_sub_x.len() != batch || rec.b_sub_y.len() != batch {
                        continue 'check;
                    }
                    let valid = (0..batch).all(|j| {
                        verify_share_against_commitments(
                            &rec.a_sub_x[j],
                            &expected_rho_commitments[j],
                            sender + 1,
                        ) && verify_share_against_commitments(
                            &rec.b_sub_y[j],
                            &expected_sigma_commitments[j],
                            sender + 1,
                        )
                    });
                    if !valid {
                        warn!("dropping invalid rho/sigma shares from party {sender}");
                        continue 'check;
                    }
                    round0_received.insert(sender, (rec.a_sub_x, rec.b_sub_y));

                    if expected_check_commitments.is_none() && round0_received.len() >= t + 1 {
                        let mut rho_pub = Vec::with_capacity(batch);
                        let mut sigma_pub = Vec::with_capacity(batch);
                        for j in 0..batch {
                            let rho_j: Vec<_> = round0_received
                                .values()
                                .map(|(r, _)| r[j].clone())
                                .collect();
                            let sigma_j: Vec<_> = round0_received
                                .values()
                                .map(|(_, s)| s[j].clone())
                                .collect();
                            let (_, rho_val) =
                                FeldmanShamirShare::recover_secret(&rho_j, self.n_parties, t)?;
                            let (_, sigma_val) =
                                FeldmanShamirShare::recover_secret(&sigma_j, self.n_parties, t)?;
                            rho_pub.push(rho_val);
                            sigma_pub.push(sigma_val);
                        }

                        let mut check_shares = Vec::with_capacity(batch);
                        for j in 0..batch {
                            check_shares.push(Self::compute_check(
                                &candidates[j],
                                &sacrifices[j],
                                t_pub,
                                rho_pub[j],
                                sigma_pub[j],
                            )?);
                        }
                        let expected_check: Vec<Vec<C>> =
                            check_shares.iter().map(|s| s.commitments.clone()).collect();

                        let mut bytes_check = Vec::new();
                        check_shares.serialize_compressed(&mut bytes_check)?;
                        let round1_sid = AvssSessionId::new(
                            ProtocolType::TripleCheck,
                            AvssSessionId::pack_slot(session_id.exec_id(), self.id as u8, 1),
                            session_id.instance_id(),
                        );
                        let round1_msg = TripleCheckMessage::new(self.id, session_id, bytes_check);
                        self.rbc
                            .init(
                                bincode::serialize(&round1_msg)?,
                                round1_sid,
                                network.clone(),
                            )
                            .await?;

                        expected_check_commitments = Some(expected_check);
                    }
                }
                1 => {
                    if round1_pending.contains_key(&sender) {
                        continue 'check;
                    }
                    let shares: Vec<FeldmanShamirShare<F, C>> =
                        match CanonicalDeserialize::deserialize_compressed(msg.payload.as_slice()) {
                            Ok(s) => s,
                            Err(_) => continue 'check,
                        };
                    if shares.len() != batch {
                        continue 'check;
                    }
                    round1_pending.insert(sender, shares);
                }
                _ => continue 'check,
            }

            if let Some(expected_check) = &expected_check_commitments {
                let verified: Vec<Vec<FeldmanShamirShare<F, C>>> = round1_pending
                    .iter()
                    .filter(|(sender, shares)| {
                        shares.len() == batch
                            && (0..batch).all(|j| {
                                verify_share_against_commitments(
                                    &shares[j],
                                    &expected_check[j],
                                    **sender + 1,
                                )
                            })
                    })
                    .map(|(_, shares)| shares.clone())
                    .collect();
                if verified.len() >= t + 1 {
                    let mut check_pub = Vec::with_capacity(batch);
                    for j in 0..batch {
                        let j_shares: Vec<_> = verified.iter().map(|v| v[j].clone()).collect();
                        let (_, val) =
                            FeldmanShamirShare::recover_secret(&j_shares, self.n_parties, t)?;
                        check_pub.push(val);
                    }
                    break 'check check_pub;
                }
            }
        };

        if check_pub.iter().any(|v| *v != F::zero()) {
            warn!(
                ?session_id,
                "sacrifice check failed, rejecting triple batch"
            );
            return Err(TripleGenError::CheckFailed(session_id));
        }

        Ok(candidates.to_vec())
    }

    fn lagrange_at_zero(x_i: F, xs: &[F]) -> F {
        // λ_i = Π_{j≠i} (-x_j)/(x_i-x_j)
        let mut num = F::one();
        let mut den = F::one();
        for &x_j in xs {
            if x_j == x_i {
                continue;
            }
            num *= -x_j;
            den *= x_i - x_j;
        }
        num * den.inverse().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::rbc::rbc::Avid;
    use ark_bls12_381::{Fr, G1Projective as G};
    use ark_std::test_rng;
    use ark_std::UniformRand;

    type Node = TripleGenNode<Fr, Avid<AvssSessionId>, G>;

    /// Builds, for every party 1..=n, a candidate BeaverTriple (secret `a_val*b_val +
    /// c_delta`) and a sacrifice BeaverTriple (secret `f_val*g_val + h_delta`), all at
    /// degree t. `c_delta`/`h_delta` are zero for an honest dealing; nonzero simulates
    /// exactly the forged AVSS-reshared value an unverified dealer could submit. Takes
    /// an external `rng` (rather than a fresh `test_rng()` each call) so callers needing
    /// multiple *independent* candidate/sacrifice pairs — e.g. to test cross-triple
    /// isolation — get genuinely different secrets instead of `test_rng()`'s fixed seed
    /// replaying the same sequence.
    fn build_triples(
        n: usize,
        t: usize,
        c_delta: Fr,
        h_delta: Fr,
        rng: &mut impl ark_std::rand::Rng,
    ) -> (Vec<BeaverTriple<Fr, G>>, Vec<BeaverTriple<Fr, G>>) {
        let ids: Vec<usize> = (1..=n).collect();

        let a_val = Fr::rand(rng);
        let b_val = Fr::rand(rng);
        let c_val = a_val * b_val + c_delta;
        let f_val = Fr::rand(rng);
        let g_val = Fr::rand(rng);
        let h_val = f_val * g_val + h_delta;

        let shares = FeldmanShamirShare::<Fr, G>::compute_shares_batch(
            &[a_val, b_val, c_val, f_val, g_val, h_val],
            n,
            t,
            Some(&ids),
            rng,
        )
        .unwrap();
        let [a_shares, b_shares, c_shares, f_shares, g_shares, h_shares]: [Vec<_>; 6] =
            shares.try_into().unwrap();

        let candidates: Vec<_> = (0..n)
            .map(|p| BeaverTriple {
                a: a_shares[p].clone(),
                b: b_shares[p].clone(),
                c: c_shares[p].clone(),
            })
            .collect();
        let sacrifices: Vec<_> = (0..n)
            .map(|p| BeaverTriple {
                a: f_shares[p].clone(),
                b: g_shares[p].clone(),
                c: h_shares[p].clone(),
            })
            .collect();
        (candidates, sacrifices)
    }

    /// Runs the sacrifice check across all `n` parties' shares (using the first `t+1`
    /// contributions to reconstruct, matching the real protocol's threshold) and
    /// returns the reconstructed check value.
    fn run_check(
        n: usize,
        t: usize,
        candidates: &[BeaverTriple<Fr, G>],
        sacrifices: &[BeaverTriple<Fr, G>],
    ) -> Fr {
        let full_batch = vec![candidates[0].clone(), sacrifices[0].clone()];
        let t_pub = Node::fiat_shamir_challenge(&full_batch);

        let rho_sigma: Vec<_> = (0..n)
            .map(|p| Node::compute_rho_sigma(&candidates[p], &sacrifices[p], t_pub).unwrap())
            .collect();
        let rho_shares: Vec<_> = rho_sigma[0..=t].iter().map(|(r, _)| r.clone()).collect();
        let sigma_shares: Vec<_> = rho_sigma[0..=t].iter().map(|(_, s)| s.clone()).collect();
        let (_, rho_pub) = FeldmanShamirShare::recover_secret(&rho_shares, n, t).unwrap();
        let (_, sigma_pub) = FeldmanShamirShare::recover_secret(&sigma_shares, n, t).unwrap();

        let check_shares: Vec<_> = (0..=t)
            .map(|p| {
                Node::compute_check(&candidates[p], &sacrifices[p], t_pub, rho_pub, sigma_pub)
                    .unwrap()
            })
            .collect();
        let (_, check_pub) = FeldmanShamirShare::recover_secret(&check_shares, n, t).unwrap();
        check_pub
    }

    #[test]
    fn honest_triple_and_sacrifice_pass() {
        let (n, t) = (4, 1);
        let mut rng = test_rng();
        let (candidates, sacrifices) =
            build_triples(n, t, Fr::from(0u64), Fr::from(0u64), &mut rng);
        assert_eq!(run_check(n, t, &candidates, &sacrifices), Fr::from(0u64));
    }

    #[test]
    fn tampered_candidate_c_is_caught() {
        // Exactly the attack this fix closes: a dealer reshares c = a*b + delta instead
        // of the true product.
        let (n, t) = (4, 1);
        let mut rng = test_rng();
        let (candidates, sacrifices) =
            build_triples(n, t, Fr::from(7u64), Fr::from(0u64), &mut rng);
        assert_ne!(run_check(n, t, &candidates, &sacrifices), Fr::from(0u64));
    }

    #[test]
    fn tampered_sacrifice_h_is_caught() {
        // A cheating dealer targeting the sacrifice triple instead of a real one is
        // caught too — every check comes out as the same nonzero constant.
        let (n, t) = (4, 1);
        let mut rng = test_rng();
        let (candidates, sacrifices) =
            build_triples(n, t, Fr::from(0u64), Fr::from(3u64), &mut rng);
        assert_ne!(run_check(n, t, &candidates, &sacrifices), Fr::from(0u64));
    }

    /// Regression test for the exact vulnerability caught in review: an earlier version
    /// of `gen_triple` checked *every* candidate in a batch against one shared sacrifice
    /// triple. This proves, mathematically, why that's unsafe — and that the current
    /// per-candidate-sacrifice design (see `gen_triple`'s Step 4) doesn't have the same
    /// hole.
    ///
    /// With a shared sacrifice `(f,g,h)`, opening `rho_i = a_i*t_pub - f` for two
    /// different candidates i,k lets anyone compute
    /// `rho_i - rho_k = t_pub*(a_i - a_k)` — a public, exact leak of the difference
    /// between two supposedly-independent Beaver triples' `a` operands, since `t_pub`
    /// is public. This test builds two genuinely independent (candidate, sacrifice)
    /// pairs and shows both directions: reusing pair 1's sacrifice to check candidate 2
    /// (the bug) reproduces that exact leak; using each candidate's own dedicated
    /// sacrifice (the fix) does not.
    #[test]
    fn shared_sacrifice_would_leak_operand_difference_independent_does_not() {
        let (n, t) = (4, 1);
        let mut rng = test_rng();
        // Two fully independent candidate/sacrifice pairs, drawn from a continuing rng
        // so they don't collide (see `build_triples`'s doc comment).
        let (candidates_1, sacrifices_1) =
            build_triples(n, t, Fr::from(0u64), Fr::from(0u64), &mut rng);
        let (candidates_2, sacrifices_2) =
            build_triples(n, t, Fr::from(0u64), Fr::from(0u64), &mut rng);

        let full_batch = vec![candidates_1[0].clone(), sacrifices_1[0].clone()];
        let t_pub = Node::fiat_shamir_challenge(&full_batch);

        // Ground truth: reconstruct each candidate's real `a` value directly from its
        // shares (the test harness holds every party's share, unlike a real network
        // observer — this is just to state what's being leaked, not part of the attack).
        let a1_shares: Vec<_> = (0..=t).map(|p| candidates_1[p].a.clone()).collect();
        let a2_shares: Vec<_> = (0..=t).map(|p| candidates_2[p].a.clone()).collect();
        let (_, a1_val) = FeldmanShamirShare::recover_secret(&a1_shares, n, t).unwrap();
        let (_, a2_val) = FeldmanShamirShare::recover_secret(&a2_shares, n, t).unwrap();

        let reconstruct_rho =
            |candidates: &[BeaverTriple<Fr, G>], sacrifices: &[BeaverTriple<Fr, G>]| -> Fr {
                let rho_shares: Vec<_> = (0..=t)
                    .map(|p| {
                        Node::compute_rho_sigma(&candidates[p], &sacrifices[p], t_pub)
                            .unwrap()
                            .0
                    })
                    .collect();
                FeldmanShamirShare::recover_secret(&rho_shares, n, t)
                    .unwrap()
                    .1
            };

        let rho_1 = reconstruct_rho(&candidates_1, &sacrifices_1);
        // The bug: candidate 2 checked against candidate 1's sacrifice instead of its own.
        let rho_2_shared_sacrifice = reconstruct_rho(&candidates_2, &sacrifices_1);
        // The fix: candidate 2 checked against its own dedicated sacrifice.
        let rho_2_independent = reconstruct_rho(&candidates_2, &sacrifices_2);

        let leaked_difference = t_pub * (a1_val - a2_val);

        assert_eq!(
            rho_1 - rho_2_shared_sacrifice,
            leaked_difference,
            "reusing one sacrifice across candidates must leak t_pub*(a1-a2) — if this \
             assertion ever fails, the vulnerability's mechanism itself has changed and \
             this test needs re-deriving, not deleting"
        );
        assert_ne!(
            rho_1 - rho_2_independent,
            leaked_difference,
            "independent per-candidate sacrifices must NOT reproduce the shared-sacrifice \
             leak — this failing means gen_triple has regressed to sharing a sacrifice \
             across multiple candidates"
        );
    }
}
