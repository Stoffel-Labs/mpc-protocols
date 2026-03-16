use crate::{
    avss_mpc::{
        triple_gen::{BeaverTriple, TripleGenError, TripleGenStore},
        AvssSessionId, AvssWrappedMessage,
    },
    common::{
        share::{avss::AvssNode, feldman::FeldmanShamirShare},
        ProtocolSessionId, RBC,
    },
};
use ark_ec::CurveGroup;
use ark_ff::FftField;
use ark_std::rand::Rng;
use std::{collections::HashMap, sync::Arc};
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::{
    mpsc::{self},
    Mutex,
};
use tracing::info;

#[derive(Clone, Debug)]
pub struct TripleGenNode<F: FftField, R: RBC, C: CurveGroup<ScalarField = F>> {
    pub id: usize,
    pub n_parties: usize,
    pub threshold: usize,
    pub avss: AvssNode<F, R, C, AvssSessionId>,
    pub avss_output: Arc<Mutex<mpsc::Receiver<AvssSessionId>>>,
    pub store: Arc<Mutex<HashMap<AvssSessionId, Arc<Mutex<TripleGenStore<F, C>>>>>>,
}

impl<F, R, C> TripleGenNode<F, R, C>
where
    F: FftField,
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
        let (tx, rx) = mpsc::channel(256);
        let avss = AvssNode::new(
            id,
            n_parties,
            threshold,
            sk_i,
            pk_map,
            tx,
            Arc::new(AvssWrappedMessage::rbc_wrap),
            Arc::new(AvssWrappedMessage::avss_wrap),
        )?;

        Ok(Self {
            id,
            n_parties,
            threshold,
            avss,
            avss_output: Arc::new(Mutex::new(rx)),
            store: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    async fn get_or_create_store(
        &mut self,
        sid: AvssSessionId,
    ) -> Arc<Mutex<TripleGenStore<F, C>>> {
        let mut map = self.store.lock().await;
        map.entry(sid)
            .or_insert(Arc::new(Mutex::new(TripleGenStore::empty(
                2 * self.threshold + 1,
            ))))
            .clone()
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

        let t = self.threshold;
        let m = 2 * t + 1;

        if a.len() != b.len() {
            return Err(TripleGenError::InvalidShareLength);
        }
        let batch = a.len();

        let session_proto = session_id
            .calling_protocol()
            .ok_or(TripleGenError::InvalidSessionId)?;

        // === Step 1: local products (vector) ===
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
                session_proto,
                AvssSessionId::pack_slot24(
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
        let store_ref = self.get_or_create_store(session_id).await;
        let xs: Vec<F> = (0..m).map(|i| F::from((i + 1) as u64)).collect();

        // === Step 3: collect dealer outputs, then lagrange-combine component-wise ===
        while let Some(done) = {
            let mut rx = self.avss_output.lock().await;
            rx.recv().await
        } {
            let same = done.calling_protocol() == Some(session_proto)
                && done.exec_id() == session_id.exec_id()
                && done.round_id() == session_id.round_id()
                && done.instance_id() == session_id.instance_id();

            if !same {
                continue;
            }

            let dealer = done.sub_id() as usize;
            if dealer >= m {
                continue; // ignore non-dealer sub-sessions
            }

            let mut avss_map = self.avss.shares.lock().await;
            let pieces = avss_map
                .remove(&done)
                .and_then(|x| x)
                .ok_or(TripleGenError::MissingDealer(dealer))?;
            drop(avss_map);
            if pieces.len() != batch {
                return Err(TripleGenError::InvalidShareLength);
            }

            let mut st = store_ref.lock().await;
            st.received.insert(dealer, pieces);
            st.reception_tracker[dealer] = true;

            if st.reception_tracker.iter().all(|&x| x) {
                // === Lagrange combine for each batch index j ===
                let mut c_out: Vec<FeldmanShamirShare<F, C>> = Vec::with_capacity(batch);

                for j in 0..batch {
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

                    c_out.push(FeldmanShamirShare::new(c_val_j, self.id, t, c_comms_j)?);
                }
                let triples: Vec<BeaverTriple<F, C>> = c_out
                    .iter()
                    .enumerate()
                    .map(|(i, c)| BeaverTriple {
                        a: a[i].clone(),
                        b: b[i].clone(),
                        c: c.clone(),
                    })
                    .collect();
                st.output = Some(triples.clone());
                return Ok(triples);
            }
        }
        unreachable!()
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
