use crate::{
    adkg::triple_gen::{BeaverTriple, TripleGenError, TripleGenStore},
    common::{
        share::{avss::AvssNode, feldman::FeldmanShamirShare},
        RBC,
    },
    honeybadger::SessionId,
};
use ark_ec::CurveGroup;
use ark_ff::FftField;
use ark_std::rand::Rng;
use itertools::Itertools;
use std::{collections::HashMap, sync::Arc};
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::{mpsc, Mutex};
use tracing::info;

#[derive(Clone, Debug)]
pub struct TripleGenNode<F: FftField, R: RBC, C: CurveGroup<ScalarField = F>> {
    pub id: usize,
    pub n_parties: usize,
    pub threshold: usize,
    pub avss: AvssNode<F, R, C>,
    pub avss_output: Arc<Mutex<mpsc::Receiver<SessionId>>>,
    pub store: Arc<Mutex<HashMap<SessionId, Arc<Mutex<TripleGenStore<F, C>>>>>>,
}

impl<F, R, C> TripleGenNode<F, R, C>
where
    F: FftField,
    R: RBC,
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
        let avss = AvssNode::new(id, n_parties, threshold, sk_i, pk_map, tx)?;

        Ok(Self {
            id,
            n_parties,
            threshold,
            avss,
            avss_output: Arc::new(Mutex::new(rx)),
            store: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    async fn get_or_create_store(&mut self, sid: SessionId) -> Arc<Mutex<TripleGenStore<F, C>>> {
        let mut map = self.store.lock().await;
        map.entry(sid)
            .or_insert(Arc::new(Mutex::new(TripleGenStore::empty(
                2 * self.threshold + 1,
            ))))
            .clone()
    }

    pub async fn gen_triple<N, G>(
        &mut self,
        session_id: SessionId,
        a: FeldmanShamirShare<F, C>,
        b: FeldmanShamirShare<F, C>,
        rng: &mut G,
        network: Arc<N>,
    ) -> Result<BeaverTriple<F, C>, TripleGenError>
    where
        N: Network + Send + Sync,
        G: Rng + Send,
    {
        info!("party {} starting triple gen", self.id);

        let t = self.threshold;
        let m = 2 * t + 1;

        // Local multiplication (degree 2t implicitly)
        let c_i_prime = a.feldmanshare.share[0] * b.feldmanshare.share[0];

        let is_dealer = self.id < m;
        if is_dealer {
            let avss_sid = SessionId::new(
                session_id.calling_protocol().unwrap(),
                session_id.exec_id(),
                self.id as u8,
                session_id.round_id(),
                session_id.instance_id(),
            );
            self.avss
                .init(c_i_prime, avss_sid, rng, network.clone())
                .await?;
        }

        // Create store once
        let store_ref = self.get_or_create_store(session_id).await;
        let xs: Vec<F> = (0..m).map(|i| F::from(i as u64)).collect();

        while let Some(done) = {
            let mut rx = self.avss_output.lock().await;
            rx.recv().await
        } {
            let same = done.calling_protocol().unwrap() == session_id.calling_protocol().unwrap()
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
            let piece = avss_map
                .remove(&done)
                .and_then(|x| x)
                .ok_or(TripleGenError::MissingDealer(dealer))?;
            drop(avss_map);

            let mut st = store_ref.lock().await;
            st.received.insert(dealer, piece);
            st.reception_tracker[dealer] = true;

            if st.reception_tracker.iter().all(|&x| x) {
                // Compute c_share = Σ λ_i * e_i(α_self)
                let mut c_val = F::zero();
                let mut c_comms = vec![C::zero(); t + 1];

                for (&dealer, &x_i) in (0..2 * t + 1).collect_vec().iter().zip(xs.iter()) {
                    let p = st
                        .received
                        .get(&dealer)
                        .ok_or(TripleGenError::MissingDealer(dealer))?;
                    let lambda = Self::lagrange_at_zero(x_i, &xs);

                    c_val += lambda * p.feldmanshare.share[0];

                    if p.commitments.len() != t + 1 {
                        return Err(TripleGenError::CommitmentLengthMismatch);
                    }
                    for k in 0..=t {
                        c_comms[k] += p.commitments[k].mul(lambda);
                    }
                }
                let c = FeldmanShamirShare::new(c_val, self.id, t, c_comms)?;
                let triple = BeaverTriple {
                    a: a.clone(),
                    b: b.clone(),
                    c,
                };
                st.output = Some(triple.clone());
                return Ok(triple);
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
