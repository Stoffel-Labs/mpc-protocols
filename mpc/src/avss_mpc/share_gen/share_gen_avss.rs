use crate::{
    avss_mpc::share_gen::{RanShaAvssError, RanShaAvssStore},
    common::{
        share::{apply_vandermonde, avss::AvssNode, feldman::FeldmanShamirShare, make_vandermonde},
        ShamirShare, RBC,
    },
    honeybadger::SessionId,
};
use ark_ec::CurveGroup;
use ark_ff::FftField;
use ark_std::rand::Rng;
use std::{collections::HashMap, sync::Arc};
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::{
    mpsc::{self, Receiver, Sender},
    Mutex,
};
use tracing::info;

#[derive(Clone, Debug)]
pub struct RanShaAvssNode<F: FftField, R: RBC, G: CurveGroup<ScalarField = F>> {
    pub id: usize,
    pub n_parties: usize,
    pub threshold: usize,
    pub store: Arc<Mutex<HashMap<SessionId, Arc<Mutex<RanShaAvssStore<F, G>>>>>>,
    pub avss: AvssNode<F, R, G>,
    pub rbc: R,
    pub output_sender: Sender<SessionId>,
    pub avss_output: Arc<Mutex<Receiver<SessionId>>>,
}

impl<F, R, C> RanShaAvssNode<F, R, C>
where
    F: FftField,
    R: RBC,
    C: CurveGroup<ScalarField = F> + Send + Sync,
{
    pub fn new(
        id: PartyId,
        n_parties: usize,
        threshold: usize,
        k: usize,
        sk_i: F,
        pk_map: Arc<Vec<C>>,
        output_sender: Sender<SessionId>,
    ) -> Result<Self, RanShaAvssError> {
        let rbc = R::new(id, n_parties, threshold, k)?;
        let (avss_sender, avss_receiver) = mpsc::channel(128);
        let avss = AvssNode::new(id, n_parties, threshold, sk_i, pk_map, avss_sender)?;
        Ok(Self {
            id,
            n_parties,
            threshold,
            store: Arc::new(Mutex::new(HashMap::new())),
            rbc,
            avss,
            output_sender,
            avss_output: Arc::new(Mutex::new(avss_receiver)),
        })
    }

    pub async fn get_or_create_store(
        &mut self,
        session_id: SessionId,
    ) -> Arc<Mutex<RanShaAvssStore<F, C>>> {
        let mut storage = self.store.lock().await;
        storage
            .entry(session_id)
            .or_insert(Arc::new(Mutex::new(RanShaAvssStore::empty(self.n_parties))))
            .clone()
    }

    pub async fn output(&mut self, session_id: SessionId) -> Vec<FeldmanShamirShare<F, C>> {
        let mut share_store = self.store.lock().await;
        let store_lock = share_store.remove(&session_id).unwrap();
        let store = store_lock.lock().await;
        store.protocol_output.clone()
    }

    pub async fn init<N, G>(
        &mut self,
        session_id: SessionId,
        rng: &mut G,
        network: Arc<N>,
    ) -> Result<(), RanShaAvssError>
    where
        N: Network + Send + Sync,
        G: Rng + Send,
    {
        info!("Receiving init for share from {0:?}", self.id);
        let secret = F::rand(rng);

        let avss_sessionid = SessionId::new(
            session_id.calling_protocol().unwrap(),
            session_id.exec_id(),
            self.id as u8,
            session_id.round_id(),
            session_id.instance_id(),
        );
        self.avss
            .init(vec![secret], avss_sessionid, rng, network.clone())
            .await?;

        while let Some(id) = {
            let mut rx = self.avss_output.lock().await;
            rx.recv().await
        } {
            if id.calling_protocol().unwrap() == session_id.calling_protocol().unwrap()
                && id.exec_id() == session_id.exec_id()
                && id.round_id() == session_id.round_id()
                && id.instance_id() == session_id.instance_id()
            {
                let mut store = self.avss.shares.lock().await;
                let avss_share = store.remove(&id).unwrap().unwrap();
                drop(store);
                let binding = self.get_or_create_store(session_id).await;
                let mut ransha_storage = binding.lock().await;
                let sender_id = id.sub_id();
                ransha_storage
                    .initial_shares
                    .insert(sender_id.into(), avss_share[0].clone());

                ransha_storage.reception_tracker[sender_id as usize] = true;
                // Check if the protocol has reached an end
                if ransha_storage
                    .reception_tracker
                    .iter()
                    .all(|&received| received)
                {
                    let mut shares_deg_t: Vec<(usize, FeldmanShamirShare<F, C>)> = ransha_storage
                        .initial_shares
                        .iter()
                        .map(|(sid, s)| (*sid, s.clone()))
                        .collect();
                    drop(ransha_storage);
                    // sort by sender_id
                    shares_deg_t.sort_by_key(|(sid, _)| *sid);

                    // drop the ids, keep only shares
                    let shares_deg_t: Vec<FeldmanShamirShare<F, C>> =
                        shares_deg_t.into_iter().map(|(_, s)| s).collect();
                    self.ransha_gen(shares_deg_t, session_id).await?;
                    break;
                }
            }
        }
        Ok(())
    }

    pub async fn ransha_gen(
        &mut self,
        shares_deg_t: Vec<FeldmanShamirShare<F, C>>,
        session_id: SessionId,
    ) -> Result<(), RanShaAvssError> {
        info!(
            "party {:?} received shares for Random sharing generation",
            self.id
        );

        let n = self.n_parties;
        let t = self.threshold;

        let shares: Vec<ShamirShare<_, 1, _>> = shares_deg_t
            .iter()
            .map(|s| s.feldmanshare.clone())
            .collect();
        let vandermonde_matrix = make_vandermonde(n, n - 1)?;
        let r_deg_t = apply_vandermonde(&vandermonde_matrix, &shares)?;

        let mut r_commitments: Vec<Vec<C>> = Vec::with_capacity(n);
        for k in 0..n {
            // commitments for output share k
            let mut ck = vec![C::zero(); t + 1];

            for i in 0..n {
                let a_ki = vandermonde_matrix[k][i]; // field element
                let ci = &shares_deg_t[i].commitments;

                for j in 0..=t {
                    ck[j] += ci[j].mul(a_ki);
                }
            }

            r_commitments.push(ck);
        }

        // Store results
        let bind_store = self.get_or_create_store(session_id).await;
        let mut store = bind_store.lock().await;

        store.computed_r_shares = (0..n)
            .map(|k| FeldmanShamirShare {
                feldmanshare: r_deg_t[k].clone(),
                commitments: r_commitments[k].clone(),
            })
            .collect();

        let output = store.computed_r_shares[2 * t..].to_vec();
        store.protocol_output = output;
        self.output_sender.send(session_id).await?;

        Ok(())
    }
}
