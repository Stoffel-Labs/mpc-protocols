use crate::{
    common::{
        share::{
            apply_vandermonde,
            avss::{AvssNode, FeldmanShamirShare},
            make_vandermonde,
        },
        ShamirShare, RBC,
    },
    honeybadger::{
        share_gen::{RanShaError, RanShaState},
        SessionId,
    },
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

#[derive(Clone, Debug)]
pub struct RanShaAvssStore<F: FftField, G: CurveGroup<ScalarField = F>> {
    pub initial_shares: HashMap<usize, FeldmanShamirShare<F, G>>,
    pub reception_tracker: Vec<bool>,
    pub computed_r_shares: Vec<FeldmanShamirShare<F, G>>,
    pub state: RanShaState,
    pub protocol_output: Vec<FeldmanShamirShare<F, G>>,
}

impl<F: FftField, G: CurveGroup<ScalarField = F>> RanShaAvssStore<F, G> {
    pub fn empty(n_parties: usize) -> Self {
        Self {
            initial_shares: HashMap::new(),
            reception_tracker: vec![false; n_parties],
            computed_r_shares: Vec::new(),
            state: RanShaState::Initialized,
            protocol_output: Vec::new(),
        }
    }
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
    ) -> Result<Self, RanShaError> {
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

    pub async fn init<N, G>(
        &mut self,
        session_id: SessionId,
        rng: &mut G,
        network: Arc<N>,
    ) -> Result<(), RanShaError>
    where
        N: Network + Send + Sync,
        G: Rng + Send,
    {
        info!("Receiving init for share from {0:?}", self.id);

        let avss_sessionid = SessionId::new(
            session_id.calling_protocol().unwrap(),
            0,
            self.id as u8,
            0,
            session_id.instance_id(),
        );
        let secret = F::rand(rng);
        self.avss
            .init(secret, avss_sessionid, rng, network.clone())
            .await?;

        let maybe_id = {
            let mut rx = self.avss_output.lock().await;
            rx.recv().await
        };
        if let Some(id) = maybe_id {
            if id.calling_protocol().unwrap() == session_id.calling_protocol().unwrap()
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
                    .insert(sender_id.into(), avss_share);

                ransha_storage.reception_tracker[sender_id as usize] = true;

                // Check if the protocol has reached an end
                if ransha_storage
                    .reception_tracker
                    .iter()
                    .all(|&received| received)
                {
                    ransha_storage.state = RanShaState::FinishedInitialSharing;
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
                    self.ransha_gen(shares_deg_t, session_id).await?
                }
            }
        }
        {
            let storage_access = self.get_or_create_store(session_id).await;
            let mut storage = storage_access.lock().await;
            storage.state = RanShaState::Initialized;
        }
        Ok(())
    }

    pub async fn ransha_gen(
        &mut self,
        shares_deg_t: Vec<FeldmanShamirShare<F, C>>,
        session_id: SessionId,
    ) -> Result<(), RanShaError> {
        info!(
            "party {:?} received shares for Random sharing generation",
            self.id
        );
        let c = shares_deg_t[0].commitments.clone();
        let shares: Vec<ShamirShare<_, 1, _>> = shares_deg_t
            .iter()
            .map(|s| s.feldmanshare.clone())
            .collect();
        let vandermonde_matrix = make_vandermonde(self.n_parties, self.n_parties - 1)?;
        let r_deg_t = apply_vandermonde(&vandermonde_matrix, &shares)?;

        let bind_store = self.get_or_create_store(session_id).await;
        let mut store = bind_store.lock().await;

        store.computed_r_shares = r_deg_t
            .iter()
            .map(|s| FeldmanShamirShare {
                feldmanshare: s.clone(),
                commitments: c.clone(),
            })
            .collect();

        let output = store.computed_r_shares[2 * self.threshold..].to_vec();
        store.state = RanShaState::Finished;
        store.protocol_output = output;
        self.output_sender.send(session_id).await?;

        Ok(())
    }
}
