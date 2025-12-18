use crate::{
    common::{
        share::{
            apply_vandermonde,
            avss::{AvssNode, Feldman, FeldmanShamirShare},
            make_vandermonde,
        },
        RandomSharingProtocol, ShamirShare, RBC,
    },
    honeybadger::{
        robust_interpolate::robust_interpolate::RobustShare,
        share_gen::{RanShaError, RanShaMessage, RanShaState},
        SessionId,
    },
};
use ark_ec::CurveGroup;
use ark_ff::FftField;
use ark_std::rand::Rng;
use async_trait::async_trait;
use std::{collections::HashMap, marker::PhantomData, sync::Arc};
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::{
    mpsc::{self, Receiver, Sender},
    Mutex,
};
use tracing::info;

#[derive(Clone, Debug)]
pub struct RanShaAvssNode<F: FftField, R: RBC, C: CurveGroup> {
    pub id: usize,
    pub n_parties: usize,
    pub threshold: usize,
    pub store: Arc<Mutex<HashMap<SessionId, Arc<Mutex<RanShaAvssStore<F>>>>>>,
    pub avss: AvssNode<F, R>,
    pub rbc: R,
    pub output_sender: Sender<SessionId>,
    pub avss_output: Arc<Mutex<Receiver<SessionId>>>,
    pub _group: std::marker::PhantomData<C>,
}

#[derive(Clone, Debug)]
pub struct RanShaAvssStore<F: FftField> {
    pub initial_shares: HashMap<usize, FeldmanShamirShare<F>>,
    pub reception_tracker: Vec<bool>,
    pub computed_r_shares: Vec<FeldmanShamirShare<F>>,
    pub state: RanShaState,
    pub protocol_output: Vec<FeldmanShamirShare<F>>,
}

impl<F: FftField> RanShaAvssStore<F> {
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
#[async_trait]
impl<F, R, C> RandomSharingProtocol<F, RobustShare<F>> for RanShaAvssNode<F, R, C>
where
    F: FftField,
    R: RBC,
    C: CurveGroup<ScalarField = F> + Send + Sync,
{
    type Error = RanShaError;
    type Group = C;

    async fn init<N, G>(
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
        self.avss
            .init::<C, _, _>(avss_sessionid, rng, network)
            .await?;

        let mut rx = self.avss_output.lock().await;
        if let Some(id) = rx.recv().await {
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
                    let mut shares_deg_t: Vec<(usize, ShamirShare<F, 1, Feldman>)> = ransha_storage
                        .initial_shares
                        .iter()
                        .map(|(sid, s)| (*sid, s.clone()))
                        .collect();
                    drop(ransha_storage);
                    // sort by sender_id
                    shares_deg_t.sort_by_key(|(sid, _)| *sid);

                    // drop the ids, keep only shares
                    let shares_deg_t: Vec<ShamirShare<F, 1, Feldman>> =
                        shares_deg_t.into_iter().map(|(_, s)| s).collect();
                    self.init_ransha(shares_deg_t, session_id, network.clone()).await?
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

    async fn process<N>(&mut self, msg: RanShaMessage, network: Arc<N>) -> Result<(), RanShaError>
    where
        N: Network + Send + Sync,
    {
        todo!()
    }
    async fn output(&mut self, session_id: SessionId) -> Vec<FeldmanShamirShare<F>> {
        let mut share_store = self.store.lock().await;
        let store_lock = share_store.remove(&session_id).unwrap();
        let store = store_lock.lock().await;
        store.protocol_output.clone()
    }
}
impl<F, R, C> RanShaAvssNode<F, R, C>
where
    F: FftField,
    R: RBC,
    C: CurveGroup + Send,
{
    pub fn new(
        id: PartyId,
        n_parties: usize,
        threshold: usize,
        k: usize,
        output_sender: Sender<SessionId>,
    ) -> Result<Self, RanShaError> {
        let rbc = R::new(id, n_parties, threshold, k)?;
        let (avss_sender, avss_receiver) = mpsc::channel(128);
        let avss = AvssNode::new(id, n_parties, threshold, avss_sender)?;
        Ok(Self {
            id,
            n_parties,
            threshold,
            store: Arc::new(Mutex::new(HashMap::new())),
            rbc,
            avss,
            output_sender,
            avss_output: Arc::new(Mutex::new(avss_receiver)),
            _group: PhantomData,
        })
    }

    pub async fn get_or_create_store(
        &mut self,
        session_id: SessionId,
    ) -> Arc<Mutex<RanShaAvssStore<F>>> {
        let mut storage = self.store.lock().await;
        storage
            .entry(session_id)
            .or_insert(Arc::new(Mutex::new(RanShaAvssStore::empty(self.n_parties))))
            .clone()
    }

    pub async fn init_ransha<N>(
        &mut self,
        shares_deg_t: Vec<FeldmanShamirShare<F>>,
        session_id: SessionId,
        network: Arc<N>,
    ) -> Result<(), RanShaError>
    where
        N: Network,
    {
        info!(
            "party {:?} received shares for Random sharing generation",
            self.id
        );
        let vandermonde_matrix = make_vandermonde(self.n_parties, self.n_parties - 1)?;
        let r_deg_t = apply_vandermonde(&vandermonde_matrix, &shares_deg_t)?;

        let bind_store = self.get_or_create_store(session_id).await;
        let mut store = bind_store.lock().await;
        store.computed_r_shares = r_deg_t.clone();
        drop(store);

        for i in 0..2 * self.threshold {
            let share_deg_t = r_deg_t[i].clone();

            //Verfify the shares and update the commitments 
            let output = store.computed_r_shares[2 * self.threshold..].to_vec();
            store.state = RanShaState::Finished;
            store.protocol_output = output;
            self.output_sender.send(session_id).await?;
        }
        Ok(())
    }
}
