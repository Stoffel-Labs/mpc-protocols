use crate::common::session_store::{Admission, SessionStore};
use crate::{
    avss_mpc::{
        share_gen::{RanShaAvssError, RanShaAvssStore},
        AvssSessionId, AvssWrappedMessage,
    },
    common::{
        share::{
            apply_vandermonde,
            avss::{AvssError, AvssNode, MAX_PENDING_SESSIONS},
            feldman::FeldmanShamirShare,
            make_vandermonde,
        },
        ProtocolSessionId, ShamirShare, RBC,
    },
};
use ark_ec::CurveGroup;
use ark_ff::FftField;
use ark_std::rand::Rng;
use std::sync::Arc;
use std::time::Instant;
use stoffelnet::network_utils::{Network, PartyId};
use tokio::{
    sync::{
        mpsc::{self, Receiver},
        Mutex,
    },
    time::{timeout, Duration},
};
use tracing::{info, warn};

#[derive(Clone, Debug)]
pub struct RanShaAvssNode<F: FftField, R: RBC, G: CurveGroup<ScalarField = F>> {
    pub id: usize,
    pub n_parties: usize,
    pub threshold: usize,
    pub store: Arc<
        Mutex<SessionStore<AvssSessionId, (usize, Instant, Arc<Mutex<RanShaAvssStore<F, G>>>)>>,
    >,
    pub avss: AvssNode<F, R, G, AvssSessionId>,
    pub avss_output: Arc<Mutex<Receiver<AvssSessionId>>>,
}

const MAX_RANSHA_AVSS_SESSIONS: usize = 256;

impl<F, R, C> RanShaAvssNode<F, R, C>
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
    ) -> Result<Self, RanShaAvssError> {
        // Must be >= MAX_PENDING_SESSIONS: AvssNode::process uses try_send and drops
        // notifications on a full channel rather than blocking, so a smaller capacity here
        // would silently lose notifications well before the session cache itself is full.
        let (avss_sender, avss_receiver) = mpsc::channel(MAX_PENDING_SESSIONS);
        let avss = AvssNode::new(
            id,
            n_parties,
            (1..=n_parties).collect(),
            threshold,
            sk_i,
            pk_map,
            avss_sender,
            Arc::new(AvssWrappedMessage::rbc_wrap),
            Arc::new(AvssWrappedMessage::avss_wrap),
        )?;
        Ok(Self {
            id,
            n_parties,
            threshold,
            store: Arc::new(Mutex::new(SessionStore::with_default_cap())),
            avss,
            avss_output: Arc::new(Mutex::new(avss_receiver)),
        })
    }

    pub async fn get_or_create_store(
        &mut self,
        session_id: AvssSessionId,
        initiator_id: usize,
    ) -> Option<Arc<Mutex<RanShaAvssStore<F, C>>>> {
        match self.store.lock().await.get_or_admit(
            session_id,
            initiator_id,
            MAX_RANSHA_AVSS_SESSIONS,
            MAX_RANSHA_AVSS_SESSIONS / self.n_parties,
            || Arc::new(Mutex::new(RanShaAvssStore::empty(self.n_parties))),
        ) {
            Admission::Got(arc) => Some(arc),
            Admission::Retired => None,
            Admission::Rejected => {
                warn!("RanShaAvss session limit reached");
                None
            }
        }
    }

    /// Retires this session and clears every per-dealer AVSS sub-session it created.
    pub async fn clear_store(&self, session_id: AvssSessionId) -> bool {
        for dealer in 0..self.n_parties {
            let avss_sessionid = AvssSessionId::new(
                session_id.calling_protocol().unwrap(),
                AvssSessionId::pack_slot(session_id.exec_id(), dealer as u8, session_id.round_id()),
                session_id.instance_id(),
            );
            self.avss.clear_session(avss_sessionid).await;
        }

        let mut store = self.store.lock().await;
        store.retire(session_id)
    }

    pub async fn wait_for_result(
        &self,
        session_id: AvssSessionId,
        duration: Duration,
    ) -> Result<Vec<FeldmanShamirShare<F, C>>, RanShaAvssError> {
        let output_receiver = {
            let storage = self.store.lock().await;
            let storage_bind = match storage.get(&session_id) {
                Some((_, _, arc)) => arc,
                None => return Err(RanShaAvssError::NoSuchSessionId(session_id)),
            };
            let mut storage = storage_bind.lock().await;

            storage
                .output_receiver
                .take()
                .ok_or(RanShaAvssError::ResultAlreadyReceived(session_id))?
        };

        match timeout(duration, output_receiver).await {
            Err(_) => Err(RanShaAvssError::Timeout(session_id)),
            Ok(Err(_)) => Err(RanShaAvssError::ReceiveError(session_id)),
            Ok(Ok(shares)) => Ok(shares),
        }
    }

    pub async fn init<N, G>(
        &mut self,
        session_id: AvssSessionId,
        rng: &mut G,
        network: Arc<N>,
    ) -> Result<(), RanShaAvssError>
    where
        N: Network + Send + Sync,
        G: Rng + Send,
    {
        self.init_batch(session_id, 1, rng, network).await
    }

    /// Generates `batch_size * (n - 2t)` random sharings in one AVSS round.
    ///
    /// Each party deals `batch_size` independent secrets in a single vectorized
    /// AVSS message. The Vandermonde transform is then applied independently to
    /// every vector position.
    pub async fn init_batch<N, G>(
        &mut self,
        session_id: AvssSessionId,
        batch_size: usize,
        rng: &mut G,
        network: Arc<N>,
    ) -> Result<(), RanShaAvssError>
    where
        N: Network + Send + Sync,
        G: Rng + Send,
    {
        info!("Receiving init for share from {0:?}", self.id);
        if batch_size == 0 {
            return Err(RanShaAvssError::InvalidBatchSize);
        }
        let secrets = (0..batch_size).map(|_| F::rand(rng)).collect();

        let avss_sessionid = AvssSessionId::new(
            session_id.calling_protocol().unwrap(),
            AvssSessionId::pack_slot(session_id.exec_id(), self.id as u8, session_id.round_id()),
            session_id.instance_id(),
        );
        self.avss
            .init(secrets, avss_sessionid, rng, network.clone())
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
                // The entry can be evicted by `admit`'s idle-session sweep between the
                // notification being queued and this loop draining it (this node fell
                // behind, or another dealer's flood forced capacity pressure). Skip this
                // dealer's contribution rather than panicking the node — the loop is still
                // waiting on the rest.
                let Some(avss_share) = self.avss.take_share(id).await.flatten() else {
                    warn!(?id, "AVSS share evicted before consumption; skipping");
                    continue;
                };
                let binding = match self.get_or_create_store(session_id, self.id).await {
                    Some(s) => s,
                    None => return Ok(()),
                };
                let mut ransha_storage = binding.lock().await;
                let sender_id = id.sub_id();
                if usize::from(sender_id) >= self.n_parties {
                    return Err(RanShaAvssError::InvalidPartyId);
                }
                if avss_share.len() != batch_size {
                    return Err(RanShaAvssError::InvalidBatchSize);
                }
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
                    let mut shares_deg_t: Vec<(usize, Vec<FeldmanShamirShare<F, C>>)> =
                        ransha_storage
                            .initial_shares
                            .iter()
                            .map(|(sid, s)| (*sid, s.clone()))
                            .collect();
                    drop(ransha_storage);
                    // sort by sender_id
                    shares_deg_t.sort_by_key(|(sid, _)| *sid);

                    // drop the ids, keep only shares
                    let shares_deg_t: Vec<Vec<FeldmanShamirShare<F, C>>> =
                        shares_deg_t.into_iter().map(|(_, s)| s).collect();
                    self.ransha_gen_batch(shares_deg_t, session_id).await?;
                    break;
                }
            }
        }
        Ok(())
    }

    pub async fn ransha_gen(
        &mut self,
        shares_deg_t: Vec<FeldmanShamirShare<F, C>>,
        session_id: AvssSessionId,
    ) -> Result<(), RanShaAvssError> {
        self.ransha_gen_batch(
            shares_deg_t.into_iter().map(|share| vec![share]).collect(),
            session_id,
        )
        .await
    }

    async fn ransha_gen_batch(
        &mut self,
        shares_deg_t: Vec<Vec<FeldmanShamirShare<F, C>>>,
        session_id: AvssSessionId,
    ) -> Result<(), RanShaAvssError> {
        info!(
            "party {:?} received shares for Random sharing generation",
            self.id
        );

        let n = self.n_parties;
        let t = self.threshold;
        if shares_deg_t.len() != n {
            return Err(RanShaAvssError::InvalidBatchSize);
        }
        let batch_size = shares_deg_t
            .first()
            .map(Vec::len)
            .filter(|size| *size > 0)
            .ok_or(RanShaAvssError::InvalidBatchSize)?;
        if shares_deg_t.iter().any(|shares| shares.len() != batch_size) {
            return Err(RanShaAvssError::InvalidBatchSize);
        }
        let vandermonde_matrix = make_vandermonde(n, n - 1)?;

        let mut computed = Vec::with_capacity(batch_size * n);
        let mut output = Vec::with_capacity(batch_size * (n - 2 * t));
        for batch_index in 0..batch_size {
            let shares: Vec<ShamirShare<_, 1, _>> = shares_deg_t
                .iter()
                .map(|dealer_shares| dealer_shares[batch_index].feldmanshare.clone())
                .collect();
            let r_deg_t = apply_vandermonde(&vandermonde_matrix, &shares)?;

            for k in 0..n {
                let mut commitments = vec![C::zero(); t + 1];
                for i in 0..n {
                    let dealer_commitments = &shares_deg_t[i][batch_index].commitments;
                    if dealer_commitments.len() != t + 1 {
                        return Err(RanShaAvssError::AvssError(
                            AvssError::InvalidCommitmentLength,
                        ));
                    }
                    for j in 0..=t {
                        commitments[j] += dealer_commitments[j].mul(vandermonde_matrix[k][i]);
                    }
                }
                let share = FeldmanShamirShare {
                    feldmanshare: r_deg_t[k].clone(),
                    commitments,
                };
                if k >= 2 * t {
                    output.push(share.clone());
                }
                computed.push(share);
            }
        }

        // Store results
        let bind_store = match self.get_or_create_store(session_id, self.id).await {
            Some(s) => s,
            None => return Ok(()),
        };
        let mut store = bind_store.lock().await;

        store.computed_r_shares = computed;
        store.protocol_output = output.clone();

        if let Some(sender) = store.output_sender.take() {
            sender
                .send(output)
                .map_err(|_| RanShaAvssError::SendError(session_id))?;
        }
        Ok(())
    }
}
