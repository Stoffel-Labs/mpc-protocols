use ark_ff::FftField;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use bincode::Options;
use std::{sync::Arc, time::Instant};
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};
use tracing::warn;

use crate::honeybadger::MAX_MESSAGE_SIZE;
use crate::{
    common::{
        session_store::{Admission, SessionStore},
        share::{apply_vandermonde, make_vandermonde, ShareError},
        utils::deser_bounded_vec,
        ProtocolSessionId, SecretSharingScheme, ShamirShare, RBC,
    },
    honeybadger::{
        dn07::{phase_of, ProtocolPhase},
        robust_interpolate::robust_interpolate::{Robust, RobustShare},
        zero_share::{
            ZeroShaError, ZeroShaMessage, ZeroShaMessageType, ZeroShaPayload, ZeroShaState,
            ZeroShaStore,
        },
        SessionId, WrappedMessage,
    },
};

/// Refuses a session whose calling protocol runs in the online phase.
///
/// # Why this is a check and not a type
///
/// The repo's containment mechanism for degree-`2t` work is
/// [`PreprocessingSessionId`](crate::honeybadger::dn07::PreprocessingSessionId), which
/// [`MulPubNode::init`](crate::honeybadger::mul_pub::mul_pub::MulPubNode::init) and the DN07 nodes
/// take in their signatures. [`ZeroShaNode::init_batch`] keeps a bare [`SessionId`] for the same
/// reason [`TripleGenNode`](crate::honeybadger::triple_gen::triple_generation::TripleGenNode)
/// does: the wrapper's constructor also asserts a root-shaped session, and ZeroSha's `round_id`
/// is copied through into the per-verifier RBC child sessions minted in
/// [`ZeroShaNode::reconstruction_handler`], so it is part of this protocol's own addressing
/// rather than spare space. What generalises is the phase half, against the same exhaustive
/// [`phase_of`](crate::honeybadger::dn07::phase_of) match.
fn require_preprocessing_phase(session_id: SessionId) -> Result<(), ZeroShaError> {
    let Some(tag) = session_id.calling_protocol() else {
        // No calling protocol at all: malformed rather than mis-phased. `reconstruction_handler`
        // needs the tag to route the OK-vote broadcast back to the right field's node, so a
        // session without one could not complete anyway.
        return Err(ZeroShaError::SessionIdError(session_id));
    };
    match phase_of(tag) {
        ProtocolPhase::Preprocessing => Ok(()),
        ProtocolPhase::Online => Err(ZeroShaError::OnlinePhaseForbidden {
            session_id,
            tag: tag as u8,
        }),
        // A transport tag never names a calling protocol.
        ProtocolPhase::Transport => Err(ZeroShaError::SessionIdError(session_id)),
    }
}

#[derive(Clone, Debug)]
pub struct ZeroShaNode<F: FftField, R: RBC> {
    pub id: usize,
    pub n_parties: usize,
    pub threshold: usize,
    pub store: Arc<Mutex<SessionStore<SessionId, (usize, Instant, Arc<Mutex<ZeroShaStore<F>>>)>>>,
    pub rbc: R,
    pub rbc_output: Arc<Mutex<tokio::sync::mpsc::Receiver<SessionId>>>,
}

const MAX_ZERO_SHARE_SESSIONS: usize = 1024;

impl<F, R> ZeroShaNode<F, R>
where
    F: FftField,
    R: RBC<Id = SessionId>,
{
    pub fn new(
        id: PartyId,
        n_parties: usize,
        threshold: usize,
        k: usize,
    ) -> Result<Self, ZeroShaError> {
        let (rbc_sender, rbc_receiver) = tokio::sync::mpsc::channel(200);
        let rbc = R::new(
            id,
            n_parties,
            threshold,
            k,
            rbc_sender,
            Arc::new(WrappedMessage::rbc_wrap),
        )?;
        Ok(Self {
            id,
            n_parties,
            threshold,
            store: Arc::new(Mutex::new(SessionStore::with_default_cap())),
            rbc,
            rbc_output: Arc::new(Mutex::new(rbc_receiver)),
        })
    }

    /// Number of live ZeroSha sessions (used by the node's preprocessing trace).
    pub async fn store_len(&self) -> usize {
        self.store.lock().await.len()
    }

    pub async fn drain_rbc_output(&mut self) -> Result<(), ZeroShaError> {
        loop {
            let id = {
                let mut rx = self.rbc_output.lock().await;
                match rx.try_recv() {
                    Ok(id) => id,
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        return Err(ZeroShaError::Abort);
                    }
                }
            };
            let output = self.rbc.get_store(id).await?;
            let mut msg: ZeroShaMessage = bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .allow_trailing_bytes()
                .with_limit(MAX_MESSAGE_SIZE)
                .deserialize(&output)?;
            let authenticated_sender = id.sub_id() as usize;
            if msg.sender_id != authenticated_sender {
                warn!("Dropping RBC output: sender mismatch");
                continue;
            }
            if msg.session_id.exec_id() != id.exec_id()
                || msg.session_id.instance_id() != id.instance_id()
            {
                warn!("Dropping RBC output: session_id mismatch");
                continue;
            }
            if msg.session_id.round_id() != id.round_id() || msg.session_id.sub_id() != 0 {
                warn!("Dropping RBC output: metadata mismatch");
                continue;
            }
            msg.sender_id = authenticated_sender;
            self.output_handler(msg).await?;
        }
        Ok(())
    }

    pub async fn get_or_create_store(
        &mut self,
        session_id: SessionId,
        initiator_id: usize,
    ) -> Option<Arc<Mutex<ZeroShaStore<F>>>> {
        let n_parties = self.n_parties;
        match self.store.lock().await.get_or_admit(
            session_id,
            initiator_id,
            MAX_ZERO_SHARE_SESSIONS,
            MAX_ZERO_SHARE_SESSIONS / n_parties,
            || Arc::new(Mutex::new(ZeroShaStore::empty(n_parties))),
        ) {
            Admission::Got(arc) => Some(arc),
            Admission::Retired => None,
            Admission::Rejected => {
                warn!("ZeroSha session limit reached");
                None
            }
        }
    }

    pub async fn clear_store(&self, session_id: SessionId) -> bool {
        self.store.lock().await.retire(session_id)
    }

    pub async fn wait_for_result(
        &self,
        session_id: SessionId,
        duration: Duration,
    ) -> Result<Vec<RobustShare<F>>, ZeroShaError> {
        let output_receiver = {
            let storage = self.store.lock().await;
            let storage_bind = match storage.get(&session_id) {
                Some((_, _, value)) => value,
                None => return Err(ZeroShaError::NoSuchSessionId(session_id)),
            };
            let mut inner = storage_bind.lock().await;

            inner
                .output_receiver
                .take()
                .ok_or(ZeroShaError::ResultAlreadyReceived(session_id))?
        };
        match timeout(duration, output_receiver).await {
            Err(_) => Err(ZeroShaError::Timeout(session_id)),
            Ok(Err(_)) => Err(ZeroShaError::ReceiveError(session_id)),
            Ok(Ok(shares)) => Ok(shares),
        }
    }

    async fn try_finalize(&mut self, session_id: SessionId) -> Result<bool, ZeroShaError> {
        let output = {
            // Retired or capacity-rejected: nothing left to finalize for this session.
            let store_bind = match self.get_or_create_store(session_id, self.id).await {
                Some(s) => s,
                None => return Ok(false),
            };
            let mut store = store_bind.lock().await;
            if store.state == ZeroShaState::Finished {
                return Ok(true);
            }
            if store.received_ok_msg.len() < 2 * self.threshold {
                return Ok(false);
            }
            if store.computed_r_shares.len() < store.batch_size * self.n_parties {
                return Ok(false);
            }
            let mut output =
                Vec::with_capacity(store.batch_size * (self.n_parties - 2 * self.threshold));
            for shares in store.computed_r_shares.chunks_exact(self.n_parties) {
                output.extend_from_slice(&shares[2 * self.threshold..]);
            }
            store.state = ZeroShaState::Finished;
            store.protocol_output = output.clone();
            let sender = store.output_sender.take().unwrap();
            (sender, output)
        };
        let (sender, output) = output;
        sender
            .send(output)
            .map_err(|_| ZeroShaError::SendError(session_id))?;
        Ok(true)
    }

    pub async fn init<N, G>(
        &mut self,
        session_id: SessionId,
        rng: &mut G,
        network: Arc<N>,
    ) -> Result<(), ZeroShaError>
    where
        N: Network,
        G: Rng,
    {
        self.init_batch(session_id, 1, rng, network).await
    }

    /// Generates `batch_size` independent zero-sharings in one exchange: all
    /// `batch_size` shares destined for a given recipient are packed into a
    /// single message, so the round count stays fixed (2 rounds total)
    /// regardless of `batch_size` — only the payload size and local
    /// Vandermonde computation scale with it.
    pub async fn init_batch<N, G>(
        &mut self,
        session_id: SessionId,
        batch_size: usize,
        rng: &mut G,
        network: Arc<N>,
    ) -> Result<(), ZeroShaError>
    where
        N: Network,
        G: Rng,
    {
        // The phase barrier. See `require_preprocessing_phase`: this both produces degree-2t
        // sharings and verifies them by reconstructing at degree 2t after hearing from all n.
        require_preprocessing_phase(session_id)?;
        assert_eq!(session_id.sub_id(), 0);
        let batch_size = batch_size.max(1);

        // secret is always zero, degree is 2t
        let mut shares_by_recipient = vec![Vec::with_capacity(batch_size); self.n_parties];
        for _ in 0..batch_size {
            let shares_deg_2t = RobustShare::compute_shares(
                F::zero(),
                self.n_parties,
                2 * self.threshold,
                None,
                rng,
            )?;
            for (recipient_id, share) in shares_deg_2t.into_iter().enumerate() {
                shares_by_recipient[recipient_id].push(share);
            }
        }

        for (recipient_id, shares) in shares_by_recipient.into_iter().enumerate() {
            let payload = if batch_size == 1 {
                let mut payload = Vec::new();
                shares[0].serialize_compressed(&mut payload)?;
                ZeroShaPayload::Share(payload)
            } else {
                let mut payload = Vec::new();
                shares.serialize_compressed(&mut payload)?;
                ZeroShaPayload::SharesBatch(payload)
            };
            let msg = WrappedMessage::ZeroSha(ZeroShaMessage::new(
                self.id,
                ZeroShaMessageType::ShareMessage,
                session_id,
                payload,
            ));
            network
                .send(recipient_id, &bincode::serialize(&msg)?)
                .await?;
        }

        let storage_access = self
            .get_or_create_store(session_id, self.id)
            .await
            .ok_or(ZeroShaError::LimitError)?;
        let mut store = storage_access.lock().await;
        store.batch_size = batch_size;
        store.state = ZeroShaState::Initialized;
        Ok(())
    }

    pub async fn receive_shares_handler<N>(
        &mut self,
        msg: ZeroShaMessage,
        network: Arc<N>,
    ) -> Result<(), ZeroShaError>
    where
        N: Network,
    {
        if msg.session_id.sub_id() != 0 {
            return Err(ZeroShaError::SessionIdError(msg.session_id));
        }
        if msg.sender_id >= self.n_parties {
            return Err(ZeroShaError::InvalidPartyId);
        }

        let shares: Vec<ShamirShare<F, 1, Robust>> = match msg.payload {
            ZeroShaPayload::Share(payload) => {
                vec![CanonicalDeserialize::deserialize_compressed(
                    payload.as_slice(),
                )?]
            }
            ZeroShaPayload::SharesBatch(payload) => {
                deser_bounded_vec(&mut payload.as_slice(), payload.len())?
            }
            _ => return Err(ZeroShaError::Abort),
        };
        for share in &shares {
            if share.id != self.id {
                return Err(ShareError::IdMismatch.into());
            }
            // degree check uses 2t
            if share.degree != 2 * self.threshold {
                return Err(ShareError::DegreeMismatch.into());
            }
        }

        // Attributed to `msg.sender_id`: whichever party's message happens to
        // create this entry, so no single sender can flood past its own
        // per-peer share of the cap.
        let binding = match self
            .get_or_create_store(msg.session_id, msg.sender_id)
            .await
        {
            Some(s) => s,
            None => return Ok(()),
        };
        let mut store = binding.lock().await;

        if store.initial_shares.is_empty() {
            store.batch_size = shares.len();
        } else if store.batch_size != shares.len() {
            return Err(ZeroShaError::Abort);
        }

        if store.state == ZeroShaState::FinishedInitialSharing
            || store.state == ZeroShaState::Finished
        {
            return Ok(());
        }
        if store.initial_shares.contains_key(&msg.sender_id) {
            warn!("Duplicate share from {:?}, ignoring.", msg.sender_id);
            return Ok(());
        }

        store.initial_shares.insert(msg.sender_id, shares);
        store.reception_tracker[msg.sender_id] = true;

        if store.reception_tracker.iter().all(|&r| r) {
            store.state = ZeroShaState::FinishedInitialSharing;
            let batch_size = store.batch_size;
            let mut shares_deg_2t: Vec<(usize, Vec<ShamirShare<F, 1, Robust>>)> = store
                .initial_shares
                .iter()
                .map(|(sid, s)| (*sid, s.clone()))
                .collect();
            drop(store);
            shares_deg_2t.sort_by_key(|(sid, _)| *sid);

            let mut shares_by_batch = vec![Vec::with_capacity(self.n_parties); batch_size];
            for (_, sender_shares) in shares_deg_2t {
                for (batch_index, share) in sender_shares.into_iter().enumerate() {
                    shares_by_batch[batch_index].push(share);
                }
            }
            self.init_zerosha_batch(shares_by_batch, msg.session_id, network)
                .await?
        }
        Ok(())
    }

    pub async fn init_zerosha<N>(
        &mut self,
        shares_deg_2t: Vec<RobustShare<F>>,
        session_id: SessionId,
        network: Arc<N>,
    ) -> Result<(), ZeroShaError>
    where
        N: Network,
    {
        self.init_zerosha_batch(vec![shares_deg_2t], session_id, network)
            .await
    }

    async fn init_zerosha_batch<N>(
        &mut self,
        shares_by_batch: Vec<Vec<RobustShare<F>>>,
        session_id: SessionId,
        network: Arc<N>,
    ) -> Result<(), ZeroShaError>
    where
        N: Network,
    {
        let vandermonde_matrix = make_vandermonde(self.n_parties, self.n_parties - 1)?;
        let mut r_deg_2t = Vec::with_capacity(shares_by_batch.len() * self.n_parties);
        for shares_deg_2t in shares_by_batch {
            r_deg_2t.extend(apply_vandermonde(&vandermonde_matrix, &shares_deg_2t)?);
        }

        let bind_store = match self.get_or_create_store(session_id, self.id).await {
            Some(s) => s,
            None => return Ok(()),
        };
        let mut store = bind_store.lock().await;
        store.batch_size = r_deg_2t.len() / self.n_parties;
        store.computed_r_shares = r_deg_2t.clone();
        drop(store);

        if self.try_finalize(session_id).await? {
            return Ok(());
        }

        for i in 0..2 * self.threshold {
            let shares: Vec<_> = r_deg_2t
                .chunks_exact(self.n_parties)
                .map(|batch_shares| batch_shares[i].clone())
                .collect();
            let payload = if shares.len() == 1 {
                let mut bytes = Vec::new();
                shares[0].serialize_compressed(&mut bytes)?;
                ZeroShaPayload::Reconstruct(bytes)
            } else {
                let mut bytes = Vec::new();
                shares.serialize_compressed(&mut bytes)?;
                ZeroShaPayload::ReconstructSharesBatch(bytes)
            };
            let message = WrappedMessage::ZeroSha(ZeroShaMessage::new(
                self.id,
                ZeroShaMessageType::ReconstructMessage,
                session_id,
                payload,
            ));
            network.send(i, &bincode::serialize(&message)?).await?;
        }
        Ok(())
    }

    pub async fn reconstruction_handler<N>(
        &mut self,
        msg: ZeroShaMessage,
        network: Arc<N>,
    ) -> Result<(), ZeroShaError>
    where
        N: Network + Send + Sync,
    {
        if msg.session_id.sub_id() != 0 {
            return Err(ZeroShaError::SessionIdError(msg.session_id));
        }

        let shares: Vec<ShamirShare<F, 1, Robust>> = match msg.payload {
            ZeroShaPayload::Reconstruct(payload) => {
                vec![CanonicalDeserialize::deserialize_compressed(
                    payload.as_slice(),
                )?]
            }
            ZeroShaPayload::ReconstructSharesBatch(payload) => {
                deser_bounded_vec(&mut payload.as_slice(), payload.len())?
            }
            _ => return Err(ZeroShaError::Abort),
        };
        for share in &shares {
            // degree is 2t
            if share.degree != 2 * self.threshold {
                return Err(ZeroShaError::ShareError(ShareError::DegreeMismatch));
            }
            if share.id != msg.sender_id {
                return Err(ZeroShaError::ShareError(ShareError::IdMismatch));
            }
        }

        // Attributed to `msg.sender_id` — see receive_shares_handler for why.
        let binding = match self
            .get_or_create_store(msg.session_id, msg.sender_id)
            .await
        {
            Some(s) => s,
            None => return Ok(()),
        };
        let mut store = binding.lock().await;
        if store.state == ZeroShaState::Finished {
            return Ok(());
        }
        if store.received_r_shares.is_empty() {
            store.batch_size = shares.len();
        } else if store.batch_size != shares.len() {
            return Err(ZeroShaError::Abort);
        }
        store.state = ZeroShaState::Reconstruction;
        store.received_r_shares.insert(msg.sender_id, shares);

        if self.id < 2 * self.threshold && store.received_r_shares.len() >= self.n_parties {
            let batch_size = store.batch_size;
            let mut shares_by_batch =
                vec![Vec::with_capacity(store.received_r_shares.len()); batch_size];
            for sender_shares in store.received_r_shares.values() {
                for (batch_index, share) in sender_shares.iter().cloned().enumerate() {
                    shares_by_batch[batch_index].push(share);
                }
            }
            drop(store);

            let mut ok = true;
            // recover at degree 2t AND check secret is zero, for every batch item
            for shares in shares_by_batch {
                match RobustShare::recover_secret(&shares, self.n_parties, self.threshold) {
                    Ok(r) => {
                        let poly = DensePolynomial::from_coefficients_slice(&r.0);
                        if !(poly.degree() == 2 * self.threshold && r.1.is_zero()) {
                            ok = false;
                            break;
                        }
                    }
                    Err(_) => {
                        ok = false;
                        break;
                    }
                }
            }

            let result = ZeroShaMessage::new(
                self.id,
                ZeroShaMessageType::OutputMessage,
                msg.session_id,
                ZeroShaPayload::Output(ok),
            );
            let bytes = bincode::serialize(&result)?;
            // Tag read dynamically from the caller's own session (not hardcoded
            // to ZeroSha) so the small-field instance's OK-vote broadcast routes
            // back to the small-field node instead of the big-field one.
            let session_id = SessionId::new(
                msg.session_id
                    .calling_protocol()
                    .ok_or(ZeroShaError::SessionIdError(msg.session_id))?,
                SessionId::pack_slot(
                    msg.session_id.exec_id(),
                    self.id as u8,
                    msg.session_id.round_id(),
                ),
                msg.session_id.instance_id(),
            );
            self.rbc
                .init(bytes, session_id, Arc::clone(&network))
                .await?;
        }
        Ok(())
    }

    pub async fn output_handler(&mut self, msg: ZeroShaMessage) -> Result<(), ZeroShaError> {
        let ok = match msg.payload {
            ZeroShaPayload::Output(o) => o,
            _ => return Err(ZeroShaError::Abort),
        };
        if !ok {
            return Err(ZeroShaError::NotZero);
        }
        if msg.session_id.sub_id() != 0 {
            return Err(ZeroShaError::SessionIdError(msg.session_id));
        }
        if msg.sender_id >= 2 * self.threshold {
            warn!("Rejecting output from non-verifier party {}", msg.sender_id);
            return Err(ZeroShaError::InvalidPartyId);
        }

        // Attributed to `msg.sender_id` — see receive_shares_handler for why.
        let binding = match self
            .get_or_create_store(msg.session_id, msg.sender_id)
            .await
        {
            Some(s) => s,
            None => return Ok(()),
        };
        let mut store = binding.lock().await;
        if !store.received_ok_msg.contains(&msg.sender_id) {
            store.received_ok_msg.push(msg.sender_id);
        }
        drop(store);
        self.try_finalize(msg.session_id).await?;
        Ok(())
    }

    pub async fn process<N>(
        &mut self,
        msg: ZeroShaMessage,
        network: Arc<N>,
    ) -> Result<(), ZeroShaError>
    where
        N: Network + Send + Sync,
    {
        match msg.msg_type {
            ZeroShaMessageType::ShareMessage => self.receive_shares_handler(msg, network).await,
            ZeroShaMessageType::OutputMessage => Ok(()),
            ZeroShaMessageType::ReconstructMessage => {
                self.reconstruction_handler(msg, network).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::rbc::rbc::Avid;
    use crate::honeybadger::dn07::{Dn07Error, PreprocessingSessionId};
    use crate::honeybadger::ProtocolType;
    use ark_bls12_381::Fr;
    use ark_std::rand::SeedableRng;
    use stoffelmpc_network::fake_network::{FakeInnerNetwork, FakeNetwork, FakeNetworkConfig};

    type Node = ZeroShaNode<Fr, Avid<SessionId>>;

    fn network() -> Arc<FakeNetwork> {
        let inner = FakeInnerNetwork::new(5, None, FakeNetworkConfig::new(10)).0;
        Arc::new(FakeNetwork::new(0, inner))
    }

    /// The barrier, mirroring `gf_dn07::tests::online_sessions_cannot_even_be_named`.
    ///
    /// Before this change `init_batch` asserted only `sub_id == 0`, so any of these tags would
    /// have been carried into a protocol that deals degree-2t sharings, waits for all `n` parties
    /// and reconstructs at degree 2t — none of which the asynchronous robust path can do.
    #[tokio::test]
    async fn an_online_session_is_refused_before_any_share_is_dealt() {
        for tag in [
            ProtocolType::Input,
            ProtocolType::Mul,
            ProtocolType::FpMul,
            ProtocolType::Trunc,
            ProtocolType::FpDivConst,
            ProtocolType::GfMul,
            ProtocolType::A2B,
            ProtocolType::A2BGfMul,
            ProtocolType::B2A,
        ] {
            let mut node = Node::new(0, 5, 1, 2).unwrap();
            let session_id = SessionId::new(tag, SessionId::pack_slot(7, 0, 0), 42);
            let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(7);

            let err = node
                .init_batch(session_id, 2, &mut rng, network())
                .await
                .expect_err("an online tag must not reach a degree-2t protocol");
            assert!(
                matches!(err, ZeroShaError::OnlinePhaseForbidden { tag: t, .. } if t == tag as u8),
                "init_batch accepted {tag:?}: got {err:?}"
            );

            // Refused before any state was created, and before a single share left this node.
            assert_eq!(node.store_len().await, 0);
        }
    }

    /// The negative control: the tag the production caller actually passes is still admitted, so
    /// the barrier rejects a phase rather than rejecting everything.
    #[tokio::test]
    async fn the_preprocessing_caller_is_still_admitted() {
        let session_id = SessionId::new(ProtocolType::ZeroSha, SessionId::pack_slot(7, 0, 0), 42);
        assert!(require_preprocessing_phase(session_id).is_ok());
        // Every preprocessing tag, so a future caller retagging its ZeroSha sessions — the way
        // `reconstruction_handler` already reads the tag back dynamically to route the OK vote —
        // is not silently locked out.
        for tag in [
            ProtocolType::Randousha,
            ProtocolType::Ransha,
            ProtocolType::Triple,
            ProtocolType::Dousha,
            ProtocolType::PRandInt,
            ProtocolType::GfRansha,
            ProtocolType::RandBit,
            ProtocolType::ZeroSha,
            ProtocolType::GfDousha,
            ProtocolType::GfRandousha,
            ProtocolType::GfTriple,
            ProtocolType::DaBit,
            ProtocolType::DaBitMul,
            ProtocolType::DaBitOpen,
            ProtocolType::DaBitGfMul,
            ProtocolType::DaBitGfOpen,
            ProtocolType::Dn07,
            ProtocolType::GfDn07,
        ] {
            assert!(
                require_preprocessing_phase(SessionId::new(tag, SessionId::pack_slot(7, 0, 0), 42))
                    .is_ok(),
                "{tag:?} is preprocessing and must be admitted"
            );
        }
    }

    /// A transport tag names no calling protocol, so it is malformed here rather than mis-phased —
    /// and `reconstruction_handler` would fail on it anyway when it reads the tag back to address
    /// the OK-vote broadcast.
    #[tokio::test]
    async fn a_transport_tag_is_rejected_as_malformed_not_as_online() {
        for tag in [
            ProtocolType::Rbc,
            ProtocolType::BatchRecon,
            ProtocolType::GfBatchRecon,
            ProtocolType::None,
        ] {
            let sid = SessionId::new(tag, SessionId::pack_slot(7, 0, 0), 42);
            assert!(matches!(
                require_preprocessing_phase(sid).unwrap_err(),
                ZeroShaError::SessionIdError(_)
            ));
        }
    }

    /// Evidence for the note on `require_preprocessing_phase`: ZeroSha's `round_id` is copied into
    /// the RBC child session `reconstruction_handler` mints, so it is this protocol's own
    /// addressing space and not spare room the wrapper type could claim.
    #[tokio::test]
    async fn round_id_is_addressing_space_here_so_the_wrapper_type_does_not_fit() {
        let sid = SessionId::new(ProtocolType::ZeroSha, SessionId::pack_slot(7, 0, 3), 42);
        assert!(matches!(
            PreprocessingSessionId::new(sid).unwrap_err(),
            Dn07Error::MalformedSessionId(_)
        ));
        assert!(require_preprocessing_phase(sid).is_ok());
    }
}
