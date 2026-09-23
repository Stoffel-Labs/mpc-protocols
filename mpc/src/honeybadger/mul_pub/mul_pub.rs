use crate::common::session_store::{Admission, SessionStore};
use crate::{
    common::utils::deser_bounded_vec,
    honeybadger::{
        batch_recon::batch_recon::BatchReconNode,
        dn07::PreprocessingSessionId,
        mul_pub::{MulPubError, MulPubState, MulPubStore},
        robust_interpolate::robust_interpolate::RobustShare,
        SessionId,
    },
};
use ark_ff::FftField;
use std::{sync::Arc, time::Instant};
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::{mpsc::Receiver, Mutex};
use tokio::time::{timeout, Duration};
use tracing::warn;

const MAX_MUL_PUB_SESSIONS: usize = 256;
/// Largest number of `2t+1`-wide batch-reconstruction groups a single `init` may open. Every
/// group contributes one field element to the same eval/reveal message pair, so this bounds the
/// payload of one session. Callers split larger requests via [`MulPubNode::max_batch_size`].
const MAX_MUL_PUB_GROUPS: usize = 256;

/// Opens `a * b` in the clear, in one batch-reconstruction round.
///
/// **PREPROCESSING.** The share it reconstructs is `a_j * b_j + [0]_{2t}`, a degree-`2t` sharing:
/// its [`BatchReconNode`] is constructed with reconstruction degree `2 * threshold`, three lines
/// below. A degree-`2t` opening needs `n >= 4t+1` to be robustly reconstructible, and this network
/// is `n = 3t+1`, so on the asynchronous online path the `t` shares an adversary may simply never
/// send are enough to stall it forever — and the `2t+1` honest shares that do arrive are not
/// enough to error-correct. Preprocessing is synchronous and may abort, which is what makes the
/// same opening legal there.
///
/// That is a statement about *which sessions may reach this node*, so [`MulPubNode::init`] takes a
/// [`PreprocessingSessionId`] and not a bare [`SessionId`], exactly as
/// [`Dn07MulNode::init_mul`](crate::honeybadger::dn07::dn07::Dn07MulNode::init_mul) does. The
/// classification lives in one place — [`phase_of`](crate::honeybadger::dn07::phase_of)'s
/// exhaustive match — so a new [`ProtocolType`](crate::honeybadger::ProtocolType) cannot be added
/// without someone deciding its phase, and a future second MulPub caller cannot reach this opening
/// from an online session without first failing to name it.
#[derive(Clone, Debug)]
pub struct MulPubNode<F: FftField> {
    pub id: usize,
    pub n_parties: usize,
    pub threshold: usize,
    pub store: Arc<Mutex<SessionStore<SessionId, (usize, Instant, Arc<Mutex<MulPubStore<F>>>)>>>,
    pub batch_recon: BatchReconNode<F>,
    pub batch_output: Arc<Mutex<Receiver<SessionId>>>,
}

impl<F: FftField> MulPubNode<F> {
    pub fn new(id: PartyId, n_parties: usize, threshold: usize) -> Result<Self, MulPubError> {
        let (batch_sender, batch_receiver) = tokio::sync::mpsc::channel(200);
        let batch_recon =
            BatchReconNode::new(id, n_parties, threshold, 2 * threshold, batch_sender)?;
        Ok(Self {
            id,
            n_parties,
            threshold,
            store: Arc::new(Mutex::new(SessionStore::with_default_cap())),
            batch_recon,
            batch_output: Arc::new(Mutex::new(batch_receiver)),
        })
    }

    pub async fn get_or_create_store(
        &self,
        session_id: SessionId,
        initiator_id: usize,
        k: usize,
    ) -> Option<Arc<Mutex<MulPubStore<F>>>> {
        match self.store.lock().await.get_or_admit(
            session_id,
            initiator_id,
            MAX_MUL_PUB_SESSIONS,
            MAX_MUL_PUB_SESSIONS / self.n_parties,
            || Arc::new(Mutex::new(MulPubStore::new(k))),
        ) {
            Admission::Got(arc) => Some(arc),
            Admission::Retired => None,
            Admission::Rejected => {
                warn!("MulPub session limit reached");
                None
            }
        }
    }

    /// Largest `k` a single [`MulPubNode::init`] call can open. Callers that may need more
    /// should chunk against this rather than reimplementing the `2t+1` group arithmetic.
    pub fn max_batch_size(&self) -> usize {
        MAX_MUL_PUB_GROUPS * (2 * self.threshold + 1)
    }

    /// Number of live MulPub sessions (used by the node's preprocessing trace).
    pub async fn store_len(&self) -> usize {
        self.store.lock().await.len()
    }

    pub async fn clear_store(&self, session_id: SessionId) -> bool {
        self.batch_recon.clear_store(session_id).await;
        self.store.lock().await.retire(session_id)
    }

    /// Opens `a_j * b_j` for every `j`, re-randomised by `zero_shares[j]`.
    ///
    /// # Phase
    ///
    /// `session_id` is a [`PreprocessingSessionId`], which is the containment: this opens at
    /// degree `2t` (see the type docs on [`MulPubNode`]), and the only constructor of that type
    /// classifies the session's calling protocol through
    /// [`phase_of`](crate::honeybadger::dn07::phase_of) and refuses an online one with
    /// [`Dn07Error::OnlinePhaseForbidden`](crate::honeybadger::dn07::Dn07Error::OnlinePhaseForbidden).
    /// It also carries the root-session shape this call used to assert by hand — `sub_id` and
    /// `round_id` both zero, leaving the child-minting space free for the batch reconstruction
    /// below — so those checks are gone from this body rather than merely restated in it.
    pub async fn init<N: Network + Send + Sync + 'static>(
        &mut self,
        session_id: PreprocessingSessionId,
        a: Vec<RobustShare<F>>,
        b: Vec<RobustShare<F>>,
        zero_shares: Vec<RobustShare<F>>,
        network: Arc<N>,
    ) -> Result<(), MulPubError> {
        let session_id = session_id.get();
        if a.len() != b.len() {
            return Err(MulPubError::InvalidInput(
                "a and b must have equal length".into(),
            ));
        }
        let k = a.len();
        if k != zero_shares.len() {
            return Err(MulPubError::InvalidInput(format!(
                "{k} multiplications but {} zero shares provided",
                zero_shares.len()
            )));
        }
        if k == 0 {
            return Err(MulPubError::InvalidInput("empty input".into()));
        }
        if zero_shares.iter().any(|s| s.degree != 2 * self.threshold) {
            return Err(MulPubError::InvalidInput(
                "zero shares must have degree 2t".into(),
            ));
        }
        if k > self.max_batch_size() {
            return Err(MulPubError::BatchTooLarge {
                requested: k,
                max: self.max_batch_size(),
            });
        }
        let storage_bind = match self.get_or_create_store(session_id, self.id, k).await {
            Some(s) => s,
            None => return Err(MulPubError::LimitError),
        };
        // Set k and atomically claim any reconstruction result that arrived
        // before this call (a faster quorum can finish this node's own
        // reconstruction before it reaches `init`).
        let pending_batch_recon_payload = {
            let mut store = storage_bind.lock().await;
            store.k = k;
            store.pending_batch_recon_payload.take()
        };
        if let Some(payload) = pending_batch_recon_payload {
            self.finish_from_payload(session_id, storage_bind.clone(), payload)
                .await?;
            if storage_bind.lock().await.state == MulPubState::Finished {
                // Already have the result — skip the redundant network round.
                return Ok(());
            }
        }

        let batch_size = 2 * self.threshold + 1;
        let num_batches = (k + batch_size - 1) / batch_size;

        let mut all_shares: Vec<RobustShare<F>> = (0..k)
            .map(|j| {
                let product = a[j].share_mul(&b[j])?;
                product + zero_shares[j].clone()
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| MulPubError::InvalidInput(e.to_string()))?;

        // Pad the last batch with 1s to reach an exact multiple of batch_size = 2t+1
        while all_shares.len() < num_batches * batch_size {
            all_shares.push(RobustShare::new(F::one(), self.id, 2 * self.threshold));
        }

        // One combined batch-recon round for every chunk, instead of one round
        // per chunk — round count is now independent of k.
        self.batch_recon
            .init_batch_reconstruct_many(&all_shares, session_id, Arc::clone(&network))
            .await?;
        Ok(())
    }

    pub async fn drain_batch_recon_output(&mut self) -> Result<(), MulPubError> {
        loop {
            let sid = {
                let mut rx = self.batch_output.lock().await;
                match rx.try_recv() {
                    Ok(id) => id,
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        return Err(MulPubError::Abort);
                    }
                }
            };

            // Create the session if `init` hasn't run locally yet — a faster quorum can
            // finish this node's own reconstruction first. `k = 0` is never valid for a
            // real `init` call, so it's a safe placeholder here.
            let storage_bind = match self.get_or_create_store(sid, self.id, 0).await {
                Some(b) => b,
                None => continue,
            };
            let poly_bytes = self.batch_recon.get_store(sid).await?;
            self.finish_from_payload(sid, storage_bind, poly_bytes)
                .await?;
        }
        Ok(())
    }

    /// Decodes a completed batch-reconstruction payload and finishes the session, or —
    /// if `init` hasn't set `k` locally yet — parks the raw bytes for `init` to replay.
    async fn finish_from_payload(
        &self,
        session_id: SessionId,
        storage_bind: Arc<Mutex<MulPubStore<F>>>,
        payload: Vec<u8>,
    ) -> Result<(), MulPubError> {
        let mut store = storage_bind.lock().await;
        if store.state == MulPubState::Finished {
            return Ok(());
        }
        if store.k == 0 {
            store.pending_batch_recon_payload = Some(payload);
            return Ok(());
        }

        let batch_size = 2 * self.threshold + 1;
        let num_batches = (store.k + batch_size - 1) / batch_size;
        let coeffs: Vec<F> = deser_bounded_vec(&mut payload.as_slice(), num_batches * batch_size)
            .map_err(MulPubError::ArkSerialization)?;

        if coeffs.len() < store.k {
            warn!("MulPub: short coefficient vector for session {session_id:?}");
            return Ok(());
        }

        // Only the first store.k values are real; the rest is padding from
        // completing the last chunk.
        let output: Vec<F> = coeffs.into_iter().take(store.k).collect();
        store.state = MulPubState::Finished;
        if let Some(tx) = store.output_sender.take() {
            tx.send(output).map_err(|_| MulPubError::SendError)?;
        }
        Ok(())
    }

    pub async fn wait_for_result(
        &self,
        session_id: SessionId,
        duration: Duration,
    ) -> Result<Vec<F>, MulPubError> {
        let rx = {
            let storage = self.store.lock().await;
            let (_, _, bind) = storage
                .get(&session_id)
                .ok_or(MulPubError::NoSuchSession(session_id))?;
            let mut store = bind.lock().await;
            store
                .output_receiver
                .take()
                .ok_or(MulPubError::ResultAlreadyReceived(session_id))?
        };
        match timeout(duration, rx).await {
            Err(_) => Err(MulPubError::Timeout(session_id)),
            Ok(Err(_)) => Err(MulPubError::ReceiveError(session_id)),
            Ok(Ok(result)) => Ok(result),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::ProtocolSessionId;
    use crate::honeybadger::dn07::Dn07Error;
    use crate::honeybadger::ProtocolType;
    use ark_bls12_381::Fr;
    use ark_serialize::CanonicalSerialize;
    use stoffelmpc_network::fake_network::{FakeInnerNetwork, FakeNetwork, FakeNetworkConfig};

    #[tokio::test]
    async fn buffers_batch_reconstruction_that_finishes_before_local_init() {
        let mut node = MulPubNode::<Fr>::new(0, 5, 1).unwrap();
        // `RandBit`, not `Mul`. This test used to name `ProtocolType::Mul` — an *online* tag — on
        // a node that opens at degree 2t, and nothing anywhere refused it. That it now cannot
        // compile with an online tag is the point of `PreprocessingSessionId`.
        let pre_sid = PreprocessingSessionId::new(SessionId::new(
            ProtocolType::RandBit,
            SessionId::pack_slot(7, 0, 0),
            42,
        ))
        .unwrap();
        let session_id = pre_sid.get();

        // k = 3, batch_size = 2t+1 = 3, so this is exactly one batch's worth of coefficients.
        let coeffs = vec![Fr::from(1_u64), Fr::from(2_u64), Fr::from(3_u64)];
        let mut payload = Vec::new();
        coeffs.serialize_compressed(&mut payload).unwrap();

        // Before this fix: dropped silently ("no session; init not yet called"), and
        // `wait_for_result` would time out despite the value already being correctly,
        // robustly reconstructed.
        let storage_bind = node
            .get_or_create_store(session_id, node.id, 0)
            .await
            .unwrap();
        node.finish_from_payload(session_id, storage_bind.clone(), payload.clone())
            .await
            .unwrap();

        {
            let store = storage_bind.lock().await;
            assert_eq!(store.state, MulPubState::Running);
            assert_eq!(
                store.pending_batch_recon_payload.as_deref(),
                Some(payload.as_slice())
            );
        }

        let a: Vec<RobustShare<Fr>> = coeffs
            .iter()
            .map(|v| RobustShare::new(*v, node.id, 1))
            .collect();
        let b = a.clone();
        let zero_shares: Vec<RobustShare<Fr>> = coeffs
            .iter()
            .map(|_| RobustShare::new(Fr::from(0_u64), node.id, 2))
            .collect();
        let inner = FakeInnerNetwork::new(5, None, FakeNetworkConfig::new(10)).0;

        node.init(
            pre_sid,
            a,
            b,
            zero_shares,
            Arc::new(FakeNetwork::new(node.id, inner)),
        )
        .await
        .unwrap();

        let result = node
            .wait_for_result(session_id, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(result, coeffs);

        let store = storage_bind.lock().await;
        assert_eq!(store.state, MulPubState::Finished);
        assert!(store.pending_batch_recon_payload.is_none());
    }

    /// The barrier, mirroring `gf_dn07::tests::online_sessions_cannot_even_be_named`.
    ///
    /// `init` takes a `PreprocessingSessionId`, so an online session cannot be handed to MulPub at
    /// all — the attempt has to be made here, at the constructor, and it fails before a single
    /// share is touched. Every online tag is checked, not just one: a tag added to `ProtocolType`
    /// and classified `Online` is covered by this test the moment `phase_of` is updated, which is
    /// the only edit that can add one.
    #[tokio::test]
    async fn online_sessions_cannot_even_be_named() {
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
            let err =
                PreprocessingSessionId::new(SessionId::new(tag, SessionId::pack_slot(7, 0, 0), 42))
                    .unwrap_err();
            assert!(
                matches!(err, Dn07Error::OnlinePhaseForbidden { tag: t, .. } if t == tag as u8),
                "MulPub opens at degree 2t; {tag:?} must not be able to name one of its sessions, \
                 got {err:?}"
            );
            // And the refusal is reportable as a MulPub error, which is how `RandBit::init`
            // surfaces it to its own caller.
            let as_mul_pub: MulPubError =
                PreprocessingSessionId::new(SessionId::new(tag, SessionId::pack_slot(7, 0, 0), 42))
                    .unwrap_err()
                    .into();
            assert!(matches!(
                as_mul_pub,
                MulPubError::SessionPhase(Dn07Error::OnlinePhaseForbidden { .. })
            ));
        }
    }

    /// The preprocessing tags that actually reach MulPub are accepted, so the barrier above is
    /// rejecting a phase rather than rejecting everything.
    #[tokio::test]
    async fn the_preprocessing_caller_is_still_admitted() {
        assert!(PreprocessingSessionId::new(SessionId::new(
            ProtocolType::RandBit,
            SessionId::pack_slot(7, 0, 0),
            42,
        ))
        .is_ok());
    }
}
