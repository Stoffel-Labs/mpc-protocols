use crate::common::session_store::SessionStore;
use crate::common::ProtocolSessionId;
use crate::honeybadger::fpmul::{ProtocolState, RandBitError, RandBitStorage};
use crate::honeybadger::mul_pub::mul_pub::MulPubNode;
use crate::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use crate::honeybadger::SessionId;
use ark_ff::FftField;
use std::ops::{Add, Mul};
use std::sync::Arc;
use std::time::Instant;
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};
use tracing::warn;

/// Represents the random bit generation protocol.
///
/// # Output
///
/// One random bit per element of `a`. MulPub pads its last group internally, so the input count
/// is unconstrained.
/// Inputs whose square opens to zero are dropped (see `init`), so the output can be shorter than
/// the input; callers top the pool back up on the next round.
///
/// # Assumptions
///
/// `a` is a vector of random shares and `zero_shares` a matching vector of degree-`2t` sharings of
/// zero. The squaring is performed by MulPub: each party squares its own share locally (giving a
/// degree-`2t` sharing) and the zero-sharing re-randomises it before it is opened. The zero-sharing
/// is mandatory, not an optimisation — opening `phi_a(x)^2` unrandomised reveals the whole
/// degree-`2t` polynomial, and its square root gives `+/- phi_a`, hence the bit.
#[derive(Clone, Debug)]
pub struct RandBit<F>
where
    F: FftField,
{
    /// The ID of the node.
    pub id: PartyId,
    /// The number of parties participating in the protocol.
    pub n_parties: usize,
    /// The threshold of corrupted parties.
    pub threshold: usize,
    /// Storage for the protocol.
    pub storage:
        Arc<Mutex<SessionStore<SessionId, (usize, Instant, Arc<Mutex<RandBitStorage<F>>>)>>>,
    /// Opens `a^2` in a single batch-reconstruction round.
    pub mul_pub: MulPubNode<F>,
}
const MAX_RANDBIT_SESSIONS: usize = 512;

impl<F> RandBit<F>
where
    F: FftField,
{
    pub fn new(id: PartyId, n_parties: usize, threshold: usize) -> Result<Self, RandBitError> {
        let mul_pub =
            MulPubNode::new(id, n_parties, threshold).map_err(RandBitError::MulPubError)?;
        Ok(Self {
            id,
            n_parties,
            threshold,
            storage: Arc::new(Mutex::new(SessionStore::with_default_cap())),
            mul_pub,
        })
    }

    pub async fn clear_store(&self, session_id: SessionId) -> bool {
        self.mul_pub.clear_store(session_id).await;

        let mut store = self.storage.lock().await;
        store.retire(session_id)
    }

    pub async fn store_len(&self) -> usize {
        self.storage.lock().await.len()
    }

    pub async fn get_or_create_storage(
        &self,
        session_id: SessionId,
        initiator_id: usize,
    ) -> Option<Arc<Mutex<RandBitStorage<F>>>> {
        self.storage
            .lock()
            .await
            .get_or_admit(
                session_id,
                initiator_id,
                MAX_RANDBIT_SESSIONS,
                MAX_RANDBIT_SESSIONS / self.n_parties,
                || Arc::new(Mutex::new(RandBitStorage::empty())),
            )
            .ok()
    }

    pub async fn wait_for_result(
        &self,
        session_id: SessionId,
        duration: Duration,
    ) -> Result<Vec<RobustShare<F>>, RandBitError> {
        let output_receiver = {
            let storage = self.storage.lock().await;
            let storage_bind = match storage.get(&session_id) {
                Some((_, _, arc)) => arc,
                None => return Err(RandBitError::NoSuchSessionId(session_id)),
            };
            let mut storage = storage_bind.lock().await;

            storage
                .output_receiver
                .take()
                .ok_or(RandBitError::ResultAlreadyReceived(session_id))?
        };

        match timeout(duration, output_receiver).await {
            Err(_) => Err(RandBitError::Timeout(session_id)),
            Ok(Err(_)) => Err(RandBitError::ReceiveError(session_id)),
            Ok(Ok(shares)) => Ok(shares),
        }
    }

    /// Computes `[a^2]` via MulPub (public opening), then derives the random bit
    /// `[d] = ([a]/sqrt(a^2) + 1) / 2`.
    ///
    /// `zero_shares`: one degree-`2t` sharing of zero per element of `a`.
    pub async fn init<N>(
        &mut self,
        a: Vec<RobustShare<F>>,
        zero_shares: Vec<RobustShare<F>>,
        session_id: SessionId,
        duration: Duration,
        network: Arc<N>,
    ) -> Result<(), RandBitError>
    where
        N: Network + Send + Sync + 'static,
    {
        if a.len() != zero_shares.len() {
            return Err(RandBitError::Incompatible);
        }
        // No constraint on `a.len()` beyond that: MulPub pads its last group internally and
        // enforces its own per-session batch ceiling, so the `2t+1` grouping stays its business.
        // Callers that may exceed it chunk against `mul_pub.max_batch_size()`.

        assert!(session_id.calling_protocol().is_some());
        assert_eq!(session_id.sub_id(), 0);
        assert_eq!(session_id.round_id(), 0);

        // Mark the protocol as initialized.
        {
            let storage_bind = match self.get_or_create_storage(session_id, self.id).await {
                Some(s) => s,
                None => return Ok(()),
            };
            let mut storage = storage_bind.lock().await;
            storage.protocol_state = ProtocolState::Initialized;
            storage.a_share = Some(a.clone());
        }

        self.mul_pub
            .init(session_id, a.clone(), a.clone(), zero_shares, network)
            .await
            .map_err(RandBitError::MulPubError)?;

        let a_square_vals = self
            .mul_pub
            .wait_for_result(session_id, duration)
            .await
            .map_err(RandBitError::MulPubError)?;

        // `a = 0` happens with probability ~1/|F| per input. Dropping the affected index costs one
        // bit rather than the whole batch; the caller tops the pool back up on the next round.
        let two_inv = (F::one() + F::one())
            .inverse()
            .ok_or(RandBitError::Inverse)?;
        let mut d_share_array = Vec::with_capacity(a.len());
        for (a_share, a_square) in a.iter().zip(&a_square_vals) {
            if a_square.is_zero() {
                warn!(
                    node_id = self.id,
                    ?session_id,
                    "RandBit: dropping input whose square opened to zero"
                );
                continue;
            }
            let b = a_square.sqrt().ok_or(RandBitError::SquareRoot)?;
            let b_inv = b.inverse().ok_or(RandBitError::Inverse)?;
            let c_share = a_share.clone().mul(b_inv)?;
            d_share_array.push(c_share.add(F::one())?.mul(two_inv)?);
        }

        let storage_bind = match self.get_or_create_storage(session_id, self.id).await {
            Some(s) => s,
            None => return Ok(()),
        };
        let mut storage = storage_bind.lock().await;
        if storage.protocol_state == ProtocolState::Finished {
            return Ok(());
        }
        storage.protocol_state = ProtocolState::Finished;
        storage.protocol_output = Some(d_share_array.clone());
        let sender = storage
            .output_sender
            .take()
            .ok_or(RandBitError::SendError(session_id))?;
        sender
            .send(d_share_array)
            .map_err(|_| RandBitError::SendError(session_id))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;

    #[tokio::test]
    async fn test_randbit_storage_limit() {
        let node = RandBit::<Fr>::new(0, 5, 1).unwrap();

        // Fill up storage to the per-peer limit (MAX_RANDBIT_SESSIONS / n_parties)
        let per_peer_limit = super::MAX_RANDBIT_SESSIONS / 5;
        for i in 0..per_peer_limit {
            let session_id = SessionId::new(
                crate::honeybadger::ProtocolType::RandBit,
                SessionId::pack_slot(i as u64, 0, 0),
                111,
            );
            let _ = node.get_or_create_storage(session_id, 0).await;
        }
        assert_eq!(node.store_len().await, per_peer_limit);

        // One more session from the same peer should be silently rejected
        let session_id = SessionId::new(
            crate::honeybadger::ProtocolType::RandBit,
            SessionId::pack_slot(per_peer_limit as u64, 0, 0),
            111,
        );
        let result = node.get_or_create_storage(session_id, 0).await;
        assert!(
            result.is_none(),
            "Should reject sessions past the per-peer limit"
        );
    }
}
