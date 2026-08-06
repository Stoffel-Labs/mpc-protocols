use crate::common::session_store::{Admission, SessionStore};
use crate::{
    common::{share::ShareError, ProtocolSessionId, SecretSharingScheme},
    honeybadger::{
        fpmul::{
            mod_pow_2_from_field, pow2_f, TruncPrError, TruncPrMessage, TruncPrStore, TruncState,
        },
        robust_interpolate::robust_interpolate::RobustShare,
        SessionId, WrappedMessage,
    },
};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::sync::Arc;
use std::time::Instant;
use stoffelnet::network_utils::Network;
use tokio::{
    sync::Mutex,
    time::{timeout, Duration},
};
use tracing::{error, info, warn};

#[derive(Debug, Clone)]
pub struct TruncPrNode<F: PrimeField> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    pub store: Arc<Mutex<SessionStore<SessionId, (usize, Instant, Arc<Mutex<TruncPrStore<F>>>)>>>,
}
const MAX_TRUNCPR_SESSIONS: usize = 1024;

impl<F: PrimeField> TruncPrNode<F> {
    pub fn new(id: usize, n: usize, t: usize) -> Result<Self, TruncPrError> {
        Ok(Self {
            id,
            n,
            t,
            store: Arc::new(Mutex::new(SessionStore::with_default_cap())),
        })
    }

    pub async fn get_or_create_store(
        &mut self,
        session: SessionId,
        initiator_id: usize,
    ) -> Option<Arc<Mutex<TruncPrStore<F>>>> {
        match self.store.lock().await.get_or_admit(
            session,
            initiator_id,
            MAX_TRUNCPR_SESSIONS,
            MAX_TRUNCPR_SESSIONS / self.n,
            || Arc::new(Mutex::new(TruncPrStore::empty())),
        ) {
            Admission::Got(arc) => Some(arc),
            Admission::Retired => None,
            Admission::Rejected => {
                warn!("TruncPr session limit reached");
                None
            }
        }
    }

    pub async fn store_len(&self) -> usize {
        self.store.lock().await.len()
    }

    pub async fn clear_store(&self, session_id: SessionId) -> bool {
        let mut store = self.store.lock().await;
        store.retire(session_id)
    }

    pub async fn wait_for_result(
        &self,
        session_id: SessionId,
        duration: Duration,
    ) -> Result<RobustShare<F>, TruncPrError> {
        let output_receiver = {
            let storage_bind = {
                let storage = self.store.lock().await;
                match storage.get(&session_id) {
                    Some((_, _, arc)) => arc.clone(),
                    None => return Err(TruncPrError::NoSuchSessionId(session_id)),
                }
            };
            let mut storage = storage_bind.lock().await;

            storage
                .output_receiver
                .take()
                .ok_or(TruncPrError::ResultAlreadyReceived(session_id))?
        };

        match timeout(duration, output_receiver).await {
            Err(_) => Err(TruncPrError::Timeout(session_id)),
            Ok(Err(_)) => Err(TruncPrError::ReceiveError(session_id)),
            Ok(Ok(shares)) => Ok(shares),
        }
    }

    async fn try_finalize(
        &self,
        session_id: SessionId,
        store_mutex: Arc<Mutex<TruncPrStore<F>>>,
    ) -> Result<bool, TruncPrError> {
        // ---- phase 1: decide + extract (no side effects) ----
        let (shares, m, r_dash, a) = {
            let s = store_mutex.lock().await;

            if s.state == TruncState::Finished {
                return Ok(true);
            }

            if s.share_a.is_none() || s.r_dash.is_none() {
                return Ok(false);
            }

            if s.open_buf.len() < 2 * self.t + 1 {
                return Ok(false);
            }

            let shares: Vec<RobustShare<F>> = s.open_buf.values().cloned().collect();
            let m = s.m;
            let r_dash = s.r_dash.clone().unwrap();
            let a = s.share_a.clone().unwrap();

            (shares, m, r_dash, a)
        };

        // ---- phase 2: compute outside lock ----
        let (_, c) = RobustShare::recover_secret(&shares, self.n, self.t)?;
        let c_mod = mod_pow_2_from_field::<F>(c, m);

        let a_prime = RobustShare::from_scalar_sub(c_mod, &r_dash);
        let inv_2m = pow2_f::<F>(m).inverse().expect("2^m invertible mod q");
        let d = ((a - a_prime)? * inv_2m)?;

        // ---- phase 3: commit + send (one-shot) ----
        let sender = {
            let mut s = store_mutex.lock().await;

            if s.state == TruncState::Finished {
                return Ok(true);
            }

            s.state = TruncState::Finished;
            s.share_d = Some(d.clone());
            s.open_buf.clear();

            s.output_sender
                .take()
                .ok_or(TruncPrError::SendError(session_id))?
        };

        sender
            .send(d)
            .map_err(|_| TruncPrError::SendError(session_id))?;

        Ok(true)
    }

    /// Start TruncPr:
    /// - builds [r'] and [r] from preseeded randomness,
    /// - forms share of (b + r) where b = 2^{k-1} + [a],
    /// - broadcasts the share for opening.
    pub async fn init<N: Network + Send + Sync>(
        &mut self,
        a: RobustShare<F>,
        k: usize,
        m: usize,
        r_bits: Vec<RobustShare<F>>,
        r_int: RobustShare<F>,
        session: SessionId,
        network: Arc<N>,
    ) -> Result<(), TruncPrError> {
        info!(node_id = self.id, session_id = ?session, "TruncPr start");

        if session.calling_protocol().is_none() {
            return Err(TruncPrError::SessionIdError(session));
        }

        let store = match self.get_or_create_store(session, self.id).await {
            Some(s) => s,
            None => return Ok(()),
        };
        let (r_dash, b) = {
            let mut s = store.lock().await;
            s.k = k;
            s.m = m;
            s.share_a = Some(a.clone());

            // b = 2^{k-1} + [a]   (2^{k-1} is public constant in the field)
            let b = (a + pow2_f::<F>(k - 1))?;

            // [r'] = sum_{i=0}^{m-1} 2^i [r_i]
            let mut r_dash = RobustShare::new(F::zero(), self.id, self.t);
            for (i, bit_share) in r_bits.iter().take(m).enumerate() {
                r_dash = (r_dash + (bit_share.clone() * pow2_f::<F>(i))?)?;
            }
            s.r_dash = Some(r_dash.clone());
            s.state = TruncState::Initialized;
            (r_dash, b)
        };

        if self.try_finalize(session, store.clone()).await? {
            return Ok(());
        }

        // [r] = 2^m [r''] + [r']
        let r = ((r_int * pow2_f::<F>(m))? + r_dash)?;

        // share of (b + r)
        let open_share = (b + r)?;

        // Serialize and broadcast directly (point-to-point). Robust reconstruction in
        // `try_finalize` tolerates up to `t` bad shares among the received ones, so this
        // doesn't need RBC's reliable-broadcast agreement.
        let mut payload = Vec::new();
        open_share.serialize_compressed(&mut payload)?;
        let trunc_msg = TruncPrMessage::new(self.id, session, payload);
        let wrapped = WrappedMessage::Trunc(trunc_msg);
        let bytes_wrapped = bincode::serialize(&wrapped)?;

        network.broadcast(&bytes_wrapped).await?;
        Ok(())
    }

    pub async fn process(&mut self, msg: TruncPrMessage) -> Result<(), TruncPrError> {
        info!(
            node_id = self.id,
            sender = msg.sender_id,
            "TruncPr open handler"
        );

        if msg.session_id.sub_id() != 0 || msg.session_id.round_id() != 0 {
            error!(
                "Wrong session. Sub ID or Round ID is not zero. Session ID: {:?}",
                msg.session_id
            );
            return Err(TruncPrError::SessionIdError(msg.session_id));
        }

        let store = match self
            .get_or_create_store(msg.session_id, msg.sender_id)
            .await
        {
            Some(s) => s,
            None => return Ok(()),
        };
        {
            let mut s = store.lock().await;

            if s.state == TruncState::Finished {
                return Ok(());
            }
            // deserialize incoming share of (b + r)
            let share_i: RobustShare<F> =
                CanonicalDeserialize::deserialize_compressed(msg.payload.as_slice())?;
            if share_i.id != msg.sender_id {
                return Err(ShareError::IdMismatch.into());
            }
            if share_i.degree != self.t {
                return Err(ShareError::DegreeMismatch.into());
            }
            // dedup
            if s.open_buf.contains_key(&msg.sender_id) {
                error!(
                    "Shares where already received from sender {:?}",
                    msg.sender_id
                );
                return Err(TruncPrError::Duplicate(msg.sender_id));
            }
            s.open_buf.insert(msg.sender_id, share_i);
        }

        self.try_finalize(msg.session_id, store.clone()).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::honeybadger::fpmul::{TruncPrError, TruncPrMessage};
    use crate::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
    use crate::honeybadger::SessionId;
    use ark_bls12_381::Fr;
    use ark_serialize::CanonicalSerialize;

    #[tokio::test]
    async fn test_truncpr_handle_open_invalid_sub_id() {
        let mut node = TruncPrNode::<Fr>::new(0, 5, 1).unwrap();

        // Create a session id with sub_id != 0
        let session_id = SessionId::new(
            crate::honeybadger::ProtocolType::Trunc,
            SessionId::pack_slot(0, 1, 0),
            111,
        );

        // Create a dummy payload
        let dummy_share = RobustShare::new(Fr::from(1u8), 0, 1);
        let mut payload = Vec::new();
        dummy_share.serialize_compressed(&mut payload).unwrap();

        let msg = TruncPrMessage::new(0, session_id, payload);

        // Should return a SessionIdError due to sub_id != 0
        let result = node.process(msg).await;
        match result {
            Err(TruncPrError::SessionIdError(sid)) => assert_eq!(sid, session_id),
            _ => panic!("Expected SessionIdError for invalid sub_id"),
        }
    }
}
