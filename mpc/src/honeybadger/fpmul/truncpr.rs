use crate::honeybadger::fpmul::mod_pow_2_from_field;
use crate::{
    common::{ProtocolSessionId, SecretSharingScheme, RBC},
    honeybadger::{
        fpmul::{pow2_f, TruncPrError, TruncPrMessage, TruncPrStore, TruncState},
        robust_interpolate::robust_interpolate::RobustShare,
        SessionId, WrappedMessage,
    },
};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::{collections::HashMap, sync::Arc};
use stoffelnet::network_utils::Network;
use tokio::{
    sync::Mutex,
    time::{timeout, Duration},
};
use tracing::info;

#[derive(Debug, Clone)]
pub struct TruncPrNode<F: PrimeField, R: RBC> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    pub store: Arc<Mutex<HashMap<SessionId, Arc<Mutex<TruncPrStore<F>>>>>>,
    pub rbc: R,
}

impl<F: PrimeField, R: RBC<Id = SessionId>> TruncPrNode<F, R> {
    pub fn new(id: usize, n: usize, t: usize) -> Result<Self, TruncPrError> {
        let rbc = R::new(id, n, t, t + 1, Arc::new(WrappedMessage::rbc_wrap))?;
        Ok(Self {
            id,
            n,
            t,
            store: Arc::new(Mutex::new(HashMap::new())),
            rbc,
        })
    }

    pub async fn get_or_create_store(&mut self, session: SessionId) -> Arc<Mutex<TruncPrStore<F>>> {
        let mut map = self.store.lock().await;

        // should always hold, since only exec ID changes between different sessions
        assert!(map.len() <= 256);

        map.entry(session)
            .or_insert((|| Arc::new(Mutex::new(TruncPrStore::empty())))())
            .clone()
    }

    pub async fn clear_store(&self) {
        let mut store = self.store.lock().await;
        self.rbc.clear_store().await;
        store.clear();
    }

    pub async fn wait_for_result(
        &self,
        session_id: SessionId,
        duration: Duration,
    ) -> Result<RobustShare<F>, TruncPrError> {
        let output_receiver = {
            let storage = self.store.lock().await;
            let storage_bind = match storage.get(&session_id) {
                Some(value) => value,
                None => return Err(TruncPrError::SessionIdError(session_id)),
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
        let (_, c) = RobustShare::recover_secret(&shares, self.n)?;
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
        info!(node_id = self.id, "TruncPr start");

        let calling_proto = match session.calling_protocol() {
            Some(proto) => proto,
            None => {
                return Err(TruncPrError::SessionIdError(session));
            }
        };

        let store = self.get_or_create_store(session).await; // k,m already set in store
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
        drop(s);
        if self.try_finalize(session, store.clone()).await? {
            return Ok(());
        }
        // [r] = 2^m [r''] + [r']
        let r = ((r_int * pow2_f::<F>(m))? + r_dash)?;

        // share of (b + r)
        let open_share = (b + r)?;

        // serialize and broadcast
        let mut payload = Vec::new();
        open_share.serialize_compressed(&mut payload)?;
        let wrapped = WrappedMessage::Trunc(TruncPrMessage::new(self.id, session, payload));
        let bytes_wrapped = bincode::serialize(&wrapped)?;

        let sessionid = SessionId::new(
            calling_proto,
            SessionId::pack_slot24(session.exec_id(), 0, self.id as u8),
            session.instance_id(),
        );
        self.rbc
            .init(
                bytes_wrapped,
                sessionid, // A unique session id per node
                Arc::clone(&network),
            )
            .await?;
        Ok(())
    }

    async fn handle_open(&mut self, msg: TruncPrMessage) -> Result<(), TruncPrError> {
        info!(
            node_id = self.id,
            sender = msg.sender_id,
            "TruncPr open handler"
        );

        if msg.session_id.sub_id() != 0 || msg.session_id.round_id() != 0 {
            return Err(TruncPrError::SessionIdError(msg.session_id));
        }

        let store = self.get_or_create_store(msg.session_id).await;
        let mut s = store.lock().await;

        if s.state == TruncState::Finished {
            return Ok(());
        }
        // de-serialize incoming share of (b + r)
        let share_i: RobustShare<F> =
            CanonicalDeserialize::deserialize_compressed(msg.payload.as_slice())?;

        // dedup
        if s.open_buf.contains_key(&msg.sender_id) {
            return Err(TruncPrError::Duplicate(msg.sender_id));
        }
        s.open_buf.insert(msg.sender_id, share_i);

        drop(s);
        self.try_finalize(msg.session_id, store.clone()).await?;

        Ok(())
    }

    /// Handle received messages
    pub async fn process<N: Network>(
        &mut self,
        msg: TruncPrMessage,
        _network: Arc<N>,
    ) -> Result<(), TruncPrError> {
        self.handle_open(msg).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::rbc::rbc::Avid;
    use crate::honeybadger::fpmul::{TruncPrError, TruncPrMessage};
    use crate::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
    use crate::honeybadger::SessionId;
    use ark_bls12_381::Fr;
    use ark_serialize::CanonicalSerialize;

    #[tokio::test]
    async fn test_truncpr_handle_open_invalid_sub_id() {
        let mut node = TruncPrNode::<Fr, Avid<SessionId>>::new(0, 5, 1).unwrap();

        // Create a session id with sub_id != 0
        let session_id = SessionId::new(
            crate::honeybadger::ProtocolType::Trunc,
            SessionId::pack_slot24(0, 1, 0),
            111,
        );

        // Create a dummy payload
        let dummy_share = RobustShare::new(Fr::from(1u8), 0, 1);
        let mut payload = Vec::new();
        dummy_share.serialize_compressed(&mut payload).unwrap();

        let msg = TruncPrMessage::new(0, session_id, payload);

        // Should return a SessionIdError due to sub_id != 0
        let result = node.handle_open(msg).await;
        match result {
            Err(TruncPrError::SessionIdError(sid)) => assert_eq!(sid, session_id),
            _ => panic!("Expected SessionIdError for invalid sub_id"),
        }
    }
}
