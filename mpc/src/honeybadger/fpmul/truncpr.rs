use crate::{
    common::{share::ShareError, ProtocolSessionId, SecretSharingScheme, RBC},
    honeybadger::{
        fpmul::{
            mod_pow_2_from_field, pow2_f, TruncPrError, TruncPrMessage, TruncPrStore, TruncState,
        },
        robust_interpolate::robust_interpolate::RobustShare,
        SessionId, WrappedMessage, MAX_MESSAGE_SIZE,
    },
};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bincode::Options;
use std::{collections::HashMap, sync::Arc};
use stoffelnet::network_utils::Network;
use tokio::{
    sync::{
        mpsc::{self, Receiver},
        Mutex,
    },
    time::{timeout, Duration},
};
use tracing::{error, info, warn};

#[derive(Debug, Clone)]
pub struct TruncPrNode<F: PrimeField, R: RBC> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    pub store: Arc<Mutex<HashMap<SessionId, Arc<Mutex<TruncPrStore<F>>>>>>,
    pub rbc: R,
    pub rbc_output: Arc<Mutex<Receiver<SessionId>>>,
}

impl<F: PrimeField, R: RBC<Id = SessionId>> TruncPrNode<F, R> {
    pub fn new(id: usize, n: usize, t: usize) -> Result<Self, TruncPrError> {
        let (rbc_sender, rbc_receiver) = mpsc::channel(200);

        let rbc = R::new(
            id,
            n,
            t,
            t + 1,
            rbc_sender,
            Arc::new(WrappedMessage::rbc_wrap),
        )?;
        Ok(Self {
            id,
            n,
            t,
            store: Arc::new(Mutex::new(HashMap::new())),
            rbc,
            rbc_output: Arc::new(Mutex::new(rbc_receiver)),
        })
    }

    pub async fn drain_rbc_output(&mut self) -> Result<(), TruncPrError> {
        info!(node_id = self.id, "TruncPr is draining RBC output");
        loop {
            let id = {
                let mut rx = self.rbc_output.lock().await;
                match rx.try_recv() {
                    Ok(id) => id,
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        error!(
                            node_id = self.id,
                            "Channel for RBC in TruncPr is disconnected"
                        );
                        return Err(TruncPrError::Abort);
                    }
                }
            };

            let output = self.rbc.get_store(id).await?;
            let mut msg: TruncPrMessage = bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .allow_trailing_bytes()
                .with_limit(MAX_MESSAGE_SIZE)
                .deserialize(&output)?;
            let authenticated_sender = id.sub_id() as usize;
            if msg.sender_id != authenticated_sender {
                warn!(
                    "Dropping RBC output: inner sender_id {} does not match session round_id {}",
                    msg.sender_id, authenticated_sender
                );
                continue;
            }
            if msg.session_id.exec_id() != id.exec_id()
                || msg.session_id.instance_id() != id.instance_id()
            {
                warn!("Dropping RBC output: inner session_id does not match RBC session metadata");
                continue;
            }
            if msg.session_id.round_id() != id.round_id() || msg.session_id.sub_id() != 0 {
                warn!("Dropping RBC output: inner session metadata does not match RBC session metadata");
                continue;
            }

            msg.sender_id = authenticated_sender;
            info!(
                node_id = self.id,
                "TruncPr received RBC output for open handler"
            );
            match self.handle_open(msg).await {
                Ok(()) => {}
                Err(e) => {
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    pub async fn get_or_create_store(
        &mut self,
        session: SessionId,
    ) -> Result<Arc<Mutex<TruncPrStore<F>>>, TruncPrError> {
        let mut map = self.store.lock().await;
        // At capacity: evict the oldest (min-id) session to admit the new one
        // rather than aborting the node. Keeps the store bounded against
        // late-message resurrection instead of fatally failing.
        if map.len() >= 256 && !map.contains_key(&session) {
            if let Some(oldest) = map.keys().min().copied() {
                map.remove(&oldest);
                warn!(evicted = ?oldest, "TruncPr session store full; evicted oldest session");
            }
        }
        Ok(map
            .entry(session)
            .or_insert((|| Arc::new(Mutex::new(TruncPrStore::empty())))())
            .clone())
    }

    pub async fn clear_store(&self, session_id: SessionId) -> Result<(), TruncPrError> {
        // Clear only THIS session's per-dealer RBC broadcast sessions (keyed
        // `(exec_id, dealer_id, 0)`; see `open` above), via the reuse-safe
        // per-session clear that records them as cleared. The old no-arg
        // `rbc.clear_store()` wiped the ENTIRE AVID store, killing in-flight
        // sessions of other/concurrent truncations ("Session ID does not exist")
        // and corrupting their opened values.
        if let Some(calling_proto) = session_id.calling_protocol() {
            for p in 0..self.n {
                let rbc_id = SessionId::new(
                    calling_proto,
                    SessionId::pack_slot24(session_id.exec_id(), p as u8, 0),
                    session_id.instance_id(),
                );
                self.rbc.clear_session(rbc_id).await;
            }
        }
        let mut store = self.store.lock().await;
        store
            .remove(&session_id)
            .map(|_| ())
            .ok_or(TruncPrError::ClearStoreError(session_id))
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
                    Some(inner_store) => inner_store.clone(),
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

        let calling_proto = match session.calling_protocol() {
            Some(proto) => proto,
            None => {
                return Err(TruncPrError::SessionIdError(session));
            }
        };

        let store = self.get_or_create_store(session).await?; // k,m already set in store
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

        // serialize and broadcast
        let mut payload = Vec::new();
        open_share.serialize_compressed(&mut payload)?;
        let wrapped = TruncPrMessage::new(self.id, session, payload);
        let bytes_wrapped = bincode::serialize(&wrapped)?;

        let session_id = SessionId::new(
            calling_proto,
            SessionId::pack_slot24(session.exec_id(), self.id as u8, 0),
            session.instance_id(),
        );
        self.rbc
            .init(
                bytes_wrapped,
                session_id, // A unique session id per node
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
            error!(
                "Wrong session. Sub ID or Round ID is not zero. Session ID: {:?}",
                msg.session_id
            );
            return Err(TruncPrError::SessionIdError(msg.session_id));
        }

        let store = self.get_or_create_store(msg.session_id).await?;
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
