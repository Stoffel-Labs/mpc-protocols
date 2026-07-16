use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use bincode::ErrorKind;
use serde::{Deserialize, Serialize};
use stoffelnet::network_utils::{Network, NetworkError};
use tokio::sync::{mpsc::Sender, Mutex};

use crate::{avss_mpc::AvssSessionId, common::aba::TaggedMessage, honeybadger::WrappedMessage};

#[derive(thiserror::Error, Debug)]
pub enum BvBroadcastError {
    #[error("there was an error in the network: {0:?}")]
    NetworkError(#[from] NetworkError),

    #[error("Unknown message type: {0:?}")]
    UnknownMessageType(TaggedMessage),

    #[error("error while serializing the object into bytes: {0:?}")]
    SerializationError(#[from] Box<ErrorKind>),
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub(crate) struct BvBroadcastMessage<I> {
    pub sender_id: usize,       // ID of the sender node
    pub session_id: I,          // Unique session ID for each broadcast instance
    pub round_id: usize,        //Round ID
    pub payload: TaggedMessage, // Actual data being broadcasted (e.g., bytes of a secret or message)
}

impl BvBroadcastMessage<AvssSessionId> {
    pub fn new(
        sender_id: usize,
        session_id: AvssSessionId,
        round_id: usize,
        payload: TaggedMessage,
    ) -> Self {
        Self {
            sender_id,
            session_id,
            round_id,
            payload,
        }
    }
}

#[derive(Default, Debug)]
struct BvBroadcastStore {
    bit_sent: bool,
    protocol_ended: bool,
    bin_values: HashSet<(usize, u8)>,
}

pub(crate) struct BvBroadcast<I> {
    id: usize,
    n_parties: usize,
    threshold: usize,
    store: Arc<Mutex<HashMap<I, (usize, Arc<Mutex<BvBroadcastStore>>)>>>,
    output: Sender<I>,
}

fn encode_message_bv_broadcast_avss(
    m: BvBroadcastMessage<AvssSessionId>,
) -> Result<Vec<u8>, BvBroadcastError> {
    let wrapped = WrappedMessage::BvBroadcast(m);
    let bytes = bincode::serialize(&wrapped)?;
    Ok(bytes)
}

impl BvBroadcast<AvssSessionId> {
    pub fn new(
        id: usize,
        n_parties: usize,
        threshold: usize,
        output: Sender<AvssSessionId>,
    ) -> Self {
        Self {
            id,
            store: Arc::new(Mutex::new(HashMap::new())),
            output,
            n_parties,
            threshold,
        }
    }

    pub async fn init<N>(
        &self,
        session_id: AvssSessionId,
        round_id: usize,
        v: u8,
        network: Arc<N>,
    ) -> Result<Option<Vec<u8>>, BvBroadcastError>
    where
        N: Network + Send + Sync,
    {
        for pid in 0..self.n_parties {
            let enc_bit = encode_message_bv_broadcast_avss(BvBroadcastMessage::new(
                self.id,
                session_id,
                round_id,
                TaggedMessage::Binary(v),
            ))?;
            network.send(pid, &enc_bit);
        }

        if let Some(store) = self.get_or_create_store(session_id, self.id).await {
            let bin_values = store
                .lock()
                .await
                .bin_values
                .iter()
                .filter(|(_, inner_v)| *inner_v == v)
                .map(|(_, inner_v)| *inner_v)
                .collect();
            return Ok(Some(bin_values));
        } else {
            // The protocol already ended.
            return Ok(None);
        }
    }

    async fn get_or_create_store(
        &self,
        session_id: AvssSessionId,
        sender_id: usize,
    ) -> Option<Arc<Mutex<BvBroadcastStore>>> {
        let store_lock = {
            let mut store = self.store.lock().await;
            store
                .entry(session_id)
                .or_insert_with(|| (sender_id, Arc::new(Mutex::new(BvBroadcastStore::default()))))
                .1
                .clone()
        };

        {
            let store_guard = store_lock.lock().await;
            if store_guard.protocol_ended {
                return None;
            }
        }
        Some(store_lock)
    }

    pub async fn binary_handle<N>(
        &self,
        message: BvBroadcastMessage<AvssSessionId>,
        network: Arc<N>,
    ) -> Result<(), BvBroadcastError>
    where
        N: Network + Send + Sync,
    {
        let store = match self
            .get_or_create_store(message.session_id, message.sender_id)
            .await
        {
            Some(store) => store,
            // The protocol already ended.
            None => return Ok(()),
        };

        if store.lock().await.bit_sent {
            // The node already sent its bit in Line 6, Algorithm 3.
            return Ok(());
        }

        if let TaggedMessage::Binary(recv_v) = message.payload {
            let n_recv_v = store
                .lock()
                .await
                .bin_values
                .iter()
                .filter(|(_, v)| *v == recv_v)
                .count();

            // We only ask for t as the received one counts as 1, t + 1 in total.
            if n_recv_v == self.threshold {
                let enc_bit = encode_message_bv_broadcast_avss(BvBroadcastMessage::new(
                    self.id,
                    message.session_id,
                    message.round_id,
                    TaggedMessage::Binary(recv_v),
                ))?;
                store.lock().await.bit_sent = true;
                network.broadcast(&enc_bit).await;
            } else if n_recv_v == 2 * self.threshold {
                store
                    .lock()
                    .await
                    .bin_values
                    .insert((message.sender_id, recv_v));
            }
        }

        Ok(())
    }

    pub async fn process<N>(
        &self,
        message: BvBroadcastMessage<AvssSessionId>,
        network: Arc<N>,
    ) -> Result<(), BvBroadcastError>
    where
        N: Network + Send + Sync,
    {
        match message.payload {
            TaggedMessage::Binary(_) => self.binary_handle(message, network).await?,
            unk_msg => return Err(BvBroadcastError::UnknownMessageType(unk_msg)),
        }
        Ok(())
    }
}
