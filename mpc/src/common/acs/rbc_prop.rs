use std::{
    collections::{hash_map::Entry, HashMap},
    sync::Arc,
};

use stoffelnet::network_utils::Network;
use tokio::sync::{
    mpsc::{self, error::TryRecvError, Receiver},
    watch, Mutex,
};
use tracing::warn;

use crate::common::{
    acs::{
        is_acs_session_id, parent_session_id, sub_session_id, AcsProposals, MAX_PARTIES,
        PROPOSALS_ROUND,
    },
    rbc::{rbc_store::Msg, RbcError},
    ProtocolSessionId, RbcWrapFn, RBC,
};

/// How many deliveries the RBC may report before one is drained.
///
/// Backpressure here is safe rather than deadlocking: the sender is the RBC, inside
/// [`RBC::process`], and every entry point of this layer drains the channel before it returns, so a
/// caller blocked on a full channel is freed by the next one through.
const MAX_PENDING_DELIVERIES: usize = 120;

#[derive(thiserror::Error, Debug)]
pub enum RbcProposalError<S> {
    /// A session ID whose protocol tag this build does not recognize. Returned rather than
    /// unwrapped: the tag travels on the wire, so a peer can put anything there.
    #[error("session ID {0:?} carries an unrecognized protocol tag")]
    UnknownProtocol(S),
    /// See [`is_acs_session_id`]. Raised for the *parent* IDs this layer is handed, never for the
    /// sub-session IDs it derives from them.
    #[error("session ID {0:?} is not a well-formed ACS session ID: sub_id and round_id must be 0")]
    MalformedSessionId(S),
    #[error("a message for session {found:?} was routed to session {expected:?}")]
    SessionIdMismatch { expected: S, found: S },
    #[error("party ID {id} is out of range for {n_parties} parties")]
    InvalidPartyId { id: usize, n_parties: usize },
    /// See [`MAX_PARTIES`].
    #[error("n = {n_parties} parties exceeds the {} the session ID space addresses", MAX_PARTIES)]
    TooManyParties { n_parties: usize },
    #[error("error in the RBC: {0:?}")]
    Rbc(#[from] RbcError),
    /// Unreachable while this layer is alive: the sending half lives in the RBC this struct owns.
    #[error("the channel of RBC deliveries closed")]
    DeliveryChannelClosed,
}

/// The proposal layer of a classic ACS: one reliable broadcast per party.
///
/// `j` is justified when `RBC_j` delivers, which is step 2 of Figure 4 of HoneyBadgerBFT. That is
/// the condition [`AcsProposals::justified`] needs, because RBC agreement gives exactly the missing
/// half: if the broadcast delivered at one correct party it eventually delivers at all of them, so
/// an `ABA_j` that decides 1 cannot leave anyone waiting forever for `v_j`.
///
/// Payloads are opaque here. What a proposal *means* is the caller's business, and keeping this
/// layer to `Vec<u8>` is what keeps a decoding failure — on bytes a Byzantine dealer chose — out of
/// the agreement path, where there would be nothing sensible to do about it.
pub struct RbcProposal<R, S>
where
    R: RBC<Id = S>,
    S: ProtocolSessionId,
{
    /// This party's index, and the `sub_id` its own broadcast goes out under.
    id: usize,
    n_parties: usize,
    rbc: R,
    /// Receiving end of the channel the RBC reports delivered sessions on.
    ///
    /// Behind a `Mutex` because draining needs `&mut` while every entry point here takes `&self`.
    deliveries: Mutex<Receiver<S>>,
    /// Per ACS session, the justified map `T_i` this layer publishes.
    ///
    /// Keyed by the *parent* ID, since that is what [`AcsProposals::justified`] is asked for; the
    /// `RBC_j` a delivery arrives under is inverted back to it with [`parent_session_id`].
    store: Mutex<HashMap<S, watch::Sender<HashMap<usize, Vec<u8>>>>>,
}

impl<R, S> RbcProposal<R, S>
where
    R: RBC<Id = S>,
    S: ProtocolSessionId,
{
    pub fn new(
        id: usize,
        n_parties: usize,
        threshold: usize,
        k: usize,
        wrapper: RbcWrapFn<S>,
    ) -> Result<Self, RbcProposalError<S>> {
        // Checked once here so that `sub_session_id` can narrow a party index to the one byte
        // `sub_id` gives it without two `RBC_j` silently landing on the same session.
        if n_parties > MAX_PARTIES {
            return Err(RbcProposalError::TooManyParties { n_parties });
        }
        if id >= n_parties {
            return Err(RbcProposalError::InvalidPartyId { id, n_parties });
        }
        let (tx, rx) = mpsc::channel(MAX_PENDING_DELIVERIES);
        let rbc = R::new(id, n_parties, threshold, k, tx, wrapper)?;
        Ok(Self {
            id,
            n_parties,
            rbc,
            deliveries: Mutex::new(rx),
            store: Mutex::new(HashMap::new()),
        })
    }

    /// [`sub_session_id`] for the `RBC_index` of `session_id`, named against this error type.
    fn rbc_session_id(session_id: S, index: usize) -> Result<S, RbcProposalError<S>> {
        sub_session_id(session_id, PROPOSALS_ROUND, index)
            .ok_or(RbcProposalError::UnknownProtocol(session_id))
    }

    /// Records that `RBC_index` of `session_id` delivered `payload`.
    ///
    /// The first delivery for an index wins and is the only one that wakes the subscribers of
    /// [`AcsProposals::justified`], so a second one cannot displace a proposal this party may
    /// already have voted 1 on.
    async fn justify(&self, session_id: S, index: usize, payload: Vec<u8>) {
        self.store
            .lock()
            .await
            .entry(session_id)
            .or_insert_with(|| watch::Sender::new(HashMap::new()))
            .send_if_modified(|justified| match justified.entry(index) {
                Entry::Occupied(_) => false,
                Entry::Vacant(slot) => {
                    slot.insert(payload);
                    true
                }
            });
    }

    /// Moves every delivery the RBC has reported so far into the justified maps.
    ///
    /// Called at the end of each entry point rather than from a task of its own: the RBC pushes a
    /// session ID before [`RBC::process`] returns, so by the time a message that completes `RBC_j`
    /// has been handled, the delivery is already waiting here.
    async fn drain_deliveries(&self) -> Result<(), RbcProposalError<S>> {
        loop {
            let delivered = { self.deliveries.lock().await.try_recv() };
            let sub_sid = match delivered {
                Ok(sub_sid) => sub_sid,
                Err(TryRecvError::Empty) => return Ok(()),
                Err(TryRecvError::Disconnected) => {
                    return Err(RbcProposalError::DeliveryChannelClosed)
                }
            };

            // Everything the delivery is filed under comes from the ID the RBC delivered under, and
            // none of it from the payload the dealer itself wrote: `sub_id` says who broadcast, and
            // inverting the ID says which ACS session it belongs to. A field for either inside the
            // payload would let a dealer claim another party's slot, or another session's.
            let index = sub_sid.sub_id() as usize;
            if index >= self.n_parties || sub_sid.round_id() != PROPOSALS_ROUND {
                warn!(session_id = ?sub_sid, "dropping an RBC delivery addressed outside this layer");
                continue;
            }
            let Some(session_id) = parent_session_id(sub_sid) else {
                warn!(session_id = ?sub_sid, "dropping an RBC delivery whose session cannot be inverted");
                continue;
            };

            let payload = match self.rbc.get_store(sub_sid).await {
                Ok(payload) => payload,
                // A delivery for a session cleared under us: stale, not a reason to stop draining.
                Err(RbcError::Internal(message)) if message.contains("does not exist") => {
                    warn!(session_id = ?sub_sid, "ignoring an RBC delivery for a cleared session");
                    continue;
                }
                Err(error) => return Err(error.into()),
            };

            self.justify(session_id, index, payload).await;
        }
    }
}

impl<R, S> AcsProposals for RbcProposal<R, S>
where
    R: RBC<Id = S>,
    S: ProtocolSessionId,
{
    type SessionId = S;
    type Error = RbcProposalError<S>;
    type Message = Msg<S>;
    type Input = Vec<u8>;
    type Item = Vec<u8>;

    /// Broadcasts `value` under this party's own index.
    ///
    /// `RBC_i`'s `sub_id` is the only statement of who proposed it, and what every other party keys
    /// the proposal by; see [`Self::drain_deliveries`].
    async fn propose<N>(
        &self,
        value: Self::Input,
        sid: Self::SessionId,
        net: Arc<N>,
    ) -> Result<(), Self::Error>
    where
        N: Network + Send + Sync + 'static,
    {
        if !is_acs_session_id(sid) {
            return Err(RbcProposalError::MalformedSessionId(sid));
        }
        self.rbc
            .init(value, Self::rbc_session_id(sid, self.id)?, net)
            .await?;
        self.drain_deliveries().await
    }

    async fn justified(
        &self,
        sid: Self::SessionId,
    ) -> watch::Receiver<HashMap<usize, Self::Item>> {
        self.store
            .lock()
            .await
            .entry(sid)
            .or_insert_with(|| watch::Sender::new(HashMap::new()))
            .subscribe()
    }

    /// Feeds one RBC message to the instance it names, then collects whatever it delivered.
    ///
    /// `sid` is the `RBC_j` sub-session the ACS routed by, and a message naming a different session
    /// is rejected rather than handed to the RBC, which would otherwise open state under the ID
    /// inside the message — an ID no `clear_session` of this layer reaches.
    async fn process<N>(
        &self,
        sid: Self::SessionId,
        message: Self::Message,
        net: Arc<N>,
    ) -> Result<(), Self::Error>
    where
        N: Network + Send + Sync + 'static,
    {
        if message.session_id != sid {
            return Err(RbcProposalError::SessionIdMismatch {
                expected: sid,
                found: message.session_id,
            });
        }
        self.rbc.process(message, net).await?;
        self.drain_deliveries().await
    }

    async fn clear_session(&self, session_id: Self::SessionId) -> Result<(), Self::Error> {
        // Checked before anything is derived from it: a malformed parent would address, and so
        // clear, the broadcasts of some other ACS session.
        if !is_acs_session_id(session_id) {
            return Err(RbcProposalError::MalformedSessionId(session_id));
        }
        self.store.lock().await.remove(&session_id);
        for index in 0..self.n_parties {
            self.rbc
                .clear_session(Self::rbc_session_id(session_id, index)?)
                .await;
        }
        Ok(())
    }

    async fn clear_store(&self) -> Result<(), Self::Error> {
        self.store.lock().await.clear();
        self.rbc.clear_store().await;
        Ok(())
    }
}
