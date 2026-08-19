use std::{
    collections::{BTreeMap, HashMap, HashSet},
    future::Future,
    sync::Arc,
};

use crate::common::{
    aba::{Aba, BinValue, Decision},
    acs::{
        is_acs_session_id, sub_session_id, Acs, AcsOutput, AcsProposals, ABA_ROUND, MAX_PARTIES,
        PROPOSALS_ROUND,
    },
    ProtocolSessionId,
};
use serde::{de::DeserializeOwned, Serialize};
use stoffelnet::network_utils::Network;
use thiserror::Error;
use tokio::{
    sync::{mpsc, watch, Mutex},
    task::JoinHandle,
};
use tracing::warn;

#[derive(Error, Debug)]
pub enum HbAcsError<I> {
    #[error("error while sending the readyness of the ABA")]
    SendErrorAbaCheck(#[from] mpsc::error::SendError<usize>),
    #[error("error while receiving the readyness of the ABA")]
    RecvErrorAbaCheck(#[from] watch::error::RecvError),
    #[error("a message for session {found:?} was routed to session {expected:?}")]
    SessionIdMismatch { expected: I, found: I },
    /// A session ID whose protocol tag this build does not recognize. Returned rather than
    /// unwrapped: the tag travels on the wire, so a peer can put anything there.
    #[error("session ID {0:?} carries an unrecognized protocol tag")]
    UnknownProtocol(I),
    /// See [`is_acs_session_id`].
    #[error("session ID {0:?} is not a well-formed ACS session ID: sub_id and round_id must be 0")]
    MalformedSessionId(I),
    #[error("n = {n_parties} parties cannot tolerate t = {threshold} Byzantine ones, since ACS needs n >= 3t + 1")]
    InvalidThreshold { n_parties: usize, threshold: usize },
    /// See [`MAX_PARTIES`].
    #[error("n = {n_parties} parties exceeds the {} the session ID space addresses", MAX_PARTIES)]
    TooManyParties { n_parties: usize },
    /// Boxed rather than generic in the ABA: a `HbAcsError: From<A::Error>` bound would need a
    /// hand-written `From` impl for every ABA this is instantiated with, and [`Aba::Error`] already
    /// guarantees the `Error + Send + Sync + 'static` this box needs.
    #[error("error in the ABA: {0}")]
    AbaError(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// Boxed for the same reason as [`Self::AbaError`], with [`AcsProposals::Error`] carrying the
    /// same guarantee.
    #[error("error in the proposal layer: {0}")]
    ProposalsError(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("session ID not found: {0:?}")]
    SessionIdNotFound(I),
    /// An index that no party answers to. Rejected rather than forwarded: `sub_id` travels on the
    /// wire, so a peer can put anything there.
    #[error("session ID {session_id:?} addresses instance {index}, but there are only {n_parties} parties")]
    InvalidPartyIndex {
        session_id: I,
        index: usize,
        n_parties: usize,
    },
    /// See [`HbAcs::process`].
    #[error("a message was routed to session {0:?}, whose round tag does not match the kind of message it is")]
    MisroutedMessage(I),
    /// Step 4 was waiting on the layer's justifications when the session was cleared under it.
    #[error("the channel of justified indexes closed: {0:?}")]
    JustificationChannelClosed(#[source] watch::error::RecvError),
    /// Unreachable: the wait returns only once the index is present, and entries are never removed.
    /// An error rather than an `unwrap`, as with
    /// [`CrainAbaError::MissingView`](crate::common::aba::crain_aba::CrainAbaError::MissingView).
    #[error("index {0} was reported as justified but is missing")]
    MissingJustification(usize),
}

impl<I> HbAcsError<I> {
    /// Wraps an [`Aba::Error`] into [`HbAcsError::AbaError`], for use with `map_err`.
    fn from_aba<E>(error: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::AbaError(Box::new(error))
    }

    /// Wraps an [`AcsProposals::Error`] into [`HbAcsError::ProposalsError`], for use with `map_err`.
    fn from_proposals<E>(error: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::ProposalsError(Box::new(error))
    }
}

/// Every message this ACS routes, from either of the two layers beneath it.
///
/// This is the [`Acs::Message`] of [`HbAcs`], and exists so that a dispatcher hands everything
/// addressed to the ACS through the single [`HbAcs::process`] entry point, without having to know
/// whether a given message drives a proposal instance or an ABA.
///
/// The ACS itself sends nothing: every message on the wire belongs to one of the layers, which
/// serialize their own types. So this is not a wire format either — it is what a dispatcher wraps
/// *after* decoding, and it carries no session ID of its own, since the one the message named is
/// what the dispatcher routed by and is passed alongside.
#[derive(Clone, Debug)]
pub enum HbAcsMessage<P, A> {
    /// A message of the proposal layer, addressed under [`PROPOSALS_ROUND`].
    Proposals(P),
    /// A message of the ABA stack, addressed under [`ABA_ROUND`].
    Aba(A),
}

pub struct HbAcsStore<T> {
    /// The agreed subset once step 4 has produced it: the payload of every `j` whose ABA decided 1,
    /// keyed by proposing party.
    result: watch::Sender<AcsOutput<T>>,
    /// Set of indexes for which the input to `ABA_j` was already provided.
    ///
    /// First input for an index wins, which is what stops a justification arriving after step 3 has
    /// voted 0 from voting 1 in the same ABA. See [`provide_aba_input`].
    aba_provided_inputs: HashSet<usize>,
    /// Handles of this session's background tasks: the [`Aba::init`] futures of steps 2 and 3, one
    /// decision watcher per ABA instance, and the justification watcher.
    ///
    /// They outlive the call that spawned them, so dropping this store does not stop them; retaining
    /// the handles is what lets [`Acs::clear_session`] abort them. See [`HbAcs::spawn_for_session`].
    tasks: Vec<JoinHandle<()>>,
}

impl<T> HbAcsStore<T> {
    pub fn empty() -> Self {
        Self {
            result: watch::Sender::new(AcsOutput::Pending),
            aba_provided_inputs: HashSet::new(),
            tasks: Vec::new(),
        }
    }
}

pub struct HbAcs<I, P, A>
where
    P: AcsProposals<SessionId = I>,
    A: Aba<SessionId = I> + 'static,
    I: ProtocolSessionId + DeserializeOwned + Serialize + 'static,
{
    n_parties: usize,
    threshold: usize,
    aba: Arc<A>,
    proposals: P,
    store: Arc<Mutex<HashMap<I, Arc<Mutex<HbAcsStore<P::Item>>>>>>,
}

impl<I, P, A> HbAcs<I, P, A>
where
    P: AcsProposals<SessionId = I>,
    A: Aba<SessionId = I>,
    I: ProtocolSessionId + DeserializeOwned + Serialize,
{
    pub async fn get_or_create_store(&self, session_id: I) -> Arc<Mutex<HbAcsStore<P::Item>>> {
        let store_lock = {
            let mut store = self.store.lock().await;
            store
                .entry(session_id)
                .or_insert_with(|| Arc::new(Mutex::new(HbAcsStore::empty())))
                .clone()
        };

        store_lock
    }

    /// [`sub_session_id`] for one of this session's `ABA_j`, named against this error type.
    fn aba_session_id(session_id: I, index: usize) -> Result<I, HbAcsError<I>> {
        sub_session_id(session_id, ABA_ROUND, index).ok_or(HbAcsError::UnknownProtocol(session_id))
    }

    /// Spawns `task` as a background task of `session_id`, logged under the name `label`.
    ///
    /// Use this in preference to a bare [`tokio::spawn`], which drops the [`JoinHandle`] and so both
    /// discards the task's error and leaves no way to stop it. The error matters because an
    /// [`Aba::init`] that fails never decides, and the collection loop of [`Acs::init`] then waits
    /// forever; logging it here does not rescue the session, but makes the hang diagnosable. The
    /// handle matters because [`Acs::clear_session`] needs it to abort the task.
    async fn spawn_for_session(
        &self,
        session_id: I,
        label: &'static str,
        task: impl Future<Output = Result<(), HbAcsError<I>>> + Send + 'static,
    ) {
        let handle = tokio::spawn(async move {
            if let Err(error) = task.await {
                warn!(?session_id, %error, "the {label} task of the ACS failed");
            }
        });
        self.get_or_create_store(session_id)
            .await
            .lock()
            .await
            .tasks
            .push(handle);
    }

    /// Aborts every background task of `session`, leaving its `tasks` list empty.
    async fn abort_tasks(session: &Mutex<HbAcsStore<P::Item>>) {
        for task in session.lock().await.tasks.drain(..) {
            task.abort();
        }
    }
}

/// Waits for the ABA for `party_id` to finish with value one.
async fn check_ready_aba_for_party<I>(
    session_id: I,
    mut decision_tracker: watch::Receiver<Decision>,
    success_tx: mpsc::Sender<usize>,
) -> Result<(), HbAcsError<I>>
where
    I: ProtocolSessionId,
{
    let decision = decision_tracker
        .wait_for(|d| matches!(d, Decision::Ready(_)))
        .await?
        .clone();
    if let Decision::Ready(BinValue::One) = decision {
        success_tx.send(session_id.sub_id() as usize).await?;
    }
    Ok(())
}

/// Hands `value` to the ABA of `index`, unless this session already gave that ABA an input.
///
/// The first input for an index wins, per Figure 4: a party that voted 0 in `ABA_j` at step 3 must
/// not vote 1 when `j` is justified afterwards, and the other way round. The check and the mark
/// happen under one lock, so two concurrent callers cannot both start the same ABA.
///
/// [`Aba::init`] is spawned rather than awaited, both because it has to keep running after the
/// decision — see its documentation — and because the caller has other indexes to serve. The handle
/// joins the session's task list so [`Acs::clear_session`] can abort it.
async fn provide_aba_input<I, A, T, N>(
    store: &Mutex<HbAcsStore<T>>,
    aba: Arc<A>,
    index: usize,
    sid_aba: I,
    value: BinValue,
    network: Arc<N>,
) where
    I: ProtocolSessionId + 'static,
    A: Aba<SessionId = I> + 'static,
    T: Send + Sync + 'static,
    N: Network + Send + Sync + 'static,
{
    let mut guard = store.lock().await;
    if !guard.aba_provided_inputs.insert(index) {
        return;
    }
    let handle = tokio::spawn(async move {
        if let Err(error) = aba.init(value, sid_aba, network).await {
            warn!(session_id = ?sid_aba, %error, "the ABA input task of the ACS failed");
        }
    });
    guard.tasks.push(handle);
}

/// Votes 1 in `ABA_j` for every index the proposal layer justifies, for as long as the session runs.
///
/// Step 2 of Figure 4, with "`RBC_j` delivered" generalized to "the layer justified `j`". Detached
/// from [`Acs::init`], which is busy collecting decisions, and it must outlive nothing in
/// particular: it ends when the layer drops the session, or when [`Acs::clear_session`] aborts it.
///
/// `aba_sids` is indexed by party, and is passed in already built because a detached task has no
/// `Self` to derive session IDs with.
async fn vote_for_justified<I, A, T, N>(
    mut justified: watch::Receiver<HashMap<usize, T>>,
    aba_sids: Vec<I>,
    aba: Arc<A>,
    store: Arc<Mutex<HbAcsStore<T>>>,
    network: Arc<N>,
) -> Result<(), HbAcsError<I>>
where
    I: ProtocolSessionId + 'static,
    A: Aba<SessionId = I> + 'static,
    T: Send + Sync + 'static,
    N: Network + Send + Sync + 'static,
{
    loop {
        // Collected out of the guard before any await: the value cannot be borrowed across one.
        let indexes: Vec<usize> = justified.borrow_and_update().keys().copied().collect();
        for index in indexes {
            match aba_sids.get(index) {
                Some(&sid_aba) => {
                    provide_aba_input(
                        &store,
                        aba.clone(),
                        index,
                        sid_aba,
                        BinValue::One,
                        network.clone(),
                    )
                    .await
                }
                // Indexing the parties is the layer's job, so an out-of-range key is a bug there
                // rather than a reason to stop voting on the rest.
                None => warn!(index, "the proposal layer justified an index with no party"),
            }
        }
        if justified.changed().await.is_err() {
            // The layer dropped this session: nothing further can be justified.
            return Ok(());
        }
    }
}

impl<I, P, A> Acs for HbAcs<I, P, A>
where
    P: AcsProposals<SessionId = I>,
    A: Aba<SessionId = I>,
    I: ProtocolSessionId + Serialize + DeserializeOwned + 'static,
{
    type Aba = A;
    type Proposals = P;
    type SessionId = I;
    type Message = HbAcsMessage<P::Message, A::Message>;
    type Error = HbAcsError<I>;

    fn new(
        id: usize,
        n_parties: usize,
        threshold: usize,
        proposals: P,
        coin: A::Coin,
    ) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        if n_parties < 3 * threshold + 1 {
            return Err(HbAcsError::InvalidThreshold {
                n_parties,
                threshold,
            });
        }
        // Checked once here so that `sub_session_id` can narrow a party index to the one byte
        // `sub_id` gives it without two `ABA_j` silently landing on the same session.
        if n_parties > MAX_PARTIES {
            return Err(HbAcsError::TooManyParties { n_parties });
        }
        let aba = A::new(id, n_parties, threshold, coin).map_err(HbAcsError::from_aba)?;
        Ok(Self {
            n_parties,
            threshold,
            aba: Arc::new(aba),
            proposals,
            store: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    async fn init<N>(
        &self,
        value: P::Input,
        session_id: Self::SessionId,
        network: Arc<N>,
    ) -> Result<(), Self::Error>
    where
        N: Network + Send + Sync + 'static,
    {
        if !is_acs_session_id(session_id) {
            return Err(HbAcsError::MalformedSessionId(session_id));
        }

        // Built once here rather than in the tasks below, which run detached and so have no `Self`
        // to derive session IDs against.
        let aba_sids = (0..self.n_parties)
            .map(|index| Self::aba_session_id(session_id, index))
            .collect::<Result<Vec<_>, _>>()?;

        let store = self.get_or_create_store(session_id).await;

        // Step 2, started before this party proposes: justifications that land while `propose` is
        // still publishing are as good as any other, and dropping them would delay `ABA_j`.
        self.spawn_for_session(
            session_id,
            "justification watcher",
            vote_for_justified(
                self.proposals.justified(session_id).await,
                aba_sids.clone(),
                self.aba.clone(),
                store.clone(),
                network.clone(),
            ),
        )
        .await;

        // Step 1. The layer decides what publishing means and under which index: for an RBC it is a
        // broadcast keyed by this party's own ID, for a layer observing an ACSS it may be nothing.
        self.proposals
            .propose(value, session_id, network.clone())
            .await
            .map_err(HbAcsError::from_proposals)?;

        // Analyzes if the `ABA_j` finished and take those that finished with one. This is a
        // continuous check over all the ABA instances, rather than something re-run on each new
        // justification.
        let (tx_success, mut rx_success) = mpsc::channel(self.n_parties);
        for &sid_aba in &aba_sids {
            let tx_success = tx_success.clone();
            let decision_tracker = self.aba.subscribe_to_decision(sid_aba).await;
            self.spawn_for_session(
                session_id,
                "ABA decision watcher",
                check_ready_aba_for_party(sid_aba, decision_tracker, tx_success),
            )
            .await;
        }

        drop(tx_success);

        let mut finished_abas_one = HashSet::new();
        while let Some(idx_aba) = rx_success.recv().await {
            finished_abas_one.insert(idx_aba);
            // Step 3: once n - t have decided 1, every ABA still without an input gets a 0.
            if finished_abas_one.len() >= self.n_parties - self.threshold {
                let unfinished_indexes: Vec<_> = (0..self.n_parties)
                    .filter(|index| !finished_abas_one.contains(index))
                    .collect();
                for unfinished_idx in unfinished_indexes {
                    provide_aba_input(
                        &store,
                        self.aba.clone(),
                        unfinished_idx,
                        aba_sids[unfinished_idx],
                        BinValue::Zero,
                        network.clone(),
                    )
                    .await;
                }
            }
        }

        // All ABAs have finished, so `finished_abas_one` is the set C of Figure 4. Step 4 waits for
        // the layer to justify every j in C before producing the union: this party may not have
        // justified j yet, since `ABA_j` deciding 1 only says that some correct party did.
        // Subscribing once up front suffices, as `wait_for` checks the current value before it
        // waits, so justifications that arrived earlier are not missed.
        let mut justified = self.proposals.justified(session_id).await;
        let mut result = BTreeMap::new();
        for fin_aba_one_idx in finished_abas_one {
            let item = justified
                .wait_for(|justified| justified.contains_key(&fin_aba_one_idx))
                .await
                .map_err(HbAcsError::JustificationChannelClosed)?
                .get(&fin_aba_one_idx)
                .cloned()
                .ok_or(HbAcsError::MissingJustification(fin_aba_one_idx))?;
            result.insert(fin_aba_one_idx, item);
        }

        store.lock().await.result.send_replace(AcsOutput::Ready(result));

        Ok(())
    }

    /// Entry point for every message routed to this ACS, at either layer beneath it.
    ///
    /// `session_id` is the *sub-session* the message named — the `ABA_j` or the proposal instance —
    /// not the ACS session that [`parent_session_id`] recovers from it. This is the one entry
    /// point that is keyed that way, and deliberately so: it is the id a dispatcher reads off the
    /// decoded message, and the same convention the justification path follows. The layer below
    /// checks it against the id inside the message itself, which is why nothing here needs to.
    async fn process<N>(
        &self,
        session_id: Self::SessionId,
        message: Self::Message,
        network: Arc<N>,
    ) -> Result<(), Self::Error>
    where
        N: Network + Send + Sync + 'static,
    {
        // Checked before the message is handed anywhere: `sub_id` picks one of the n instances of a
        // layer, so an index with no party behind it would have that layer allocate state for a
        // session nobody drives, nobody decides, and `Self::clear_session` never reaches.
        let index = session_id.sub_id() as usize;
        if index >= self.n_parties {
            return Err(HbAcsError::InvalidPartyIndex {
                session_id,
                index,
                n_parties: self.n_parties,
            });
        }

        // Dispatched on the round tag, and the kind of message has to agree with it. Both come from
        // the sender, so letting the kind alone decide would let a peer drive the ABA under an ID in
        // the layer's half of the space — which is exactly the state `Self::clear_session` looks for
        // under the other tag, and so would never free.
        match (session_id.round_id(), message) {
            (ABA_ROUND, HbAcsMessage::Aba(message)) => self
                .aba
                .process(session_id, message, network)
                .await
                .map_err(HbAcsError::from_aba),
            (PROPOSALS_ROUND, HbAcsMessage::Proposals(message)) => self
                .proposals
                .process(session_id, message, network)
                .await
                .map_err(HbAcsError::from_proposals),
            _ => Err(HbAcsError::MisroutedMessage(session_id)),
        }
    }

    async fn subscribe_to_result(
        &self,
        session_id: Self::SessionId,
    ) -> watch::Receiver<AcsOutput<P::Item>> {
        self.get_or_create_store(session_id)
            .await
            .lock()
            .await
            .result
            .subscribe()
    }

    async fn clear_session(&self, session_id: I) -> Result<(), Self::Error> {
        // Checked before anything is derived from it: a malformed parent would address, and so
        // clear, the sub-sessions of some other ACS session.
        if !is_acs_session_id(session_id) {
            return Err(HbAcsError::MalformedSessionId(session_id));
        }
        let session = self
            .store
            .lock()
            .await
            .remove(&session_id)
            .ok_or(HbAcsError::SessionIdNotFound(session_id))?;
        // Before the layers underneath are torn down: an `Aba::init` left running would go on
        // driving state that `Aba::clear_session` is about to drop.
        Self::abort_tasks(&session).await;
        // The parent ID, not a derived one: the layer owns `PROPOSALS_ROUND` and derives whatever
        // sub-sessions it keeps under it.
        self.proposals
            .clear_session(session_id)
            .await
            .map_err(HbAcsError::from_proposals)?;
        for i in 0..self.n_parties {
            self.aba
                .clear_session(Self::aba_session_id(session_id, i)?)
                .await;
        }
        Ok(())
    }

    async fn clear_store(&self) -> Result<(), Self::Error> {
        // Taken out of the map first, so the aborts happen without the map held: a task being
        // aborted may itself be blocked on that lock in `get_or_create_store`.
        let sessions: Vec<_> = self.store.lock().await.drain().map(|(_, s)| s).collect();
        for session in sessions {
            Self::abort_tasks(&session).await;
        }
        self.proposals
            .clear_store()
            .await
            .map_err(HbAcsError::from_proposals)?;
        self.aba.clear_store().await;
        Ok(())
    }
}
