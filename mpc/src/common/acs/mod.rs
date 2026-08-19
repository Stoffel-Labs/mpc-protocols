use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    sync::Arc,
};

use serde::{de::DeserializeOwned, Serialize};
use stoffelnet::network_utils::Network;
use tokio::sync::watch;

use crate::common::{aba::Aba, ProtocolSessionId};

pub mod hb_acs;
pub mod rbc_prop;

/// Round tag reserved for the proposal layer, which packs its own sub-sessions under it.
///
/// The ACS never derives a session ID with this tag itself; it exists so that the core and the
/// layer agree on who owns which part of the ID space.
pub const PROPOSALS_ROUND: u8 = 0;

/// Round tag of the session IDs handed to the ABA layer.
pub const ABA_ROUND: u8 = 1;

/// Largest party count the ID space addresses, since `sub_id` is one byte wide.
///
/// Checked once where a party count enters, so that [`sub_session_id`] can narrow an index without
/// two parties silently aliasing onto one sub-session.
pub const MAX_PARTIES: usize = u8::MAX as usize + 1;

/// Whether `session_id` is a well-formed ACS session ID.
///
/// An ACS session is keyed by protocol, `exec_id` and `instance_id` alone. The remaining two fields
/// are the address space the ACS hands out to the instances beneath it, so they must be zero in the
/// parent: [`sub_session_id`] overwrites them, which would make two parents differing only there
/// share every instance, and would leave [`parent_session_id`] unable to say which of the two a
/// delivery belonged to.
pub fn is_acs_session_id<I: ProtocolSessionId>(session_id: I) -> bool {
    session_id.sub_id() == 0 && session_id.round_id() == 0
}

/// The session ID of instance `index` in the layer tagged `round`, under the ACS session
/// `session_id`. `round` is [`PROPOSALS_ROUND`] or [`ABA_ROUND`].
///
/// Shared by the core and its layers rather than reimplemented on each side: two encodings of the
/// same address that drift apart route messages to instances that never look for them.
///
/// `None` when `session_id` carries a protocol tag this build does not recognize — the tag travels
/// on the wire, so a peer can put anything there, and each caller names its own error for it.
/// `index` must be below [`MAX_PARTIES`], which every entry point holding a party count checks.
pub fn sub_session_id<I: ProtocolSessionId>(session_id: I, round: u8, index: usize) -> Option<I> {
    debug_assert!(index < MAX_PARTIES, "index does not fit in sub_id");
    let protocol = session_id.calling_protocol()?;
    Some(I::new(
        protocol,
        I::pack_slot(session_id.exec_id(), index as u8, round),
        session_id.instance_id(),
    ))
}

/// The ACS session that [`sub_session_id`] derived `derived` from.
///
/// It inverts cleanly because a sub-session ID keeps its parent's protocol, `exec_id` and
/// `instance_id`, and [`is_acs_session_id`] guarantees the parent held nothing else. Recovering the
/// session this way, rather than reading it out of a delivered payload, is what stops a Byzantine
/// dealer from filing its proposal against a session of its choosing.
pub fn parent_session_id<I: ProtocolSessionId>(derived: I) -> Option<I> {
    let protocol = derived.calling_protocol()?;
    Some(I::new(
        protocol,
        I::pack_slot(derived.exec_id(), 0, 0),
        derived.instance_id(),
    ))
}


/// Where an [`Acs`] gets its justifications: the events that entitle this party to vote 1 in
/// `ABA_j`, and the payload each index carries into the result.
///
/// Splitting this out is what lets one agreement core serve both uses. In a classic ACS the layer
/// is a reliable broadcast, and `j` is justified when `RBC_j` delivers. In the DPSS resharing of
/// [ePrint 2022/971](https://eprint.iacr.org/2022/971) Algorithm 5 the layer observes a
/// dual-committee ACSS, and `j` is justified when dealer `j`'s instance completes locally.
pub trait AcsProposals: Send + Sync {
    type SessionId: ProtocolSessionId;

    /// What this party proposes. `()` for a layer that has nothing to publish.
    type Input: Serialize + DeserializeOwned + Send;

    /// What a justified index carries into [`AcsOutput::Ready`].
    ///
    /// `Clone` because the core copies it out of [`Self::justified`] when assembling the result;
    /// `Send + Sync + 'static` because it lives in a [`watch`] channel read from spawned tasks.
    type Item: Clone + Send + Sync + 'static;

    /// Every message this layer and the protocols beneath it put on the wire, as one type — the
    /// same arrangement as [`Aba::Message`], for the same reason.
    ///
    /// A layer that observes a protocol it does not own, rather than running one, has no messages of
    /// its own and can set this to an uninhabited type.
    type Message: Send;

    type Error: std::error::Error + Send + Sync + 'static;

    fn propose<N>(
        &self,
        value: Self::Input,
        sid: Self::SessionId,
        net: Arc<N>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        N: Network + Send + Sync + 'static;

    /// This party's local view `T_i`: the indices it may vote 1 for, and their payloads.
    ///
    /// The core reads this twice. Early, to vote 1 on each index as it appears. Late, to block until
    /// the indices the ABAs selected are present locally — `ABA_j` deciding 1 only means *some*
    /// correct party justified `j`, so this party may still be waiting on it.
    ///
    /// Two obligations on the implementor. It must insert `j` only once the condition that makes the
    /// second read terminate holds, namely that every correct party eventually justifies `j` too;
    /// and it must keep entries, since a subscriber arriving late still has to observe them.
    fn justified(
        &self,
        sid: Self::SessionId,
    ) -> impl Future<Output = watch::Receiver<HashMap<usize, Self::Item>>> + Send;

    /// Feeds one incoming message of [`Self::Message`] to the session it belongs to.
    ///
    /// `sid` is the routing key the ACS settled on: the sub-session ID the message named, in the
    /// part of the ID space the layer owns. A message that disagrees with it must be rejected rather
    /// than processed under either id.
    fn process<N>(
        &self,
        sid: Self::SessionId,
        message: Self::Message,
        net: Arc<N>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        N: Network + Send + Sync + 'static;

    /// Drops the layer's state for the ACS session `session_id`, deriving whatever sub-sessions it
    /// owns itself.

    fn clear_session(
        &self,
        session_id: Self::SessionId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn clear_store(&self) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// The agreed set, keyed by proposing party, or [`Self::Pending`] before agreement.
///
/// Concrete rather than an opaque associated type so that code generic over [`Acs`] can read a
/// result it subscribed to. The payload still varies with the proposal layer, hence the parameter.
pub enum AcsOutput<T> {
    Pending,
    Ready(BTreeMap<usize, T>),
}

pub trait Acs: Send + Sync {
    type SessionId: ProtocolSessionId;
    type Proposals: AcsProposals<SessionId = Self::SessionId>;
    type Aba: Aba<SessionId = Self::SessionId>;
    type Error: std::error::Error + Send + Sync + 'static;

    /// Every message this ACS and the layers beneath it put on the wire.
    ///
    /// A single type for the whole stack, as on [`Aba::Message`]: a caller routing network traffic
    /// to an ACS should not have to know whether a message belongs to the RBC, the ABA, or the ACS
    /// itself. [`Self::process`] is the one entry point for all of them.
    type Message: Send;

    fn new(
        id: usize,
        n_parties: usize,
        threshold: usize,
        proposals: Self::Proposals,
        coin: <Self::Aba as Aba>::Coin,
    ) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Proposes `value` in `session_id`.
    ///
    /// One implementor serves many concurrent sessions, as on [`Aba`], so every entry point is
    /// keyed: the id given here is the one [`Self::subscribe_to_result`] and
    /// [`Self::clear_session`] refer to.
    fn init<N>(
        &self,
        value: <Self::Proposals as AcsProposals>::Input,
        session_id: Self::SessionId,
        network: Arc<N>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        N: Network + Send + Sync + 'static;

    /// Feeds one incoming message of [`Self::Message`] to the session it belongs to.
    ///
    /// `session_id` is the routing key the caller decided on; a message that disagrees with it is
    /// rejected rather than processed under either id.
    fn process<N>(
        &self,
        session_id: Self::SessionId,
        message: Self::Message,
        network: Arc<N>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        N: Network + Send + Sync + 'static;

    /// Returns a receiver that fires when `session_id` agrees on a set, keyed by proposing party.
    fn subscribe_to_result(
        &self,
        session_id: Self::SessionId,
    ) -> impl Future<Output = watch::Receiver<AcsOutput<<Self::Proposals as AcsProposals>::Item>>> + Send;

    /// Drops all state held for `session_id`, at every layer of the implementation.
    fn clear_session(
        &self,
        session_id: Self::SessionId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Drops all state for every session.
    fn clear_store(&self) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

