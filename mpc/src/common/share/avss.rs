use crate::common::{
    lagrange_interpolate,
    rbc::RbcError,
    session_store::{session_ttl, RetiredSet, DEFAULT_RETIRED_CAP},
    share::{feldman::FeldmanShamirShare, shamir::Shamirshare},
    ProtocolSessionId, RbcWrapFn, RBC,
};
use ark_ec::CurveGroup;
use ark_ff::{FftField, PrimeField};
use ark_poly::Polynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{
    rngs::{OsRng, StdRng},
    Rng, SeedableRng,
};
use bincode::ErrorKind;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Instant,
};
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::{
    mpsc::{self, Receiver, Sender},
    Mutex,
};
use tracing::{info, warn};

const MAX_MESSAGE_SIZE: u64 = 10 * 1024 * 1024; // 10 MiB
/// Upper bound on unconsumed AVSS sessions. Callers constructing an `AvssNode`'s
/// `output_sender`/`output_receiver` pair must size that channel to at least this capacity —
/// see `AvssNode::process`, which relies on the channel never blocking as long as this cap
/// hasn't been exceeded.
pub const MAX_PENDING_SESSIONS: usize = 512;

/// Upper bound on the number of secrets a single AVSS dealing may carry.
///
/// `AvssMessage::public_commitments` is otherwise only constrained relative to the per-party
/// ciphertext count, never absolutely, and each entry costs `t + 1` point decompressions to
/// decode — so without this a peer could turn one wire-sized message into an arbitrary number
/// of elliptic-curve square roots.
///
/// This is the primitive's own limit. Consumers that chunk their dealings (see
/// `avss_mpc::MAX_AVSS_BATCH_SIZE`) must keep their chunk size at or below it; that
/// relationship is enforced by a static assertion at the consumer, so the two cannot drift
/// apart into silently-rejected honest dealings.
pub const MAX_DEAL_BATCH: usize = 128;

/// Upper bound on the serialized size of a single group element or scalar carried in a
/// `Reveal` message (`k_id`, and each of `DleqProof`'s `a1`/`a2`/`z`). Generous headroom
/// over any real curve's compressed point/scalar size (e.g. 48 bytes for BLS12-381 G1) —
/// this only exists to reject obviously-malformed/padded input before it's buffered.
const MAX_DLEQ_FIELD_SIZE: usize = 128;

#[derive(Debug, thiserror::Error)]
pub enum AvssError {
    #[error("inner error: {0}")]
    RbcError(#[from] RbcError),
    #[error("sender mismatch")]
    SenderMismatch,
    #[error("invalid feldman share")]
    InvalidShare,
    #[error("invalid feldman commitment length")]
    InvalidCommitmentLength,
    #[error("invalid share length")]
    InvalidShareLength,
    #[error("commitments unavailable")]
    CommitmentsNotFound,
    #[error("serialization error")]
    Serialization(#[from] ark_serialize::SerializationError),
    #[error("error while serializing the object into bytes: {0:?}")]
    SerializationError(#[from] Box<ErrorKind>),
    #[error("network error")]
    Network(#[from] stoffelnet::network_utils::NetworkError),
    #[error("share error")]
    ShareError(#[from] crate::common::share::ShareError),
    #[error("Channel closed")]
    Abort,
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("pending session limit exceeded")]
    LimitExceeded,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvssMessage<Id: ProtocolSessionId> {
    pub session_id: Id,
    pub dealer_pk: Vec<u8>,
    pub public_commitments: Vec<Vec<Vec<u8>>>,
    pub encrypted_shares: Vec<Vec<Vec<u8>>>,
}

impl<Id: ProtocolSessionId> AvssMessage<Id>
where
    Id: ProtocolSessionId,
{
    pub fn new(
        session_id: Id,
        dealer_pk: Vec<u8>,
        public_commitments: Vec<Vec<Vec<u8>>>,
        encrypted_shares: Vec<Vec<Vec<u8>>>,
    ) -> Self {
        Self {
            session_id,
            dealer_pk,
            public_commitments,
            encrypted_shares,
        }
    }
}

pub fn verify_feldman<F: FftField, G: CurveGroup<ScalarField = F>>(
    share: FeldmanShamirShare<F, G>,
    expected_id: usize,
) -> bool {
    if share.commitments.len() != share.feldmanshare.degree + 1 {
        return false;
    }
    if share.feldmanshare.id != expected_id {
        return false;
    }
    let x = F::from(share.feldmanshare.id as u64);
    let mut rhs = G::zero();
    let mut pow = F::one();

    for c in share.commitments {
        rhs += c.mul(pow);
        pow *= x;
    }

    G::generator().mul(share.feldmanshare.share[0]) == rhs
}

/// Non-interactive Chaum-Pedersen proof of equality of discrete logarithms:
/// `NIZK{(alpha) : x = g0^alpha ∧ y = g1^alpha}`. Used to reveal a session-scoped
/// ECDH secret (`Ki_d = pk_d^sk_i`) as proof of a dealer's misbehavior, without
/// revealing the long-term `sk_i` itself — the prover convinces everyone the
/// revealed value was genuinely derived from the secret key matching their own
/// already-known public key, and nothing more.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DleqProof {
    a1: Vec<u8>,
    a2: Vec<u8>,
    z: Vec<u8>,
}

fn dleq_challenge<F, G>(g0: &G, x: &G, g1: &G, y: &G, a1: &G, a2: &G) -> Result<F, AvssError>
where
    F: PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    let mut buf = Vec::new();
    g0.serialize_compressed(&mut buf)?;
    x.serialize_compressed(&mut buf)?;
    g1.serialize_compressed(&mut buf)?;
    y.serialize_compressed(&mut buf)?;
    a1.serialize_compressed(&mut buf)?;
    a2.serialize_compressed(&mut buf)?;
    Ok(F::from_le_bytes_mod_order(&Sha256::digest(&buf)))
}

/// Proves `x = g0^alpha ∧ y = g1^alpha` for a known witness `alpha`, without
/// revealing it.
fn dleq_prove<F, G>(
    alpha: F,
    g0: G,
    x: G,
    g1: G,
    y: G,
    rng: &mut impl Rng,
) -> Result<DleqProof, AvssError>
where
    F: PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    let beta = F::rand(rng);
    let a1 = g0.mul(beta);
    let a2 = g1.mul(beta);
    let e: F = dleq_challenge(&g0, &x, &g1, &y, &a1, &a2)?;
    let z = beta - alpha * e;

    let mut a1_bytes = Vec::new();
    a1.serialize_compressed(&mut a1_bytes)?;
    let mut a2_bytes = Vec::new();
    a2.serialize_compressed(&mut a2_bytes)?;
    let mut z_bytes = Vec::new();
    z.serialize_compressed(&mut z_bytes)?;

    Ok(DleqProof {
        a1: a1_bytes,
        a2: a2_bytes,
        z: z_bytes,
    })
}

/// Verifies a `DleqProof` for the statement `x = g0^alpha ∧ y = g1^alpha`.
fn dleq_verify<F, G>(proof: &DleqProof, g0: G, x: G, g1: G, y: G) -> bool
where
    F: PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    let (Ok(a1), Ok(a2), Ok(z)) = (
        G::deserialize_compressed(&proof.a1[..]),
        G::deserialize_compressed(&proof.a2[..]),
        F::deserialize_compressed(&proof.z[..]),
    ) else {
        return false;
    };
    let Ok(e) = dleq_challenge::<F, G>(&g0, &x, &g1, &y, &a1, &a2) else {
        return false;
    };
    a1 == g0.mul(z) + x.mul(e) && a2 == g1.mul(z) + y.mul(e)
}

fn kdf_from_point<G: CanonicalSerialize>(p: &G) -> [u8; 32] {
    let mut buf = Vec::new();
    p.serialize_compressed(&mut buf).unwrap();
    let hash = Sha256::digest(&buf);
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    key
}

fn encrypt(key: [u8; 32], plaintext: &[u8], rng: &mut impl Rng) -> Result<Vec<u8>, AvssError> {
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| AvssError::InvalidShare)?;

    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce =
        Nonce::from(<[u8; 12]>::try_from(nonce_bytes).map_err(|_| AvssError::InvalidShare)?);

    let mut ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| AvssError::InvalidShare)?;

    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.append(&mut ct);
    Ok(out)
}

fn decrypt(key32: [u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, AvssError> {
    if ciphertext.len() < 12 {
        return Err(AvssError::InvalidShare);
    }
    let (nonce_bytes, ct) = ciphertext.split_at(12);
    let cipher = ChaCha20Poly1305::new_from_slice(&key32).map_err(|_| AvssError::InvalidShare)?;
    let nonce =
        Nonce::from(<[u8; 12]>::try_from(nonce_bytes).map_err(|_| AvssError::InvalidShare)?);

    cipher
        .decrypt(&nonce, ct)
        .map_err(|_| AvssError::InvalidShare)
}

pub type AvssWrapFn<Id> =
    Arc<dyn Fn(AvssMessage<Id>) -> Result<Vec<u8>, RbcError> + Send + Sync + 'static>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AvssAgreementMessage<Id: ProtocolSessionId> {
    Ok {
        session_id: Id,
        voter: PartyId,
    },
    Ready {
        session_id: Id,
        voter: PartyId,
    },
    Reveal {
        session_id: Id,
        party_id: PartyId,
        k_id: Vec<u8>,
        proof: DleqProof,
    },
}

impl<Id: ProtocolSessionId> AvssAgreementMessage<Id> {
    pub fn session_id(&self) -> Id {
        match self {
            Self::Ok { session_id, .. } => *session_id,
            Self::Ready { session_id, .. } => *session_id,
            Self::Reveal { session_id, .. } => *session_id,
        }
    }

    /// The party this message is attributed to — used by callers to authenticate that the
    /// transport-level sender matches the party the message claims to speak for.
    pub fn claimed_sender(&self) -> PartyId {
        match self {
            Self::Ok { voter, .. } => *voter,
            Self::Ready { voter, .. } => *voter,
            Self::Reveal { party_id, .. } => *party_id,
        }
    }
}

pub type AvssAgreementWrapFn<Id> =
    Arc<dyn Fn(AvssAgreementMessage<Id>) -> Result<Vec<u8>, RbcError> + Send + Sync + 'static>;

/// The parts of a dealing an `AgreementState` needs once this node has locally processed it:
/// enough to redo any peer's decryption+Feldman-check during recovery, plus this node's own
/// verdict.
struct DealingInfo<F, G>
where
    F: FftField,
    G: CurveGroup<ScalarField = F>,
{
    pk_d: G,
    all_commitments: Vec<Vec<G>>,
    encrypted_shares: Vec<Vec<Vec<u8>>>,
    own_valid: bool,
    own_shares: Option<Vec<FeldmanShamirShare<F, G>>>,
}

struct AgreementState<F, G>
where
    F: FftField,
    G: CurveGroup<ScalarField = F>,
{
    created_at: Instant,
    /// Who this entry's admission slot is billed to. Set once at creation — `process()`
    /// charges the RBC-authenticated dealer (`session_id.dealer_id()`, trustworthy because
    /// the RBC layer already checked the sender against it upstream); a vote-triggered lazy
    /// creation charges the authenticated voter instead, since `session_id` itself carries no
    /// authenticated dealer identity in that case. See `admit`.
    charged_to: u8,
    dealing: Option<DealingInfo<F, G>>,
    ok_votes: BTreeSet<PartyId>,
    ready_votes: BTreeSet<PartyId>,
    sent_ready: bool,
    /// Feldman-verified rows recovered from other parties' `Reveal`s, keyed by the party
    /// they belong to. Once `t + 1` accumulate, Feldman's binding property guarantees they
    /// lie on the unique degree-`t` polynomial the (RBC-agreed) commitments commit to,
    /// regardless of OK/READY timing — recovery does not need to wait on Bracha quorum.
    recovered: BTreeMap<PartyId, Vec<FeldmanShamirShare<F, G>>>,
    sent_reveal: bool,
    /// Reveals buffered before `dealing` was known, keyed by `party_id` — a party can only
    /// ever speak for itself (`claimed_sender() == party_id`), so this naturally caps at
    /// `n_parties` entries and a repeat send from the same party overwrites rather than
    /// accumulates.
    pending_reveals: BTreeMap<PartyId, (Vec<u8>, DleqProof)>,
    finished: bool,
}

impl<F, G> AgreementState<F, G>
where
    F: FftField,
    G: CurveGroup<ScalarField = F>,
{
    fn pending(charged_to: u8) -> Self {
        Self {
            created_at: Instant::now(),
            charged_to,
            dealing: None,
            ok_votes: BTreeSet::new(),
            ready_votes: BTreeSet::new(),
            sent_ready: false,
            recovered: BTreeMap::new(),
            sent_reveal: false,
            pending_reveals: BTreeMap::new(),
            finished: false,
        }
    }

    /// `true` once enough votes are in that this node should have echoed READY, whether or
    /// not it already has (used both when a new vote arrives and, symmetrically, when the
    /// local dealing finally arrives after votes that were already sufficient).
    fn should_amplify_ready(&self, t: usize) -> bool {
        !self.sent_ready && (self.ok_votes.len() >= 2 * t + 1 || self.ready_votes.len() >= t + 1)
    }

    /// Own share to finalize-and-output via the direct (non-recovery) path, if the READY
    /// quorum has been met and this node's own row verified.
    fn direct_finalize_shares(&self, t: usize) -> Option<Vec<FeldmanShamirShare<F, G>>> {
        if self.finished {
            return None;
        }
        let dealing = self.dealing.as_ref()?;
        if dealing.own_valid && self.ready_votes.len() >= 2 * t + 1 {
            dealing.own_shares.clone()
        } else {
            None
        }
    }
}

#[derive(Clone)]
pub struct AvssNode<F, R, G, Id>
where
    F: FftField,
    R: RBC,
    G: CurveGroup<ScalarField = F>,
    Id: ProtocolSessionId,
{
    pub id: PartyId,
    pub ids: Vec<usize>,
    pub n_parties: usize,
    pub t: usize,
    pub sk_i: F,
    pub pk_map: Arc<Vec<G>>,
    pub shares: Arc<Mutex<BTreeMap<Id, (Instant, Option<Vec<FeldmanShamirShare<F, G>>>)>>>,
    /// Tombstones for `shares`/`agreement` entries already consumed (or otherwise cleared),
    /// so a late/duplicate message can't silently resurrect a session nobody is waiting on
    /// anymore.
    retired: Arc<Mutex<RetiredSet<Id>>>,
    agreement: Arc<Mutex<BTreeMap<Id, AgreementState<F, G>>>>,
    pub rbc: R,
    pub rbc_output: Arc<Mutex<Receiver<Id>>>,
    pub output_sender: Sender<Id>,
    pub wrapper: AvssWrapFn<Id>,
    pub agreement_wrapper: AvssAgreementWrapFn<Id>,
}
impl<F, R, G, Id> std::fmt::Debug for AvssNode<F, R, G, Id>
where
    F: FftField,
    R: RBC + std::fmt::Debug,
    G: CurveGroup<ScalarField = F>,
    Id: ProtocolSessionId,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AvssNode")
            .field("id", &self.id)
            .field("n_parties", &self.n_parties)
            .field("t", &self.t)
            .field("shares", &self.shares)
            .field("agreement", &"<agreement state>")
            .field("rbc", &self.rbc)
            .field("wrapper", &"<fn>") // 👈 intentionally opaque
            .finish()
    }
}

impl<F, R, G, Id> AvssNode<F, R, G, Id>
where
    F: FftField,
    R: RBC<Id = Id>,
    G: CurveGroup<ScalarField = F>,
    Id: ProtocolSessionId + for<'a> Deserialize<'a> + Serialize,
{
    pub fn new(
        id: PartyId,
        n_parties: usize,
        ids: Vec<usize>,
        t: usize,
        sk_i: F,
        pk_map: Arc<Vec<G>>,
        output_sender: Sender<Id>,
        rbc_wrapper: RbcWrapFn<Id>,
        avss_wrapper: AvssWrapFn<Id>,
        agreement_wrapper: AvssAgreementWrapFn<Id>,
    ) -> Result<Self, AvssError> {
        if ids.len() != n_parties {
            return Err(AvssError::InvalidInput(
                "ids length must equal n_parties".into(),
            ));
        }
        if ids.iter().any(|&id| id == 0) {
            return Err(AvssError::InvalidInput("ids must not contain 0".into()));
        }
        let mut seen = std::collections::HashSet::new();
        if !ids.iter().all(|id| seen.insert(id)) {
            return Err(AvssError::InvalidInput("ids must be unique".into()));
        }
        let (rbc_sender, rbc_receiver) = mpsc::channel(200);
        let rbc = R::new(id, n_parties, t, t + 1, rbc_sender, rbc_wrapper)?;
        Ok(Self {
            id,
            n_parties,
            ids,
            t,
            sk_i,
            pk_map,
            shares: Arc::new(Mutex::new(BTreeMap::new())),
            retired: Arc::new(Mutex::new(RetiredSet::new(DEFAULT_RETIRED_CAP))),
            agreement: Arc::new(Mutex::new(BTreeMap::new())),
            rbc,
            rbc_output: Arc::new(Mutex::new(rbc_receiver)),
            output_sender,
            wrapper: avss_wrapper,
            agreement_wrapper,
        })
    }

    /// Clears the dealer share mailbox entry, the agreement state, and the underlying RBC
    /// broadcast session for a single AVSS instance. Callers that derive one `Id` per dealer
    /// must call this once per dealer to fully release a round.
    pub async fn clear_session(&self, id: Id) {
        self.rbc.clear_session(id).await;
        self.agreement.lock().await.remove(&id);
        // `shares` and `retired` are held together (shares first) so this can't interleave
        // with `finalize`'s own check-then-act on the same two locks — see `finalize`.
        let mut map = self.shares.lock().await;
        map.remove(&id);
        self.retired.lock().await.record(id);
    }

    /// Removes and returns a dealer's share, tombstoning the id so a late
    /// duplicate of the same dealer message can't resurrect it after the
    /// consumer has already moved on.
    pub async fn take_share(&self, id: Id) -> Option<Option<Vec<FeldmanShamirShare<F, G>>>> {
        self.agreement.lock().await.remove(&id);
        // See `clear_session`'s comment on lock ordering: `shares` held across the
        // `retired` mark so this can't interleave with `finalize`.
        let mut map = self.shares.lock().await;
        let value = map.remove(&id).map(|(_, v)| v);
        self.retired.lock().await.record(id);
        value
    }

    /// Returns `true` if `map` has room for one more entry. Entries only leave this map via
    /// `take_share`/`clear_session`, both driven by the consuming protocol's success path — a
    /// session no local caller ever finishes waiting on (timed out, or never legitimately
    /// started) would otherwise squat here forever. If `map` is full, evicts anything idle
    /// past the global session TTL first to reclaim room from exactly that kind of entry
    /// before giving up.
    async fn admit(&self, map: &mut BTreeMap<Id, AgreementState<F, G>>, charged_to: u8) -> bool {
        let over_capacity =
            |map: &BTreeMap<Id, AgreementState<F, G>>| map.len() >= MAX_PENDING_SESSIONS;
        // Per-peer quota, mirroring `SessionStore::get_or_admit`. Without it the global cap is
        // first-come-first-served, so a single party can occupy all `MAX_PENDING_SESSIONS`
        // slots and starve every honest dealer.
        //
        // Attribution is by `charged_to`, an authenticated identity the *caller* picks — not
        // by reading `session_id.dealer_id()` here, which would be unauthenticated for a
        // vote-triggered admission (an `Ok`/`Ready`/`Reveal` carries its `session_id` as plain
        // data, so its embedded dealer bits could name anyone). `process()` passes the
        // RBC-authenticated dealer for a real dealing; `get_or_admit_agreement` passes the
        // authenticated voter for a lazily-created, vote-triggered entry. Each entry's charge
        // is fixed at creation (`AgreementState::pending`) and never re-attributed.
        let per_peer_cap = (MAX_PENDING_SESSIONS / self.n_parties).max(1);
        let peer_count = |map: &BTreeMap<Id, AgreementState<F, G>>| {
            map.values()
                .filter(|state| state.charged_to == charged_to)
                .count()
        };

        if over_capacity(map) || peer_count(map) >= per_peer_cap {
            let stale: Vec<Id> = map
                .iter()
                .filter(|(_, state)| state.created_at.elapsed() >= session_ttl())
                .map(|(id, _)| *id)
                .collect();
            if !stale.is_empty() {
                // A stale entry may have already finalized into `shares` without ever being
                // drained by `take_share` (e.g. the output notification was dropped under a
                // full channel) — clear that too, or it would outlive its own agreement entry
                // and leak indefinitely. `shares` locked before `retired` (never the reverse)
                // to match `finalize`/`clear_session`/`take_share`'s ordering — this runs
                // while the caller already holds `agreement`, so the global order stays
                // `agreement` -> `shares` -> `retired` everywhere and can't deadlock against
                // them.
                let mut shares = self.shares.lock().await;
                let mut retired = self.retired.lock().await;
                for id in stale {
                    map.remove(&id);
                    shares.remove(&id);
                    retired.record(id);
                }
            }
        }
        !over_capacity(map) && peer_count(map) < per_peer_cap
    }

    pub async fn drain_rbc_output<N: Network + Send + Sync>(
        &mut self,
        net: Arc<N>,
    ) -> Result<(), AvssError>
    where
        F: PrimeField,
    {
        loop {
            let id = {
                let mut rx = self.rbc_output.lock().await;
                match rx.try_recv() {
                    Ok(id) => id,
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        return Err(AvssError::Abort);
                    }
                }
            };

            let output = self.rbc.get_store(id).await?;
            let msg: AvssMessage<Id> =
                crate::common::wire_format::deserialize_limited(&output, MAX_MESSAGE_SIZE)?;

            if msg.session_id != id {
                warn!("Dropping RBC output: inner session_id does not match RBC session metadata");
                continue;
            }

            match self.process(msg, net.clone()).await {
                Ok(()) => {}
                Err(e) => {
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    pub async fn init<Rnd, N>(
        &mut self,
        secrets: Vec<F>,
        session_id: Id,
        rng: &mut Rnd,
        net: Arc<N>,
    ) -> Result<(), AvssError>
    where
        N: Network + Sync + Send,
        Rnd: Rng,
    {
        info!("Receiving init for avss from {0:?}", self.id);
        // Generate the random polynomial of degree `degree` with `secret` as constant term

        let shares: Vec<Vec<FeldmanShamirShare<F, G>>> = FeldmanShamirShare::compute_shares_batch(
            &secrets,
            self.n_parties,
            self.t,
            Some(&self.ids),
            rng,
        )?;

        // Dealer ephemeral keypair
        let sk_d = F::rand(rng);
        let pk_d = G::generator().mul(sk_d);

        let mut pk_d_bytes = Vec::new();
        pk_d.serialize_compressed(&mut pk_d_bytes)?;

        let mut encrypted: Vec<Vec<Vec<u8>>> =
            vec![Vec::with_capacity(shares.len()); self.n_parties];

        let keys: Vec<_> = self
            .pk_map
            .iter()
            .map(|pk| {
                let ss = pk.mul(sk_d);
                kdf_from_point(&ss)
            })
            .collect();
        let mut public_commitments: Vec<Vec<Vec<u8>>> = Vec::with_capacity(shares.len());
        let mut pt = Vec::new();
        for x in &shares {
            assert_eq!(x.len(), self.n_parties);
            // commitments are identical across all parties for the same polynomial
            let commitment_bytes = x[0]
                .commitments
                .iter()
                .map(|c| {
                    let mut b = Vec::new();
                    c.serialize_compressed(&mut b).map(|_| b)
                })
                .collect::<Result<Vec<_>, _>>()?;
            public_commitments.push(commitment_bytes);

            for (i, share) in x.iter().enumerate() {
                pt.clear();
                share.feldmanshare.serialize_compressed(&mut pt)?; // scalar only
                encrypted[i].push(encrypt(keys[i].clone(), &pt, rng)?);
            }
        }

        //Broadcast to servers
        let msg = AvssMessage {
            session_id: session_id,
            dealer_pk: pk_d_bytes,
            public_commitments,
            encrypted_shares: encrypted,
        };

        let bytes = crate::common::wire_format::serialize(&msg)?;
        if bytes.len() as u64 > MAX_MESSAGE_SIZE {
            return Err(AvssError::InvalidInput(format!(
                "batched AVSS payload exceeds {} bytes",
                MAX_MESSAGE_SIZE
            )));
        }
        self.rbc.init(bytes, session_id, net).await?;

        Ok(())
    }

    /// Validates the shape of a dealing — deserializable `dealer_pk`, consistent lengths,
    /// well-formed commitment points — everything that must hold before this node's own row
    /// can even be decrypted. Kept separate from `process` so a failure here has a single,
    /// centralized cleanup site instead of repeating it at each of the checks below.
    fn validate_dealing(
        &self,
        msg: &AvssMessage<Id>,
    ) -> Result<(G, Vec<Vec<G>>, [u8; 32], Vec<Vec<u8>>), AvssError> {
        let pk_d: G = CanonicalDeserialize::deserialize_compressed(&msg.dealer_pk[..])?;
        if pk_d.is_zero() {
            return Err(AvssError::InvalidShare);
        }
        if msg.encrypted_shares.len() != self.n_parties {
            return Err(AvssError::InvalidShareLength);
        }
        if msg
            .encrypted_shares
            .iter()
            .any(|ciphertexts| ciphertexts.len() != msg.public_commitments.len())
        {
            return Err(AvssError::InvalidShareLength);
        }
        let cts: Vec<Vec<u8>> = msg
            .encrypted_shares
            .get(self.id)
            .ok_or(AvssError::InvalidShare)?
            .clone();

        let ss = pk_d.mul(self.sk_i);
        let key = kdf_from_point(&ss);

        // Bound the batch before decoding it — see `MAX_DEAL_BATCH`. Anything larger is
        // malformed by construction, since every consumer chunks its dealings at or below
        // this limit.
        if msg.public_commitments.len() > MAX_DEAL_BATCH {
            return Err(AvssError::InvalidCommitmentLength);
        }
        if msg
            .public_commitments
            .iter()
            .any(|commitments| commitments.len() != self.t + 1)
        {
            return Err(AvssError::InvalidCommitmentLength);
        }
        let all_commitments: Vec<Vec<G>> = msg
            .public_commitments
            .iter()
            .map(|cs| {
                cs.iter()
                    .map(|b| G::deserialize_compressed(&b[..]))
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;

        if cts.is_empty() {
            return Err(AvssError::InvalidShareLength);
        }
        if cts.len() != all_commitments.len() {
            return Err(AvssError::InvalidShareLength);
        }

        Ok((pk_d, all_commitments, key, cts))
    }

    pub async fn process<N: Network + Send + Sync>(
        &mut self,
        msg: AvssMessage<Id>,
        net: Arc<N>,
    ) -> Result<(), AvssError>
    where
        F: PrimeField,
    {
        info!(
            party_id = ?self.id,
            session_id = msg.session_id.as_u128(),
            "Processing AVSS share"
        );
        match msg.session_id.calling_protocol() {
            Some(proto) => proto,
            None => {
                return Err(AvssError::InvalidInput(format!(
                    "Unknown calling protocol in session ID {:?}",
                    msg.session_id
                )));
            }
        };
        let already_dealt = {
            let mut map = self.agreement.lock().await;
            if self.retired.lock().await.contains(&msg.session_id) {
                return Ok(()); // already consumed — drop the straggler instead of resurrecting it
            }
            if !map.contains_key(&msg.session_id) {
                // Reject an over-quota dealer here, before the decryption and curve
                // arithmetic below. Everything from `dealer_pk` onwards costs real work —
                // `t + 1` point decompressions per commitment plus a Feldman verification
                // per share — and without this the quota only limited what an attacker
                // could *cache*, not what it could make us *compute*.
                //
                // `admit` does not insert, so this is purely an early-out; the authoritative
                // check still runs after verification, because the lock is released in between
                // and another task may take the last slot meanwhile.
                // `session_id.dealer_id()` is trustworthy here: `avss_mpc`'s dispatch already
                // checked the RBC sender against it before this dealing was accepted.
                let dealer = msg.session_id.dealer_id();
                if !self.admit(&mut map, dealer).await {
                    warn!(
                        session_id = msg.session_id.as_u128(),
                        "AVSS agreement cache full or dealer {} over its per-peer quota; rejecting before verification",
                        dealer
                    );
                    self.rbc.clear_session(msg.session_id).await;
                    return Err(AvssError::LimitExceeded);
                }
                map.insert(msg.session_id, AgreementState::pending(dealer));
            }
            map.get(&msg.session_id)
                .is_some_and(|state| state.dealing.is_some())
        };
        if already_dealt {
            return Ok(()); // duplicate dealing delivery — RBC should not redeliver, but guard anyway
        }

        let (pk_d, all_commitments, key, cts) = match self.validate_dealing(&msg) {
            Ok(v) => v,
            Err(e) => {
                // The dealing itself is malformed — RBC will never redeliver a corrected
                // payload for this session_id, so any agreement state accumulated for it is
                // dead regardless. Clean up rather than leaving the slot (and the RBC-layer
                // payload) to squat until TTL, mirroring the admission-rejection branch above.
                self.agreement.lock().await.remove(&msg.session_id);
                self.retired.lock().await.record(msg.session_id);
                self.rbc.clear_session(msg.session_id).await;
                return Err(e);
            }
        };

        // Unlike plain AVSS's all-or-nothing early return, a bad row is now a local verdict
        // (`own_valid = false`) rather than a hard error — the whole point of the agreement
        // layer below is to let this node recover via its peers instead of being stuck.
        let mut own_shares = Vec::with_capacity(cts.len());
        let mut own_valid = true;
        for (ct, commitments) in cts.iter().zip(all_commitments.iter()) {
            let row = decrypt(key.clone(), ct).ok().and_then(|pt| {
                let shamirshare: Shamirshare<F> =
                    CanonicalDeserialize::deserialize_compressed(&pt[..]).ok()?;
                if shamirshare.id != self.ids[self.id] || shamirshare.degree != self.t {
                    return None;
                }
                let share = FeldmanShamirShare {
                    feldmanshare: shamirshare,
                    commitments: commitments.clone(),
                };
                verify_feldman(share.clone(), self.ids[self.id]).then_some(share)
            });
            match row {
                Some(share) => own_shares.push(share),
                None => {
                    own_valid = false;
                    break;
                }
            }
        }
        let own_shares = own_valid.then_some(own_shares);

        {
            let mut agreement = self.agreement.lock().await;
            let Some(state) = agreement.get_mut(&msg.session_id) else {
                return Ok(()); // evicted between admission and now
            };
            state.dealing = Some(DealingInfo {
                pk_d,
                all_commitments,
                encrypted_shares: msg.encrypted_shares.clone(),
                own_valid,
                own_shares,
            });
        }

        // Replay any `Reveal` this node saw before it could verify it — verification needs
        // `pk_d`, just learned above.
        let pending_reveals = {
            let mut agreement = self.agreement.lock().await;
            match agreement.get_mut(&msg.session_id) {
                Some(state) => std::mem::take(&mut state.pending_reveals),
                None => BTreeMap::new(),
            }
        };
        for (party_id, (k_id, proof)) in pending_reveals {
            self.apply_reveal(msg.session_id, party_id, k_id, proof, net.clone())
                .await?;
        }

        let (should_amplify, direct_finalize) = {
            let mut agreement = self.agreement.lock().await;
            let Some(state) = agreement.get_mut(&msg.session_id) else {
                return Ok(());
            };
            let should_amplify = state.should_amplify_ready(self.t);
            if should_amplify {
                state.sent_ready = true;
            }
            let direct_finalize = state.direct_finalize_shares(self.t);
            if direct_finalize.is_some() {
                state.finished = true;
            }
            (should_amplify, direct_finalize)
        };

        if should_amplify {
            self.broadcast_ready(msg.session_id, net.clone()).await?;
        }
        if let Some(shares) = direct_finalize {
            self.finalize(msg.session_id, shares).await;
        }

        if own_valid {
            self.broadcast_ok(msg.session_id, net).await?;
        } else {
            self.broadcast_reveal(msg.session_id, net).await?;
        }

        Ok(())
    }

    /// Dispatches an incoming OK/READY/Reveal vote.
    pub async fn process_agreement<N: Network + Send + Sync>(
        &mut self,
        msg: AvssAgreementMessage<Id>,
        net: Arc<N>,
    ) -> Result<(), AvssError>
    where
        F: PrimeField,
    {
        match msg {
            AvssAgreementMessage::Ok { session_id, voter } => {
                self.handle_ok(session_id, voter, net).await
            }
            AvssAgreementMessage::Ready { session_id, voter } => {
                self.handle_ready(session_id, voter, net).await
            }
            AvssAgreementMessage::Reveal {
                session_id,
                party_id,
                k_id,
                proof,
            } => {
                self.handle_reveal(session_id, party_id, k_id, proof, net)
                    .await
            }
        }
    }

    /// Gets (lazily admitting/creating if needed) the agreement entry for `session_id`,
    /// returning `None` if the session is retired or the cache is full. Mirrors
    /// `get_or_create_store`-style lazy admission elsewhere in the codebase: votes and the
    /// local dealing race over independent channels, so whichever arrives first creates the
    /// entry.
    ///
    /// `charged_to` must be an *authenticated* identity (the caller's already-verified
    /// voter/party_id) — never derived from `session_id` itself, since a vote's `session_id`
    /// is unauthenticated plain data and could name any dealer.
    async fn get_or_admit_agreement(&self, session_id: Id, charged_to: u8) -> bool {
        let mut agreement = self.agreement.lock().await;
        if agreement.contains_key(&session_id) {
            return true;
        }
        if self.retired.lock().await.contains(&session_id) {
            return false;
        }
        if !self.admit(&mut agreement, charged_to).await {
            return false;
        }
        agreement.insert(session_id, AgreementState::pending(charged_to));
        true
    }

    async fn handle_ok<N: Network + Send + Sync>(
        &mut self,
        session_id: Id,
        voter: PartyId,
        net: Arc<N>,
    ) -> Result<(), AvssError> {
        if voter >= self.n_parties || !self.get_or_admit_agreement(session_id, voter as u8).await {
            return Ok(());
        }
        let should_amplify = {
            let mut agreement = self.agreement.lock().await;
            let Some(state) = agreement.get_mut(&session_id) else {
                return Ok(());
            };
            if state.finished {
                return Ok(());
            }
            state.ok_votes.insert(voter);
            let amplify = state.should_amplify_ready(self.t);
            if amplify {
                state.sent_ready = true;
            }
            amplify
        };
        if should_amplify {
            self.broadcast_ready(session_id, net).await?;
        }
        Ok(())
    }

    async fn handle_ready<N: Network + Send + Sync>(
        &mut self,
        session_id: Id,
        voter: PartyId,
        net: Arc<N>,
    ) -> Result<(), AvssError> {
        if voter >= self.n_parties || !self.get_or_admit_agreement(session_id, voter as u8).await {
            return Ok(());
        }
        let (should_amplify, direct_finalize) = {
            let mut agreement = self.agreement.lock().await;
            let Some(state) = agreement.get_mut(&session_id) else {
                return Ok(());
            };
            if state.finished {
                return Ok(());
            }
            state.ready_votes.insert(voter);
            let amplify = state.should_amplify_ready(self.t);
            if amplify {
                state.sent_ready = true;
            }
            let direct_finalize = state.direct_finalize_shares(self.t);
            if direct_finalize.is_some() {
                state.finished = true;
            }
            (amplify, direct_finalize)
        };
        if should_amplify {
            self.broadcast_ready(session_id, net.clone()).await?;
        }
        if let Some(shares) = direct_finalize {
            self.finalize(session_id, shares).await;
        }
        Ok(())
    }

    async fn handle_reveal<N: Network + Send + Sync>(
        &mut self,
        session_id: Id,
        party_id: PartyId,
        k_id: Vec<u8>,
        proof: DleqProof,
        net: Arc<N>,
    ) -> Result<(), AvssError>
    where
        F: PrimeField,
    {
        if party_id >= self.n_parties {
            return Ok(());
        }
        // Cheap size guard before admission or any buffering: a genuine k_id/proof field is
        // one compressed group element or scalar (tens of bytes). Without this, a session
        // whose dealing hasn't arrived yet would let a single sender pad each of its (at most
        // one, per `pending_reveals` being keyed by `party_id`) buffered fields out toward
        // the wrapper's own message-size cap.
        if k_id.len() > MAX_DLEQ_FIELD_SIZE
            || proof.a1.len() > MAX_DLEQ_FIELD_SIZE
            || proof.a2.len() > MAX_DLEQ_FIELD_SIZE
            || proof.z.len() > MAX_DLEQ_FIELD_SIZE
        {
            return Ok(());
        }
        if !self
            .get_or_admit_agreement(session_id, party_id as u8)
            .await
        {
            return Ok(());
        }
        {
            let mut agreement = self.agreement.lock().await;
            let Some(state) = agreement.get_mut(&session_id) else {
                return Ok(());
            };
            if state.finished {
                return Ok(());
            }
            if state.dealing.is_none() {
                // Can't verify the NIZK yet — needs `pk_d` from the local dealing, which
                // hasn't arrived. Buffer for replay from `process` once it does. Keyed by
                // `party_id` (not appended), so a repeat send from the same party overwrites
                // rather than growing this entry without bound.
                state.pending_reveals.insert(party_id, (k_id, proof));
                return Ok(());
            }
        }
        self.apply_reveal(session_id, party_id, k_id, proof, net)
            .await
    }

    /// Verifies and applies one `Reveal`, assuming this node's own copy of the dealing is
    /// already known (checked by both callers: `handle_reveal` buffers otherwise, and
    /// `process`'s replay only runs after setting `dealing`).
    async fn apply_reveal<N: Network + Send + Sync>(
        &mut self,
        session_id: Id,
        party_id: PartyId,
        k_id_bytes: Vec<u8>,
        proof: DleqProof,
        net: Arc<N>,
    ) -> Result<(), AvssError>
    where
        F: PrimeField,
    {
        let Ok(k_id) = G::deserialize_compressed(&k_id_bytes[..]) else {
            return Ok(());
        };
        let (pk_d, all_commitments, encrypted_shares, own_valid, sent_reveal) = {
            let agreement = self.agreement.lock().await;
            let Some(state) = agreement.get(&session_id) else {
                return Ok(());
            };
            if state.finished {
                return Ok(());
            }
            let Some(dealing) = &state.dealing else {
                return Ok(());
            };
            (
                dealing.pk_d.clone(),
                dealing.all_commitments.clone(),
                dealing.encrypted_shares.clone(),
                dealing.own_valid,
                state.sent_reveal,
            )
        };

        let pk_party = self.pk_map[party_id].clone();
        if !dleq_verify(&proof, G::generator(), pk_party, pk_d.clone(), k_id.clone()) {
            return Ok(()); // fabricated or inconsistent — ignore
        }

        // A genuine reveal means some node needed one for this session. If our own row
        // already verified, help by revealing our own key too (once) — cheap, since it only
        // exposes our ECDH secret for *this one dealing*: the whole point of deriving it
        // from a per-dealing ephemeral key rather than our long-term key (hbACSS §V-C) is to
        // make that safe. Gating it on having actually observed a reveal (rather than doing
        // it unconditionally) means a dealing that behaves for everyone never has anyone
        // reveal anything.
        if own_valid && !sent_reveal {
            let already_sending = {
                let mut agreement = self.agreement.lock().await;
                match agreement.get_mut(&session_id) {
                    Some(state) if !state.sent_reveal && !state.finished => {
                        state.sent_reveal = true;
                        false
                    }
                    _ => true,
                }
            };
            if !already_sending {
                self.broadcast_reveal(session_id, net.clone()).await?;
            }
        }

        if own_valid {
            return Ok(()); // we already have our own valid share — no need to track recovery
        }
        if party_id >= encrypted_shares.len() {
            return Ok(());
        }

        // Re-derive `party_id`'s row using the now-proven-genuine key. Feldman's binding
        // property makes this safe to trust regardless of *why* `party_id` revealed: the
        // outcome is fixed by the dealer's original (RBC-agreed) ciphertext for `party_id`,
        // not by anything the revealer controls.
        let key = kdf_from_point(&k_id);
        let cts = &encrypted_shares[party_id];
        if cts.is_empty() || cts.len() != all_commitments.len() {
            return Ok(());
        }
        let mut shares = Vec::with_capacity(cts.len());
        for (ct, commitments) in cts.iter().zip(all_commitments.iter()) {
            let Ok(pt) = decrypt(key, ct) else {
                return Ok(()); // confirms party_id's own row was genuinely bad
            };
            let Ok(shamirshare) = Shamirshare::<F>::deserialize_compressed(&pt[..]) else {
                return Ok(());
            };
            if shamirshare.id != self.ids[party_id] || shamirshare.degree != self.t {
                return Ok(());
            }
            let share = FeldmanShamirShare {
                feldmanshare: shamirshare,
                commitments: commitments.clone(),
            };
            if !verify_feldman(share.clone(), self.ids[party_id]) {
                return Ok(());
            }
            shares.push(share);
        }

        let finalize_input = {
            let mut agreement = self.agreement.lock().await;
            let Some(state) = agreement.get_mut(&session_id) else {
                return Ok(());
            };
            if state.finished {
                return Ok(());
            }
            state.recovered.insert(party_id, shares);
            if state.recovered.len() >= self.t + 1 {
                state.finished = true;
                let recovered = std::mem::take(&mut state.recovered);
                let commitments = state
                    .dealing
                    .as_ref()
                    .map(|d| d.all_commitments.clone())
                    .unwrap_or_default();
                Some((recovered, commitments))
            } else {
                None
            }
        };
        if let Some((recovered, commitments)) = finalize_input {
            let my_shares = self.interpolate_own_share(&recovered, &commitments)?;
            self.finalize(session_id, my_shares).await;
        }
        Ok(())
    }

    /// Interpolates this node's own share at each batch position from `t + 1` (or more)
    /// Feldman-verified peer rows recovered via `Reveal`.
    fn interpolate_own_share(
        &self,
        recovered: &BTreeMap<PartyId, Vec<FeldmanShamirShare<F, G>>>,
        all_commitments: &[Vec<G>],
    ) -> Result<Vec<FeldmanShamirShare<F, G>>, AvssError> {
        let my_x = F::from(self.ids[self.id] as u64);
        let mut out = Vec::with_capacity(all_commitments.len());
        for (batch_index, commitments) in all_commitments.iter().enumerate() {
            let mut x_vals = Vec::with_capacity(recovered.len());
            let mut y_vals = Vec::with_capacity(recovered.len());
            for (&party, shares) in recovered.iter() {
                let share = shares
                    .get(batch_index)
                    .ok_or(AvssError::InvalidShareLength)?;
                x_vals.push(F::from(self.ids[party] as u64));
                y_vals.push(share.feldmanshare.share[0]);
            }
            let poly = lagrange_interpolate(&x_vals, &y_vals)?;
            let y = poly.evaluate(&my_x);
            out.push(FeldmanShamirShare {
                feldmanshare: Shamirshare::new(y, self.ids[self.id], self.t),
                commitments: commitments.clone(),
            });
        }
        Ok(out)
    }

    /// Writes a finalized result (direct or recovered) to the output cache and notifies the
    /// consumer, unless the session was cleared/consumed in the meantime.
    async fn finalize(&self, session_id: Id, shares: Vec<FeldmanShamirShare<F, G>>) {
        {
            // `shares` held across the `retired` check so this can't interleave with
            // `clear_session`/`take_share`'s own remove-then-retire: whichever of the two
            // gets `shares`'s lock first completes its whole check-then-act atomically,
            // instead of a retire landing in the gap between this check and the insert below
            // and orphaning an entry `admit`'s TTL sweep (which only scans `agreement`) can
            // never reach again.
            let mut map = self.shares.lock().await;
            if self.retired.lock().await.contains(&session_id) {
                return; // cleared/consumed already — drop the belated result
            }
            map.insert(session_id, (Instant::now(), Some(shares)));
        }

        // A blocking `.send().await` here would stall this node's entire message-processing
        // loop (not just AVSS) whenever the output channel fills up — e.g. an attacker
        // sending sessions the consumer isn't currently draining (it's only active during
        // specific protocol phases). `try_send` never blocks: on a full channel we drop the
        // notification and log it. The verified share is already cached above regardless, so
        // this only risks that one session's notification going unseen (bounded by the
        // channel capacity, which callers size to `MAX_PENDING_SESSIONS`) rather than an
        // unbounded node-wide hang.
        match self.output_sender.try_send(session_id) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!(
                    session_id = session_id.as_u128(),
                    "AVSS output channel full; dropping notification for cached session"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                warn!(
                    session_id = session_id.as_u128(),
                    "AVSS output receiver dropped; discarding notification"
                );
            }
        }
    }

    async fn broadcast_ok<N: Network + Send + Sync>(
        &self,
        session_id: Id,
        net: Arc<N>,
    ) -> Result<(), AvssError> {
        let msg = AvssAgreementMessage::Ok {
            session_id,
            voter: self.id,
        };
        let bytes = (self.agreement_wrapper)(msg)?;
        net.broadcast(&bytes).await?;
        Ok(())
    }

    async fn broadcast_ready<N: Network + Send + Sync>(
        &self,
        session_id: Id,
        net: Arc<N>,
    ) -> Result<(), AvssError> {
        let msg = AvssAgreementMessage::Ready {
            session_id,
            voter: self.id,
        };
        let bytes = (self.agreement_wrapper)(msg)?;
        net.broadcast(&bytes).await?;
        Ok(())
    }

    async fn broadcast_reveal<N: Network + Send + Sync>(
        &self,
        session_id: Id,
        net: Arc<N>,
    ) -> Result<(), AvssError>
    where
        F: PrimeField,
    {
        let pk_d = {
            let agreement = self.agreement.lock().await;
            let Some(state) = agreement.get(&session_id) else {
                return Ok(());
            };
            let Some(dealing) = &state.dealing else {
                return Ok(());
            };
            dealing.pk_d.clone()
        };
        let k_id = pk_d.clone().mul(self.sk_i);
        let mut k_id_bytes = Vec::new();
        k_id.serialize_compressed(&mut k_id_bytes)?;

        let mut rng =
            StdRng::from_rng(OsRng).map_err(|e| AvssError::InvalidInput(e.to_string()))?;
        let proof = dleq_prove(
            self.sk_i,
            G::generator(),
            self.pk_map[self.id].clone(),
            pk_d,
            k_id,
            &mut rng,
        )?;

        let msg = AvssAgreementMessage::Reveal {
            session_id,
            party_id: self.id,
            k_id: k_id_bytes,
            proof,
        };
        let bytes = (self.agreement_wrapper)(msg)?;
        net.broadcast(&bytes).await?;
        Ok(())
    }
}

#[cfg(test)]
mod dleq_tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Projective as G};
    use ark_ec::PrimeGroup;
    use ark_std::test_rng;
    use ark_std::UniformRand;

    /// Completeness: a proof generated with the real witness verifies against the
    /// real statement.
    #[test]
    fn valid_proof_verifies() {
        let mut rng = test_rng();
        let alpha = Fr::rand(&mut rng);
        let g0 = G::generator();
        let g1 = G::generator() * Fr::rand(&mut rng);
        let x = g0 * alpha;
        let y = g1 * alpha;

        let proof = dleq_prove(alpha, g0, x, g1, y, &mut rng).unwrap();
        assert!(dleq_verify(&proof, g0, x, g1, y));
    }

    /// Soundness sanity check: a proof for one statement must not verify against
    /// a different `y` (i.e., a different claimed Ki_d) — this is exactly the
    /// griefing case: someone claiming a fabricated shared secret.
    #[test]
    fn proof_rejects_mismatched_y() {
        let mut rng = test_rng();
        let alpha = Fr::rand(&mut rng);
        let g0 = G::generator();
        let g1 = G::generator() * Fr::rand(&mut rng);
        let x = g0 * alpha;
        let y = g1 * alpha;
        let wrong_y = g1 * Fr::rand(&mut rng);

        let proof = dleq_prove(alpha, g0, x, g1, y, &mut rng).unwrap();
        assert!(!dleq_verify(&proof, g0, x, g1, wrong_y));
    }

    /// Soundness sanity check: a proof must not verify against a different `x`
    /// (i.e., claiming the reveal came from a different party's public key).
    #[test]
    fn proof_rejects_mismatched_x() {
        let mut rng = test_rng();
        let alpha = Fr::rand(&mut rng);
        let g0 = G::generator();
        let g1 = G::generator() * Fr::rand(&mut rng);
        let x = g0 * alpha;
        let y = g1 * alpha;
        let wrong_x = g0 * Fr::rand(&mut rng);

        let proof = dleq_prove(alpha, g0, x, g1, y, &mut rng).unwrap();
        assert!(!dleq_verify(&proof, g0, wrong_x, g1, y));
    }

    /// A prover who doesn't actually know a consistent witness (x and y derived
    /// from *different* exponents) cannot produce a proof that verifies — this is
    /// the actual griefing attempt: fabricating a `(Ki_d, proof)` pair without ever
    /// having a real ECDH witness tying them together.
    #[test]
    fn cannot_fake_proof_without_consistent_witness() {
        let mut rng = test_rng();
        let g0 = G::generator();
        let g1 = G::generator() * Fr::rand(&mut rng);
        let x = g0 * Fr::rand(&mut rng);
        let y = g1 * Fr::rand(&mut rng); // unrelated exponent — no real alpha exists

        // The forger's best move is to run the honest prover with *some* alpha it
        // knows (say, the one behind x) and hope it slips through for y anyway.
        let fake_alpha = Fr::rand(&mut rng);
        let proof = dleq_prove(fake_alpha, g0, x, g1, y, &mut rng).unwrap();
        assert!(!dleq_verify(&proof, g0, x, g1, y));
    }
}
