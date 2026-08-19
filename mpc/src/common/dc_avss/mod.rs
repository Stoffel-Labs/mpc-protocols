use std::{collections::HashMap, sync::Arc};

use ark_ec::CurveGroup;
use ark_ff::FftField;
use stoffelnet::network_utils::PartyId;
use tokio::sync::Mutex;

use crate::common::{share::avss::AvssNode, ProtocolSessionId, RBC};

const ROUND_NEW_COMMITTEE: usize = 1;
const ROUND_OLD_COMMITTEE: usize = 0;

/// A committee descriptor for the AVSS.
///
/// In the dual AVSS protocol, the dealer needs to send its share `s` to the old committee `C` and
/// the new committee `C'`. This descriptor captures the information of the receiver committee.
///
/// # Indexation
///
/// Three distinct index spaces meet in this struct, and conflating them is the main hazard when
/// two committees share one network:
///
/// - The **committee-relative index**, in `(0..n)`. It is the position of a party inside this
///   committee and has no meaning outside it. It is the index of `ids`, `party_ids` and
///   `pub_keys`, all three of which are parallel: `ids[i]`, `party_ids[i]` and `pub_keys[i]`
///   describe the same party.
/// - The **global network ID** ([`PartyId`]), listed in `party_ids`. The network layer exposes a
///   single flat address space shared by both committees, so this is the only index a
///   `Network::send` call accepts.
/// - The **Shamir evaluation point**, listed in `ids`. This is where a party's share is evaluated
///   on the secret-sharing polynomial.
///
/// Membership is given by the explicit `party_ids` roster rather than by an offset into a
/// contiguous range. Committees are therefore free to occupy arbitrary, non-contiguous global
/// IDs and to overlap with each other, which matters because membership churns across DPSS
/// epochs. Use [`Committee::global`] and [`Committee::local`] to move between the
/// committee-relative index and the global ID instead of doing arithmetic on either.
pub struct Committee<F, G>
where
    G: CurveGroup<ScalarField = F>,
    F: FftField,
{
    /// Shamir evaluation point of each party, indexed by committee-relative index.
    ///
    /// These are field positions, not identities: they are the `x` values at which this
    /// committee's degree-`t` polynomials are evaluated, conventionally `1..=n` (`0` is excluded
    /// because it carries the secret). Each committee interpolates its own independent
    /// polynomial and nothing is ever interpolated across committees, so `C` and `C'` may — and
    /// normally do — reuse the same evaluation points even though their `party_ids` are disjoint.
    pub ids: Vec<usize>,
    /// Global network ID of each party, indexed by committee-relative index.
    ///
    /// This is the roster that defines committee membership, and the values here are the ones
    /// understood by the network layer. Entries must be distinct.
    pub party_ids: Vec<PartyId>,
    /// Number of parties in this committee.
    ///
    /// Equal to the length of `ids`, `party_ids` and `pub_keys`, and the exclusive upper bound
    /// of the committee-relative index space.
    pub n: usize,
    /// Corruption threshold of this committee, requiring `n >= 3t + 1`.
    ///
    /// It is also the degree of the sharing polynomials, so `t + 1` shares reconstruct. The two
    /// committees carry independent thresholds: the number of matching commitments a party waits
    /// for in the dual-committee check is the *other* committee's `t + 1`, not its own.
    pub t: usize,
    /// Public key of each party, indexed by committee-relative index.
    ///
    /// The dealer derives a per-party symmetric key from these to encrypt the individual shares,
    /// so `pub_keys[i]` must be the key of the party at `party_ids[i]` holding evaluation point
    /// `ids[i]`. Shared behind an [`Arc`] because every AVSS instance dealing to this committee
    /// reads the same list.
    pub pub_keys: Arc<Vec<G>>,
}

impl<F, G> Committee<F, G>
where
    G: CurveGroup<ScalarField = F>,
    F: FftField,
{
    /// Converts a committee-relative index into a global network [`PartyId`].
    ///
    /// The `local` index is the party's position within this committee, in `(0..n)`, as protocol
    /// specifications and Shamir bookkeeping use it. The returned ID is the address understood
    /// by the network layer, and is the value to pass to `Network::send`.
    ///
    /// Returns `None` when `local` is not a valid index for this committee.
    pub fn global(&self, local: usize) -> Option<PartyId> {
        self.party_ids.get(local).copied()
    }

    /// Converts a global network [`PartyId`] into an index relative to this committee.
    ///
    /// This is the inverse of [`Committee::global`], and is the check that decides committee
    /// membership: a `Some` result means `global` belongs to this committee and gives its
    /// position within it, while `None` means the party is not a member.
    ///
    /// Because committee membership and message provenance are the same question here, callers
    /// on a receive path should treat `None` as "reject this message", not as an error to
    /// propagate: with both committees sharing one network, messages from the other committee
    /// arrive routinely and are simply not addressed to this protocol instance.
    pub fn local(&self, global: PartyId) -> Option<usize> {
        self.party_ids.iter().position(|&id| id == global)
    }
}

pub struct DualAvssNode<F, R, G, I>
where
    F: FftField,
    I: ProtocolSessionId,
    R: RBC<Id = I>,
    G: CurveGroup<ScalarField = F>,
{
    id: usize,
    avss_node: AvssNode<F, R, G, I>,
    storage: Arc<Mutex<HashMap<usize, Arc<Mutex<DualAvssStorage>>>>>,
}

pub struct DualAvssStorage {}
