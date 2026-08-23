use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub const DEFAULT_RETIRED_CAP: usize = 1024;

const DEFAULT_SESSION_TTL_MS: u64 = 300_000; // 300s

/// Global, process-wide idle-session eviction TTL, in milliseconds. A session store entry idle
/// longer than this is treated as abandoned — either a legitimately timed-out run, or an
/// unsolicited/foreign session ID that no local `wait_for_result`-style call will ever visit and
/// therefore ever `retire()`. [`SessionStore::admit`] sweeps entries older than this once a
/// session-count cap is hit, so a peer can't permanently burn its quota with garbage.
///
/// Shared by every protocol's store rather than threaded through each `Node::new(...)` — there
/// is exactly one sensible TTL per process,.
static SESSION_TTL_MS: AtomicU64 = AtomicU64::new(DEFAULT_SESSION_TTL_MS);

/// Returns the current global session TTL. Defaults to 300s; see `set_session_ttl`.
pub fn session_ttl() -> Duration {
    Duration::from_millis(SESSION_TTL_MS.load(Ordering::Relaxed))
}

/// Overrides the global session TTL used by every protocol store's stale-session eviction
/// (`SessionStore::admit`). Applies process-wide and takes effect immediately. Tests use this to
/// exercise eviction without waiting out the 300s default.
pub fn set_session_ttl(ttl: Duration) {
    SESSION_TTL_MS.store(ttl.as_millis() as u64, Ordering::Relaxed);
}

/// Bounded LRU tombstone set. Once an ID is recorded it stays until evicted by
/// the ring-buffer cap, preventing zombie re-creation after session cleanup.
#[derive(Debug)]
pub struct RetiredSet<Id> {
    order: VecDeque<Id>,
    set: HashSet<Id>,
    cap: usize,
}

impl<Id: std::hash::Hash + Eq + Copy> RetiredSet<Id> {
    pub fn new(cap: usize) -> Self {
        Self {
            order: VecDeque::new(),
            set: HashSet::new(),
            cap,
        }
    }

    pub fn record(&mut self, id: Id) {
        if self.set.insert(id) {
            self.order.push_back(id);
            if self.order.len() > self.cap {
                if let Some(old) = self.order.pop_front() {
                    self.set.remove(&old);
                }
            }
        }
    }

    pub fn contains(&self, id: &Id) -> bool {
        self.set.contains(id)
    }

    pub fn clear(&mut self) {
        self.order.clear();
        self.set.clear();
    }
}

/// Drop-in replacement for bare `HashMap` session stores.
///
/// The only creation point is `get_or_create_with`, which returns `None` for
/// retired IDs so callers can drop the message without any state allocation.
/// The `retire` method replaces `HashMap::remove`: it evicts the entry and
/// records a tombstone so late-arriving stragglers cannot re-create the session.
///
/// There is no `remove` method — the pattern is structurally enforced.
#[derive(Debug)]
pub struct SessionStore<Id, V> {
    active: HashMap<Id, V>,
    retired: RetiredSet<Id>,
}

impl<Id: std::hash::Hash + Eq + Copy, V: Clone> SessionStore<Id, V> {
    pub fn new(retired_cap: usize) -> Self {
        Self {
            active: HashMap::new(),
            retired: RetiredSet::new(retired_cap),
        }
    }

    pub fn with_default_cap() -> Self {
        Self::new(DEFAULT_RETIRED_CAP)
    }

    /// Returns `None` if `id` is retired — caller must drop the message.
    /// Creates a new entry via `init` if the session is genuinely new.
    pub fn get_or_create_with<F: FnOnce() -> V>(&mut self, id: Id, init: F) -> Option<V> {
        if self.retired.contains(&id) {
            return None;
        }
        Some(self.active.entry(id).or_insert_with(init).clone())
    }

    /// Evicts the active entry and records a tombstone.
    /// Returns `true` if the session was in the active map.
    pub fn retire(&mut self, id: Id) -> bool {
        let existed = self.active.remove(&id).is_some();
        self.retired.record(id);
        existed
    }

    pub fn get(&self, id: &Id) -> Option<&V> {
        self.active.get(id)
    }

    pub fn contains_key(&self, id: &Id) -> bool {
        self.active.contains_key(id)
    }

    pub fn len(&self) -> usize {
        self.active.len()
    }

    pub fn is_empty(&self) -> bool {
        self.active.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Id, &V)> {
        self.active.iter()
    }

    /// Retires every active entry for which `is_stale` returns true. Returns the number evicted.
    ///
    /// Intended for reclaiming session-count quota from abandoned entries (timed-out or
    /// unsolicited sessions that no local caller will ever `retire()` itself) once a
    /// capacity cap is hit, without waiting for a background reaper.
    pub fn evict_stale<P: FnMut(&V) -> bool>(&mut self, mut is_stale: P) -> usize {
        let ids: Vec<Id> = self
            .active
            .iter()
            .filter(|(_, v)| is_stale(v))
            .map(|(id, _)| *id)
            .collect();
        let n = ids.len();
        for id in ids {
            self.retire(id);
        }
        n
    }

    /// Retires every active session, tombstoning each one before clearing the
    /// active map. Unlike a bare `HashMap::clear`, this still blocks late
    /// stragglers for every session that was active at the time of the call —
    /// it just does it for all of them at once instead of one at a time.
    pub fn clear_all(&mut self) {
        let ids: Vec<Id> = self.active.keys().copied().collect();
        self.active.clear();
        for id in ids {
            self.retired.record(id);
        }
    }

    /// Clears the tombstone set, letting previously retired IDs be created again.
    /// Use only for full resets (e.g. between tests) — never during normal
    /// operation, or late stragglers for already-retired sessions will resurrect zombies.
    pub fn clear_retired(&mut self) {
        self.retired.clear();
    }
}

impl<Id: std::hash::Hash + Eq + Copy, Owner: Clone> SessionStore<Id, (usize, Instant, Owner)> {
    /// Returns `true` if a new session belonging to `initiator_id` fits within `global_cap` and
    /// `per_peer_cap`. If a cap is currently full, first evicts entries idle past the global
    /// session TTL (`session_ttl()`) to reclaim room from abandoned sessions before giving up —
    /// a session that timed out, or one created by a foreign/unsolicited ID nobody locally waits
    /// on, would otherwise squat on its slot forever, since active entries are otherwise only
    /// reclaimed by the owning protocol's own success-path `retire()` call.
    fn admit(&mut self, initiator_id: usize, global_cap: usize, per_peer_cap: usize) -> bool {
        if self.len() >= global_cap {
            self.evict_stale(|(_, created_at, _)| created_at.elapsed() >= session_ttl());
            if self.len() >= global_cap {
                return false;
            }
        }

        let peer_count = |store: &Self| {
            store
                .iter()
                .filter(|(_, (id, _, _))| *id == initiator_id)
                .count()
        };
        if peer_count(self) >= per_peer_cap {
            self.evict_stale(|(id, created_at, _)| {
                *id == initiator_id && created_at.elapsed() >= session_ttl()
            });
            if peer_count(self) >= per_peer_cap {
                return false;
            }
        }
        true
    }

    /// Combines the standard `contains_key` / `admit` / `get_or_create_with` dance into one
    /// call. See [`Admission`] for what each outcome means and why the distinction matters.
    ///
    /// New sub-protocols that need a session-count-capped store should use this rather than
    /// reimplementing the check themselves, because:
    /// - it's the only path that gets the stale-session reclaim in `admit` for free — a
    ///   hand-rolled `if store.len() >= MAX { return None }` check has no way to recover quota
    ///   from abandoned sessions, so it silently degrades into a permanent denial-of-service
    ///   once a peer (or a run of timeouts) fills the cap with garbage;
    /// - this exact class of bug (a session store with no cap, or a cap with no reclaim) has
    ///   been found and fixed independently across a dozen-plus protocol stores in this
    ///   codebase already — reusing the vetted primitive is how it stops recurring;
    /// - it's less code at the call site, and the call site can't get the tuple shape
    ///   (`initiator_id`, timestamp, owner) wrong since `get_or_admit` builds it internally,
    ///   nor can it conflate "retired" with "capacity-rejected" the way a bare `Option` would.
    pub fn get_or_admit<F: FnOnce() -> Owner>(
        &mut self,
        id: Id,
        initiator_id: usize,
        global_cap: usize,
        per_peer_cap: usize,
        init: F,
    ) -> Admission<Owner> {
        if !self.contains_key(&id) && !self.admit(initiator_id, global_cap, per_peer_cap) {
            return Admission::Rejected;
        }
        match self.get_or_create_with(id, || (initiator_id, Instant::now(), init())) {
            Some((_, _, owner)) => Admission::Got(owner),
            None => Admission::Retired,
        }
    }
}

/// Outcome of [`SessionStore::get_or_admit`].
///
/// Kept as three explicit variants rather than `Option<Owner>` because "no owner" has two
/// causes that callers must not conflate: a `None` from `Retired` is an ordinary late/duplicate
/// message for a session that already finished — silently drop it. A `None` from `Rejected`
/// means a genuinely new session hit the (TTL-reclaim-aware) capacity cap — that's the
/// DoS-relevant case some callers escalate into a hard error or a logged warning. Collapsing
/// both into plain `None` (as an earlier version of this method did) makes a retired session's
/// late stragglers look identical to a capacity attack, which is wrong on both sides: it
/// misreports harmless traffic as an attack, and would hide a real one behind "eh, probably just
/// a retired session."
#[derive(Debug)]
pub enum Admission<Owner> {
    /// The session's owner — either it already existed, or it was newly admitted and created.
    Got(Owner),
    /// The session ID is retired (tombstoned): drop the message, this isn't a capacity issue.
    Retired,
    /// A genuinely new session was rejected: the cap is still full even after reclaiming
    /// TTL-expired entries.
    Rejected,
}

impl<Owner> Admission<Owner> {
    /// Discards the `Retired` / `Rejected` distinction for callers that only care whether they
    /// got an owner.
    pub fn ok(self) -> Option<Owner> {
        match self {
            Admission::Got(owner) => Some(owner),
            Admission::Retired | Admission::Rejected => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    #[test]
    fn retired_id_blocked_after_active_map_is_empty() {
        let mut store: SessionStore<u32, Arc<Mutex<u32>>> = SessionStore::with_default_cap();

        // Create and retire session 1
        let _s = store.get_or_create_with(1, || Arc::new(Mutex::new(42)));
        assert!(store.retire(1));
        assert!(store.active.is_empty());

        // Straggler for ID 1 must be rejected even though active map is empty
        let result = store.get_or_create_with(1, || Arc::new(Mutex::new(99)));
        assert!(result.is_none(), "retired ID must not be re-created");
    }

    #[test]
    fn non_retired_id_is_created() {
        let mut store: SessionStore<u32, u32> = SessionStore::with_default_cap();
        let v = store.get_or_create_with(42, || 100);
        assert_eq!(v, Some(100));
    }

    #[test]
    fn cap_evicts_oldest_tombstone() {
        let mut store: SessionStore<u32, u32> = SessionStore::new(2);
        store.get_or_create_with(1, || 0);
        store.retire(1);
        store.get_or_create_with(2, || 0);
        store.retire(2);
        // Retiring ID 3 evicts ID 1 from the tombstone set (cap = 2)
        store.get_or_create_with(3, || 0);
        store.retire(3);

        // ID 1 is no longer in the retired set — can be re-created
        assert!(store.get_or_create_with(1, || 0).is_some());
        // IDs 2 and 3 are still retired
        assert!(store.get_or_create_with(2, || 0).is_none());
        assert!(store.get_or_create_with(3, || 0).is_none());
    }

    #[test]
    fn clear_all_tombstones_active_sessions() {
        let mut store: SessionStore<u32, u32> = SessionStore::with_default_cap();
        store.get_or_create_with(1, || 0);
        store.get_or_create_with(2, || 0);

        store.clear_all();
        assert!(store.is_empty());

        // Late stragglers for either session must not resurrect them
        assert!(store.get_or_create_with(1, || 99).is_none());
        assert!(store.get_or_create_with(2, || 99).is_none());
    }

    #[test]
    fn evict_stale_retires_matching_entries_only() {
        let mut store: SessionStore<u32, bool> = SessionStore::with_default_cap();
        store.get_or_create_with(1, || true); // stale
        store.get_or_create_with(2, || false); // fresh
        store.get_or_create_with(3, || true); // stale

        let evicted = store.evict_stale(|is_stale| *is_stale);
        assert_eq!(evicted, 2);
        assert_eq!(store.len(), 1);
        assert!(store.contains_key(&2));

        // Evicted IDs are tombstoned, not just removed — stragglers must not resurrect them.
        assert!(store.get_or_create_with(1, || false).is_none());
        assert!(store.get_or_create_with(3, || false).is_none());
    }

    #[test]
    fn admit_allows_under_cap_and_blocks_at_cap() {
        let mut store: SessionStore<u32, (usize, Instant, u32)> = SessionStore::with_default_cap();
        for id in 0..3u32 {
            assert!(store.admit(0, 3, 3));
            store.get_or_create_with(id, || (0, Instant::now(), 0));
        }
        // Global cap (3) reached, nothing stale yet (default 300s TTL) — must be rejected.
        assert!(!store.admit(0, 3, 3));
    }

    #[test]
    fn admit_blocks_one_peer_from_starving_others() {
        let mut store: SessionStore<u32, (usize, Instant, u32)> = SessionStore::with_default_cap();
        // Peer 0 fills its per-peer quota (2 of a 10-session global cap).
        for id in 0..2u32 {
            assert!(store.admit(0, 10, 2));
            store.get_or_create_with(id, || (0, Instant::now(), 0));
        }
        // Peer 0 is at its per-peer cap even though the global cap has room.
        assert!(!store.admit(0, 10, 2));
        // Peer 1 is unaffected.
        assert!(store.admit(1, 10, 2));
    }

    #[test]
    fn admit_reclaims_stale_entries_once_ttl_elapses() {
        let mut store: SessionStore<u32, (usize, Instant, u32)> = SessionStore::with_default_cap();
        set_session_ttl(Duration::from_millis(10));

        assert!(store.admit(0, 1, 1));
        store.get_or_create_with(1, || (0, Instant::now(), 0));
        // Cap is full and the entry isn't stale yet.
        assert!(!store.admit(0, 1, 1));

        std::thread::sleep(Duration::from_millis(20));
        // Now stale — admit must evict it and allow a new one in.
        assert!(store.admit(0, 1, 1));

        set_session_ttl(Duration::from_millis(DEFAULT_SESSION_TTL_MS));
    }

    #[test]
    fn get_or_admit_creates_then_returns_same_owner() {
        let mut store: SessionStore<u32, (usize, Instant, u32)> = SessionStore::with_default_cap();
        assert!(matches!(
            store.get_or_admit(1, 0, 10, 10, || 42),
            Admission::Got(42)
        ));
        // Second call for the same id must return the existing owner, not re-run init.
        assert!(matches!(
            store.get_or_admit(1, 0, 10, 10, || 99),
            Admission::Got(42)
        ));
    }

    #[test]
    fn get_or_admit_rejects_over_cap_new_session_but_not_existing() {
        let mut store: SessionStore<u32, (usize, Instant, u32)> = SessionStore::with_default_cap();
        assert!(matches!(
            store.get_or_admit(1, 0, 1, 1, || 1),
            Admission::Got(1)
        ));
        // Cap is full: a genuinely new session is rejected...
        assert!(matches!(
            store.get_or_admit(2, 0, 1, 1, || 2),
            Admission::Rejected
        ));
        // ...but revisiting the existing one still succeeds (contains_key short-circuits admit).
        assert!(matches!(
            store.get_or_admit(1, 0, 1, 1, || 1),
            Admission::Got(1)
        ));
    }

    #[test]
    fn get_or_admit_reports_retired_not_rejected() {
        // Regression test: a retired session must be reported as `Retired`, never `Rejected` —
        // conflating the two once caused a real bug where a late message for an already-completed
        // session was misreported as a capacity attack (wrong error type in batch_recon, wrong
        // "session limit reached" log everywhere else), even though the cap had room to spare.
        let mut store: SessionStore<u32, (usize, Instant, u32)> = SessionStore::with_default_cap();
        assert!(matches!(
            store.get_or_admit(1, 0, 10, 10, || 1),
            Admission::Got(1)
        ));
        store.retire(1);
        // Plenty of room under the cap (1 of 10) — a `Rejected` result here would be wrong.
        assert!(matches!(
            store.get_or_admit(1, 0, 10, 10, || 99),
            Admission::Retired
        ));
    }

    #[test]
    fn get_or_admit_ok_collapses_retired_and_rejected() {
        let mut store: SessionStore<u32, (usize, Instant, u32)> = SessionStore::with_default_cap();
        assert_eq!(store.get_or_admit(1, 0, 10, 10, || 1).ok(), Some(1));
        store.retire(1);
        assert_eq!(store.get_or_admit(1, 0, 10, 10, || 1).ok(), None);
        assert_eq!(store.get_or_admit(2, 0, 0, 0, || 2).ok(), None);
    }

    #[test]
    fn clear_retired_allows_recreation() {
        let mut store: SessionStore<u32, u32> = SessionStore::with_default_cap();
        store.get_or_create_with(1, || 0);
        store.retire(1);
        assert!(store.get_or_create_with(1, || 0).is_none());

        store.clear_retired();
        assert!(store.get_or_create_with(1, || 0).is_some());
    }
}
