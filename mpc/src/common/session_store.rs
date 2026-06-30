use std::collections::{HashMap, HashSet, VecDeque};

pub const DEFAULT_RETIRED_CAP: usize = 1024;

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
    fn clear_retired_allows_recreation() {
        let mut store: SessionStore<u32, u32> = SessionStore::with_default_cap();
        store.get_or_create_with(1, || 0);
        store.retire(1);
        assert!(store.get_or_create_with(1, || 0).is_none());

        store.clear_retired();
        assert!(store.get_or_create_with(1, || 0).is_some());
    }
}
