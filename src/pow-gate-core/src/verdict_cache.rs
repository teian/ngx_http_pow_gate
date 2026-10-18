//! Bounded DNS-verdict cache. Full caches fail closed rather than evicting live
//! verdicts. Generation IDs prevent late DNS replies changing newer entries.

use std::{
    collections::HashMap,
    hash::Hash,
    time::{Duration, Instant},
};

pub enum Lookup {
    Cached(bool),
    Start(u64),
    Full,
}
struct Entry {
    verdict: bool,
    at: Instant,
    generation: u64,
}
pub struct VerdictCache<K> {
    entries: HashMap<K, Entry>,
    capacity: usize,
    ttl: Duration,
    next_sweep: Instant,
    generation: u64,
}

impl<K: Eq + Hash> VerdictCache<K> {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            capacity,
            ttl,
            next_sweep: Instant::now(),
            generation: 0,
        }
    }
    pub fn begin(&mut self, key: K, now: Instant) -> Lookup {
        if let Some(entry) = self.entries.get(&key) {
            if now.saturating_duration_since(entry.at) < self.ttl {
                return Lookup::Cached(entry.verdict);
            }
            self.entries.remove(&key);
        }
        // Sweep at most once per second, not once per attacker-controlled IP.
        if self.entries.len() >= self.capacity && now >= self.next_sweep {
            self.entries
                .retain(|_, entry| now.saturating_duration_since(entry.at) < self.ttl);
            self.next_sweep = now + Duration::from_secs(1);
        }
        if self.entries.len() >= self.capacity {
            return Lookup::Full;
        }
        self.generation = self.generation.wrapping_add(1);
        let generation = self.generation;
        self.entries.insert(
            key,
            Entry {
                verdict: false,
                at: now,
                generation,
            },
        );
        Lookup::Start(generation)
    }
    pub fn complete(&mut self, key: &K, generation: u64, verdict: bool, now: Instant) {
        if let Some(entry) = self.entries.get_mut(key) {
            if entry.generation == generation {
                entry.verdict = verdict;
                entry.at = now;
            }
        }
    }
    pub fn cancel(&mut self, key: &K, generation: u64) {
        if self
            .entries
            .get(key)
            .is_some_and(|e| e.generation == generation)
        {
            self.entries.remove(key);
        }
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
