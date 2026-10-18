use pow_gate_core::verdict_cache::{Lookup, VerdictCache};
use std::time::{Duration, Instant};

fn generation(value: Lookup) -> u64 {
    match value {
        Lookup::Start(n) => n,
        _ => panic!("expected new lookup"),
    }
}
#[test]
fn capacity_is_bounded_and_expired_slots_become_available() {
    let now = Instant::now();
    let mut cache = VerdictCache::new(2, Duration::from_secs(1));
    generation(cache.begin(1, now));
    generation(cache.begin(2, now));
    for key in 3..10000 {
        assert!(matches!(cache.begin(key, now), Lookup::Full));
    }
    assert_eq!(cache.len(), 2);
    generation(cache.begin(3, now + Duration::from_secs(2)));
    assert_eq!(cache.len(), 1);
}
#[test]
fn pending_lookup_is_deduplicated_and_completed_verdict_is_cached() {
    let now = Instant::now();
    let mut cache = VerdictCache::new(2, Duration::from_secs(30));
    let id = generation(cache.begin(1, now));
    assert!(matches!(cache.begin(1, now), Lookup::Cached(false)));
    cache.complete(&1, id, true, now);
    assert!(matches!(cache.begin(1, now), Lookup::Cached(true)));
}
#[test]
fn cancelled_or_stale_lookup_cannot_overwrite_newer_verdict() {
    let now = Instant::now();
    let mut cache = VerdictCache::new(1, Duration::from_secs(1));
    let old = generation(cache.begin(1, now));
    let current = generation(cache.begin(1, now + Duration::from_secs(2)));
    cache.complete(&1, old, true, now + Duration::from_secs(2));
    cache.cancel(&1, old);
    assert!(matches!(
        cache.begin(1, now + Duration::from_secs(2)),
        Lookup::Cached(false)
    ));
    cache.cancel(&1, current);
    assert!(cache.is_empty());
    cache.complete(&1, current, true, now);
    assert!(cache.is_empty(), "late responses must not grow the cache");
}
