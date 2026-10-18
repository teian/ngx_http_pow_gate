use pow_gate_core::redemption::{consume, id, Entry, Outcome};
#[test]
fn one_use_and_expired_slots_are_reclaimed() {
    let mut entries = vec![Entry::default(); 4];
    assert_eq!(
        consume(&mut entries, id("challenge"), 120, 100),
        Outcome::Accepted
    );
    assert_eq!(
        consume(&mut entries, id("challenge"), 120, 119),
        Outcome::Reused
    );
    assert_eq!(
        consume(&mut entries, id("challenge"), 120, 120),
        Outcome::Expired
    );
    assert_eq!(
        consume(&mut entries, id("new"), 200, 120),
        Outcome::Accepted
    );
}
#[test]
fn capacity_exhaustion_never_evicts_live_entries() {
    let mut entries = vec![Entry::default(); 2];
    assert_eq!(consume(&mut entries, id("a"), 120, 100), Outcome::Accepted);
    assert_eq!(consume(&mut entries, id("b"), 120, 100), Outcome::Accepted);
    assert_eq!(consume(&mut entries, id("c"), 120, 100), Outcome::Full);
    assert_eq!(consume(&mut entries, id("a"), 120, 100), Outcome::Reused);
    assert_eq!(consume(&mut entries, id("c"), 240, 120), Outcome::Accepted);
    assert_eq!(consume(&mut [], id("c"), 240, 120), Outcome::Full);
}
#[test]
fn expired_holes_do_not_hide_live_duplicate_entries() {
    let mut entries = vec![Entry::default(); 4];
    let first = [0u8; 32];
    let mut second = first;
    second[31] = 1;
    assert_eq!(consume(&mut entries, first, 110, 100), Outcome::Accepted);
    assert_eq!(consume(&mut entries, second, 200, 100), Outcome::Accepted);
    assert_eq!(consume(&mut entries, second, 200, 110), Outcome::Reused);
}
#[test]
fn concurrent_redemption_has_exactly_one_winner_under_shared_lock() {
    use std::sync::{Arc, Barrier, Mutex};
    let entries = Arc::new(Mutex::new(vec![Entry::default(); 32]));
    let barrier = Arc::new(Barrier::new(32));
    let threads: Vec<_> = (0..32)
        .map(|_| {
            let entries = entries.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                consume(&mut entries.lock().unwrap(), id("same-token"), 200, 100)
            })
        })
        .collect();
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(
        results.iter().filter(|r| **r == Outcome::Accepted).count(),
        1
    );
    assert_eq!(
        results.iter().filter(|r| **r == Outcome::Reused).count(),
        31
    );
}
#[test]
fn table_fits_fixed_two_mib_zone() {
    assert!(std::mem::size_of::<Entry>() * 32768 + 32 < 2 * 1024 * 1024);
}

#[test]
fn saturated_probe_window_fails_closed_even_with_free_slots_elsewhere() {
    let mut entries = vec![Entry::default(); 128];
    for value in 0..64u8 {
        let mut id = [0u8; 32];
        id[31] = value;
        assert_eq!(consume(&mut entries, id, 200, 100), Outcome::Accepted);
    }
    let mut overflow = [0u8; 32];
    overflow[31] = 64;
    assert_eq!(consume(&mut entries, overflow, 200, 100), Outcome::Full);
    assert_eq!(consume(&mut entries, [0u8; 32], 200, 100), Outcome::Reused);
}
