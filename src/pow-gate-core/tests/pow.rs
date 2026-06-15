//! End-to-end PoW handshake tests. Own test crate; public API only.

use pow_gate_core::pow::{issue, verify_solution, Verdict};
use pow_gate_core::target::solution_valid;

const KEY: &[u8] = b"server-secret-key";

fn solve(salt: &str, difficulty: u64) -> u64 {
    let mut n = 0u64;
    while !solution_valid(salt, n, difficulty) {
        n += 1;
    }
    n
}

#[test]
fn full_handshake_accepts_a_real_solution() {
    let c = issue(KEY, 2000, 1000, 30);
    let nonce = solve(&c.salt, c.difficulty);
    assert_eq!(
        verify_solution(KEY, &c.salt, c.exp, &c.token, nonce, c.difficulty, 1005),
        Verdict::Ok
    );
}

#[test]
fn rejects_expired() {
    let c = issue(KEY, 2000, 1000, 30);
    let nonce = solve(&c.salt, c.difficulty);
    assert_eq!(
        verify_solution(KEY, &c.salt, c.exp, &c.token, nonce, c.difficulty, 9999),
        Verdict::Expired
    );
}

#[test]
fn rejects_forged_or_tampered_token() {
    let c = issue(KEY, 2000, 1000, 30);
    let nonce = solve(&c.salt, c.difficulty);
    assert_eq!(
        verify_solution(KEY, &c.salt, c.exp, "not-the-token", nonce, c.difficulty, 1005),
        Verdict::BadToken
    );
    assert_eq!(
        verify_solution(KEY, "00000000", c.exp, &c.token, nonce, c.difficulty, 1005),
        Verdict::BadToken
    );
}

#[test]
fn rejects_wrong_nonce() {
    let c = issue(KEY, 1 << 30, 1000, 30);
    let bad = if solution_valid(&c.salt, 0, c.difficulty) { 1 } else { 0 };
    assert_eq!(
        verify_solution(KEY, &c.salt, c.exp, &c.token, bad, c.difficulty, 1005),
        Verdict::WrongSolution
    );
}

#[test]
fn client_cannot_downgrade_difficulty() {
    // A solution valid at an easy difficulty must NOT pass when the server
    // verifies at its own (harder) difficulty.
    let server_difficulty = 1 << 28;
    let c = issue(KEY, server_difficulty, 1000, 30);
    let easy_nonce = solve(&c.salt, 4); // trivially solvable
    assert_ne!(
        verify_solution(KEY, &c.salt, c.exp, &c.token, easy_nonce, server_difficulty, 1005),
        Verdict::Ok
    );
}
