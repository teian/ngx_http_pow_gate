//! Tests for difficulty → target and the PoW hash check. Own test crate;
//! public API only.

use pow_gate_core::target::{difficulty_to_target, hash_below, pow_hash, solution_valid};

#[test]
fn difficulty_one_or_zero_is_max_target() {
    assert_eq!(difficulty_to_target(1), [0xff; 32]);
    assert_eq!(difficulty_to_target(0), [0xff; 32]);
}

#[test]
fn difficulty_two_halves_target() {
    // 2^256 / 2 = 2^255 = 0x80 then 31 zero bytes.
    let mut expected = [0u8; 32];
    expected[0] = 0x80;
    assert_eq!(difficulty_to_target(2), expected);
}

#[test]
fn difficulty_256_shifts_one_byte() {
    // 2^256 / 256 = 2^248. Byte 0 is most-significant, so bit 248 lands as the
    // low bit of byte 0: result = 0x01 followed by 31 zero bytes.
    let mut expected = [0u8; 32];
    expected[0] = 0x01;
    assert_eq!(difficulty_to_target(256), expected);
}

#[test]
fn hash_below_orders_big_endian_strictly() {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a[0] = 0x10;
    b[0] = 0x20;
    assert!(hash_below(&a, &b));
    assert!(!hash_below(&b, &a));
    assert!(!hash_below(&a, &a));
}

#[test]
fn pow_hash_is_stable() {
    // Pin the contract the browser must reproduce: SHA-256(utf8(salt ‖ nonce)).
    let h1 = pow_hash("deadbeef", 42);
    let h2 = pow_hash("deadbeef", 42);
    assert_eq!(h1, h2);
    assert_ne!(h1, pow_hash("deadbeef", 43));
    assert_ne!(h1, pow_hash("deadbeee", 42));
}

#[test]
fn a_solution_can_be_found_and_verifies() {
    let salt = "deadbeef";
    let difficulty = 2000;
    let mut nonce = 0u64;
    while !solution_valid(salt, nonce, difficulty) {
        nonce += 1;
        assert!(nonce < 10_000_000, "should find a solution quickly");
    }
    assert!(solution_valid(salt, nonce, difficulty));
    // a hard target makes that same nonce overwhelmingly unlikely to pass
    assert!(!solution_valid("cafebabe", nonce, 1 << 40));
}
