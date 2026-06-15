//! Difficulty ⇄ target, and the big-endian comparison the PoW check uses.
//!
//! A solution is valid when `SHA-256(salt ‖ nonce) < target`, where
//! `target = floor(2^256 / difficulty)`. So a larger `difficulty` yields a
//! smaller target, meaning fewer of the 2^256 possible hashes qualify, meaning
//! the client must try ~`difficulty` of them on average. The browser computes the
//! identical target from the same `difficulty`, so both sides agree on success.

use sha2::{Digest, Sha256};

/// `target = floor(2^256 / difficulty)` as a 256-bit big-endian array.
///
/// `difficulty <= 1` returns the maximum target (every hash passes) — a useful
/// "effectively off" value. The division is exact long division base-256 over the
/// 33-byte numerator `2^256` (`0x01` followed by 32 zero bytes).
pub fn difficulty_to_target(difficulty: u64) -> [u8; 32] {
    if difficulty <= 1 {
        return [0xff; 32];
    }
    // Numerator 2^256 = one leading 1 byte then 32 zero bytes (33 digits base 256).
    let mut numerator = [0u8; 33];
    numerator[0] = 1;

    let d = difficulty as u128;
    let mut quotient = [0u8; 33];
    let mut remainder: u128 = 0;
    for i in 0..33 {
        let cur = (remainder << 8) | numerator[i] as u128;
        quotient[i] = (cur / d) as u8; // < 256 because remainder < d
        remainder = cur % d;
    }
    // For difficulty >= 2 the result fits in 256 bits, so quotient[0] == 0.
    let mut target = [0u8; 32];
    target.copy_from_slice(&quotient[1..33]);
    target
}

/// `true` iff `hash` (big-endian) is strictly less than `target` (big-endian).
pub fn hash_below(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    for i in 0..32 {
        if hash[i] != target[i] {
            return hash[i] < target[i];
        }
    }
    false
}

/// The PoW hash: `SHA-256(utf8(salt) ‖ utf8(decimal nonce))`.
///
/// Defined over the ASCII forms of `salt` and `nonce` so the browser can compute
/// it byte-for-byte with `TextEncoder` + WebCrypto `SHA-256`.
pub fn pow_hash(salt: &str, nonce: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(salt.as_bytes());
    h.update(nonce.to_string().as_bytes());
    h.finalize().into()
}

/// `true` iff `nonce` solves `salt` at `difficulty`.
pub fn solution_valid(salt: &str, nonce: u64, difficulty: u64) -> bool {
    hash_below(&pow_hash(salt, nonce), &difficulty_to_target(difficulty))
}
