//! Challenge issuance and solution verification — the stateless PoW handshake.
//!
//! The server keeps **no per-challenge state**. It binds the random `salt` and
//! the expiry to itself with an HMAC `token`; at verify time it re-derives that
//! token to confirm the pair is one it issued and unexpired, then checks the
//! hash. The difficulty (hence the target) is taken from server config at verify
//! time, never from the client — so a client cannot ask for an easier target.

use crate::codec::{b64url, hex};
use crate::mac::{ct_eq, hmac};
use crate::target::solution_valid;

/// What `GET {endpoint}challenge` returns to the browser.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Challenge {
    /// Random per-request salt (hex).
    pub salt: String,
    /// Unix seconds after which a solution is rejected.
    pub exp: i64,
    /// Expected-hash count; the browser derives the same target from it.
    pub difficulty: u64,
    /// HMAC binding `salt`+`exp` to the server (opaque to the client).
    pub token: String,
}

/// What the salt/exp are bound under. Kept private and stable so issue and verify
/// always agree.
fn binding(salt: &str, exp: i64) -> Vec<u8> {
    format!("{salt}|{exp}").into_bytes()
}

/// Issue a fresh challenge. `now` and `ttl` are seconds; `ttl` bounds how long the
/// client has to solve (defeats precomputation).
pub fn issue(key: &[u8], difficulty: u64, now: i64, ttl: i64) -> Challenge {
    let mut raw = [0u8; 16];
    getrandom::getrandom(&mut raw).expect("OS RNG");
    let salt = hex(&raw);
    let exp = now + ttl;
    let token = b64url(&hmac(key, &binding(&salt, exp)));
    Challenge {
        salt,
        exp,
        difficulty,
        token,
    }
}

/// Outcome of verifying a submitted solution.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Ok,
    Expired,
    BadToken,
    WrongSolution,
}

/// Verify a submitted solution against a challenge the server issued.
///
/// `difficulty` is the server's current configured value (NOT echoed from the
/// client). All of: token authentic, not expired, and hash below target.
pub fn verify_solution(
    key: &[u8],
    salt: &str,
    exp: i64,
    token: &str,
    nonce: u64,
    difficulty: u64,
    now: i64,
) -> Verdict {
    let expect = b64url(&hmac(key, &binding(salt, exp)));
    if !ct_eq(expect.as_bytes(), token.as_bytes()) {
        return Verdict::BadToken;
    }
    if exp <= now {
        return Verdict::Expired;
    }
    if !solution_valid(salt, nonce, difficulty) {
        return Verdict::WrongSolution;
    }
    Verdict::Ok
}
