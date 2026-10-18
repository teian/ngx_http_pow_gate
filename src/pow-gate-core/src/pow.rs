//! Protocol v2: PoW is bound to the client's canonical public key and opaque
//! client/policy context. Successful verification must be followed by atomic
//! redemption of `token` before issuing clearance (see `redemption`).

use crate::codec::{b64url, hex};
use crate::mac::{ct_eq, hmac};
use crate::target::solution_valid;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Challenge {
    pub version: u8,
    pub salt: String,
    pub exp: i64,
    pub difficulty: u64,
    pub token: String,
}

fn binding(salt: &str, exp: i64, difficulty: u64, pk: &[u8], context: &str) -> Vec<u8> {
    serde_json::to_vec(&(
        "pow-gate-challenge-v2",
        salt,
        exp,
        difficulty,
        b64url(pk),
        context,
    ))
    .expect("serialize")
}

pub fn issue(
    key: &[u8],
    pk: &[u8],
    context: &str,
    difficulty: u64,
    now: i64,
    ttl: i64,
) -> Challenge {
    let mut raw = [0u8; 16];
    getrandom::getrandom(&mut raw).expect("OS RNG");
    let salt = hex(&raw);
    let exp = now + ttl;
    let token = b64url(&hmac(key, &binding(&salt, exp, difficulty, pk, context)));
    Challenge {
        version: 2,
        salt,
        exp,
        difficulty,
        token,
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Ok,
    Expired,
    BadToken,
    WrongSolution,
}

pub fn verify_solution(
    key: &[u8],
    challenge: &Challenge,
    nonce: u64,
    pk: &[u8],
    context: &str,
    required_difficulty: u64,
    now: i64,
) -> Verdict {
    let expect = b64url(&hmac(
        key,
        &binding(
            &challenge.salt,
            challenge.exp,
            challenge.difficulty,
            pk,
            context,
        ),
    ));
    if challenge.version != 2
        || challenge.difficulty == 0
        || challenge.difficulty != required_difficulty
        || !ct_eq(expect.as_bytes(), challenge.token.as_bytes())
    {
        return Verdict::BadToken;
    }
    if challenge.exp <= now {
        return Verdict::Expired;
    }
    if !solution_valid(&challenge.salt, nonce, challenge.difficulty) {
        return Verdict::WrongSolution;
    }
    Verdict::Ok
}
