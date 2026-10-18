use pow_gate_core::{
    pow::{self, Challenge, Verdict},
    target::solution_valid,
};

const KEY: &[u8] = b"server-secret-key";
const PK: &[u8] = b"committed-client-public-key";
const CONTEXT: &str = "client-and-policy";

fn issue(difficulty: u64) -> Challenge {
    pow::issue(KEY, PK, CONTEXT, difficulty, 1000, 30)
}
fn solve(c: &Challenge) -> u64 {
    (0..)
        .find(|n| solution_valid(&c.salt, *n, c.difficulty))
        .unwrap()
}
fn verify(c: &Challenge, nonce: u64, now: i64) -> Verdict {
    pow::verify_solution(KEY, c, nonce, PK, CONTEXT, c.difficulty, now)
}

#[test]
fn accepts_solution_and_rejects_at_expiry() {
    let c = issue(2000);
    let n = solve(&c);
    assert_eq!(verify(&c, n, 1005), Verdict::Ok);
    assert_eq!(verify(&c, n, c.exp), Verdict::Expired);
}

#[test]
fn rejects_tampered_parameters_and_legacy_version() {
    let c = issue(512);
    let n = solve(&c);
    for field in 0..5 {
        let mut bad = c.clone();
        match field {
            0 => bad.token.push('x'),
            1 => bad.salt.push('x'),
            2 => bad.exp += 1,
            3 => bad.difficulty = 1,
            _ => bad.version = 1,
        }
        assert_eq!(verify(&bad, n, 1005), Verdict::BadToken);
    }
}

#[test]
fn rejects_wrong_solution() {
    let c = issue(1 << 30);
    let bad = (0..)
        .find(|n| !solution_valid(&c.salt, *n, c.difficulty))
        .unwrap();
    assert_eq!(verify(&c, bad, 1005), Verdict::WrongSolution);
}

#[test]
fn binds_key_client_context_and_current_issuing_policy() {
    let c = issue(512);
    let n = solve(&c);
    for (key, pk, context, difficulty) in [
        (&b"wrong-server-key"[..], PK, CONTEXT, 512),
        (KEY, &b"different-public-key"[..], CONTEXT, 512),
        (KEY, PK, "other-client-or-policy", 512),
        (KEY, PK, CONTEXT, 2000),
    ] {
        assert_eq!(
            pow::verify_solution(key, &c, n, pk, context, difficulty, 1005),
            Verdict::BadToken
        );
    }
}

#[test]
fn cannot_echo_an_easier_difficulty() {
    let mut c = issue(1 << 28);
    c.difficulty = 1;
    assert_eq!(verify(&c, 0, 1005), Verdict::BadToken);
}
