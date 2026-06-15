//! Black-box end-to-end test for the PoW gate.
//!
//! Drives a live nginx (with the module loaded) through the whole handshake,
//! reusing `pow-gate-core` to solve the PoW and `p256` to sign the per-request
//! proof — the exact primitives the browser solver uses. Exits non-zero on the
//! first failed assertion, so it doubles as a CI gate.
//!
//!   BASE_URL (env, default http://localhost:8080)
//!
//! Steps:
//!   1. /healthz is excluded (pow_gate off) → 200 "ok"
//!   2. GET /  with no cookie → a challenge page (NOT upstream content)
//!   3. GET /.pow/challenge → { salt, exp, difficulty, token }
//!   4. solve the PoW (pow_gate_core::target::solution_valid)
//!   5. POST /.pow/verify → 204 + Set-Cookie: pow_clearance=...
//!   6. GET /  with the cookie (+ X-Pow-Proof) → upstream content

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use pow_gate_core::target::solution_valid;
use rand_core::OsRng;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(serde::Deserialize)]
struct Challenge {
    salt: String,
    exp: i64,
    difficulty: u64,
    token: String,
}

fn base() -> String {
    std::env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:8080".into())
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

fn fail(msg: impl AsRef<str>) -> ! {
    eprintln!("E2E FAIL: {}", msg.as_ref());
    std::process::exit(1);
}

fn main() {
    let base = base();
    println!("e2e: target {base}");

    // 1. excluded path is never gated
    let health = ureq::get(&format!("{base}/healthz")).call();
    match health {
        Ok(r) if r.status() == 200 => println!("✓ /healthz excluded (200)"),
        other => fail(format!("/healthz expected 200, got {other:?}")),
    }

    // 2. uncleared request gets a challenge, not upstream content
    let first = ureq::get(&format!("{base}/"))
        .set("User-Agent", "e2e-client")
        .call();
    let body = match first {
        Ok(r) => r.into_string().unwrap_or_default(),
        Err(ureq::Error::Status(_, r)) => r.into_string().unwrap_or_default(),
        Err(e) => fail(format!("GET / failed: {e}")),
    };
    if body.contains("upstream-content") {
        fail("uncleared request reached upstream — gate not engaged");
    }
    println!("✓ uncleared request was challenged");

    // 3. fetch a challenge
    let ch: Challenge = match ureq::get(&format!("{base}/.pow/challenge")).call() {
        Ok(r) => r.into_json().unwrap_or_else(|e| fail(format!("bad challenge json: {e}"))),
        Err(e) => fail(format!("GET /.pow/challenge failed: {e}")),
    };
    println!("✓ challenge: difficulty={} exp={}", ch.difficulty, ch.exp);

    // 4. solve it
    let mut nonce = 0u64;
    while !solution_valid(&ch.salt, nonce, ch.difficulty) {
        nonce += 1;
        if nonce > 50_000_000 {
            fail("could not solve challenge — difficulty too high for the test");
        }
    }
    println!("✓ solved: nonce={nonce}");

    // keypair for clearance binding + proof
    let sk = SigningKey::random(&mut OsRng);
    let pk = VerifyingKey::from(&sk).to_encoded_point(false).as_bytes().to_vec();
    let pubkey = B64.encode(&pk);

    // 5. submit the solution
    let verify = ureq::post(&format!("{base}/.pow/verify")).send_json(ureq::json!({
        "salt": ch.salt, "exp": ch.exp, "token": ch.token,
        "nonce": nonce, "pubkey": pubkey,
    }));
    let set_cookie = match verify {
        Ok(r) if r.status() == 204 || r.status() == 200 => r
            .header("set-cookie")
            .map(str::to_string)
            .unwrap_or_else(|| fail("/verify did not set a cookie")),
        Ok(r) => fail(format!("/verify status {}", r.status())),
        Err(e) => fail(format!("POST /.pow/verify failed: {e}")),
    };
    let cookie = set_cookie
        .split(';')
        .next()
        .unwrap_or("")
        .to_string();
    println!("✓ verified, got clearance cookie");

    // 6. cleared request reaches upstream
    let ts = now();
    let msg = format!("GET / {ts}");
    let sig: Signature = sk.sign(msg.as_bytes());
    let proof = format!("{}.{}", B64.encode(sig.to_bytes()), ts);

    let cleared = ureq::get(&format!("{base}/"))
        .set("Cookie", &cookie)
        .set("X-Pow-Proof", &proof)
        .set("User-Agent", "e2e-client")
        .call();
    let cleared_body = match cleared {
        Ok(r) => r.into_string().unwrap_or_default(),
        Err(ureq::Error::Status(s, _)) => fail(format!("cleared GET / status {s}")),
        Err(e) => fail(format!("cleared GET / failed: {e}")),
    };
    if !cleared_body.contains("upstream-content") {
        fail("cleared request did NOT reach upstream");
    }

    println!("✓ cleared request reached upstream");

    // 7. verifier: a UA that maps to verify:test reaches upstream WITHOUT solving,
    //    once the background refresher has loaded the IP-range feed (0.0.0.0/0 ⇒
    //    any client IP is in range). Retry to absorb the refresher's startup.
    let mut verified = false;
    for _ in 0..40 {
        let body = ureq::get(&format!("{base}/"))
            .set("User-Agent", "verifierbot/1.0")
            .call()
            .map(|r| r.into_string().unwrap_or_default())
            .unwrap_or_default();
        if body.contains("upstream-content") {
            verified = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    if !verified {
        fail("verified good-bot (verify:test) did not reach upstream");
    }
    println!("✓ verified good-bot allowed via IP-range verifier");

    println!("\nE2E PASS");
}
