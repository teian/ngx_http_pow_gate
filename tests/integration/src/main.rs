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
//!   6b. fetch/XHR (Sec-Fetch-Dest: empty) without proof → challenged
//!       (require_proof is enabled on / in the test config)
//!   6c. fetch/XHR with a fresh proof → upstream content
//!   6d. navigation (Sec-Fetch-Mode: navigate) on the cookie alone → upstream
//!   6e. tag subresources (image / font / module script) on the cookie alone
//!       → upstream (they cannot carry the proof header)
//!   6f. /default-proof (require_proof unset ⇒ default off): fetch/XHR on the
//!       cookie alone → upstream

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

    // 6b. require_proof (enabled on / in the test config): a fetch/XHR request
    //     (Sec-Fetch-Dest: empty — the only kind that CAN attach a custom
    //     header) WITHOUT a proof must be challenged, even with a valid
    //     clearance cookie — this is what defeats stolen-cookie replay.
    let no_proof_fetch = ureq::get(&format!("{base}/"))
        .set("Cookie", &cookie)
        .set("Sec-Fetch-Mode", "cors")
        .set("Sec-Fetch-Dest", "empty")
        .set("User-Agent", "e2e-client")
        .call();
    let no_proof_body = match no_proof_fetch {
        Ok(r) => r.into_string().unwrap_or_default(),
        Err(ureq::Error::Status(_, r)) => r.into_string().unwrap_or_default(),
        Err(e) => fail(format!("fetch-no-proof GET / failed: {e}")),
    };
    if no_proof_body.contains("upstream-content") {
        fail("fetch/XHR request without proof reached upstream — replay not blocked");
    }
    println!("✓ fetch/XHR without proof was challenged (require_proof)");

    // 6c. the same fetch/XHR request WITH a fresh valid proof passes.
    let ts2 = now();
    let sig2: Signature = sk.sign(format!("GET / {ts2}").as_bytes());
    let proof2 = format!("{}.{}", B64.encode(sig2.to_bytes()), ts2);
    let with_proof = ureq::get(&format!("{base}/"))
        .set("Cookie", &cookie)
        .set("Sec-Fetch-Mode", "cors")
        .set("Sec-Fetch-Dest", "empty")
        .set("X-Pow-Proof", &proof2)
        .set("User-Agent", "e2e-client")
        .call();
    let with_proof_body = match with_proof {
        Ok(r) => r.into_string().unwrap_or_default(),
        Err(ureq::Error::Status(s, _)) => fail(format!("fetch-with-proof GET / status {s}")),
        Err(e) => fail(format!("fetch-with-proof GET / failed: {e}")),
    };
    if !with_proof_body.contains("upstream-content") {
        fail("fetch/XHR request WITH valid proof did NOT reach upstream");
    }
    println!("✓ fetch/XHR with valid proof reached upstream");

    // 6d. a top-level navigation (Sec-Fetch-Mode: navigate) passes on the cookie
    //     alone — it cannot carry a custom header.
    let nav = ureq::get(&format!("{base}/"))
        .set("Cookie", &cookie)
        .set("Sec-Fetch-Mode", "navigate")
        .set("User-Agent", "e2e-client")
        .call();
    let nav_body = match nav {
        Ok(r) => r.into_string().unwrap_or_default(),
        Err(ureq::Error::Status(s, _)) => fail(format!("navigation GET / status {s}")),
        Err(e) => fail(format!("navigation GET / failed: {e}")),
    };
    if !nav_body.contains("upstream-content") {
        fail("navigation request on cookie alone did NOT reach upstream");
    }
    println!("✓ navigation on cookie alone reached upstream");

    // 6e. tag-driven subresource loads pass on the cookie alone: the browser
    //     issues them itself, so they can never carry X-Pow-Proof. Covers the
    //     three Sec-Fetch shapes browsers use — classic tags (no-cors), fonts
    //     and module scripts (both cors, which is why mode alone must NOT be
    //     used to demand a proof). Regression test for the bug where every
    //     asset on a gated page was served the challenge page.
    for (mode, dest, what) in [
        ("no-cors", "image", "<img> load"),
        ("cors", "font", "font load"),
        ("cors", "script", "module-script load"),
    ] {
        let sub = ureq::get(&format!("{base}/"))
            .set("Cookie", &cookie)
            .set("Sec-Fetch-Mode", mode)
            .set("Sec-Fetch-Dest", dest)
            .set("Sec-Fetch-Site", "same-origin")
            .set("User-Agent", "e2e-client")
            .call();
        let sub_body = match sub {
            Ok(r) => r.into_string().unwrap_or_default(),
            Err(ureq::Error::Status(s, _)) => fail(format!("{what} status {s}")),
            Err(e) => fail(format!("{what} failed: {e}")),
        };
        if !sub_body.contains("upstream-content") {
            fail(format!("{what} (mode={mode}, dest={dest}) on cookie alone did NOT reach upstream"));
        }
        println!("✓ {what} on cookie alone reached upstream");
    }

    // 6f. a location that does NOT set pow_gate_require_proof gets the default
    //     (off): fetch/XHR passes on the cookie alone, no proof demanded.
    let default_proof = ureq::get(&format!("{base}/default-proof"))
        .set("Cookie", &cookie)
        .set("Sec-Fetch-Mode", "cors")
        .set("Sec-Fetch-Dest", "empty")
        .set("User-Agent", "e2e-client")
        .call();
    let default_proof_body = match default_proof {
        Ok(r) => r.into_string().unwrap_or_default(),
        Err(ureq::Error::Status(s, _)) => fail(format!("default-proof GET status {s}")),
        Err(e) => fail(format!("default-proof GET failed: {e}")),
    };
    if !default_proof_body.contains("upstream-content") {
        fail("fetch/XHR without proof was challenged on default require_proof — default is not off");
    }
    println!("✓ fetch/XHR without proof reached upstream where require_proof is unset (default off)");

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

    // 8. challenge:<N> — a UA mapped to challenge:5000 is issued exactly that
    //    difficulty, the echoed value verifies, and echoing a LOWER one with
    //    the same token is rejected (HMAC-bound).
    let hard: Challenge = match ureq::get(&format!("{base}/.pow/challenge"))
        .set("User-Agent", "hardbot/1.0")
        .call()
    {
        Ok(r) => r.into_json().unwrap_or_else(|e| fail(format!("bad hardbot challenge json: {e}"))),
        Err(e) => fail(format!("hardbot GET /.pow/challenge failed: {e}")),
    };
    if hard.difficulty != 5000 {
        fail(format!("challenge:5000 override not applied — issued difficulty {}", hard.difficulty));
    }
    let mut hard_nonce = 0u64;
    while !solution_valid(&hard.salt, hard_nonce, hard.difficulty) {
        hard_nonce += 1;
    }
    let downgrade = ureq::post(&format!("{base}/.pow/verify")).send_json(ureq::json!({
        "salt": hard.salt, "exp": hard.exp, "token": hard.token,
        "nonce": hard_nonce, "pubkey": pubkey, "difficulty": 4,
    }));
    match downgrade {
        Err(ureq::Error::Status(400, _)) => println!("✓ difficulty downgrade rejected (400)"),
        other => fail(format!("downgraded difficulty expected 400, got {other:?}")),
    }
    let hard_ok = ureq::post(&format!("{base}/.pow/verify")).send_json(ureq::json!({
        "salt": hard.salt, "exp": hard.exp, "token": hard.token,
        "nonce": hard_nonce, "pubkey": pubkey, "difficulty": hard.difficulty,
    }));
    match hard_ok {
        Ok(r) if r.status() == 204 || r.status() == 200 => {
            println!("✓ challenge:5000 solved + verified with echoed difficulty")
        }
        other => fail(format!("hardbot verify expected 204, got {other:?}")),
    }

    // 9. challenge:js — the lightweight tier issues difficulty 1 (any nonce).
    let js: Challenge = match ureq::get(&format!("{base}/.pow/challenge"))
        .set("User-Agent", "litebot/1.0")
        .call()
    {
        Ok(r) => r.into_json().unwrap_or_else(|e| fail(format!("bad litebot challenge json: {e}"))),
        Err(e) => fail(format!("litebot GET /.pow/challenge failed: {e}")),
    };
    if js.difficulty != 1 {
        fail(format!("challenge:js expected difficulty 1, got {}", js.difficulty));
    }
    let mut js_nonce = 0u64;
    while !solution_valid(&js.salt, js_nonce, js.difficulty) {
        js_nonce += 1;
    }
    let js_ok = ureq::post(&format!("{base}/.pow/verify")).send_json(ureq::json!({
        "salt": js.salt, "exp": js.exp, "token": js.token,
        "nonce": js_nonce, "pubkey": pubkey, "difficulty": js.difficulty,
    }));
    match js_ok {
        Ok(r) if r.status() == 204 || r.status() == 200 => {
            println!("✓ challenge:js (difficulty 1) verified")
        }
        other => fail(format!("litebot verify expected 204, got {other:?}")),
    }

    // 10. challenge:nojs — the full meta-refresh flow, exactly as a text
    //     browser walks it. No redirect-following: we assert each hop.
    let agent = ureq::builder().redirects(0).build();
    let nojs_path = "/?q=some+query&page=2"; // return path must survive verbatim
    let nojs_page = match agent
        .get(&format!("{base}{nojs_path}"))
        .set("User-Agent", "nojsbot/1.0")
        .call()
    {
        Ok(r) => r.into_string().unwrap_or_default(),
        Err(ureq::Error::Status(s, _)) => fail(format!("nojs GET expected 200 page, got {s}")),
        Err(e) => fail(format!("nojs GET failed: {e}")),
    };
    if !nojs_page.contains("http-equiv=\"refresh\"") {
        fail("challenge:nojs did not serve the meta-refresh page");
    }
    let pass_url = extract_pass_url(&nojs_page)
        .unwrap_or_else(|| fail("no pass URL in the nojs page"));
    println!("✓ nojs page served with meta refresh → {pass_url}");

    // 10a. redeeming immediately must NOT clear — it re-serves the page with a
    //      fresh grant (the wait starts over).
    let early = match agent
        .get(&format!("{base}{pass_url}"))
        .set("User-Agent", "nojsbot/1.0")
        .call()
    {
        Ok(r) => {
            if r.header("set-cookie").is_some() {
                fail("too-early pass redeem set a clearance cookie");
            }
            r.into_string().unwrap_or_default()
        }
        other => fail(format!("too-early pass expected 200 page, got {other:?}")),
    };
    if !early.contains("http-equiv=\"refresh\"") {
        fail("too-early pass redeem did not re-serve the nojs page");
    }
    let fresh_pass_url = extract_pass_url(&early)
        .unwrap_or_else(|| fail("no pass URL in the too-early re-challenge"));
    println!("✓ too-early redeem re-challenged without cookie");

    // 10b. wait out the (fresh) grant's delay, then redeem: 302 + cookie +
    //      Location = the original path, verbatim.
    std::thread::sleep(std::time::Duration::from_millis(2500));
    let redeemed = match agent
        .get(&format!("{base}{fresh_pass_url}"))
        .set("User-Agent", "nojsbot/1.0")
        .call()
    {
        Ok(r) if r.status() == 302 => r,
        other => fail(format!("pass redeem expected 302, got {other:?}")),
    };
    let nojs_cookie = redeemed
        .header("set-cookie")
        .unwrap_or_else(|| fail("pass redeem did not set a clearance cookie"))
        .split(';')
        .next()
        .unwrap_or("")
        .to_string();
    let location = redeemed.header("location").unwrap_or("").to_string();
    if location != nojs_path {
        fail(format!("pass redirect Location {location:?} != original path {nojs_path:?}"));
    }
    println!("✓ pass redeemed after wait: 302 to original path + cookie");

    // 10c. the no-JS clearance opens the gate like any other.
    let nojs_cleared = ureq::get(&format!("{base}/default-proof"))
        .set("Cookie", &nojs_cookie)
        .set("User-Agent", "nojsbot/1.0")
        .call()
        .map(|r| r.into_string().unwrap_or_default())
        .unwrap_or_default();
    if !nojs_cleared.contains("upstream-content") {
        fail("nojs clearance cookie did not reach upstream");
    }
    println!("✓ nojs clearance cookie reached upstream");

    println!("\nE2E PASS");
}

/// Pull the pass URL out of the nojs page (`content="2;url=<here>"`).
fn extract_pass_url(page: &str) -> Option<String> {
    let i = page.find(";url=")? + 5;
    let rest = &page[i..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}
