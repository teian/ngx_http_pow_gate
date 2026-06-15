//! Load generator that measures the PoW gate's per-request impact and surfaces
//! the bottleneck, by comparing four request classes against a live nginx:
//!
//!   baseline   GET excluded path (gate off)        — bare nginx static serve
//!   challenge  GET / with no cookie                — gate serves the challenge page
//!   cleared    GET / with the clearance cookie      — steady state, HMAC verify only
//!   proof      GET / with cookie + X-Pow-Proof      — adds the ECDSA proof verify
//!
//! The `cleared` vs `proof` gap is the cost of the per-request proof (ECDSA),
//! which the microbenchmarks (`cargo bench -p pow-gate-core`) show is ~100× the
//! HMAC clearance check. See docs/performance.md.
//!
//! Env: BASE_URL (default http://localhost:8080), PERF_DURATION secs (default 5),
//!      PERF_CONCURRENCY (default 8), PERF_MODES (csv, default all).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use pow_gate_core::target::solution_valid;
use rand_core::OsRng;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(serde::Deserialize)]
struct Challenge {
    salt: String,
    exp: i64,
    difficulty: u64,
    token: String,
}

fn env(k: &str, default: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| default.into())
}
fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

/// One immutable client identity: the clearance cookie + the keypair that signs
/// proofs. Shared read-only across worker threads.
struct Identity {
    cookie: String,
    signing: SigningKey,
}

fn handshake(base: &str) -> Identity {
    let ch: Challenge = ureq::get(&format!("{base}/.pow/challenge"))
        .call()
        .expect("challenge")
        .into_json()
        .expect("challenge json");
    let mut nonce = 0u64;
    while !solution_valid(&ch.salt, nonce, ch.difficulty) {
        nonce += 1;
    }
    let sk = SigningKey::random(&mut OsRng);
    let pk = VerifyingKey::from(&sk).to_encoded_point(false).as_bytes().to_vec();
    let res = ureq::post(&format!("{base}/.pow/verify")).send_json(ureq::json!({
        "salt": ch.salt, "exp": ch.exp, "token": ch.token,
        "nonce": nonce, "pubkey": B64.encode(&pk),
    }));
    let set_cookie = res
        .expect("verify")
        .header("set-cookie")
        .expect("set-cookie")
        .to_string();
    let cookie = set_cookie.split(';').next().unwrap_or("").to_string();
    Identity { cookie, signing: sk }
}

fn proof_header(id: &Identity, method: &str, path: &str) -> String {
    let ts = now();
    let sig: Signature = id.signing.sign(format!("{method} {path} {ts}").as_bytes());
    format!("{}.{}", B64.encode(sig.to_bytes()), ts)
}

#[derive(Clone, Copy)]
enum Mode {
    Baseline,
    Challenge,
    Cleared,
    Proof,
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Mode::Baseline => "baseline",
            Mode::Challenge => "challenge",
            Mode::Cleared => "cleared",
            Mode::Proof => "proof",
        }
    }
    fn parse(s: &str) -> Option<Mode> {
        Some(match s {
            "baseline" => Mode::Baseline,
            "challenge" => Mode::Challenge,
            "cleared" => Mode::Cleared,
            "proof" => Mode::Proof,
            _ => return None,
        })
    }
}

/// One request on a keepalive `agent` (connection reuse avoids socket churn);
/// returns its latency, or None on error.
fn one_request(agent: &ureq::Agent, base: &str, mode: Mode, id: &Identity) -> Option<Duration> {
    let t = Instant::now();
    let res = match mode {
        Mode::Baseline => agent.get(&format!("{base}/healthz")).call(),
        Mode::Challenge => agent.get(&format!("{base}/")).set("User-Agent", "perf").call(),
        Mode::Cleared => agent.get(&format!("{base}/")).set("Cookie", &id.cookie).call(),
        Mode::Proof => agent
            .get(&format!("{base}/"))
            .set("Cookie", &id.cookie)
            .set("X-Pow-Proof", &proof_header(id, "GET", "/"))
            .call(),
    };
    // challenge returns 200 (page); others 200; any 2xx/3xx counts as served.
    match res {
        Ok(_) => Some(t.elapsed()),
        Err(ureq::Error::Status(_, _)) => Some(t.elapsed()), // served, non-2xx still timed
        Err(_) => None,
    }
}

struct Stats {
    errors: u64,
    rps: f64,
    p50: u128,
    p95: u128,
    p99: u128,
    max: u128,
}

fn run_mode(base: &str, mode: Mode, dur: Duration, conc: usize, id: &Identity) -> Stats {
    let stop = Arc::new(AtomicBool::new(false));
    let base = Arc::new(base.to_string());
    let id = Arc::new(Identity {
        cookie: id.cookie.clone(),
        signing: id.signing.clone(),
    });

    let mut handles = Vec::new();
    let start = Instant::now();
    for _ in 0..conc {
        let stop = stop.clone();
        let base = base.clone();
        let id = id.clone();
        handles.push(std::thread::spawn(move || {
            let agent = ureq::AgentBuilder::new()
                .max_idle_connections_per_host(1)
                .build();
            let mut lats: Vec<u128> = Vec::new();
            let mut errors = 0u64;
            while !stop.load(Ordering::Relaxed) {
                match one_request(&agent, &base, mode, &id) {
                    Some(d) => lats.push(d.as_micros()),
                    None => errors += 1,
                }
            }
            (lats, errors)
        }));
    }
    std::thread::sleep(dur);
    stop.store(true, Ordering::Relaxed);

    let mut all: Vec<u128> = Vec::new();
    let mut errors = 0u64;
    for h in handles {
        let (lats, e) = h.join().unwrap();
        all.extend(lats);
        errors += e;
    }
    let elapsed = start.elapsed().as_secs_f64();
    all.sort_unstable();
    let pct = |p: f64| -> u128 {
        if all.is_empty() {
            0
        } else {
            all[((all.len() as f64 * p) as usize).min(all.len() - 1)]
        }
    };
    Stats {
        errors,
        rps: all.len() as f64 / elapsed,
        p50: pct(0.50),
        p95: pct(0.95),
        p99: pct(0.99),
        max: all.last().copied().unwrap_or(0),
    }
}

fn main() {
    let base = env("BASE_URL", "http://localhost:8080");
    let dur = Duration::from_secs(env("PERF_DURATION", "5").parse().unwrap_or(5));
    let conc: usize = env("PERF_CONCURRENCY", "8").parse().unwrap_or(8);
    let modes_csv = env("PERF_MODES", "baseline,challenge,cleared,proof");
    let modes: Vec<Mode> = modes_csv.split(',').filter_map(Mode::parse).collect();

    eprintln!("perf: {base}  duration={dur:?}  concurrency={conc}");
    let id = handshake(&base);

    println!(
        "{:<10} {:>10} {:>8} {:>10} {:>10} {:>10} {:>10}",
        "mode", "req/s", "errors", "p50(µs)", "p95(µs)", "p99(µs)", "max(µs)"
    );
    let mut baseline_rps = None;
    for m in &modes {
        let s = run_mode(&base, *m, dur, conc, &id);
        if matches!(m, Mode::Baseline) {
            baseline_rps = Some(s.rps);
        }
        println!(
            "{:<10} {:>10.0} {:>8} {:>10} {:>10} {:>10} {:>10}",
            m.name(),
            s.rps,
            s.errors,
            s.p50,
            s.p95,
            s.p99,
            s.max
        );
    }
    if let Some(b) = baseline_rps {
        eprintln!(
            "\nbaseline {:.0} req/s = the ungated ceiling. Compare the gated rows;\n\
             the cleared→proof drop is the per-request ECDSA proof cost.",
            b
        );
    }
}
