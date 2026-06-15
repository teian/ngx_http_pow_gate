//! Microbenchmarks of the engine's per-request hot path — they pinpoint which
//! cryptographic operation dominates the cost the nginx module pays per request.
//!
//! Run: `cargo bench -p pow-gate-core` (results under target/criterion).
//!
//! What to look for (see docs/performance.md):
//!   * `clearance_verify` (HMAC-SHA256) is sub-microsecond — cheap.
//!   * `proof_verify` (ECDSA P-256) is tens of microseconds — the dominant
//!     per-request cost when the optional `X-Pow-Proof` is present.
//!   * `pow_hash` is a single SHA-256 — the *server* does ~one per /verify; the
//!     *client* does ~`difficulty` of them (that cost is the browser's, by design).

use criterion::{criterion_group, criterion_main, Criterion};
use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use pow_gate_core::{clearance, pow, proof, target};
use rand_core::OsRng;
use std::hint::black_box;

const KEY: &[u8] = b"benchmark-server-secret-key-32by";

fn bench_target(c: &mut Criterion) {
    c.bench_function("difficulty_to_target", |b| {
        b.iter(|| target::difficulty_to_target(black_box(50_000)))
    });
    c.bench_function("pow_hash", |b| {
        b.iter(|| target::pow_hash(black_box("deadbeefcafe0000"), black_box(123_456)))
    });
}

fn bench_clearance(c: &mut Criterion) {
    let pk = [4u8; 65];
    let token = clearance::issue(KEY, &pk, 1000, 43200);

    c.bench_function("clearance_issue", |b| {
        b.iter(|| clearance::issue(black_box(KEY), black_box(&pk), 1000, 43200))
    });
    c.bench_function("clearance_verify", |b| {
        b.iter(|| clearance::verify(black_box(KEY), black_box(&token), 2000))
    });
}

fn bench_pow_verify(c: &mut Criterion) {
    let ch = pow::issue(KEY, 2000, 1000, 300);
    // find a real nonce once, outside the timed loop
    let mut nonce = 0u64;
    while !target::solution_valid(&ch.salt, nonce, ch.difficulty) {
        nonce += 1;
    }
    c.bench_function("pow_verify_solution", |b| {
        b.iter(|| {
            pow::verify_solution(
                black_box(KEY),
                black_box(&ch.salt),
                ch.exp,
                black_box(&ch.token),
                black_box(nonce),
                ch.difficulty,
                1100,
            )
        })
    });
}

fn bench_proof(c: &mut Criterion) {
    let sk = SigningKey::random(&mut OsRng);
    let pk = VerifyingKey::from(&sk)
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let sig: Signature = sk.sign(proof::message("GET", "/dashboard", 1000).as_bytes());
    let sig = sig.to_bytes().to_vec();

    c.bench_function("proof_verify", |b| {
        b.iter(|| {
            proof::verify(
                black_box(&pk),
                black_box("GET"),
                black_box("/dashboard"),
                1000,
                black_box(&sig),
                1001,
                5,
            )
        })
    });
}

criterion_group!(benches, bench_target, bench_clearance, bench_pow_verify, bench_proof);
criterion_main!(benches);
