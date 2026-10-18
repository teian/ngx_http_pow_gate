//! Microbenchmarks of the engine's per-request hot path — they pinpoint which
//! cryptographic operation dominates the cost the nginx module pays per request.
//!
//! Run: `cargo bench -p pow-gate-core` (results under target/criterion).
//!
//! What to look for (see docs/performance.md):
//!   * `clearance_verify` measures HMAC-SHA256 and token parsing.
//!   * `proof_verify` (ECDSA P-256) is the dominant
//!     per-request cost when the optional `X-Pow-Proof` is present.
//!   * `pow_hash` is a single SHA-256 — the *server* does ~one per /verify; the
//!     *client* does ~`difficulty` of them (that cost is the browser's, by design).

use criterion::measurement::{Measurement, ValueFormatter, WallTime};
use criterion::{criterion_group, criterion_main, Criterion};
use std::time::{Duration, Instant};

/// Set POW_BENCH_CPU=1 on Linux to exclude scheduler wait from crypto timings.
/// Wall-clock measurements remain the default. CPU frequency/cache contention
/// can still affect CPU time, so record host load and compare repeated runs.
struct BenchClock;
enum Started {
    Wall(Instant),
    Cpu(Duration),
}

#[cfg(target_os = "linux")]
fn thread_cpu() -> Duration {
    let mut value = std::mem::MaybeUninit::<libc::timespec>::uninit();
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, value.as_mut_ptr()) },
        0
    );
    let value = unsafe { value.assume_init() };
    Duration::new(value.tv_sec as u64, value.tv_nsec as u32)
}
#[cfg(not(target_os = "linux"))]
fn thread_cpu() -> Duration {
    panic!("POW_BENCH_CPU requires Linux");
}

impl Measurement for BenchClock {
    type Intermediate = Started;
    type Value = Duration;
    fn start(&self) -> Started {
        if std::env::var_os("POW_BENCH_CPU").as_deref() == Some(std::ffi::OsStr::new("1")) {
            Started::Cpu(thread_cpu())
        } else {
            Started::Wall(Instant::now())
        }
    }
    fn end(&self, start: Started) -> Duration {
        match start {
            Started::Cpu(value) => thread_cpu() - value,
            Started::Wall(value) => value.elapsed(),
        }
    }
    fn add(&self, a: &Duration, b: &Duration) -> Duration {
        *a + *b
    }
    fn zero(&self) -> Duration {
        Duration::ZERO
    }
    fn to_f64(&self, value: &Duration) -> f64 {
        value.as_nanos() as f64
    }
    fn formatter(&self) -> &dyn ValueFormatter {
        static WALL: WallTime = WallTime;
        WALL.formatter()
    }
}
use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use pow_gate_core::{clearance, context, pow, proof, target};
use rand_core::OsRng;
use std::hint::black_box;

const KEY: &[u8] = b"benchmark-server-secret-key-32by";

// Frozen v2 decoder from before the allocation pass. Use the same prepared
// authenticator/backend for both paths so this isolates decoding/ownership.
fn owned_clearance_reference(
    key: &pow_gate_core::HmacKey,
    token: &str,
    context: &str,
    required: context::Assurance,
    now: i64,
    max_age: i64,
) -> Option<clearance::Clearance> {
    use pow_gate_core::codec::unb64url;
    use subtle::ConstantTimeEq;
    if token.len() > 4096 {
        return None;
    }
    let (payload, tag) = token.split_once('.')?;
    let expected = key.parts(&[b"pow-gate-clearance-v2|", payload.as_bytes()]);
    let tag = unb64url(tag)?;
    if !bool::from(expected.as_slice().ct_eq(&tag)) {
        return None;
    }
    let payload: clearance::Clearance = serde_json::from_slice(&unb64url(payload)?).ok()?;
    if payload.version != 2
        || !bool::from(payload.context.as_bytes().ct_eq(context.as_bytes()))
        || !payload.assurance.satisfies(required)
        || payload.exp <= now
        || payload.iat > now
        || max_age <= 0
        || now.checked_sub(payload.iat)? >= max_age
    {
        return None;
    }
    let pk = payload.pk_bytes()?;
    match payload.assurance {
        context::Assurance::Pow { .. } if pk.len() != 65 || pk[0] != 4 => return None,
        context::Assurance::NoJs { .. } if !pk.is_empty() => return None,
        _ => {}
    }
    Some(payload)
}

fn bench_target(c: &mut Criterion<BenchClock>) {
    c.bench_function("difficulty_to_target", |b| {
        b.iter(|| target::difficulty_to_target(black_box(50_000)))
    });
    c.bench_function("pow_hash", |b| {
        b.iter(|| target::pow_hash(black_box("deadbeefcafe0000"), black_box(123_456)))
    });
}

fn bench_clearance(c: &mut Criterion<BenchClock>) {
    let pk = SigningKey::random(&mut OsRng)
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let token = clearance::issue(
        KEY,
        &pk,
        "context",
        pow_gate_core::context::Assurance::Pow { difficulty: 2000 },
        1000,
        43200,
    );
    let key = pow_gate_core::HmacKey::new(KEY);
    let required = context::Assurance::Pow { difficulty: 2000 };
    assert!(owned_clearance_reference(&key, &token, "context", required, 2000, 43200).is_some());
    assert!(
        clearance::with_verified_prepared(
            &key,
            &token,
            "context",
            required,
            2000,
            43200,
            |value| value.public_key().len()
        ) == Some(65)
    );
    c.bench_function("clearance_verify_reference", |b| {
        b.iter(|| {
            owned_clearance_reference(
                black_box(&key),
                black_box(&token),
                "context",
                required,
                2000,
                43200,
            )
        })
    });
    c.bench_function("clearance_verify_borrowed", |b| {
        b.iter(|| {
            clearance::with_verified_prepared(
                black_box(&key),
                black_box(&token),
                "context",
                required,
                2000,
                43200,
                |value| value.public_key().len(),
            )
        })
    });

    c.bench_function("clearance_issue", |b| {
        b.iter(|| {
            clearance::issue(
                black_box(KEY),
                black_box(&pk),
                "context",
                pow_gate_core::context::Assurance::Pow { difficulty: 2000 },
                1000,
                43200,
            )
        })
    });
    c.bench_function("clearance_verify", |b| {
        b.iter(|| {
            clearance::verify(
                black_box(KEY),
                black_box(&token),
                "context",
                pow_gate_core::context::Assurance::Pow { difficulty: 2000 },
                2000,
                43200,
            )
        })
    });
}

fn bench_context(c: &mut Criterion<BenchClock>) {
    let ip = "192.0.2.42".parse().unwrap();
    let ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/154.0.0.0 Safari/537.36";
    let scope = r#"["animexx.de","pow_clearance","/","/.pow/","default"]"#;
    let issuer = [42u8; 32];
    c.bench_function("context_binding", |b| {
        b.iter(|| {
            context::binding(
                black_box(KEY),
                ip,
                black_box(ua),
                scope,
                &issuer,
                context::AddressPolicy::default(),
            )
        })
    });
    let prepared = pow_gate_core::HmacKey::new(KEY);
    let prepared_scope = context::Scope::new(None, "pow_clearance", "/", "/.pow/", "default");
    c.bench_function("scope_host", |b| {
        b.iter(|| prepared_scope.for_host(black_box("Example.COM")))
    });
    let binding = context::binding(
        KEY,
        ip,
        ua,
        scope,
        &issuer,
        context::AddressPolicy::default(),
    )
    .unwrap();
    let pk = SigningKey::random(&mut OsRng)
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let required = context::Assurance::Pow { difficulty: 500000 };
    let token = clearance::issue(KEY, &pk, &binding, required, 1000, 43200);
    c.bench_function("bound_clearance_crypto_path", |b| {
        b.iter(|| {
            let binding = context::binding(
                black_box(KEY),
                ip,
                black_box(ua),
                scope,
                &issuer,
                context::AddressPolicy::default(),
            )
            .unwrap();
            clearance::verify(KEY, black_box(&token), &binding, required, 2000, 43200)
        })
    });
    c.bench_function("bound_clearance_prepared", |b| {
        b.iter(|| {
            let binding = context::binding_prepared(
                black_box(&prepared),
                ip,
                black_box(ua),
                scope,
                &issuer,
                context::AddressPolicy::default(),
            )
            .unwrap();
            clearance::verify_prepared(
                &prepared,
                black_box(&token),
                &binding,
                required,
                2000,
                43200,
            )
        })
    });
}

fn bench_pow_verify(c: &mut Criterion<BenchClock>) {
    let ch = pow::issue(KEY, b"pk", "context", 2000, 1000, 300);
    // find a real nonce once, outside the timed loop
    let mut nonce = 0u64;
    while !target::solution_valid(&ch.salt, nonce, ch.difficulty) {
        nonce += 1;
    }
    c.bench_function("pow_verify_solution", |b| {
        b.iter(|| {
            pow::verify_solution(
                black_box(KEY),
                black_box(&ch),
                black_box(nonce),
                b"pk",
                "context",
                ch.difficulty,
                1100,
            )
        })
    });
}

fn bench_hmac(c: &mut Criterion<BenchClock>) {
    #[cfg(feature = "native-crypto")]
    {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let portable = Hmac::<Sha256>::new_from_slice(KEY).unwrap();
        let native = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, KEY);
        let input = [42u8; 512];
        c.bench_function("hmac_sha256_portable", |b| {
            b.iter(|| {
                let mut message = portable.clone();
                message.update(black_box(&input));
                message.finalize().into_bytes()
            })
        });
        c.bench_function("hmac_sha256_native", |b| {
            b.iter(|| ring::hmac::sign(&native, black_box(&input)))
        });
    }
    #[cfg(not(feature = "native-crypto"))]
    let _ = c;
}

fn bench_ranges(c: &mut Criterion<BenchClock>) {
    let mut ranges = pow_gate_core::ranges::IpRangeSet::new();
    for i in 0..10_000u32 {
        ranges.add_cidr(&format!(
            "{}/32",
            std::net::Ipv4Addr::from(0x0a000000 + i * 2)
        ));
    }
    let missing = "203.0.113.1".parse().unwrap();
    let legacy: Vec<_> = (0..10_000u32)
        .map(|i| (0x0a000000 + i * 2, u32::MAX))
        .collect();
    c.bench_function("ranges_10000_linear_miss", |b| {
        b.iter(|| {
            let address = black_box(0xcb007101u32);
            legacy.iter().any(|(net, mask)| address & mask == *net)
        })
    });
    c.bench_function("ranges_10000_miss", |b| {
        b.iter(|| ranges.contains(black_box(missing)))
    });
    let address = "10.0.39.14".parse().unwrap();
    c.bench_function("ranges_10000_hit", |b| {
        b.iter(|| ranges.contains(black_box(address)))
    });
}

fn bench_proof(c: &mut Criterion<BenchClock>) {
    let sk = SigningKey::random(&mut OsRng);
    let pk = VerifyingKey::from(&sk)
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let sig: Signature = sk.sign(proof::message("GET", "/dashboard", 1000).as_bytes());
    let sig = sig.to_bytes().to_vec();

    #[cfg(feature = "native-crypto")]
    c.bench_function("proof_verify_portable", |b| {
        use p256::ecdsa::signature::Verifier;
        b.iter(|| {
            let vk = VerifyingKey::from_sec1_bytes(black_box(&pk)).unwrap();
            let signature = Signature::from_slice(black_box(&sig)).unwrap();
            vk.verify(
                proof::message("GET", "/dashboard", 1000).as_bytes(),
                &signature,
            )
        })
    });
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

criterion_group! {
    name = benches;
    config = Criterion::default().with_measurement(BenchClock);
    targets = bench_target, bench_clearance, bench_context, bench_pow_verify, bench_proof, bench_ranges, bench_hmac
}
criterion_main!(benches);
