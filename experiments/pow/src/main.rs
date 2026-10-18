//! Isolated native verifier-cost experiment. Never linked into the nginx module.
use std::{hint::black_box, time::Instant};
use sha2::{Digest, Sha256};
fn measure(label: &str, count: u32, mut work: impl FnMut(u32)) {
    let start = Instant::now();
    for nonce in 0..count { work(black_box(nonce)); }
    println!("{label}: {:.3} us/verification ({count} samples)", start.elapsed().as_secs_f64()*1e6/count as f64);
}
fn main() {
    let challenge = b"pow-gate-native-cost-experiment-v1";
    measure("SHA-256", 100_000, |n| { black_box(Sha256::digest([challenge.as_slice(), &n.to_le_bytes()].concat())); });
    // Match the Anubis prototype's Argon2 defaults; validation recomputes one hash.
    let argon = argon2::Argon2::default();
    measure("Argon2id (19 MiB, t=2, p=1)", 20, |n| {
        let mut out = [0;32]; argon.hash_password_into(challenge, &(n as u64).to_le_bytes(), &mut out).unwrap(); black_box(out);
    });
    // Include program construction in verifier cost. Production may cache this,
    // but an attacker can always submit a different authenticated challenge.
    let seed = (0u32..).map(|n| [challenge.as_slice(), &n.to_le_bytes()].concat()).find(|s| hashx::HashX::new(s).is_ok()).unwrap();
    measure("HashX (including seed program setup)", 1000, |n| { black_box(hashx::HashX::new(&seed).unwrap().hash_to_u64(n as u64)); });
}
