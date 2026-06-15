//! Per-request proof tests. Own test crate; constructs real ECDSA signatures
//! with p256 (the same primitive WebCrypto produces in the browser).

use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use pow_gate_core::proof::{message, verify};
use rand_core::OsRng;

fn keypair() -> (SigningKey, Vec<u8>) {
    let sk = SigningKey::random(&mut OsRng);
    let pk = VerifyingKey::from(&sk)
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    (sk, pk)
}

fn sign(sk: &SigningKey, method: &str, path: &str, ts: i64) -> Vec<u8> {
    let sig: Signature = sk.sign(message(method, path, ts).as_bytes());
    sig.to_bytes().to_vec()
}

#[test]
fn valid_proof_verifies() {
    let (sk, pk) = keypair();
    let sig = sign(&sk, "GET", "/dashboard", 1000);
    assert!(verify(&pk, "GET", "/dashboard", 1000, &sig, 1003, 5));
}

#[test]
fn stale_timestamp_rejected() {
    let (sk, pk) = keypair();
    let sig = sign(&sk, "GET", "/dashboard", 1000);
    assert!(!verify(&pk, "GET", "/dashboard", 1000, &sig, 1100, 5));
    // also reject a future timestamp beyond skew
    assert!(!verify(&pk, "GET", "/dashboard", 1000, &sig, 900, 5));
}

#[test]
fn tampered_request_rejected() {
    let (sk, pk) = keypair();
    let sig = sign(&sk, "GET", "/dashboard", 1000);
    assert!(!verify(&pk, "GET", "/admin", 1000, &sig, 1003, 5));
    assert!(!verify(&pk, "POST", "/dashboard", 1000, &sig, 1003, 5));
    assert!(!verify(&pk, "GET", "/dashboard", 1001, &sig, 1003, 5));
}

#[test]
fn wrong_key_rejected() {
    let (sk, _pk) = keypair();
    let (_sk2, pk2) = keypair();
    let sig = sign(&sk, "GET", "/x", 1000);
    assert!(!verify(&pk2, "GET", "/x", 1000, &sig, 1001, 5));
}

#[test]
fn garbage_signature_rejected() {
    let (_sk, pk) = keypair();
    assert!(!verify(&pk, "GET", "/x", 1000, &[0u8; 10], 1001, 5));
    assert!(!verify(&pk, "GET", "/x", 1000, &[0u8; 64], 1001, 5));
}
