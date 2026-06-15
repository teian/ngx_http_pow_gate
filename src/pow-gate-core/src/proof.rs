//! The per-request proof: an ECDSA P-256 signature binding one request to the
//! cleared client's keypair.
//!
//! The client signs the ASCII message `"<method> <path> <ts>"` with the private
//! key whose public half is in the clearance token. The server reconstructs the
//! message, checks the timestamp is within `skew` of now (so a captured proof
//! can't be replayed later), and verifies the signature against that public key.
//!
//! Signature encoding is the fixed 64-byte `r ‖ s` produced by WebCrypto's
//! `ECDSA` with `SHA-256` — which is exactly what `p256` verifies.

use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

/// The signed message for `(method, path, ts)`.
pub fn message(method: &str, path: &str, ts: i64) -> String {
    format!("{method} {path} {ts}")
}

/// Verify a per-request proof.
///
/// * `pk_sec1` — the client public key from the clearance token (raw SEC1 bytes).
/// * `sig` — the 64-byte `r ‖ s` signature.
/// * `skew` — max allowed `|now - ts|`, seconds.
pub fn verify(
    pk_sec1: &[u8],
    method: &str,
    path: &str,
    ts: i64,
    sig: &[u8],
    now: i64,
    skew: i64,
) -> bool {
    if (now - ts).abs() > skew {
        return false;
    }
    let Ok(vk) = VerifyingKey::from_sec1_bytes(pk_sec1) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(sig) else {
        return false;
    };
    vk.verify(message(method, path, ts).as_bytes(), &signature)
        .is_ok()
}
