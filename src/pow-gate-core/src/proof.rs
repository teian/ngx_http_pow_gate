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

use p256::ecdsa::VerifyingKey;
#[cfg(not(feature = "native-crypto"))]
use p256::ecdsa::{signature::Verifier, Signature};

fn verify_signature(pk: &[u8], message: &[u8], sig: &[u8]) -> bool {
    #[cfg(feature = "native-crypto")]
    {
        // Preserve the portable API's support for compressed SEC1 keys. The
        // nginx wire protocol requires the uncompressed encoding, its fast path.
        let encoded;
        let pk = if pk.len() == 33 {
            let Ok(key) = VerifyingKey::from_sec1_bytes(pk) else {
                return false;
            };
            encoded = key.to_encoded_point(false);
            encoded.as_bytes()
        } else {
            pk
        };
        ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, pk)
            .verify(message, sig)
            .is_ok()
    }
    #[cfg(not(feature = "native-crypto"))]
    {
        let Ok(vk) = VerifyingKey::from_sec1_bytes(pk) else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(sig) else {
            return false;
        };
        vk.verify(message, &sig).is_ok()
    }
}

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
    if skew < 0 || now.abs_diff(ts) > skew as u64 {
        return false;
    }
    verify_signature(pk_sec1, message(method, path, ts).as_bytes(), sig)
}

/// Canonical WebCrypto SEC1 encoding; rejects malformed and alternate encodings.
pub fn valid_public_key(pk: &[u8]) -> bool {
    pk.len() == 65 && pk[0] == 4 && VerifyingKey::from_sec1_bytes(pk).is_ok()
}

/// Redemption proves possession of the key committed to the challenge.
pub fn challenge_message(token: &str) -> String {
    format!("pow-gate-redeem-v2 {token}")
}

pub fn verify_challenge(pk: &[u8], token: &str, sig: &[u8]) -> bool {
    verify_signature(pk, challenge_message(token).as_bytes(), sig)
}
