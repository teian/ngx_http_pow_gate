//! The clearance token: proof a client already solved a challenge.
//!
//! Format (a cookie value):
//!
//! ```text
//!   <payload_b64> "." <tag_b64>
//!   payload_b64 = base64url(JSON{ pk, iat, exp })
//!   tag_b64     = base64url(HMAC-SHA256(key, payload_b64))
//! ```
//!
//! `pk` is the client's public key (base64url SEC1) so the per-request
//! [`crate::proof`] can be checked against it. The HMAC makes the token
//! unforgeable; verification is constant-time and enforces expiry.

use crate::codec::{b64url, unb64url};
use crate::mac::{ct_eq, hmac};

/// Decoded clearance payload.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Clearance {
    /// Client public key, base64url SEC1 (uncompressed) — binds the token to a key.
    pub pk: String,
    /// Issued-at, unix seconds.
    pub iat: i64,
    /// Expiry, unix seconds (`iat + clearance_ttl`).
    pub exp: i64,
}

impl Clearance {
    /// Raw SEC1 public-key bytes, for [`crate::proof::verify`].
    pub fn pk_bytes(&self) -> Option<Vec<u8>> {
        unb64url(&self.pk)
    }
}

/// Mint a clearance token for `pk_sec1` (raw SEC1 public key bytes).
pub fn issue(key: &[u8], pk_sec1: &[u8], iat: i64, ttl: i64) -> String {
    let payload = Clearance {
        pk: b64url(pk_sec1),
        iat,
        exp: iat + ttl,
    };
    let payload_b64 = b64url(&serde_json::to_vec(&payload).expect("serialize"));
    let tag = b64url(&hmac(key, payload_b64.as_bytes()));
    format!("{payload_b64}.{tag}")
}

/// Verify a clearance token. Returns the payload only when the HMAC is authentic
/// (constant-time) and `exp` is still in the future.
pub fn verify(key: &[u8], token: &str, now: i64) -> Option<Clearance> {
    let (payload_b64, tag_b64) = token.split_once('.')?;
    let expected = hmac(key, payload_b64.as_bytes());
    let provided = unb64url(tag_b64)?;
    if !ct_eq(&expected, &provided) {
        return None;
    }
    let payload: Clearance = serde_json::from_slice(&unb64url(payload_b64)?).ok()?;
    if payload.exp <= now {
        return None;
    }
    Some(payload)
}
