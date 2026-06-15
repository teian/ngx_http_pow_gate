//! Clearance token tests. Own test crate; public API only.

use pow_gate_core::clearance::{issue, verify, Clearance};
use pow_gate_core::codec::b64url;

const KEY: &[u8] = b"server-secret-key";
const PK: &[u8] = b"\x04fake-sec1-public-key-bytes-................";

#[test]
fn issue_then_verify_roundtrips() {
    let token = issue(KEY, PK, 1000, 3600);
    let c = verify(KEY, &token, 1500).expect("valid");
    assert_eq!(c.iat, 1000);
    assert_eq!(c.exp, 4600);
    assert_eq!(c.pk_bytes().unwrap(), PK);
}

#[test]
fn rejects_expired() {
    let token = issue(KEY, PK, 1000, 3600);
    assert!(verify(KEY, &token, 99999).is_none());
}

#[test]
fn rejects_wrong_key() {
    let token = issue(KEY, PK, 1000, 3600);
    assert!(verify(b"other-key", &token, 1500).is_none());
}

#[test]
fn rejects_tampered_payload() {
    let token = issue(KEY, PK, 1000, 3600);
    let (_payload, tag) = token.split_once('.').unwrap();
    // forge a longer-lived payload but keep the old tag → HMAC mismatch
    let forged = Clearance { pk: b64url(PK), iat: 1000, exp: 1 << 40 };
    let forged_b64 = b64url(&serde_json::to_vec(&forged).unwrap());
    assert!(verify(KEY, &format!("{forged_b64}.{tag}"), 1500).is_none());
}

#[test]
fn rejects_garbage() {
    assert!(verify(KEY, "no-dot", 1500).is_none());
    assert!(verify(KEY, "a.b.c", 1500).is_none());
}
