use p256::ecdsa::SigningKey;
use pow_gate_core::{
    clearance::{issue, verify},
    codec::b64url,
    context::Assurance,
};

const KEY: &[u8] = b"server-secret-key";
const CONTEXT: &str = "bound-client-and-policy";
const REQUIRED: Assurance = Assurance::Pow { difficulty: 2000 };
fn pk() -> Vec<u8> {
    SigningKey::from_bytes((&[1u8; 32]).into())
        .unwrap()
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}
fn cookie() -> String {
    issue(KEY, &pk(), CONTEXT, REQUIRED, 1000, 3600)
}
fn check(token: &str, now: i64) -> bool {
    verify(KEY, token, CONTEXT, REQUIRED, now, 3600).is_some()
}

#[test]
fn roundtrip_and_expiry() {
    let token = cookie();
    let c = verify(KEY, &token, CONTEXT, REQUIRED, 1500, 3600).unwrap();
    assert_eq!(c.iat, 1000);
    assert_eq!(c.exp, 4600);
    assert_eq!(c.pk_bytes().unwrap(), pk());
    assert!(!check(&token, 4600));
}

#[test]
fn rejects_client_policy_and_server_key_changes() {
    let token = cookie();
    assert!(verify(KEY, &token, "other-context", REQUIRED, 1500, 3600).is_none());
    assert!(verify(b"wrong-key", &token, CONTEXT, REQUIRED, 1500, 3600).is_none());
    assert!(verify(
        KEY,
        &token,
        CONTEXT,
        Assurance::Pow { difficulty: 2001 },
        1500,
        3600
    )
    .is_none());
    assert!(verify(
        KEY,
        &token,
        CONTEXT,
        Assurance::Pow { difficulty: 1000 },
        1500,
        3600
    )
    .is_some());
}

#[test]
fn nojs_never_satisfies_pow() {
    let token = issue(KEY, &[], CONTEXT, Assurance::NoJs { delay: 2 }, 1000, 3600);
    assert!(!check(&token, 1500));
    assert!(verify(
        KEY,
        &token,
        CONTEXT,
        Assurance::NoJs { delay: 2 },
        1500,
        3600
    )
    .is_some());
    assert!(verify(
        KEY,
        &token,
        CONTEXT,
        Assurance::NoJs { delay: 3 },
        1500,
        3600
    )
    .is_none());
}

#[test]
fn shortened_ttl_applies_to_existing_cookies_and_future_issue_time_is_rejected() {
    let token = cookie();
    assert!(verify(KEY, &token, CONTEXT, REQUIRED, 1500, 500).is_none());
    assert!(verify(KEY, &token, CONTEXT, REQUIRED, 1499, 500).is_some());
    assert!(!check(&token, 999));
}

#[test]
fn rejects_legacy_garbage_and_tampering() {
    for token in ["no-dot", "a.b.c", "", "e30.bad-tag"] {
        assert!(!check(token, 1500));
    }
    let token = cookie();
    let (_, tag) = token.split_once('.').unwrap();
    let mut payload = verify(KEY, &token, CONTEXT, REQUIRED, 1500, 3600).unwrap();
    payload.exp += 10000;
    let forged = format!("{}.{tag}", b64url(&serde_json::to_vec(&payload).unwrap()));
    assert!(!check(&forged, 1500));
    // A correctly signed legacy cookie still cannot pass v2 domain separation.
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let old = b64url(br#"{"pk":"","iat":1000,"exp":99999}"#);
    let mut mac = Hmac::<Sha256>::new_from_slice(KEY).unwrap();
    mac.update(old.as_bytes());
    assert!(!check(
        &format!("{old}.{}", b64url(&mac.finalize().into_bytes())),
        1500
    ));
}
