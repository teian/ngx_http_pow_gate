//! The no-JS (meta-refresh) challenge grant — the token behind `challenge:nojs`.
//!
//! A no-JS client cannot hash or sign, so the challenge is *time*: the page
//! carries `<meta http-equiv="refresh" content="{delay};url={endpoint}pass?t={grant}">`
//! and the `pass` endpoint only honours the grant once `delay` seconds have
//! elapsed since issuance. That filters clients that fetch HTML but don't
//! behave like a rendering agent (no meta-refresh processing, no waiting).
//! It is deliberately the weakest challenge tier — a headless browser passes
//! it trivially — which is why it is only ever reachable via an explicit
//! `challenge:nojs` decision, never by client choice.
//!
//! Format mirrors [`crate::clearance`] (`payload_b64 "." tag_b64`) but the MAC
//! is domain-separated (`"nojs|" + payload`), so a grant can never be replayed
//! as a clearance cookie or vice versa. The payload binds the return path, so
//! the redirect target cannot be tampered with either.

use crate::codec::{b64url, unb64url};
use crate::mac::{ct_eq, hmac};

/// How long (seconds) a grant stays redeemable after issuance. Bounds the
/// farming window the same way the PoW challenge grace does.
pub const NOJS_GRACE: i64 = 120;

/// Decoded grant payload.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Grant {
    /// Same-site return path (starts with `/`), redirected to after the wait.
    pub path: String,
    /// Issued-at, unix seconds.
    pub iat: i64,
    /// Minimum wait in seconds before the grant may be redeemed.
    pub delay: i64,
}

/// Outcome of verifying a submitted grant.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Waited long enough: redirect to the contained path and set clearance.
    Ok(Grant),
    /// Authentic but redeemed before `iat + delay`: re-challenge (fresh wait).
    TooEarly(Grant),
    /// Forged, malformed, expired, or unsafe path.
    Bad,
}

fn mac_input(payload_b64: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(5 + payload_b64.len());
    v.extend_from_slice(b"nojs|");
    v.extend_from_slice(payload_b64.as_bytes());
    v
}

/// A safe same-site redirect path — see [`crate::uri::same_site_path`].
fn path_ok(path: &str) -> bool {
    crate::uri::same_site_path(path)
}

/// Mint a grant for `path` with a `delay`-second minimum wait. An unsafe path
/// degrades to `/` rather than failing — the client still gets challenged.
pub fn issue(key: &[u8], path: &str, delay: i64, now: i64) -> String {
    let grant = Grant {
        path: if path_ok(path) { path.to_string() } else { "/".to_string() },
        iat: now,
        delay,
    };
    let payload_b64 = b64url(&serde_json::to_vec(&grant).expect("serialize"));
    let tag = b64url(&hmac(key, &mac_input(&payload_b64)));
    format!("{payload_b64}.{tag}")
}

/// Verify a grant. Constant-time MAC check, then expiry and minimum-wait.
pub fn verify(key: &[u8], token: &str, now: i64) -> Verdict {
    let Some((payload_b64, tag_b64)) = token.split_once('.') else {
        return Verdict::Bad;
    };
    let expected = hmac(key, &mac_input(payload_b64));
    let Some(provided) = unb64url(tag_b64) else {
        return Verdict::Bad;
    };
    if !ct_eq(&expected, &provided) {
        return Verdict::Bad;
    }
    let Some(raw) = unb64url(payload_b64) else {
        return Verdict::Bad;
    };
    let Ok(grant) = serde_json::from_slice::<Grant>(&raw) else {
        return Verdict::Bad;
    };
    if !path_ok(&grant.path) || grant.delay < 0 {
        return Verdict::Bad;
    }
    if now >= grant.iat + NOJS_GRACE {
        return Verdict::Bad; // stale grant: full re-challenge
    }
    if now < grant.iat + grant.delay {
        return Verdict::TooEarly(grant);
    }
    Verdict::Ok(grant)
}
