//! Clearance validation — read the cookie + optional per-request proof off the
//! request and verify them with [`pow_gate_core`].

use ngx::ffi::ngx_http_request_t;
use ngx::http::Request;
use pow_gate_core::{clearance, codec, proof};

use crate::runtime::{self, Cfg};

/// Validate the clearance cookie and the per-request proof.
///
/// `true` iff the cookie's HMAC verifies and it is unexpired, *and* the proof
/// requirement is met:
///
/// * A present `X-Pow-Proof` header is always verified against the cookie-bound
///   key within `proof_skew`; a present-but-bad proof fails closed.
/// * An absent proof is accepted only when the request is a top-level navigation
///   (which cannot send a custom header) or when `pow_gate_require_proof` is off.
///   With the requirement on (default), a non-navigation request *without* a
///   valid proof is rejected — that is what stops a stolen clearance cookie from
///   being replayed by fetch/XHR/CLI tooling.
pub fn has_valid_clearance(r: &Request, cfg: &Cfg) -> bool {
    // No usable HMAC key -> never trust a clearance cookie (an empty/known key
    // would let anyone forge one). Fail closed: the client is challenged.
    if !cfg.key_ok {
        return false;
    }
    let now = runtime::now();

    let token = match runtime::cookie(r, &cfg.cookie.name) {
        Some(c) => c,
        None => return false,
    };
    let cleared = match clearance::verify(&cfg.key, &token, now) {
        Some(c) => c,
        None => return false,
    };

    match runtime::header(r, "x-pow-proof") {
        Some(proof_header) => {
            let pk = match cleared.pk_bytes() {
                Some(pk) => pk,
                None => return false,
            };
            let (sig, ts) = match parse_proof(&proof_header) {
                Some(x) => x,
                None => return false,
            };
            let raw = r as *const Request as *mut ngx_http_request_t;
            let (method, path) = unsafe { runtime::method_and_path(raw) };
            proof::verify(&pk, &method, &path, ts, &sig, now, cfg.proof_skew)
        }
        // No proof header. Accept on the cookie alone only for navigations (they
        // cannot carry a custom header) or when the requirement is disabled.
        None => !cfg.require_proof || is_navigation(r),
    }
}

/// Is this a top-level navigation? Browsers signal navigations with
/// `Sec-Fetch-Mode: navigate`. A request with **no** Sec-Fetch metadata is also
/// treated as a navigation: non-Sec-Fetch clients (older browsers, non-browser
/// agents) would never attach the proof header on a navigation, so requiring it
/// of them would lock them out. Modern fetch/XHR send a non-`navigate` mode and
/// therefore must carry a proof when `pow_gate_require_proof` is on.
fn is_navigation(r: &Request) -> bool {
    match runtime::header(r, "sec-fetch-mode") {
        Some(mode) => mode.eq_ignore_ascii_case("navigate"),
        None => true,
    }
}

/// Parse `X-Pow-Proof: <base64url-sig>.<unix-ts>`.
fn parse_proof(h: &str) -> Option<(Vec<u8>, i64)> {
    let (sig_b64, ts) = h.rsplit_once('.')?;
    let sig = codec::unb64url(sig_b64)?;
    let ts: i64 = ts.parse().ok()?;
    Some((sig, ts))
}
