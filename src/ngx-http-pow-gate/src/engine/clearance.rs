//! Clearance validation — read the cookie + optional per-request proof off the
//! request and verify them with [`pow_gate_core`].

use ngx::ffi::ngx_http_request_t;
use ngx::http::Request;
use pow_gate_core::{clearance, codec, proof};

use crate::runtime::{self, Cfg};

/// Validate the clearance cookie and, when present, the per-request proof.
///
/// `true` iff the cookie's HMAC verifies and it is unexpired. If the request also
/// carries an `X-Pow-Proof` header it must validate against the cookie-bound key
/// within `proof_skew` — a present-but-bad proof fails closed (defeats cookie
/// theft on fetch/XHR). Absent proof passes on the cookie alone, the only option
/// for top-level navigations (which cannot send custom headers).
pub fn has_valid_clearance(r: &Request, cfg: &Cfg) -> bool {
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
        None => true, // cookie alone (e.g. a top-level navigation)
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
    }
}

/// Parse `X-Pow-Proof: <base64url-sig>.<unix-ts>`.
fn parse_proof(h: &str) -> Option<(Vec<u8>, i64)> {
    let (sig_b64, ts) = h.rsplit_once('.')?;
    let sig = codec::unb64url(sig_b64)?;
    let ts: i64 = ts.parse().ok()?;
    Some((sig, ts))
}
