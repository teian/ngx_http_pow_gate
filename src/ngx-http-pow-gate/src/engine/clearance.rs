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
/// * An absent proof is accepted unless `pow_gate_require_proof` is on (off by
///   default — enabling it needs page-side integration to sign the proofs)
///   *and* the request is one that could have carried the header in the first
///   place — a `fetch()`/XHR call ([`can_carry_proof`]). Navigations and
///   tag-driven subresource loads (`<script>`, `<img>`, `<link>`, fonts, …)
///   cannot attach custom headers, so they pass on the cookie alone; demanding
///   a proof of them would challenge every asset on a gated page.
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
        // No proof header. Accept on the cookie alone unless this request could
        // have carried one (fetch/XHR) and the requirement is on.
        None => !cfg.require_proof || !can_carry_proof(r),
    }
}

/// Could this request have attached the `X-Pow-Proof` header?
///
/// Only requests issued by page JavaScript — `fetch()` and XHR — can carry a
/// custom header. Browsers mark exactly those with `Sec-Fetch-Dest: empty`;
/// every other destination (`document`, `script`, `style`, `image`, `font`, …)
/// is a navigation or a tag-driven subresource load with no way to add one.
/// Note `Sec-Fetch-Mode` is *not* a usable signal here: fonts, module scripts
/// and preloads are `mode: cors` yet still cannot carry headers.
///
/// A request with **no** Sec-Fetch metadata (older browsers, non-browser
/// agents) is treated as unable to carry a proof, so it passes on the cookie
/// alone — requiring a header such clients can never send would lock them out.
fn can_carry_proof(r: &Request) -> bool {
    match runtime::header(r, "sec-fetch-dest") {
        Some(dest) => dest.eq_ignore_ascii_case("empty"),
        None => false,
    }
}

/// Parse `X-Pow-Proof: <base64url-sig>.<unix-ts>`.
fn parse_proof(h: &str) -> Option<(Vec<u8>, i64)> {
    let (sig_b64, ts) = h.rsplit_once('.')?;
    let sig = codec::unb64url(sig_b64)?;
    let ts: i64 = ts.parse().ok()?;
    Some((sig, ts))
}
