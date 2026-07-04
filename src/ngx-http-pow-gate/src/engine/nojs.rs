//! `GET {endpoint}pass` — redeem a no-JS meta-refresh grant.
//!
//! The `challenge:nojs` page (see [`crate::challenge::serve_nojs_page`])
//! meta-refreshes to `{endpoint}pass?t=<grant>` after the grant's delay. This
//! handler verifies the grant with [`pow_gate_core::nojs`]:
//!
//!   * waited long enough  → mint a clearance (empty pubkey — a no-JS client
//!     cannot sign per-request proofs), `Set-Cookie`, `302` back to the page
//!     the client originally asked for.
//!   * redeemed too early  → re-serve the no-JS page with a FRESH grant: the
//!     impatient client starts its wait over.
//!   * forged / expired    → `302 /` — lands back on whatever challenge the
//!     decision assigns; nothing to gain by probing.

use ngx::core::Status;
use ngx::ffi::ngx_str_t;
use ngx::http::{HTTPStatus, Request};
use pow_gate_core::{clearance, nojs};

use crate::challenge::serve_nojs_page;
use crate::response::{as_str, send_and_finish_with_headers};
use crate::runtime::{self, Cfg};

pub fn pass(r: &mut Request, cfg: &Cfg, nojs_template: &ngx_str_t) -> Status {
    // No usable HMAC key -> never mint anything (same stance as /verify).
    if !cfg.key_ok {
        return send_and_finish_with_headers(
            r, HTTPStatus::SERVICE_UNAVAILABLE, "text/plain", b"unavailable\n", &[]);
    }
    let now = runtime::now();

    let token = query_param(r, "t").unwrap_or_default();
    match nojs::verify(&cfg.key, &token, now) {
        nojs::Verdict::Ok(grant) => {
            let clearance = clearance::issue(&cfg.key, &[], now, cfg.clearance_ttl);
            let set_cookie = runtime::build_set_cookie(&clearance, &cfg.cookie);
            // Tiny body doubles as the fallback for agents that don't follow
            // redirects, and guarantees the response is flushed (see the
            // contract note in response::send_with_headers).
            let body = redirect_body(&grant.path);
            send_and_finish_with_headers(
                r,
                HTTPStatus::MOVED_TEMPORARILY,
                "text/html; charset=utf-8",
                body.as_bytes(),
                &[
                    ("Location", grant.path.as_str()),
                    ("Set-Cookie", set_cookie.as_str()),
                    ("Cache-Control", "no-store"),
                ],
            )
        }
        nojs::Verdict::TooEarly(grant) => {
            // Fresh grant, wait starts over — the delay cannot be skipped by
            // hammering the pass URL.
            let fresh = nojs::issue(&cfg.key, &grant.path, grant.delay, now);
            let pass_url = format!("{}pass?t={}", cfg.endpoint, fresh);
            serve_nojs_page(r, nojs_template, &pass_url, grant.delay)
        }
        nojs::Verdict::Bad => send_and_finish_with_headers(
            r,
            HTTPStatus::MOVED_TEMPORARILY,
            "text/html; charset=utf-8",
            redirect_body("/").as_bytes(),
            &[("Location", "/"), ("Cache-Control", "no-store")],
        ),
    }
}

/// Minimal 302 body: a link for agents that don't follow redirects. `path`
/// comes out of a verified grant (or is the literal `/`), already sanitized
/// against markup/header injection by `pow_gate_core::nojs`.
fn redirect_body(path: &str) -> String {
    format!("<html><body><a href=\"{path}\">Continue</a></body></html>\n")
}

/// Value of `name` in the request's query string (no percent-decoding — grant
/// tokens are base64url + '.', never escaped).
fn query_param(r: &Request, name: &str) -> Option<String> {
    let raw = r as *const Request as *mut ngx::ffi::ngx_http_request_t;
    let args = unsafe { as_str(&(*raw).args) };
    for pair in args.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == name {
                return Some(v.to_string());
            }
        }
    }
    None
}
