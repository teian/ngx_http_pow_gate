//! nginx-facing PoW endpoints — a thin shell over [`pow_gate_core::pow`].
//!
//! `GET {endpoint}challenge` issues parameters (synchronous JSON). `POST
//! {endpoint}verify` must read the request body, which nginx does asynchronously,
//! so it kicks off [`ngx_http_read_client_request_body`] and finishes in the
//! [`verify_body`] callback. All crypto is delegated to the (tested) core.

use ngx::core::Status;
use ngx::ffi::{
    ngx_http_finalize_request, ngx_http_read_client_request_body, ngx_http_request_t,
    NGX_HTTP_SPECIAL_RESPONSE,
};
use ngx::http::{HTTPStatus, Request};
use pow_gate_core::{clearance, codec, pow};

use crate::response::{self, send_and_finish};
use crate::runtime::{self, Cfg};

/// How long (seconds) a client has to solve a challenge — anti-precompute bound.
const CHALLENGE_GRACE: i64 = 120;

/// `GET {endpoint}challenge` → issue fresh challenge parameters as JSON.
pub fn issue_challenge(r: &mut Request, cfg: &Cfg) -> Status {
    // No usable HMAC key -> refuse rather than issue a forgeable challenge token.
    if !cfg.key_ok {
        return send_and_finish(r, HTTPStatus::SERVICE_UNAVAILABLE, "text/plain", &[], None);
    }
    let challenge = pow::issue(&cfg.key, cfg.difficulty, runtime::now(), CHALLENGE_GRACE);
    let body = serde_json::to_vec(&challenge).unwrap_or_default();
    send_and_finish(r, HTTPStatus::OK, "application/json", &body, None)
}

/// `POST {endpoint}verify` → read the body asynchronously, then verify in
/// [`verify_body`]. Returns `NGX_DONE` so the phase engine waits for the body.
pub fn verify_solution(r: &mut Request) -> Status {
    let raw: *mut ngx_http_request_t = r as *mut Request as *mut ngx_http_request_t;
    let rc = unsafe { ngx_http_read_client_request_body(raw, Some(verify_body)) };
    if rc >= NGX_HTTP_SPECIAL_RESPONSE as isize {
        return Status(rc);
    }
    Status::NGX_DONE
}

/// Submitted `/verify` body. Mirrors what solver.js POSTs.
#[derive(serde::Deserialize)]
struct Submission {
    salt: String,
    exp: i64,
    token: String,
    nonce: u64,
    /// base64url SEC1 (uncompressed) public key.
    pubkey: String,
}

/// Body-ready callback: validate the solution, set the clearance cookie, finalize.
extern "C" fn verify_body(r: *mut ngx_http_request_t) {
    let req = unsafe { Request::from_ngx_http_request(r) };

    let lc = match unsafe { runtime::location_conf(r) } {
        Some(lc) => lc,
        None => return finalize_status(req, HTTPStatus::BAD_REQUEST),
    };
    let cfg = runtime::resolve(lc);
    // No usable HMAC key -> refuse to mint a clearance (it would be forgeable).
    if !cfg.key_ok {
        return finalize_status(req, HTTPStatus::SERVICE_UNAVAILABLE);
    }
    let now = runtime::now();

    let body = match unsafe { runtime::request_body(r) } {
        Some(b) => b,
        None => return finalize_status(req, HTTPStatus::BAD_REQUEST),
    };
    let sub: Submission = match serde_json::from_slice(&body) {
        Ok(s) => s,
        Err(_) => return finalize_status(req, HTTPStatus::BAD_REQUEST),
    };

    // difficulty is the server's own configured value, never the client's.
    let verdict = pow::verify_solution(
        &cfg.key, &sub.salt, sub.exp, &sub.token, sub.nonce, cfg.difficulty, now,
    );
    if verdict != pow::Verdict::Ok {
        return finalize_status(req, HTTPStatus::BAD_REQUEST);
    }

    let pk = match codec::unb64url(&sub.pubkey) {
        Some(pk) => pk,
        None => return finalize_status(req, HTTPStatus::BAD_REQUEST),
    };

    let token = clearance::issue(&cfg.key, &pk, now, cfg.clearance_ttl);
    let set_cookie = runtime::build_set_cookie(&token, &cfg.cookie);
    let _ = send_and_finish(req, HTTPStatus::NO_CONTENT, "text/plain", &[], Some(&set_cookie));
}

/// Finalize with a status-only response (no body) — used for the `400` paths.
fn finalize_status(req: &mut Request, status: HTTPStatus) {
    let _ = response::send(req, status, "text/plain", &[], None);
    let raw: *mut ngx_http_request_t = req as *mut Request as *mut ngx_http_request_t;
    unsafe { ngx_http_finalize_request(raw, Status::NGX_OK.0) };
}
