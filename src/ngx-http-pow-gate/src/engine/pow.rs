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
use pow_gate_core::{clearance, codec, context::Assurance, pow, proof};

use crate::body_limit::VERIFY_LIMIT;
use crate::response::{self, send_and_finish};
use crate::runtime::{self, Cfg};

/// How long (seconds) a client has to solve a challenge — anti-precompute bound.
const CHALLENGE_GRACE: i64 = 120;

/// `GET {endpoint}challenge` → issue fresh challenge parameters as JSON.
///
/// `difficulty` is the caller-resolved effective value for this client: the
/// configured default, or the `challenge:<N>`/`challenge:js` decision override
/// (the decision `map` evaluates identically on this request, since it keys on
/// the same client attributes). It is HMAC-bound into the token, so /verify
/// holds the client to exactly this value.
pub fn issue_challenge(r: &mut Request, cfg: &Cfg, required: Assurance) -> Status {
    // No usable HMAC key -> refuse rather than issue a forgeable challenge token.
    if !cfg.key_ok || (crate::cluster::enabled() && !crate::cluster::available()) {
        crate::observability::record(r, "error", "issuer_unavailable", 0);
        return send_and_finish(
            r,
            HTTPStatus::SERVICE_UNAVAILABLE,
            "text/plain",
            b"unavailable\n",
            None,
        );
    }
    crate::observability::record(r, "rejected", "invalid_key", 0);
    let Assurance::Pow { difficulty } = required else {
        return HTTPStatus::BAD_REQUEST.into();
    };
    let pk = runtime::header_limited(r, "x-pow-key", 87)
        .filter(|s| s.len() == 87)
        .and_then(|s| codec::unb64url(&s));
    let Some(pk) = pk.filter(|pk| proof::valid_public_key(pk)) else {
        return HTTPStatus::BAD_REQUEST.into();
    };
    let Some(context) = runtime::client_context(r, cfg) else {
        return HTTPStatus::SERVICE_UNAVAILABLE.into();
    };
    let challenge = pow::issue(
        &cfg.key,
        &pk,
        &context,
        difficulty,
        runtime::now(),
        CHALLENGE_GRACE,
    );
    crate::observability::record(r, "issued", "pow", difficulty);
    let body = serde_json::to_vec(&challenge).unwrap_or_default();
    response::send_and_finish_with_headers(
        r,
        HTTPStatus::OK,
        "application/json",
        &body,
        &[("Cache-Control", "no-store")],
    )
}

/// `POST {endpoint}verify` → read the body asynchronously, then verify in
/// [`verify_body`]. Returns `NGX_DONE` so the phase engine waits for the body.
pub fn verify_solution(r: &mut Request) -> Status {
    crate::observability::record(r, "rejected", "invalid_submission", 0);
    let raw: *mut ngx_http_request_t = r as *mut Request as *mut ngx_http_request_t;
    if unsafe { (*raw).headers_in.content_length_n } > VERIFY_LIMIT as i64 {
        return HTTPStatus::REQUEST_ENTITY_TOO_LARGE.into();
    }
    if !unsafe { crate::body_limit::enable(raw) } {
        return HTTPStatus::SERVICE_UNAVAILABLE.into();
    }
    let rc = unsafe { ngx_http_read_client_request_body(raw, Some(verify_body)) };
    if rc >= NGX_HTTP_SPECIAL_RESPONSE as isize {
        return Status(rc);
    }
    // ngx_http_read_client_request_body took a reference on the request
    // (r->main->count++). A CONTENT-phase handler would return NGX_DONE and the
    // phase engine would finalize (releasing that reference) — but the ACCESS
    // phase does NOT finalize on NGX_DONE, so release it here ourselves.
    // Without this the request never completes: the 204 still reaches the
    // client, but the keep-alive connection stays wedged and the browser's
    // next request on it (the post-verify reload) hangs forever.
    unsafe { ngx_http_finalize_request(raw, Status::NGX_DONE.0) };
    Status::NGX_DONE
}

/// Submitted `/verify` body. Mirrors what solver.js POSTs.
#[derive(serde::Deserialize)]
struct Submission {
    version: u8,
    signature: String,
    salt: String,
    exp: i64,
    token: String,
    nonce: u64,
    /// base64url SEC1 (uncompressed) public key.
    pubkey: String,
    /// Difficulty echoed from the challenge. HMAC-bound by `token`, so it
    /// cannot be lowered. Required in protocol v2; legacy clients fail closed.
    difficulty: u64,
}

/// Body-ready callback: validate the solution, set the clearance cookie, finalize.
extern "C" fn verify_body(r: *mut ngx_http_request_t) {
    let req = unsafe { Request::from_ngx_http_request(r) };

    let lc = match unsafe { runtime::location_conf(r) } {
        Some(lc) => lc,
        None => return finalize_status(req, HTTPStatus::BAD_REQUEST),
    };
    let cfg = runtime::resolve(lc);
    crate::observability::record(req, "rejected", "invalid_submission", cfg.difficulty);
    // No usable HMAC key -> refuse to mint a clearance (it would be forgeable).
    if !cfg.key_ok {
        return finalize_status(req, HTTPStatus::SERVICE_UNAVAILABLE);
    }
    let now = runtime::now();

    let body = match unsafe { runtime::request_body_limited(r, VERIFY_LIMIT) } {
        Some(b) => b,
        None => return finalize_status(req, HTTPStatus::BAD_REQUEST),
    };
    let sub: Submission = match serde_json::from_slice(&body) {
        Ok(s) => s,
        Err(_) => return finalize_status(req, HTTPStatus::BAD_REQUEST),
    };

    let required = crate::access::required_assurance(req, lc, cfg);
    let Assurance::Pow { difficulty } = required else {
        return finalize_status(req, HTTPStatus::BAD_REQUEST);
    };
    let pk = match codec::unb64url(&sub.pubkey) {
        Some(pk) if proof::valid_public_key(&pk) => pk,
        _ => return finalize_status(req, HTTPStatus::BAD_REQUEST),
    };
    let Some(context) = runtime::client_context(req, cfg) else {
        return finalize_status(req, HTTPStatus::SERVICE_UNAVAILABLE);
    };
    let challenge = pow::Challenge {
        version: sub.version,
        salt: sub.salt,
        exp: sub.exp,
        token: sub.token,
        difficulty: sub.difficulty,
    };
    if pow::verify_solution(
        &cfg.key, &challenge, sub.nonce, &pk, &context, difficulty, now,
    ) != pow::Verdict::Ok
    {
        return finalize_status(req, HTTPStatus::BAD_REQUEST);
    }
    let Some(signature) = codec::unb64url(&sub.signature) else {
        return finalize_status(req, HTTPStatus::BAD_REQUEST);
    };
    if !proof::verify_challenge(&pk, &challenge.token, &signature) {
        return finalize_status(req, HTTPStatus::BAD_REQUEST);
    }
    // Prepare a response only after cryptographic validation. The backend owns
    // completion and can mint clearance only after an authoritative acceptance.
    let token = clearance::issue(&cfg.key, &pk, &context, required, now, cfg.clearance_ttl);
    let grant = crate::redemption::Grant {
        cookie: runtime::build_set_cookie(&token, &cfg.cookie),
        redirect: None,
        difficulty,
        kind: "pow",
    };
    crate::redemption::redeem(req, &challenge.token, challenge.exp, grant);
}

/// Finalize with a terse error response — used for the `400`/`503` paths.
/// Deliberately carries a (tiny) body: an empty non-204 body would skip
/// `output_filter`, never emit a `last_buf`, and wedge the connection (the
/// response is buffered but never flushed) — see `response::send_with_headers`.
fn finalize_status(req: &mut Request, status: HTTPStatus) {
    let _ = response::send(req, status, "text/plain", b"rejected\n", None);
    let raw: *mut ngx_http_request_t = req as *mut Request as *mut ngx_http_request_t;
    unsafe { ngx_http_finalize_request(raw, Status::NGX_OK.0) };
}
