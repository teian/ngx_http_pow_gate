//! Capture a challenged non-GET request so it survives the challenge.
//!
//! Without this, a `POST` that runs into an expired clearance is simply lost:
//! the gate answers it with the challenge page, and the reload after the solve
//! is a `GET` (or a browser prompt to resubmit). Here the gate reads the body
//! first and hands the whole request back to the client inside the challenge
//! page, where `solver.js` re-issues it once the clearance cookie is set. See
//! [`pow_gate_core::replay`] for the payload format and why it needs no
//! signature.
//!
//! The nginx-specific part is the body read: it is asynchronous, so the ACCESS
//! handler kicks it off and the page is sent from the [`body_ready`] callback —
//! the same shape as `POST {endpoint}verify` in [`crate::engine::pow`].

use ngx::core::Status;
use ngx::ffi::{
    ngx_http_finalize_request, ngx_http_read_client_request_body, ngx_http_request_t, ngx_str_t,
    NGX_HTTP_SPECIAL_RESPONSE,
};
use ngx::http::{HTTPStatus, Request};
use pow_gate_core::replay::{inject, method_replayable, Captured};

use crate::challenge::serve_challenge_page;
use crate::response::{as_bytes, as_str, send_and_finish_with_headers};
use crate::runtime::{self, Cfg};

/// `Sec-Fetch-Dest` values that render an HTML document, i.e. the requests that
/// can actually run the solver and replay anything. A `fetch`/XHR call
/// (`empty`) or a subresource load gets the page as inert bytes.
const RENDERS_HTML: [&str; 3] = ["document", "iframe", "frame"];

/// Should this challenged request be captured instead of answered right away?
///
/// Yes only for a data-carrying method with a *known* length within
/// `pow_gate_replay_max_body` — a chunked body has no declared length, so it is
/// left alone rather than read blind. A request the browser marks as one that
/// will not render the page ([`RENDERS_HTML`]) is skipped too: it can never
/// replay, so reading its body would buy nothing and only hand un-cleared
/// clients a way to make the worker buffer bytes. A client that sends no
/// `Sec-Fetch-*` metadata at all is captured — it may well be a browser too old
/// to send it.
pub fn should_capture(r: &Request, cfg: &Cfg) -> bool {
    if !cfg.replay {
        return false;
    }
    let raw = r as *const Request as *mut ngx_http_request_t;
    match unsafe { runtime::content_length(raw) } {
        Some(n) if n <= cfg.replay_max_body => {}
        _ => return false,
    }
    if let Some(dest) = runtime::header(r, "sec-fetch-dest") {
        if !RENDERS_HTML.iter().any(|d| dest.eq_ignore_ascii_case(d)) {
            return false;
        }
    }
    method_replayable(unsafe { as_str(&(*raw).method_name) })
}

/// Read the body, then serve the challenge page carrying it. Returns `NGX_DONE`
/// so the ACCESS phase waits for [`body_ready`].
///
/// `page` is the fallback for a body read nginx refuses outright (allocation
/// failure, a `100-continue` it could not answer): the client still gets its
/// challenge instead of an error for something it has no way to fix.
/// `ngx_http_read_client_request_body` takes its reference back before
/// returning any such status, so sending here is correct.
///
/// Note this is *not* the `client_max_body_size` path — nginx rejects an
/// over-limit declared body with `413` in FIND_CONFIG, before ACCESS runs, so
/// those requests never reach the gate at all.
pub fn capture_then_challenge(r: &mut Request, page: &ngx_str_t) -> Status {
    let raw: *mut ngx_http_request_t = r as *mut Request as *mut ngx_http_request_t;
    let rc = unsafe { ngx_http_read_client_request_body(raw, Some(body_ready)) };
    if rc >= NGX_HTTP_SPECIAL_RESPONSE as isize {
        return serve_challenge_page(r, page);
    }
    // Release the reference the body read took (r->main->count++). The ACCESS
    // phase does not finalize on NGX_DONE the way the CONTENT phase would, so
    // this has to happen here — see the same note in engine::pow::verify_solution.
    unsafe { ngx_http_finalize_request(raw, Status::NGX_DONE.0) };
    Status::NGX_DONE
}

/// Body-ready callback: build the payload, inject it into the cached challenge
/// page, send. Any reason the request cannot be captured (unreadable body,
/// unsafe target) degrades to the plain page — the client is still challenged,
/// it just loses the request the way it did before.
extern "C" fn body_ready(r: *mut ngx_http_request_t) {
    let req = unsafe { Request::from_ngx_http_request(r) };

    let lc = match unsafe { runtime::location_conf(r) } {
        Some(lc) => lc,
        None => return finalize(req, HTTPStatus::INTERNAL_SERVER_ERROR, b"error\n"),
    };
    let cfg = runtime::resolve(lc);
    let page = unsafe { as_bytes(&lc.page_cache) };

    let body = unsafe { runtime::request_body(r) }.unwrap_or_default();
    let (method, _) = unsafe { runtime::method_and_path(r) };
    // The RAW client-sent target (still percent-encoded, unlike r->uri), so the
    // replayed request goes exactly where the original one did. Held to
    // `same_site_path` by Captured::new.
    let url = unsafe { as_str(&(*r).unparsed_uri) };
    let content_type = runtime::header(req, "content-type").unwrap_or_default();

    let rendered = match Captured::new(&method, url, &content_type, &body) {
        Some(c) if body.len() <= cfg.replay_max_body => inject(page, &c.script_tag()),
        _ => page.to_vec(),
    };

    // no-store: this page carries the client's own request back to it.
    let _ = send_and_finish_with_headers(
        req,
        HTTPStatus::OK,
        "text/html; charset=utf-8",
        &rendered,
        &[("Cache-Control", "no-store")],
    );
}

/// Terse terminal response for the paths that cannot render a page at all.
fn finalize(req: &mut Request, status: HTTPStatus, body: &[u8]) {
    let _ = send_and_finish_with_headers(req, status, "text/plain", body, &[]);
}
