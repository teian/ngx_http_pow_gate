//! Challenge-page rendering and the internal `/.pow/` endpoints.
//!
//! When the gate decides a client must prove work, it serves an HTML page (this
//! module) instead of proxying upstream. That page loads the solver, which talks
//! to three internal routes the module owns under `pow_gate_endpoint` (default
//! `/.pow/`):
//!
//!   GET  {endpoint}challenge  → fresh challenge params (difficulty, salt, exp)
//!   GET  {endpoint}solver.js  → the WASM/JS proof-of-work + signing client
//!   POST {endpoint}verify     → submit solution + pubkey; sets clearance cookie
//!
//! The crypto behind `/challenge` and `/verify` lives in `src/engine/`.
//!
//! ## Embedded assets
//!
//! Both browser-facing assets are compiled into the module with `include_bytes!`:
//!
//!   * the challenge page  ([`DEFAULT_PAGE`], `assets/challenge.html`) — the
//!     *look*, which the operator MAY override with `pow_gate_page`. If unset,
//!     the embedded page is served (zero extra files).
//!   * the solver script    ([`SOLVER_JS`], `assets/solver.js`) — the *protocol
//!     client*, which is **always served by the module** from the embedded copy.
//!     There is no override directive: the solver must stay in lockstep with the
//!     engine, so it ships with the module.

use ngx::core::Status;
use ngx::ffi::{ngx_conf_t, ngx_pnalloc, ngx_str_t, ngx_uint_t};
use ngx::http::{HTTPStatus, Request};

use crate::response::{as_bytes, as_str, send_and_finish};
use crate::runtime::Cfg;

// Assets live at the repo root; this crate is two levels down (crates/<name>/),
// so embed them via CARGO_MANIFEST_DIR to stay correct regardless of build CWD.

/// Embedded fallback so the module works with zero config (no `pow_gate_page`).
pub const DEFAULT_PAGE: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../assets/challenge.html"));

/// The solver, always served by the module at `{endpoint}solver.js`. Compiled in
/// because it is the client half of the proof-of-work protocol and must match the
/// engine; it is not operator-configurable.
pub const SOLVER_JS: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../assets/solver.js"));

/// Embedded no-JS (meta-refresh) challenge page, served on `challenge:nojs`
/// decisions. Overridable with `pow_gate_nojs_page`. Placeholders
/// (`{{pass_url}}`, `{{delay}}`) are substituted **per request** — the grant
/// token in the pass URL is one-shot — so only the raw template is cached.
pub const DEFAULT_NOJS_PAGE: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../assets/challenge-nojs.html"));

/// Load + cache the challenge page bytes for a location.
///
/// If `path` is empty (no `pow_gate_page`) -> use [`DEFAULT_PAGE`]; otherwise read
/// the file. Either way, substitute the `{{difficulty}}` / `{{endpoint}}`
/// placeholders and copy the rendered bytes into the config pool, so they live
/// for the whole cycle and are not re-read or re-rendered per request.
///
/// Returns `None` when the file cannot be read or the pool allocation fails —
/// the caller turns that into a config error (fail closed at startup, like the
/// HMAC key check), because silently serving the default page would hide a
/// broken `pow_gate_page` from the operator.
pub fn load_page(
    cf: *mut ngx_conf_t,
    path: ngx_str_t,
    difficulty: ngx_uint_t,
    endpoint: ngx_str_t,
) -> Option<ngx_str_t> {
    let raw: Vec<u8> = if path.len == 0 {
        DEFAULT_PAGE.to_vec()
    } else {
        let p = unsafe { as_str(&path) };
        match std::fs::read(p) {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!("[pow_gate] pow_gate_page: cannot read {p:?}: {e}");
                return None;
            }
        }
    };

    let rendered = replace_all(&raw, b"{{difficulty}}", difficulty.to_string().as_bytes());
    let rendered = replace_all(&rendered, b"{{endpoint}}", unsafe { as_bytes(&endpoint) });

    unsafe {
        let data = ngx_pnalloc((*cf).pool, rendered.len()) as *mut u8;
        if data.is_null() {
            return None;
        }
        std::ptr::copy_nonoverlapping(rendered.as_ptr(), data, rendered.len());
        Some(ngx_str_t { len: rendered.len(), data })
    }
}

/// Load + cache the no-JS challenge template bytes for a location — RAW, no
/// substitution (both its placeholders are per-request). Empty path -> the
/// embedded [`DEFAULT_NOJS_PAGE`]; unreadable file -> `None` (config error,
/// fail closed at startup like `pow_gate_page`).
pub fn load_nojs_page(cf: *mut ngx_conf_t, path: ngx_str_t) -> Option<ngx_str_t> {
    let raw: Vec<u8> = if path.len == 0 {
        DEFAULT_NOJS_PAGE.to_vec()
    } else {
        let p = unsafe { as_str(&path) };
        match std::fs::read(p) {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!("[pow_gate] pow_gate_nojs_page: cannot read {p:?}: {e}");
                return None;
            }
        }
    };
    unsafe {
        let data = ngx_pnalloc((*cf).pool, raw.len()) as *mut u8;
        if data.is_null() {
            return None;
        }
        std::ptr::copy_nonoverlapping(raw.as_ptr(), data, raw.len());
        Some(ngx_str_t { len: raw.len(), data })
    }
}

/// Render + serve the no-JS challenge page: substitute the one-shot pass URL
/// and the delay into the cached template. `Cache-Control: no-store` because
/// the embedded grant is time-bound and per-request.
pub fn serve_nojs_page(r: &mut Request, template: &ngx_str_t, pass_url: &str, delay: i64) -> Status {
    let raw = unsafe { as_bytes(template) };
    let body = replace_all(&replace_all(raw, b"{{pass_url}}", pass_url.as_bytes()),
                           b"{{delay}}", delay.to_string().as_bytes());
    crate::response::send_and_finish_with_headers(
        r,
        HTTPStatus::OK,
        "text/html; charset=utf-8",
        &body,
        &[("Cache-Control", "no-store")],
    )
}

/// Replace every occurrence of `needle` in `haystack` (no overlap handling
/// needed — the placeholders cannot overlap themselves).
fn replace_all(haystack: &[u8], needle: &[u8], with: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(haystack.len() + 64);
    let mut i = 0;
    while i < haystack.len() {
        if haystack[i..].starts_with(needle) {
            out.extend_from_slice(with);
            i += needle.len();
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    out
}

/// Serve the challenge page: `200 OK`, `Content-Type: text/html`, body = `page`.
///
/// The page itself then fetches `{endpoint}challenge`, runs the solver from
/// `{endpoint}solver.js`, POSTs `{endpoint}verify`, and reloads on success — the
/// module owns those internal endpoints (routed in [`route_internal`]).
pub fn serve_challenge_page(r: &mut Request, page: &ngx_str_t) -> Status {
    let body = unsafe { as_bytes(page) };
    send_and_finish(r, HTTPStatus::OK, "text/html; charset=utf-8", body, None)
}

/// Dispatch a request to `{endpoint}*` to the right engine handler.
///
/// `difficulty` is the effective PoW difficulty for THIS client (the
/// `challenge:<N>`/`challenge:js` decision override already applied), so
/// `/challenge` issues what the decision demands. `nojs_template` backs the
/// `pass` endpoint's too-early re-challenge.
///
/// Returns `Some(status)` when the request was one of ours, `None` otherwise.
pub fn route_internal(
    r: &mut Request,
    cfg: &Cfg,
    suffix: &str,
    difficulty: u64,
    nojs_template: &ngx_str_t,
) -> Option<Status> {
    match suffix {
        "challenge" => Some(crate::engine::pow::issue_challenge(r, cfg, difficulty)),
        "solver.js" => Some(serve_solver(r)),
        "verify" => Some(crate::engine::pow::verify_solution(r)),
        "pass" => Some(crate::engine::nojs::pass(r, cfg, nojs_template)),
        _ => None,
    }
}

/// Serve the solver: `200 OK`, `Content-Type: text/javascript`, body =
/// [`SOLVER_JS`] (always the module-provided embedded solver).
fn serve_solver(r: &mut Request) -> Status {
    send_and_finish(r, HTTPStatus::OK, "text/javascript; charset=utf-8", SOLVER_JS, None)
}
