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
use ngx::ffi::ngx_str_t;
use ngx::http::{HTTPStatus, Request};

use crate::response::{as_bytes, send_and_finish};
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

/// Load + cache the challenge page bytes for a location.
///
/// If `path` is empty (no `pow_gate_page`) -> use [`DEFAULT_PAGE`]; otherwise read
/// the file, substitute `{{difficulty}}` / `{{endpoint}}` placeholders, and cache
/// the result so it is not re-read per request.
pub fn load_page(path: ngx_str_t) -> ngx_str_t {
    let _ = path;
    ngx_str_t {
        len: DEFAULT_PAGE.len(),
        data: DEFAULT_PAGE.as_ptr() as *mut u8,
    }
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
/// Returns `Some(status)` when the request was one of ours, `None` otherwise.
pub fn route_internal(r: &mut Request, cfg: &Cfg, suffix: &str) -> Option<Status> {
    match suffix {
        "challenge" => Some(crate::engine::pow::issue_challenge(r, cfg)),
        "solver.js" => Some(serve_solver(r)),
        "verify" => Some(crate::engine::pow::verify_solution(r)),
        _ => None,
    }
}

/// Serve the solver: `200 OK`, `Content-Type: text/javascript`, body =
/// [`SOLVER_JS`] (always the module-provided embedded solver).
fn serve_solver(r: &mut Request) -> Status {
    send_and_finish(r, HTTPStatus::OK, "text/javascript; charset=utf-8", SOLVER_JS, None)
}
