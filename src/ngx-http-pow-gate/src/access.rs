//! ACCESS-phase handler: serve the internal `/.pow/` endpoints, then make the
//! allow / deny / challenge decision.
//!
//! Decision order (first match wins):
//!   0. internal `{endpoint}*` route → handled here (bypasses the gate; the
//!      decision is still evaluated first so `/challenge` issues the
//!      difficulty the decision demands)
//!   1. gate disabled            → DECLINED (pass straight to upstream)
//!   2. trusted network (`geo`)  → DECLINED
//!   3. decision == allow        → DECLINED
//!   4. decision == deny         → 403
//!   5. decision == verify:<n>   → run verifier; pass if it confirms the bot
//!   6. valid clearance cookie   → DECLINED
//!   7. otherwise                → serve the challenge page (200): the JS
//!      PoW page, or the no-JS meta-refresh page on `challenge:nojs`
//!
//! Decision strings (`challenge[:N|:js|:nojs[:secs]]`, `allow`, `deny`,
//! `verify:<name>`) are parsed by [`pow_gate_core::decision`].

use ngx::core::Status;
use ngx::ffi::{
    ngx_array_push, ngx_conf_t, ngx_http_complex_value_t, ngx_http_core_main_conf_t,
    ngx_http_handler_pt, ngx_http_phases_NGX_HTTP_ACCESS_PHASE, ngx_http_request_t, ngx_int_t,
};
use ngx::http::{HttpModule, HttpModuleConfExt, NgxHttpCoreModule, Request};

use pow_gate_core::nojs;
use pow_gate_core::Decision;

use crate::challenge::{route_internal, serve_challenge_page, serve_nojs_page};
use crate::config::LocationConf;
use crate::engine::clearance::has_valid_clearance;
use crate::response::as_str;
use crate::runtime;
use crate::verifier::verifier_allows;

ngx::http_request_handler!(pow_gate_access, |request: &mut Request| {
    let raw: *mut ngx_http_request_t = request as *mut Request as *mut ngx_http_request_t;

    let location_conf: &LocationConf = match unsafe { runtime::location_conf(raw) } {
        Some(lc) => lc,
        None => return Status::NGX_DECLINED,
    };
    if location_conf.enabled == 0 {
        return Status::NGX_DECLINED; // gate off here -> pass through
    }

    let cfg = runtime::resolve(location_conf);

    // The decision is evaluated up front: the internal `/challenge` endpoint
    // needs it too (a `challenge:<N>` override must shape what it issues, and
    // the decision `map` keys on client attributes, so it evaluates the same
    // on the endpoint request as on the gated one).
    let decision_raw = eval_complex_value(request, location_conf.decision);
    let decision = Decision::parse(&decision_raw);
    let effective_difficulty = match decision {
        Decision::Challenge { difficulty: Some(n) } => n,
        _ => cfg.difficulty,
    };

    // 0. internal endpoints (challenge / solver.js / verify / pass) bypass the gate.
    let uri = unsafe { as_str(&(*raw).uri) };
    if !cfg.endpoint.is_empty() && uri.starts_with(&cfg.endpoint) {
        let suffix = &uri[cfg.endpoint.len()..];
        return route_internal(
            request,
            &cfg,
            suffix,
            effective_difficulty,
            &location_conf.nojs_page_cache,
        )
        .unwrap_or(Status::NGX_DECLINED);
    }

    // 1. trusted network (native `geo`) => allow.
    if eval_complex_value(request, location_conf.trusted) == "1" {
        return Status::NGX_DECLINED;
    }

    // 2. decision (native `map` on User-Agent).
    match decision {
        Decision::Allow => return Status::NGX_DECLINED,
        Decision::Deny => return deny(request),
        Decision::Verify(name) => {
            if let Some(ip) = runtime::client_ip(request) {
                if verifier_allows(name, ip) {
                    return Status::NGX_DECLINED; // verified good bot
                }
            }
            // spoofed UA / unknown IP -> fall through to challenge
        }
        Decision::Challenge { .. } | Decision::ChallengeNoJs { .. } => {}
    }

    // 3. challenge: cleared clients pass; everyone else gets the page the
    // decision picked — JS PoW by default, meta-refresh for challenge:nojs.
    if has_valid_clearance(request, &cfg) {
        return Status::NGX_DECLINED;
    }
    if let Decision::ChallengeNoJs { delay } = decision {
        // Return path: the RAW client-sent URI (still percent-encoded, unlike
        // r->uri) — core additionally sanitizes it before it reaches a header.
        let return_path = unsafe { as_str(&(*raw).unparsed_uri) };
        let grant = nojs::issue(&cfg.key, return_path, delay, runtime::now());
        let pass_url = format!("{}pass?t={}", cfg.endpoint, grant);
        return serve_nojs_page(request, &location_conf.nojs_page_cache, &pass_url, delay);
    }
    serve_challenge_page(request, &location_conf.page_cache)
});

/// Register [`pow_gate_access`] on the ACCESS phase. Called from
/// `postconfiguration` once the config tree is complete.
pub fn install_access_handler(cf: *mut ngx_conf_t) -> ngx_int_t {
    unsafe {
        let cmcf = match (*cf)
            .http_main_conf_unchecked::<ngx_http_core_main_conf_t>(NgxHttpCoreModule::module())
        {
            Some(p) => p.as_ptr(),
            None => return Status::NGX_ERROR.0 as ngx_int_t,
        };
        let phase = &mut (*cmcf).phases[ngx_http_phases_NGX_HTTP_ACCESS_PHASE as usize];
        let h = ngx_array_push(&mut phase.handlers) as *mut ngx_http_handler_pt;
        if h.is_null() {
            return Status::NGX_ERROR.0 as ngx_int_t;
        }
        *h = Some(pow_gate_access);
        Status::NGX_OK.0 as ngx_int_t
    }
}

// ───────────────────────────────── helpers ───────────────────────────────────

/// Evaluate an `ngx_http_complex_value_t` (`$variable` or literal) for this
/// request — how the gate reads the native `geo`/`map` results.
fn eval_complex_value(r: &Request, cv: *mut ngx_http_complex_value_t) -> String {
    if cv.is_null() {
        return String::new();
    }
    match r.get_complex_value(unsafe { &*cv }) {
        Some(v) => String::from_utf8_lossy(v.as_bytes()).into_owned(),
        None => String::new(),
    }
}

/// `pow_gate_decision deny` lands here: refuse the request outright.
fn deny(_r: &mut Request) -> Status {
    ngx::http::HTTPStatus::FORBIDDEN.into()
}
