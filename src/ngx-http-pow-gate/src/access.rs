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
//!      PoW page, or the no-JS meta-refresh page on `challenge:nojs`. A
//!      data-carrying method (POST, PUT, …) is captured into that page first
//!      ([`crate::replay`]) so the solver can re-issue it after clearance.
//!
//! Decision strings (`challenge[:N|:js|:nojs[:secs]]`, `allow`, `deny`,
//! `verify:<name>`) are parsed by [`pow_gate_core::decision`].

use ngx::core::Status;
use ngx::ffi::{
    ngx_array_push, ngx_conf_t, ngx_http_complex_value_t, ngx_http_core_main_conf_t,
    ngx_http_handler_pt, ngx_http_phases_NGX_HTTP_ACCESS_PHASE, ngx_http_request_t, ngx_int_t,
};
use ngx::http::{HttpModule, HttpModuleConfExt, NgxHttpCoreModule, Request};
use std::borrow::Cow;

use pow_gate_core::nojs;
use pow_gate_core::{context::Assurance, Decision};

use crate::challenge::{route_internal, serve_challenge_page, serve_nojs_page};
use crate::config::LocationConf;
use crate::engine::clearance::has_valid_clearance;
use crate::observability::record;
use crate::replay;
use crate::response::{as_bytes, as_str};
use crate::runtime;
use crate::verifier::verifier_result;

ngx::http_request_handler!(pow_gate_access, |request: &mut Request| {
    let raw: *mut ngx_http_request_t = request as *mut Request as *mut ngx_http_request_t;

    let location_conf: &LocationConf = match unsafe { runtime::location_conf(raw) } {
        Some(lc) => lc,
        None => return Status::NGX_DECLINED,
    };
    if location_conf.enabled == 0 {
        record(request, "off", "disabled", 0);
        return Status::NGX_DECLINED; // gate off here -> pass through
    }

    let cfg = runtime::resolve(location_conf);

    // The decision is evaluated up front: the internal `/challenge` endpoint
    // needs it too (a `challenge:<N>` override must shape what it issues, and
    // the decision `map` keys on client attributes, so it evaluates the same
    // on the endpoint request as on the gated one).
    let decision_raw = eval_complex_value(request, unsafe { location_conf.decision.as_ref() });
    let decision = Decision::parse(&decision_raw);
    let required = assurance_for(&decision, cfg);
    let difficulty = match required {
        Assurance::Pow { difficulty } => difficulty,
        _ => 0,
    };
    record(request, "challenge", "no_clearance", difficulty);

    // 0. internal endpoints (challenge / solver.js / verify / pass) bypass the gate.
    let uri = unsafe { as_str(&(*raw).uri) };
    if !cfg.endpoint.is_empty() && uri.starts_with(&cfg.endpoint) {
        let suffix = &uri[cfg.endpoint.len()..];
        return route_internal(
            request,
            cfg,
            suffix,
            required,
            &location_conf.nojs_page_cache,
        )
        .unwrap_or(Status::NGX_DECLINED);
    }

    // 1. trusted network (native `geo`) => allow.
    if is_trusted(request, location_conf.trusted) {
        record(request, "bypass", "trusted", difficulty);
        return Status::NGX_DECLINED;
    }

    // 2. decision (native `map` on User-Agent).
    match decision {
        Decision::Allow => {
            record(request, "bypass", "allow", difficulty);
            return Status::NGX_DECLINED;
        }
        Decision::Deny => return deny(request),
        Decision::Verify(name) => {
            if let Some(ip) = runtime::client_ip(request) {
                let (allowed, reason) = verifier_result(name, ip);
                record(
                    request,
                    if allowed { "bypass" } else { "challenge" },
                    reason,
                    difficulty,
                );
                if allowed {
                    return Status::NGX_DECLINED; // verified good bot
                }
            }
            // spoofed UA / unknown IP -> fall through to challenge
        }
        Decision::Challenge { .. } | Decision::ChallengeNoJs { .. } => {}
    }

    // 3. challenge: cleared clients pass; everyone else gets the page the
    // decision picked — JS PoW by default, meta-refresh for challenge:nojs.
    if has_valid_clearance(request, cfg, required) {
        record(request, "bypass", "clearance", difficulty);
        return Status::NGX_DECLINED;
    }
    crate::response::no_store(request);
    if let Decision::ChallengeNoJs { delay } = decision {
        if crate::cluster::enabled() && !crate::cluster::available() {
            record(request, "error", "issuer_unavailable", 0);
            crate::response::no_store(request);
            return ngx::http::HTTPStatus::SERVICE_UNAVAILABLE.into();
        }
        // Return path: the RAW client-sent URI (still percent-encoded, unlike
        // r->uri) — core additionally sanitizes it before it reaches a header.
        let return_path = unsafe { as_str(&(*raw).unparsed_uri) };
        let Some(context) = runtime::client_context(request, cfg) else {
            return ngx::http::HTTPStatus::SERVICE_UNAVAILABLE.into();
        };
        let grant = nojs::issue(&cfg.key, return_path, delay, runtime::now(), &context);
        record(request, "issued", "nojs", 0);
        let pass_url = format!("{}pass?t={}", cfg.endpoint, grant);
        return serve_nojs_page(request, &location_conf.nojs_page_cache, &pass_url, delay);
    }
    // A POST (or any other data-carrying method) would be lost to the reload
    // after the solve, so capture it into the page first and let the solver
    // re-issue it — the body read is asynchronous, hence the separate path.
    if replay::should_capture(request, cfg) {
        return replay::capture_then_challenge(request, &location_conf.page_cache);
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
fn eval_complex_value<'a>(r: &Request, cv: Option<&'a ngx_http_complex_value_t>) -> Cow<'a, str> {
    let Some(cv) = cv else {
        return Cow::Borrowed("");
    };
    if cv.lengths.is_null() {
        // Literal values belong to the configuration pool, not the request.
        return String::from_utf8_lossy(unsafe { as_bytes(&cv.value) });
    }
    match r.get_complex_value(cv) {
        Some(v) => Cow::Owned(String::from_utf8_lossy(v.as_bytes()).into_owned()),
        None => Cow::Borrowed(""),
    }
}

fn is_trusted(r: &Request, cv: *mut ngx_http_complex_value_t) -> bool {
    let Some(cv) = (unsafe { cv.as_ref() }) else {
        return false;
    };
    r.get_complex_value(cv)
        .is_some_and(|value| value.as_bytes() == b"1")
}

/// `pow_gate_decision deny` lands here: refuse the request outright.
fn deny(r: &mut Request) -> Status {
    crate::response::no_store(r);
    record(r, "deny", "policy", 0);
    ngx::http::HTTPStatus::FORBIDDEN.into()
}

fn assurance_for(decision: &Decision<'_>, cfg: &runtime::Cfg) -> Assurance {
    match decision {
        Decision::ChallengeNoJs { delay } => Assurance::NoJs { delay: *delay },
        Decision::Challenge {
            difficulty: Some(n),
        } => Assurance::Pow { difficulty: *n },
        _ => Assurance::Pow {
            difficulty: cfg.difficulty,
        },
    }
}

/// Re-evaluate the policy in the asynchronous verify callback. The client cannot
/// choose a weaker echoed difficulty or reuse a different issuance tier.
pub fn required_assurance(r: &Request, lc: &LocationConf, cfg: &runtime::Cfg) -> Assurance {
    let raw = eval_complex_value(r, unsafe { lc.decision.as_ref() });
    assurance_for(&Decision::parse(&raw), cfg)
}
