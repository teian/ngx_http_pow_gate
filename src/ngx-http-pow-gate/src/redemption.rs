//! One fixed 2 MiB nginx shared-memory zone, shared across workers and reused
//! on graceful reload. No per-worker hash maps, heap growth or background GC.

use std::{ffi::c_void, mem::size_of, ptr};

use ngx::{core::Status, ffi::*, ngx_string};
use pow_gate_core::redemption::{self, Entry, Outcome};

const CAPACITY: usize = 32_768;
const ZONE_BYTES: usize = 2 * 1024 * 1024;

#[repr(C)]
struct State {
    issuer: [u8; 32],
    last_now: i64,
    entries: [Entry; CAPACITY],
}

// Activated from the worker's configuration cycle after fork. Parsing a failed
// reload must never leave a respawned worker pointing into a discarded cycle.
static mut ZONE: *mut ngx_shm_zone_t = ptr::null_mut();

pub unsafe fn configure(cf: *mut ngx_conf_t) -> ngx_int_t {
    let ctx = (*cf).ctx.cast::<ngx_http_conf_ctx_t>();
    let main = *(*ctx)
        .main_conf
        .add(crate::ngx_http_pow_gate_module.ctx_index as usize)
        as *mut crate::config::MainConf;
    // Redis owns the one-use ledger in cluster mode; reserve no local fallback.
    if !(*main).cluster.is_null() {
        return Status::NGX_OK.0;
    }
    let mut name = ngx_string!("pow_gate_redemptions_v2");
    let zone = ngx_shared_memory_add(
        cf,
        &mut name,
        ZONE_BYTES,
        (&raw mut crate::ngx_http_pow_gate_module).cast::<c_void>(),
    );
    if zone.is_null() {
        return Status::NGX_ERROR.0 as ngx_int_t;
    }
    (*zone).init = Some(init_zone);
    (*main).redemption_zone = zone;
    Status::NGX_OK.0 as ngx_int_t
}

pub unsafe fn activate(cycle: *mut ngx_cycle_t) -> bool {
    let ctx = *(*cycle).conf_ctx.add(ngx_http_module.index as usize) as *mut ngx_http_conf_ctx_t;
    if ctx.is_null() {
        return false;
    }
    let main = *(*ctx)
        .main_conf
        .add(crate::ngx_http_pow_gate_module.ctx_index as usize)
        as *mut crate::config::MainConf;
    if main.is_null() {
        return false;
    }
    crate::cluster::activate(main, (*cycle).log);
    ZONE = (*main).redemption_zone;
    if crate::cluster::enabled() {
        return true;
    }
    if ZONE.is_null() {
        return false;
    }
    !(*ZONE).data.is_null()
}

unsafe extern "C" fn init_zone(zone: *mut ngx_shm_zone_t, old: *mut c_void) -> ngx_int_t {
    if !old.is_null() {
        (*zone).data = old;
        return Status::NGX_OK.0 as ngx_int_t;
    }
    let pool = (*zone).shm.addr.cast::<ngx_slab_pool_t>();
    if (*zone).shm.exists != 0 {
        (*zone).data = (*pool).data;
        return Status::NGX_OK.0 as ngx_int_t;
    }
    let state = ngx_slab_calloc(pool, size_of::<State>()).cast::<State>();
    if state.is_null() {
        return Status::NGX_ERROR.0 as ngx_int_t;
    }
    // No getrandom dependency at the nginx seam; the core provides OS entropy.
    let Some(issuer) = pow_gate_core::redemption::issuer() else {
        return Status::NGX_ERROR.0 as ngx_int_t;
    };
    (*state).issuer = issuer;
    (*pool).data = state.cast();
    (*zone).data = state.cast();
    Status::NGX_OK.0 as ngx_int_t
}

pub fn issuer() -> Option<[u8; 32]> {
    if crate::cluster::enabled() {
        return crate::cluster::issuer();
    }
    unsafe {
        if ZONE.is_null() || (*ZONE).data.is_null() {
            return None;
        }
        Some((*(*ZONE).data.cast::<State>()).issuer)
    }
}

pub fn consume(token: &str, expires: i64) -> Outcome {
    // Hash outside the shared critical section. Work is bounded to 64 probes.
    let id = redemption::id(token);
    unsafe {
        if ZONE.is_null() || (*ZONE).data.is_null() {
            return Outcome::Full;
        }
        let pool = (*ZONE).shm.addr.cast::<ngx_slab_pool_t>();
        let state = (*ZONE).data.cast::<State>();
        ngx_shmtx_lock(&mut (*pool).mutex);
        // Sample time INSIDE the same lock as expiry/reuse. A worker paused
        // before taking the lock must not redeem a token another worker has
        // already expired/reclaimed. Keep a shared high-water mark so a wall
        // clock correction cannot reopen previously expired challenges.
        let now = crate::runtime::now().max((*state).last_now);
        (*state).last_now = now;
        let result = redemption::consume(&mut (*state).entries, id, expires, now);
        ngx_shmtx_unlock(&mut (*pool).mutex);
        result
    }
}

/// A prepared response is never exposed until the store accepts redemption.
pub struct Grant {
    pub cookie: String,
    pub redirect: Option<String>,
    pub difficulty: u64,
    pub kind: &'static str,
}

pub fn redeem(r: &mut ngx::http::Request, token: &str, expires: i64, grant: Grant) -> Status {
    if crate::cluster::enabled() {
        crate::cluster::redeem(r, token, expires, grant)
    } else {
        finish(r, consume(token, expires), grant)
    }
}

pub fn finish(r: &mut ngx::http::Request, outcome: Outcome, grant: Grant) -> Status {
    use crate::{observability::record, response::send_and_finish_with_headers};
    use ngx::http::HTTPStatus;
    match outcome {
        Outcome::Accepted => {
            record(r, "accepted", grant.kind, grant.difficulty);
            if let Some(path) = grant.redirect {
                let body = format!("<html><body><a href=\"{path}\">Continue</a></body></html>\n");
                send_and_finish_with_headers(
                    r,
                    HTTPStatus::MOVED_TEMPORARILY,
                    "text/html; charset=utf-8",
                    body.as_bytes(),
                    &[("Location", &path), ("Set-Cookie", &grant.cookie)],
                )
            } else {
                send_and_finish_with_headers(
                    r,
                    HTTPStatus::NO_CONTENT,
                    "text/plain",
                    &[],
                    &[("Set-Cookie", &grant.cookie)],
                )
            }
        }
        other => {
            let (status, result, reason) = match other {
                Outcome::Reused => (HTTPStatus::CONFLICT, "rejected", "replay"),
                Outcome::Expired => (HTTPStatus::BAD_REQUEST, "rejected", "expired"),
                _ => (
                    HTTPStatus::SERVICE_UNAVAILABLE,
                    "error",
                    "redemption_unavailable",
                ),
            };
            record(r, result, reason, grant.difficulty);
            send_and_finish_with_headers(r, status, "text/plain", b"redemption rejected\n", &[])
        }
    }
}
