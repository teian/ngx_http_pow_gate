//! One fixed 2 MiB nginx shared-memory zone, shared across workers and reused
//! on graceful reload. No per-worker hash maps, heap growth or background GC.
//!
//! ## Surviving a full restart (`pow_gate_state_file`)
//!
//! Clearances are bound to the store's random `issuer`, so a fresh zone with a
//! fresh issuer invalidates all of them — deliberately: the ledger of redeemed
//! challenges is gone, and without it a solution redeemed just before the
//! restart could be redeemed again. With a state file the issuer is kept on
//! disk and restored, and the replay gap is closed differently: the restored
//! store records when it was created (`floor`) and refuses every challenge or
//! grant issued at or before that second. Those are the only ones the lost
//! ledger could have seen, and they expire within two minutes anyway.

use std::{ffi::c_void, mem::size_of, ptr};

use ngx::{core::Status, ffi::*, ngx_string};
use pow_gate_core::redemption::{self, Entry, Outcome};

const CAPACITY: usize = 32_768;
const ZONE_BYTES: usize = 2 * 1024 * 1024;

#[repr(C)]
struct State {
    issuer: [u8; 32],
    last_now: i64,
    /// Non-zero when `issuer` was restored from the state file: redemptions
    /// issued at or before this second are refused.
    floor: i64,
    entries: [Entry; CAPACITY],
}

// Activated from the worker's configuration cycle after fork. Parsing a failed
// reload must never leave a respawned worker pointing into a discarded cycle.
static mut ZONE: *mut ngx_shm_zone_t = ptr::null_mut();

// Set while the master parses a configuration, read by `init_zone` later in
// the same cycle initialisation. Workers never use it.
static mut STATE_FILE: Option<String> = None;

/// Restore the issuer from `path`, or create the file with a new one. The
/// flag says whether it was restored. Any other condition — unreadable,
/// malformed, not writable — is an error: starting with a silently different
/// issuer would drop every clearance, which is what the directive is for.
fn load_or_create_issuer(path: &str) -> Result<([u8; 32], bool), String> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let text = text.trim();
            let mut issuer = [0u8; 32];
            if text.len() != 64 || !text.is_ascii() {
                return Err(format!("{path:?} is not a pow_gate state file"));
            }
            for (index, byte) in issuer.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
                    .map_err(|_| format!("{path:?} is not a pow_gate state file"))?;
            }
            Ok((issuer, true))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let issuer = pow_gate_core::redemption::issuer()
                .ok_or_else(|| "no OS entropy for the store identity".to_owned())?;
            write_issuer(path, &issuer)?;
            Ok((issuer, false))
        }
        Err(error) => Err(format!("cannot read {path:?}: {error}")),
    }
}

/// Write-then-rename, owner-only: a crash never leaves a truncated file.
fn write_issuer(path: &str, issuer: &[u8; 32]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let hex: String = issuer.iter().map(|byte| format!("{byte:02x}")).collect();
    let temporary = format!("{path}.tmp");
    let result = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temporary)
        .and_then(|mut file| {
            file.write_all(hex.as_bytes())?;
            file.write_all(b"\n")?;
            file.sync_all()
        })
        .and_then(|()| std::fs::rename(&temporary, path));
    result.map_err(|error| format!("cannot write {path:?}: {error}"))
}

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
    let state_file = crate::response::as_str(&(*main).state_file);
    STATE_FILE = (!state_file.is_empty()).then(|| state_file.to_owned());
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
    crate::metrics::activate(main);
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
    let state_file = (*(&raw const STATE_FILE)).as_deref();
    if !old.is_null() {
        (*zone).data = old;
        // The directive was added by this reload: the running store already
        // has an issuer, so record that one for the next restart.
        if let Some(path) = state_file {
            if !std::path::Path::new(path).exists() {
                if let Err(error) = write_issuer(path, &(*old.cast::<State>()).issuer) {
                    eprintln!("[pow_gate] pow_gate_state_file: {error}");
                    return Status::NGX_ERROR.0 as ngx_int_t;
                }
            }
        }
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
    let (issuer, restored) = match state_file {
        Some(path) => match load_or_create_issuer(path) {
            Ok(loaded) => loaded,
            Err(error) => {
                eprintln!("[pow_gate] pow_gate_state_file: {error}");
                return Status::NGX_ERROR.0 as ngx_int_t;
            }
        },
        // No getrandom dependency at the nginx seam; the core provides OS entropy.
        None => match pow_gate_core::redemption::issuer() {
            Some(issuer) => (issuer, false),
            None => return Status::NGX_ERROR.0 as ngx_int_t,
        },
    };
    (*state).issuer = issuer;
    if restored {
        (*state).floor = crate::runtime::now();
    }
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

pub fn consume(token: &str, expires: i64, lifetime: i64) -> Outcome {
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
        // Issued before this store existed: the ledger that could have seen
        // it redeemed is gone, so it is refused (see the module docs).
        let floor = (*state).floor;
        let result = if floor != 0 && expires - lifetime <= floor {
            Outcome::Expired
        } else {
            redemption::consume(&mut (*state).entries, id, expires, now)
        };
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
    /// Seconds between issuance and `expires` of the redeemed token.
    pub lifetime: i64,
}

pub fn redeem(r: &mut ngx::http::Request, token: &str, expires: i64, grant: Grant) -> Status {
    if crate::cluster::enabled() {
        crate::cluster::redeem(r, token, expires, grant)
    } else {
        finish(r, consume(token, expires, grant.lifetime), grant)
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
