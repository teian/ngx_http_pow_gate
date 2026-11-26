//! Outcome counters and the `pow_gate_status` endpoint.
//!
//! Every gated request ends with one `(result, reason)` pair — the same values
//! `$pow_gate_result` / `$pow_gate_reason` log. A LOG-phase handler counts that
//! final pair in a small shared-memory table, so the numbers cover all workers
//! and survive a graceful reload. `pow_gate_status;` serves them in the
//! Prometheus text format.
//!
//! The table is fixed-size and append-only: a slot is claimed under the zone
//! mutex the first time a pair is seen, then only its atomic counter changes.
//! Counting therefore never takes a lock on the request path.
//!
//! Each worker counts in its own row of counters, and the status endpoint adds
//! the rows up. Workers would otherwise all write the same counter, and the
//! cache line holding it would travel between their CPUs on every request.

use std::ffi::c_void;
use std::mem::size_of;
use std::os::raw::c_char;
use std::ptr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;

use ngx::core::{Status, NGX_CONF_OK};
use ngx::ffi::*;
use ngx::http::{HTTPStatus, Request};
use ngx::ngx_string;

/// The pairs are a closed set of string literals (about thirty today).
const SLOTS: usize = 128;
/// Counter rows. A worker uses row `ngx_worker % ROWS`; workers that share a
/// row (more than 64 workers, or old and new workers during a reload) still
/// count correctly, because the counters are atomic.
const ROWS: usize = 64;
const ZONE_BYTES: usize = 256 * 1024;
const RESULT_MAX: usize = 16;
const REASON_MAX: usize = 40;

#[repr(C)]
struct Slot {
    /// 0 while free; set last, after the label bytes, so readers never see a
    /// half-written label.
    used: AtomicU32,
    result_len: u8,
    reason_len: u8,
    result: [u8; RESULT_MAX],
    reason: [u8; REASON_MAX],
}

/// One worker's counters, indexed like `Table::slots`. Aligned so that two
/// rows never share a cache line.
#[repr(C, align(64))]
struct Row([AtomicU64; SLOTS]);

#[repr(C, align(64))]
struct Table {
    slots: [Slot; SLOTS],
    rows: [Row; ROWS],
}

// Activated from the worker's own configuration cycle, like the replay zone.
static mut ZONE: *mut ngx_shm_zone_t = ptr::null_mut();

/// Worker-local index of pairs already located: the literals have stable
/// addresses, so a hit is two pointer comparisons.
static KNOWN: Mutex<Vec<(usize, usize, usize)>> = Mutex::new(Vec::new());

pub unsafe fn configure(cf: *mut ngx_conf_t) -> ngx_int_t {
    let ctx = (*cf).ctx.cast::<ngx_http_conf_ctx_t>();
    let main = *(*ctx)
        .main_conf
        .add(crate::ngx_http_pow_gate_module.ctx_index as usize)
        as *mut crate::config::MainConf;
    let mut name = ngx_string!("pow_gate_metrics_v2");
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
    (*main).metrics_zone = zone;

    let cmcf = *(*ctx)
        .main_conf
        .add(ngx_http_core_module.ctx_index as usize)
        as *mut ngx_http_core_main_conf_t;
    let phase = &mut (*cmcf).phases[ngx_http_phases_NGX_HTTP_LOG_PHASE as usize];
    let handler = ngx_array_push(&mut phase.handlers) as *mut ngx_http_handler_pt;
    if handler.is_null() {
        return Status::NGX_ERROR.0 as ngx_int_t;
    }
    *handler = Some(count_outcome);
    Status::NGX_OK.0 as ngx_int_t
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
    let table = ngx_slab_calloc(pool, size_of::<Table>());
    if table.is_null() {
        return Status::NGX_ERROR.0 as ngx_int_t;
    }
    (*pool).data = table;
    (*zone).data = table;
    Status::NGX_OK.0 as ngx_int_t
}

pub unsafe fn activate(main: *mut crate::config::MainConf) {
    ZONE = (*main).metrics_zone;
    if let Ok(mut known) = KNOWN.lock() {
        known.clear();
    }
}

unsafe fn table<'a>() -> Option<&'a Table> {
    if ZONE.is_null() || (*ZONE).data.is_null() {
        return None;
    }
    Some(&*(*ZONE).data.cast::<Table>())
}

fn matches(slot: &Slot, result: &str, reason: &str) -> bool {
    &slot.result[..slot.result_len as usize] == result.as_bytes()
        && &slot.reason[..slot.reason_len as usize] == reason.as_bytes()
}

/// Find the pair's slot, claiming a free one under the zone mutex if needed.
/// `None` when the table is full or a label is oversized: the count is
/// dropped rather than letting metrics affect request handling.
unsafe fn locate(table: &Table, result: &str, reason: &str) -> Option<usize> {
    if result.len() > RESULT_MAX || reason.len() > REASON_MAX {
        return None;
    }
    let scan = |from: usize| -> Result<usize, usize> {
        for index in from..SLOTS {
            let slot = &table.slots[index];
            if slot.used.load(Ordering::Acquire) == 0 {
                return Err(index);
            }
            if matches(slot, result, reason) {
                return Ok(index);
            }
        }
        Err(SLOTS)
    };
    let free = match scan(0) {
        Ok(index) => return Some(index),
        Err(free) => free,
    };
    let pool = (*ZONE).shm.addr.cast::<ngx_slab_pool_t>();
    ngx_shmtx_lock(&mut (*pool).mutex);
    // Another worker may have claimed slots since the unlocked scan.
    let claimed = match scan(free) {
        Ok(index) => Some(index),
        Err(SLOTS) => None,
        Err(index) => {
            let slot = (&table.slots[index] as *const Slot).cast_mut();
            (&mut (*slot).result)[..result.len()].copy_from_slice(result.as_bytes());
            (&mut (*slot).reason)[..reason.len()].copy_from_slice(reason.as_bytes());
            (*slot).result_len = result.len() as u8;
            (*slot).reason_len = reason.len() as u8;
            (*slot).used.store(1, Ordering::Release);
            Some(index)
        }
    };
    ngx_shmtx_unlock(&mut (*pool).mutex);
    claimed
}

fn bump(result: &'static str, reason: &'static str) {
    unsafe {
        let Some(table) = table() else { return };
        let key = (result.as_ptr() as usize, reason.as_ptr() as usize);
        let Ok(mut known) = KNOWN.lock() else { return };
        let index = match known.iter().find(|entry| (entry.0, entry.1) == key) {
            Some(entry) => entry.2,
            None => {
                let Some(index) = locate(table, result, reason) else {
                    return;
                };
                known.push((key.0, key.1, index));
                index
            }
        };
        table.rows[ngx_worker % ROWS].0[index].fetch_add(1, Ordering::Relaxed);
    }
}

/// LOG phase: count the request's final outcome. Requests the gate never
/// touched (no state, or `off`) are not counted.
unsafe extern "C" fn count_outcome(r: *mut ngx_http_request_t) -> ngx_int_t {
    let state = crate::observability::state(r, false);
    if !state.is_null() && (*state).result != "off" {
        bump((*state).result, (*state).reason);
    }
    Status::NGX_OK.0 as ngx_int_t
}

/// `pow_gate_status;` — make this location serve the counters.
pub unsafe extern "C" fn set_status(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    _conf: *mut c_void,
) -> *mut c_char {
    let ctx = (*cf).ctx.cast::<ngx_http_conf_ctx_t>();
    let core = *(*ctx).loc_conf.add(ngx_http_core_module.ctx_index as usize)
        as *mut ngx_http_core_loc_conf_t;
    (*core).handler = Some(status_handler);
    NGX_CONF_OK
}

unsafe extern "C" fn status_handler(r: *mut ngx_http_request_t) -> ngx_int_t {
    if (*r).method & (NGX_HTTP_GET | NGX_HTTP_HEAD) as ngx_uint_t == 0 {
        return NGX_HTTP_NOT_ALLOWED as ngx_int_t;
    }
    let rc = ngx_http_discard_request_body(r);
    if rc != Status::NGX_OK.0 as ngx_int_t {
        return rc;
    }
    let body = render();
    let request = Request::from_ngx_http_request(r);
    crate::response::send_with_headers(
        request,
        HTTPStatus::OK,
        "text/plain; version=0.0.4; charset=utf-8",
        body.as_bytes(),
        &[],
    )
    .0
}

fn render() -> String {
    let mut out = String::with_capacity(2048);
    out.push_str(concat!(
        "# HELP pow_gate_build_info Module version.\n",
        "# TYPE pow_gate_build_info gauge\n",
        "pow_gate_build_info{version=\"",
        env!("CARGO_PKG_VERSION"),
        "\"} 1\n",
        "# HELP pow_gate_requests_total Gated requests by final outcome.\n",
        "# TYPE pow_gate_requests_total counter\n",
    ));
    unsafe {
        if let Some(table) = table() {
            for (index, slot) in table.slots.iter().enumerate() {
                if slot.used.load(Ordering::Acquire) == 0 {
                    break;
                }
                let count = table.rows.iter().fold(0u64, |total, row| {
                    total.wrapping_add(row.0[index].load(Ordering::Relaxed))
                });
                // Labels are module literals: [a-z_] only, nothing to escape.
                out.push_str(&format!(
                    "pow_gate_requests_total{{result=\"{}\",reason=\"{}\"}} {}\n",
                    std::str::from_utf8_unchecked(&slot.result[..slot.result_len as usize]),
                    std::str::from_utf8_unchecked(&slot.reason[..slot.reason_len as usize]),
                    count
                ));
            }
        }
    }
    let (load, percent) = load();
    out.push_str(&format!(
        concat!(
            "# HELP pow_gate_load1 One-minute load average seen by the gate.\n",
            "# TYPE pow_gate_load1 gauge\n",
            "pow_gate_load1 {:.2}\n",
            "# HELP pow_gate_load_percent Load average as a percentage of available CPUs.\n",
            "# TYPE pow_gate_load_percent gauge\n",
            "pow_gate_load_percent {}\n",
        ),
        load, percent
    ));
    out
}

// ───────────────────────────── system load ───────────────────────────────────

/// One-minute load average and the same value as a percentage of the CPUs
/// available to this process (100 = every CPU busy). Read from
/// `/proc/loadavg` at most once per second per worker; `(0.0, 0)` when it
/// cannot be read, so load-based policy degrades to "no surcharge".
pub fn load() -> (f64, u64) {
    static AT: AtomicU64 = AtomicU64::new(0);
    static BITS: AtomicU64 = AtomicU64::new(0);
    // The cached second is enough to decide when to re-read the file.
    let now = crate::runtime::cached_now() as u64;
    if AT.swap(now, Ordering::Relaxed) != now {
        let value = std::fs::read_to_string("/proc/loadavg")
            .ok()
            .and_then(|text| text.split_whitespace().next()?.parse::<f64>().ok())
            .filter(|value| value.is_finite() && *value >= 0.0)
            .unwrap_or(0.0);
        BITS.store(value.to_bits(), Ordering::Relaxed);
    }
    let value = f64::from_bits(BITS.load(Ordering::Relaxed));
    // Looked up once: it reads affinity and cgroup limits, which do not change
    // under a running worker often enough to pay for on the request path.
    static CPUS: std::sync::OnceLock<f64> = std::sync::OnceLock::new();
    let cpus =
        *CPUS.get_or_init(|| std::thread::available_parallelism().map_or(1, usize::from) as f64);
    (value, ((value / cpus) * 100.0).min(100_000.0) as u64)
}
