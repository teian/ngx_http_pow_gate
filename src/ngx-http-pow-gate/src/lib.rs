//! ngx_http_pow_gate_module — crate entry point.
//!
//! This file is the nginx module *definition*: the `ngx_module_t` static, its
//! HTTP module context (the create/merge/postconfiguration callbacks), and the
//! `ngx_modules!` declaration nginx needs to discover the module after `dlopen`.
//!
//! The actual behaviour is split across focused submodules:
//!
//! ```text
//!   src/
//!   ├── lib.rs        ← you are here: module registration + wiring
//!   ├── config.rs     directives, MainConf / LocationConf, create + merge
//!   ├── access.rs     ACCESS-phase handler: the allow / deny / challenge decision
//!   ├── challenge.rs  challenge-page rendering + the internal /.pow/ endpoints
//!   ├── verifier.rs   `pow_gate_verifier {}` block: verified good-bot allowlist
//!   └── engine/       the PoW crypto (clearance cookie, per-request proof, hashing)
//! ```
//!
//! A request flows: nginx ACCESS phase → [`access::pow_gate_access`] →
//! (trusted? decision? clearance?) → either `NGX_DECLINED` (pass to upstream) or
//! [`challenge::serve_challenge_page`]. See docs/architecture.md for the diagrams.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

mod access;
mod challenge;
mod config;
mod engine;
mod response;
mod runtime;
mod verifier;

use ngx::ffi::{
    ngx_command_t, ngx_http_module_t, ngx_int_t, ngx_module_t, ngx_uint_t, NGX_HTTP_MODULE,
};

// Re-export the pieces nginx links against by symbol.
use config::{create_location_conf, create_main_conf, merge_location_conf, NGX_HTTP_POW_GATE_COMMANDS};

/// HTTP module context. nginx calls these at configuration time. (The struct
/// field names below — `create_loc_conf`, `merge_loc_conf` — are nginx's own ABI
/// field names from `ngx_http_module_t`; our handlers are the full-word
/// `create_location_conf` / `merge_location_conf`.)
///
/// * `create_main_conf` / `create_location_conf` allocate the config structs.
/// * `merge_location_conf` implements directive inheritance (server → location).
/// * `postconfiguration` installs the ACCESS-phase handler once the config tree
///   is built — that is what actually puts the gate in the request pipeline.
#[no_mangle]
static NGX_HTTP_POW_GATE_MODULE_CTX: ngx_http_module_t = ngx_http_module_t {
    preconfiguration: None,
    postconfiguration: Some(postconfiguration),
    create_main_conf: Some(create_main_conf),
    init_main_conf: None,
    create_srv_conf: None,
    merge_srv_conf: None,
    create_loc_conf: Some(create_location_conf),
    merge_loc_conf: Some(merge_location_conf),
};

// Declares the exported `ngx_modules` array that nginx scans after dlopen.
ngx::ngx_modules!(ngx_http_pow_gate_module);

/// The module object itself. Field layout matches the `ngx` crate version pinned
/// in Cargo.toml; the leading/trailing reserved fields are filled by the macro
/// helpers in newer `ngx` releases. Kept explicit here for documentation value.
#[no_mangle]
#[used]
pub static mut ngx_http_pow_gate_module: ngx_module_t = ngx_module_t {
    ctx_index: ngx_uint_t::MAX,
    index: ngx_uint_t::MAX,
    name: std::ptr::null_mut(),
    spare0: 0,
    spare1: 0,
    version: ngx::ffi::nginx_version as ngx_uint_t,
    signature: ngx::ffi::NGX_RS_MODULE_SIGNATURE.as_ptr() as *const _,

    ctx: &NGX_HTTP_POW_GATE_MODULE_CTX as *const _ as *mut _,
    commands: unsafe { NGX_HTTP_POW_GATE_COMMANDS.as_ptr() as *mut ngx_command_t },
    type_: NGX_HTTP_MODULE as ngx_uint_t,

    init_master: None,
    init_module: None,
    init_process: Some(engine::init_process), // start IP-range refreshers per worker
    init_thread: None,
    exit_thread: None,
    exit_process: None,
    exit_master: None,

    spare_hook0: 0,
    spare_hook1: 0,
    spare_hook2: 0,
    spare_hook3: 0,
    spare_hook4: 0,
    spare_hook5: 0,
    spare_hook6: 0,
    spare_hook7: 0,
};

/// Runs after the full HTTP config is parsed. Pushes the gate's handler onto the
/// ACCESS phase so it runs for every request in a location where `pow_gate on;`.
///
/// Registering here (rather than per-location) keeps a single handler that reads
/// the merged [`config::LocationConf`] for the matched location at request time.
extern "C" fn postconfiguration(cf: *mut ngx::ffi::ngx_conf_t) -> ngx_int_t {
    access::install_access_handler(cf)
}
