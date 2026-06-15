//! Configuration surface: directives, config structs, and create/merge.
//!
//! Every field maps 1:1 to a directive. This array — `NGX_HTTP_POW_GATE_COMMANDS`
//! — *is* the "native config format": contexts and argument counts are encoded in
//! the `type_` bitmask exactly like every built-in nginx directive, so the gate
//! composes with `geo`, `map`, `location`, and inheritance for free.
//!
//! ## Inheritance model
//!
//! Almost every directive lives in [`LocationConf`] and is valid in `http`, `server`,
//! and `location` (a few only in `server`+`location`). That is the idiomatic
//! nginx pattern — exactly how `proxy_*` work: you set a value high in the tree
//! and override it precisely lower down, and `merge_location_conf` resolves it. This
//! means *all* the tunables (TTLs, difficulty, cookie attributes, the key file,
//! the endpoint…) inherit and can be overridden per server or per location.
//!
//! The single exception is [`MainConf`]: it holds only the named-verifier
//! registry built by the `pow_gate_verifier { }` block, which is global by nature
//! (verifiers are referenced by name via `verify:<name>` from any context).

use core::mem::offset_of;
use ngx::core::NGX_CONF_OK;
use ngx::ffi::*;
use ngx::ngx_string;
use std::os::raw::{c_char, c_void};
use std::ptr;

use crate::challenge::load_page;
use crate::verifier::pow_gate_verifier_block;

// nginx's ngx_conf_merge_* and NGX_CONF_UNSET_UINT are C macros, not exported
// symbols, so define the equivalents we need here. `*conf` keeps any value set at
// this level; otherwise it inherits `prev`, falling back to `default` when the
// parent is unset too.
const UNSET_UINT: ngx_uint_t = ngx_uint_t::MAX;

#[inline]
unsafe fn merge_flag(conf: &mut ngx_flag_t, prev: ngx_flag_t, default: ngx_flag_t) {
    if *conf == NGX_CONF_UNSET as ngx_flag_t {
        *conf = if prev == NGX_CONF_UNSET as ngx_flag_t { default } else { prev };
    }
}
#[inline]
unsafe fn merge_uint(conf: &mut ngx_uint_t, prev: ngx_uint_t, default: ngx_uint_t) {
    if *conf == UNSET_UINT {
        *conf = if prev == UNSET_UINT { default } else { prev };
    }
}
#[inline]
unsafe fn merge_sec(conf: &mut time_t, prev: time_t, default: time_t) {
    if *conf == NGX_CONF_UNSET as time_t {
        *conf = if prev == NGX_CONF_UNSET as time_t { default } else { prev };
    }
}
#[inline]
unsafe fn merge_ptr<T>(conf: &mut *mut T, prev: *mut T) {
    if conf.is_null() {
        *conf = prev;
    }
}
#[inline]
unsafe fn merge_str(conf: &mut ngx_str_t, prev: &ngx_str_t, default: &'static [u8]) {
    if conf.len == 0 {
        if prev.len != 0 {
            conf.len = prev.len;
            conf.data = prev.data;
        } else {
            conf.len = default.len();
            conf.data = default.as_ptr() as *mut u8;
        }
    }
}

// ───────────────────────── per-location configuration ─────────────────────────
//
// nginx creates one of these per location and MERGES parent into child, which is
// how `pow_gate on;` at server level and `pow_gate off;` in a `location`
// cooperate for free. EVERY inheritable knob lives here so it can be set at
// http/server/location and overridden downward.

#[repr(C)]
pub struct LocationConf {
    // ── gate + decision ──
    pub enabled: ngx_flag_t,                     // pow_gate on|off
    pub trusted: *mut ngx_http_complex_value_t,  // pow_gate_trusted   $var   (server, location)
    pub decision: *mut ngx_http_complex_value_t, // pow_gate_decision  $var   (server, location)

    // ── challenge page (the page is overridable; the solver is always the
    //    module-provided embedded one — no directive) ──
    pub page_path: ngx_str_t,  // pow_gate_page <file>
    pub page_cache: ngx_str_t, // rendered bytes (loaded once at merge)

    // ── PoW + token tunables (were http-only; now inherit to server/location) ──
    pub difficulty: ngx_uint_t,   // pow_gate_difficulty N
    pub hmac_key_file: ngx_str_t, // pow_gate_hmac_key_file <file>
    pub clearance_ttl: time_t,    // pow_gate_clearance_ttl <time>
    pub proof_skew: time_t,       // pow_gate_proof_skew <time>
    pub endpoint: ngx_str_t,      // pow_gate_endpoint <prefix>

    // ── clearance-cookie attributes (pow_gate_cookie_*) ──
    // Empty str / NGX_CONF_UNSET flag ⇒ merge applies the documented default.
    pub cookie_name: ngx_str_t,      // default: pow_clearance
    pub cookie_domain: ngx_str_t,    // default: host-only (no Domain=)
    pub cookie_path: ngx_str_t,      // default: /
    pub cookie_samesite: ngx_str_t,  // Lax|Strict|None, default: Lax
    pub cookie_secure: ngx_flag_t,   // default: on
    pub cookie_httponly: ngx_flag_t, // default: on
    // Max-Age tracks pow_gate_clearance_ttl; no separate directive.
}

// ───────────────────────── main (per-http) configuration ──────────────────────
//
// Only the global verifier registry. Everything else is inheritable LocationConf.

#[repr(C)]
pub struct MainConf {
    pub verifiers: *mut c_void, // map<name, Verifier> built by pow_gate_verifier {}
}

// Context masks reused below.
const HTTP_SERVER_LOCATION: ngx_uint_t =
    (NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF) as ngx_uint_t; // http+server+location
const SERVER_LOCATION: ngx_uint_t = (NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF) as ngx_uint_t; // server+location

// ───────────────────────────── command table ─────────────────────────────────

#[no_mangle]
pub static mut NGX_HTTP_POW_GATE_COMMANDS: [ngx_command_t; 17] = [
    // pow_gate on|off;
    ngx_command_t {
        name: ngx_string!("pow_gate"),
        type_: HTTP_SERVER_LOCATION | NGX_CONF_FLAG as ngx_uint_t,
        set: Some(ngx_conf_set_flag_slot),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: offset_of!(LocationConf, enabled),
        post: ptr::null_mut(),
    },
    // pow_gate_trusted $var;   (server + location)
    ngx_command_t {
        name: ngx_string!("pow_gate_trusted"),
        type_: SERVER_LOCATION | NGX_CONF_TAKE1 as ngx_uint_t,
        set: Some(ngx_http_set_complex_value_slot),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: offset_of!(LocationConf, trusted),
        post: ptr::null_mut(),
    },
    // pow_gate_decision $var;  allow|deny|challenge|verify:<name>   (server + location)
    ngx_command_t {
        name: ngx_string!("pow_gate_decision"),
        type_: SERVER_LOCATION | NGX_CONF_TAKE1 as ngx_uint_t,
        set: Some(ngx_http_set_complex_value_slot),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: offset_of!(LocationConf, decision),
        post: ptr::null_mut(),
    },
    // pow_gate_page <file>;
    ngx_command_t {
        name: ngx_string!("pow_gate_page"),
        type_: HTTP_SERVER_LOCATION | NGX_CONF_TAKE1 as ngx_uint_t,
        set: Some(ngx_conf_set_str_slot),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: offset_of!(LocationConf, page_path),
        post: ptr::null_mut(),
    },
    // (no pow_gate_solver: the solver is always served by the module from the
    //  embedded SOLVER_JS — it is the client half of the protocol, not config.)
    // pow_gate_difficulty N;
    ngx_command_t {
        name: ngx_string!("pow_gate_difficulty"),
        type_: HTTP_SERVER_LOCATION | NGX_CONF_TAKE1 as ngx_uint_t,
        set: Some(ngx_conf_set_num_slot),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: offset_of!(LocationConf, difficulty),
        post: ptr::null_mut(),
    },
    // pow_gate_hmac_key_file <file>;
    ngx_command_t {
        name: ngx_string!("pow_gate_hmac_key_file"),
        type_: HTTP_SERVER_LOCATION | NGX_CONF_TAKE1 as ngx_uint_t,
        set: Some(ngx_conf_set_str_slot),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: offset_of!(LocationConf, hmac_key_file),
        post: ptr::null_mut(),
    },
    // pow_gate_clearance_ttl <time>;
    ngx_command_t {
        name: ngx_string!("pow_gate_clearance_ttl"),
        type_: HTTP_SERVER_LOCATION | NGX_CONF_TAKE1 as ngx_uint_t,
        set: Some(ngx_conf_set_sec_slot),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: offset_of!(LocationConf, clearance_ttl),
        post: ptr::null_mut(),
    },
    // pow_gate_proof_skew <time>;
    ngx_command_t {
        name: ngx_string!("pow_gate_proof_skew"),
        type_: HTTP_SERVER_LOCATION | NGX_CONF_TAKE1 as ngx_uint_t,
        set: Some(ngx_conf_set_sec_slot),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: offset_of!(LocationConf, proof_skew),
        post: ptr::null_mut(),
    },
    // pow_gate_endpoint <prefix>;
    ngx_command_t {
        name: ngx_string!("pow_gate_endpoint"),
        type_: HTTP_SERVER_LOCATION | NGX_CONF_TAKE1 as ngx_uint_t,
        set: Some(ngx_conf_set_str_slot),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: offset_of!(LocationConf, endpoint),
        post: ptr::null_mut(),
    },
    // ── clearance-cookie attributes ──
    // pow_gate_cookie_name <name>;
    ngx_command_t {
        name: ngx_string!("pow_gate_cookie_name"),
        type_: HTTP_SERVER_LOCATION | NGX_CONF_TAKE1 as ngx_uint_t,
        set: Some(ngx_conf_set_str_slot),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: offset_of!(LocationConf, cookie_name),
        post: ptr::null_mut(),
    },
    // pow_gate_cookie_domain <domain>;
    ngx_command_t {
        name: ngx_string!("pow_gate_cookie_domain"),
        type_: HTTP_SERVER_LOCATION | NGX_CONF_TAKE1 as ngx_uint_t,
        set: Some(ngx_conf_set_str_slot),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: offset_of!(LocationConf, cookie_domain),
        post: ptr::null_mut(),
    },
    // pow_gate_cookie_path <path>;
    ngx_command_t {
        name: ngx_string!("pow_gate_cookie_path"),
        type_: HTTP_SERVER_LOCATION | NGX_CONF_TAKE1 as ngx_uint_t,
        set: Some(ngx_conf_set_str_slot),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: offset_of!(LocationConf, cookie_path),
        post: ptr::null_mut(),
    },
    // pow_gate_cookie_samesite Lax|Strict|None;
    ngx_command_t {
        name: ngx_string!("pow_gate_cookie_samesite"),
        type_: HTTP_SERVER_LOCATION | NGX_CONF_TAKE1 as ngx_uint_t,
        set: Some(ngx_conf_set_str_slot),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: offset_of!(LocationConf, cookie_samesite),
        post: ptr::null_mut(),
    },
    // pow_gate_cookie_secure on|off;
    ngx_command_t {
        name: ngx_string!("pow_gate_cookie_secure"),
        type_: HTTP_SERVER_LOCATION | NGX_CONF_FLAG as ngx_uint_t,
        set: Some(ngx_conf_set_flag_slot),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: offset_of!(LocationConf, cookie_secure),
        post: ptr::null_mut(),
    },
    // pow_gate_cookie_httponly on|off;
    ngx_command_t {
        name: ngx_string!("pow_gate_cookie_httponly"),
        type_: HTTP_SERVER_LOCATION | NGX_CONF_FLAG as ngx_uint_t,
        set: Some(ngx_conf_set_flag_slot),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: offset_of!(LocationConf, cookie_httponly),
        post: ptr::null_mut(),
    },
    // pow_gate_verifier <name> { ... };   global registry — http only (block).
    ngx_command_t {
        name: ngx_string!("pow_gate_verifier"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(pow_gate_verifier_block),
        conf: NGX_HTTP_MAIN_CONF_OFFSET,
        offset: 0,
        post: ptr::null_mut(),
    },
    // ngx_null_command terminator — nginx scans until it hits a zeroed entry.
    ngx_command_t {
        name: ngx_str_t { len: 0, data: ptr::null_mut() },
        type_: 0,
        set: None,
        conf: 0,
        offset: 0,
        post: ptr::null_mut(),
    },
];

// ───────────────────────── create / merge main conf ──────────────────────────

pub extern "C" fn create_main_conf(cf: *mut ngx_conf_t) -> *mut c_void {
    unsafe {
        let p = ngx_pcalloc((*cf).pool, std::mem::size_of::<MainConf>()) as *mut MainConf;
        // pcalloc zeroes; the verifier map is built lazily by the block parser.
        p as *mut c_void
    }
}

// ───────────────────────── create / merge location conf ───────────────────────────

pub extern "C" fn create_location_conf(cf: *mut ngx_conf_t) -> *mut c_void {
    unsafe {
        let p = ngx_pcalloc((*cf).pool, std::mem::size_of::<LocationConf>()) as *mut LocationConf;
        if p.is_null() {
            return ptr::null_mut();
        }
        // pcalloc zeroes; mark numeric/time/flag fields "unset" so merge can tell
        // "set here" from "inherit". (Built-in slot setters also reject a second
        // write only when the field is non-UNSET, so flags MUST start UNSET.)
        (*p).enabled = NGX_CONF_UNSET as ngx_flag_t;
        (*p).trusted = ptr::null_mut(); // NGX_CONF_UNSET_PTR conceptually
        (*p).decision = ptr::null_mut();
        (*p).difficulty = UNSET_UINT;
        (*p).clearance_ttl = NGX_CONF_UNSET as time_t;
        (*p).proof_skew = NGX_CONF_UNSET as time_t;
        (*p).cookie_secure = NGX_CONF_UNSET as ngx_flag_t;
        (*p).cookie_httponly = NGX_CONF_UNSET as ngx_flag_t;
        // str fields (page_path, hmac_key_file, endpoint, cookie_*) stay zeroed;
        // merge substitutes the canonical default string when inherited len == 0.
        p as *mut c_void
    }
}

pub extern "C" fn merge_location_conf(
    _cf: *mut ngx_conf_t,
    parent: *mut c_void,
    child: *mut c_void,
) -> *mut c_char {
    unsafe {
        let prev = &mut *(parent as *mut LocationConf);
        let conf = &mut *(child as *mut LocationConf);

        // Standard nginx inheritance: set-here beats inherited; final arg is the
        // root default. This is what lets you set any knob at http and override it
        // per server or per location — and what makes `pow_gate off;` win locally.
        merge_flag(&mut conf.enabled, prev.enabled, 0 /* default off */);
        merge_ptr(&mut conf.trusted, prev.trusted);
        merge_ptr(&mut conf.decision, prev.decision);
        merge_str(&mut conf.page_path, &prev.page_path, b"");

        merge_uint(&mut conf.difficulty, prev.difficulty, 50000);
        merge_str(&mut conf.hmac_key_file, &prev.hmac_key_file, b"");
        merge_sec(&mut conf.clearance_ttl, prev.clearance_ttl, 43200 /* 12h */);
        merge_sec(&mut conf.proof_skew, prev.proof_skew, 5);
        merge_str(&mut conf.endpoint, &prev.endpoint, b"/.pow/");

        merge_str(&mut conf.cookie_name, &prev.cookie_name, b"pow_clearance");
        merge_str(&mut conf.cookie_domain, &prev.cookie_domain, b"");
        merge_str(&mut conf.cookie_path, &prev.cookie_path, b"/");
        merge_str(&mut conf.cookie_samesite, &prev.cookie_samesite, b"Lax");
        merge_flag(&mut conf.cookie_secure, prev.cookie_secure, 1 /* on */);
        merge_flag(&mut conf.cookie_httponly, prev.cookie_httponly, 1 /* on */);

        // Load + cache the page once (falls back to the embedded default when the
        // path is empty). The solver is always the embedded SOLVER_JS, not config.
        if conf.enabled != 0 {
            conf.page_cache = load_page(conf.page_path);
        }
        NGX_CONF_OK
    }
}
