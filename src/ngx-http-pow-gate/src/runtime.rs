//! Request-time glue between nginx and the engine core: read the merged
//! `LocationConf`, reuse its worker-local resolved values and HMAC key, and
//! pull cookies / headers / the request body off the request. The nginx *input*
//! side of the FFI seam (the output side is `response.rs`).

use ngx::ffi::ngx_http_request_t;
use ngx::http::Request;
use std::borrow::Cow;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::LocationConf;
use crate::response::as_str;

/// Minimum accepted HMAC key length, in bytes. A shorter (or empty/unreadable)
/// key is rejected at config time and fails closed at runtime — it is never used
/// to HMAC, because a known/empty key makes every clearance and challenge token
/// forgeable. The docs recommend 32+ random bytes.
pub const MIN_HMAC_KEY_LEN: usize = 16;

/// Resolved configuration owned by the location and reused within each worker.
pub struct Cfg {
    pub authenticator: pow_gate_core::HmacKey,
    scope: pow_gate_core::context::Scope,
    pub key: Arc<Vec<u8>>,
    /// `true` iff the HMAC key loaded for this location is usable (present,
    /// readable, and `>= MIN_HMAC_KEY_LEN`). When `false` the gate fails closed:
    /// no clearance is trusted and the engine endpoints refuse to issue/verify,
    /// rather than HMAC-ing with an empty/weak key.
    pub key_ok: bool,
    pub difficulty: u64,
    pub address: pow_gate_core::context::AddressPolicy,
    pub clearance_ttl: i64,
    pub proof_skew: i64,
    /// Require a valid per-request proof on non-navigation requests (cookie alone
    /// is accepted only for top-level navigations, which cannot send a header).
    pub require_proof: bool,
    /// Capture a challenged non-GET body into the challenge page so the solver
    /// can re-issue the request after clearance (`pow_gate_replay`).
    pub replay: bool,
    /// Largest body captured for that replay; anything above is not read at all
    /// (`pow_gate_replay_max_body`).
    pub replay_max_body: usize,
    pub endpoint: String,
    pub cookie: CookieConfig,
}

/// Owned clearance-cookie attributes (from the `pow_gate_cookie_*` directives).
pub struct CookieConfig {
    pub name: String,
    pub domain: Option<String>,
    pub path: String,
    pub samesite: String,
    pub secure: bool,
    pub http_only: bool,
    pub max_age_secs: i64,
}

/// Unix seconds.
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The matched location's merged `LocationConf`, read from
/// `r->loc_conf[module.ctx_index]`.
///
/// # Safety
/// `r` must be a live request pointer.
pub unsafe fn location_conf<'a>(r: *mut ngx_http_request_t) -> Option<&'a LocationConf> {
    let module = &*ptr::addr_of!(crate::ngx_http_pow_gate_module);
    let p = *(*r).loc_conf.add(module.ctx_index) as *const LocationConf;
    if p.is_null() {
        None
    } else {
        Some(&*p)
    }
}

/// Lazily resolve once per location/worker. The config pool owns the cache;
/// request and async body callbacks cannot outlive their nginx config cycle.
pub fn resolve(lc: &LocationConf) -> &Cfg {
    unsafe { &*lc.resolved }.get_or_init(|| Box::new(build_cfg(lc)))
}

fn build_cfg(lc: &LocationConf) -> Cfg {
    unsafe {
        let key_path = as_str(&lc.hmac_key_file);
        let key = load_key(key_path);
        let key_ok = key.len() >= MIN_HMAC_KEY_LEN;
        let domain = as_str(&lc.cookie_domain);
        let scope = pow_gate_core::context::Scope::new(
            (!domain.is_empty()).then_some(domain),
            &nonempty(as_str(&lc.cookie_effective_name), "pow_clearance"),
            &nonempty(as_str(&lc.cookie_path), "/"),
            as_str(&lc.endpoint),
            as_str(&lc.policy),
        );
        Cfg {
            authenticator: pow_gate_core::HmacKey::new(&key),
            scope,
            key,
            key_ok,
            difficulty: lc.difficulty as u64,
            address: pow_gate_core::context::AddressPolicy {
                ipv4_prefix: lc.ipv4_prefix as u8,
                ipv6_prefix: lc.ipv6_prefix as u8,
            },
            clearance_ttl: lc.clearance_ttl as i64,
            proof_skew: lc.proof_skew as i64,
            require_proof: lc.require_proof != 0,
            replay: lc.replay != 0,
            replay_max_body: lc.replay_max_body,
            endpoint: as_str(&lc.endpoint).to_string(),
            cookie: CookieConfig {
                name: nonempty(as_str(&lc.cookie_effective_name), "pow_clearance"),
                domain: {
                    let d = as_str(&lc.cookie_domain);
                    if d.is_empty() {
                        None
                    } else {
                        Some(d.to_string())
                    }
                },
                path: nonempty(as_str(&lc.cookie_path), "/"),
                samesite: nonempty(as_str(&lc.cookie_samesite), "Lax"),
                secure: lc.cookie_secure != 0,
                http_only: lc.cookie_httponly != 0,
                max_age_secs: lc.clearance_ttl as i64,
            },
        }
    }
}

fn nonempty(s: &str, default: &str) -> String {
    if s.is_empty() {
        default.to_string()
    } else {
        s.to_string()
    }
}

/// Process-wide HMAC-key cache, keyed by file path (the directive inherits, so
/// usually one entry). Loaded once per worker, on first use.
fn load_key(path: &str) -> Arc<Vec<u8>> {
    static KEYS: OnceLock<Mutex<HashMap<String, Arc<Vec<u8>>>>> = OnceLock::new();
    let cache = KEYS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut g = cache.lock().unwrap();
    if let Some(k) = g.get(path) {
        return k.clone();
    }
    // Do NOT silently fall back to an empty key: an empty/known key makes every
    // token forgeable. On any failure we log and cache an empty Vec, which the
    // callers treat as "key not usable" and fail closed (see `Cfg::key_ok`).
    let bytes = match std::fs::read(path) {
        Ok(b) if b.len() >= MIN_HMAC_KEY_LEN => b,
        Ok(b) => {
            eprintln!(
                "[pow_gate] hmac key file {:?} is {} bytes (< {} required) — gate failing closed",
                path,
                b.len(),
                MIN_HMAC_KEY_LEN
            );
            Vec::new()
        }
        Err(e) => {
            eprintln!("[pow_gate] cannot read hmac key file {path:?}: {e} — gate failing closed");
            Vec::new()
        }
    };
    let arc = Arc::new(bytes);
    g.insert(path.to_string(), arc.clone());
    arc
}

// ───────────────────────────── header / body reads ───────────────────────────

/// Value of the cookie named `name` from the request's `Cookie` header(s).
pub fn cookie<'a>(r: &'a Request, name: &str) -> Option<Cow<'a, str>> {
    for (k, v) in r.headers_in_iterator() {
        if k.as_bytes().eq_ignore_ascii_case(b"cookie") {
            match String::from_utf8_lossy(v.as_bytes()) {
                Cow::Borrowed(value) => {
                    if let Some(value) = cookie_value(value, name) {
                        return Some(Cow::Borrowed(value));
                    }
                    continue;
                }
                Cow::Owned(value) => {
                    if let Some(value) = cookie_value(&value, name) {
                        return Some(Cow::Owned(value.to_owned()));
                    }
                    continue;
                }
            }
        }
    }
    None
}

fn cookie_value<'a>(value: &'a str, name: &str) -> Option<&'a str> {
    value
        .split(';')
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value)
}

/// Value of a request header (case-insensitive name).
pub fn header<'a>(r: &'a Request, name: &str) -> Option<Cow<'a, str>> {
    for (k, v) in r.headers_in_iterator() {
        if k.as_bytes().eq_ignore_ascii_case(name.as_bytes()) {
            return Some(String::from_utf8_lossy(v.as_bytes()));
        }
    }
    None
}

/// Read a small protocol header without first cloning an arbitrary-sized value.
pub fn header_limited(r: &Request, name: &str, limit: usize) -> Option<String> {
    for (key, value) in r.headers_in_iterator() {
        if key.as_bytes().eq_ignore_ascii_case(name.as_bytes()) {
            if value.as_bytes().len() > limit {
                return None;
            }
            return std::str::from_utf8(value.as_bytes())
                .ok()
                .map(str::to_owned);
        }
    }
    None
}

/// The connecting client's IP from `connection->sockaddr`. Honours `realip`
/// (which rewrites the connection address in an earlier phase). Family + address
/// are read positionally to stay independent of the exact `sockaddr` binding.
pub fn client_ip(r: &Request) -> Option<IpAddr> {
    unsafe {
        let c = r.connection();
        if c.is_null() {
            return None;
        }
        let sa = (*c).sockaddr as *const u8;
        if sa.is_null() {
            return None;
        }
        let family = u16::from_ne_bytes([*sa, *sa.add(1)]);
        match family as i32 {
            libc_af_inet => Some(IpAddr::V4(Ipv4Addr::new(
                *sa.add(4),
                *sa.add(5),
                *sa.add(6),
                *sa.add(7),
            ))),
            libc_af_inet6 => {
                let mut o = [0u8; 16];
                for (i, b) in o.iter_mut().enumerate() {
                    *b = *sa.add(8 + i);
                }
                Some(IpAddr::V6(Ipv6Addr::from(o)))
            }
            _ => None,
        }
    }
}

// AF_INET / AF_INET6 on Linux (the only platform nginx modules target here).
#[allow(non_upper_case_globals)]
const libc_af_inet: i32 = 2;
#[allow(non_upper_case_globals)]
const libc_af_inet6: i32 = 10;

/// The request method (e.g. `"GET"`) and path (URI), for the proof message.
pub fn method_and_path(r: &Request) -> (&str, &str) {
    let raw = r as *const Request as *const ngx_http_request_t;
    unsafe { (as_str(&(*raw).method_name), as_str(&(*raw).uri)) }
}

/// The declared request-body length, or `None` when there is none or nginx does
/// not know it yet (`Transfer-Encoding: chunked` → `content_length_n == -1`).
///
/// # Safety
/// `r` must be live.
pub unsafe fn content_length(r: *mut ngx_http_request_t) -> Option<usize> {
    match (*r).headers_in.content_length_n {
        n if n > 0 => Some(n as usize),
        _ => None,
    }
}

/// Collect the client request body into a `Vec`, reconstructed in order from the
/// `rb->bufs` chain. Handles both the in-memory case and a body that nginx
/// buffered to a temp file (in-file bufs are read back off disk). Returns `None`
/// only if the body is absent or a temp-file segment can't be read.
///
/// # Safety
/// `r` must be live with its body already read.
pub unsafe fn request_body(r: *mut ngx_http_request_t) -> Option<Vec<u8>> {
    request_body_limited(r, usize::MAX)
}

/// Collect at most `limit` bytes, including temp-file-backed segments. Used by
/// verification so large/chunked JSON cannot grow a worker's parsing buffer.
pub unsafe fn request_body_limited(r: *mut ngx_http_request_t, limit: usize) -> Option<Vec<u8>> {
    let rb = (*r).request_body;
    if rb.is_null() {
        return None;
    }
    let mut out = Vec::with_capacity(if limit == usize::MAX {
        0
    } else {
        limit.min(8192)
    });
    let mut cl = (*rb).bufs;
    while !cl.is_null() {
        let b = (*cl).buf;
        if !b.is_null() {
            if (*b).in_file() != 0 {
                // This segment spilled to the temp file: read its
                // [file_pos, file_last) byte range back from disk.
                let file = (*b).file;
                let (start, end) = ((*b).file_pos, (*b).file_last);
                if !file.is_null() && end > start {
                    let base = out.len();
                    let length = usize::try_from(end - start).ok()?;
                    if length > limit.saturating_sub(base) {
                        return None;
                    }
                    out.resize(base + length, 0);
                    if !read_file_range((*file).fd, &mut out[base..], start) {
                        return None; // unreadable temp file -> treat as bad request
                    }
                }
            } else if !(*b).pos.is_null() {
                let len = (*b).last.offset_from((*b).pos);
                if len > 0 {
                    if len as usize > limit.saturating_sub(out.len()) {
                        return None;
                    }
                    out.extend_from_slice(std::slice::from_raw_parts((*b).pos, len as usize));
                }
            }
        }
        cl = (*cl).next;
    }
    Some(out)
}

/// Fill `buf` with exactly `buf.len()` bytes read from `fd` starting at `offset`.
/// Uses positional reads so the file's own cursor is left untouched (the body fd
/// is shared with nginx). Returns `false` on EOF-short-read or error.
unsafe fn read_file_range(fd: libc::c_int, buf: &mut [u8], offset: i64) -> bool {
    let mut filled = 0usize;
    while filled < buf.len() {
        let n = libc::pread(
            fd,
            buf[filled..].as_mut_ptr() as *mut libc::c_void,
            buf.len() - filled,
            offset + filled as i64,
        );
        if n <= 0 {
            return false; // 0 = unexpected EOF, <0 = error
        }
        filled += n as usize;
    }
    true
}

/// Build a `Set-Cookie` header value from owned cookie config + a token value.
/// `SameSite=None` forces `Secure` (browsers drop it otherwise).
pub fn build_set_cookie(value: &str, c: &CookieConfig) -> String {
    let mut s = format!("{}={}", c.name, value);
    s.push_str(&format!("; Path={}", c.path));
    if let Some(d) = &c.domain {
        s.push_str(&format!("; Domain={d}"));
    }
    s.push_str(&format!("; Max-Age={}", c.max_age_secs));
    s.push_str(&format!("; SameSite={}", c.samesite));
    if c.secure || c.samesite.eq_ignore_ascii_case("None") {
        s.push_str("; Secure");
    }
    if c.http_only {
        s.push_str("; HttpOnly");
    }
    s
}

/// Opaque binding of client address, UA, policy scope and replay-store identity.
/// No client-supplied forwarding header is trusted; realip must be configured on
/// nginx when it sits behind a trusted load balancer.
pub fn client_context(r: &Request, cfg: &Cfg) -> Option<String> {
    let issuer = crate::redemption::issuer()?;
    let ip = client_ip(r)?;
    let raw = r as *const Request as *mut ngx_http_request_t;
    let scope = cfg
        .scope
        .for_host(unsafe { as_str(&(*raw).headers_in.server) })?;
    pow_gate_core::context::binding_prepared(
        &cfg.authenticator,
        ip,
        &header(r, "user-agent").unwrap_or_default(),
        &scope,
        &issuer,
        cfg.address,
    )
}
