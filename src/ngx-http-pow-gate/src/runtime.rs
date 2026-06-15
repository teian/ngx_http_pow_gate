//! Request-time glue between nginx and the engine core: read the merged
//! `LocationConf`, resolve it to owned values, load the HMAC key (cached), and
//! pull cookies / headers / the request body off the request. The nginx *input*
//! side of the FFI seam (the output side is `response.rs`).

use ngx::ffi::ngx_http_request_t;
use ngx::http::Request;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::LocationConf;
use crate::response::as_str;

/// Resolved per-request configuration (owned, so it survives across the async
/// body callback without borrowing nginx memory).
pub struct Cfg {
    pub key: Arc<Vec<u8>>,
    pub difficulty: u64,
    pub clearance_ttl: i64,
    pub proof_skew: i64,
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

/// Resolve a `LocationConf` into owned [`Cfg`]. Loads (and caches) the HMAC key.
pub fn resolve(lc: &LocationConf) -> Cfg {
    unsafe {
        let key_path = as_str(&lc.hmac_key_file);
        Cfg {
            key: load_key(key_path),
            difficulty: lc.difficulty as u64,
            clearance_ttl: lc.clearance_ttl as i64,
            proof_skew: lc.proof_skew as i64,
            endpoint: as_str(&lc.endpoint).to_string(),
            cookie: CookieConfig {
                name: nonempty(as_str(&lc.cookie_name), "pow_clearance"),
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
    let bytes = std::fs::read(path).unwrap_or_default();
    let arc = Arc::new(bytes);
    g.insert(path.to_string(), arc.clone());
    arc
}

// ───────────────────────────── header / body reads ───────────────────────────

/// Value of the cookie named `name` from the request's `Cookie` header(s).
pub fn cookie(r: &Request, name: &str) -> Option<String> {
    for (k, v) in r.headers_in_iterator() {
        if k.as_bytes().eq_ignore_ascii_case(b"cookie") {
            let val = String::from_utf8_lossy(v.as_bytes());
            for pair in val.split(';') {
                let pair = pair.trim();
                if let Some((cn, cv)) = pair.split_once('=') {
                    if cn == name {
                        return Some(cv.to_string());
                    }
                }
            }
        }
    }
    None
}

/// Value of a request header (case-insensitive name).
pub fn header(r: &Request, name: &str) -> Option<String> {
    for (k, v) in r.headers_in_iterator() {
        if k.as_bytes().eq_ignore_ascii_case(name.as_bytes()) {
            return Some(String::from_utf8_lossy(v.as_bytes()).into_owned());
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
///
/// # Safety
/// `r` must be live.
pub unsafe fn method_and_path(r: *mut ngx_http_request_t) -> (String, String) {
    let method = as_str(&(*r).method_name).to_string();
    let path = as_str(&(*r).uri).to_string();
    (method, path)
}

/// Collect the client request body into a `Vec`, reconstructed in order from the
/// `rb->bufs` chain. Handles both the in-memory case and a body that nginx
/// buffered to a temp file (in-file bufs are read back off disk). Returns `None`
/// only if the body is absent or a temp-file segment can't be read.
///
/// # Safety
/// `r` must be live with its body already read.
pub unsafe fn request_body(r: *mut ngx_http_request_t) -> Option<Vec<u8>> {
    let rb = (*r).request_body;
    if rb.is_null() {
        return None;
    }
    let mut out = Vec::new();
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
                    out.resize(base + (end - start) as usize, 0);
                    if !read_file_range((*file).fd, &mut out[base..], start) {
                        return None; // unreadable temp file -> treat as bad request
                    }
                }
            } else if !(*b).pos.is_null() {
                let len = (*b).last.offset_from((*b).pos);
                if len > 0 {
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
