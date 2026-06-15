//! `pow_gate_verifier <name> { ... }` — verified good-bot allowlist.
//!
//! Confirms that a client claiming to be a known bot (`verify:<name>`) really
//! connects from that bot's network, via two independent checks:
//!
//!   * **IP ranges** — fetch the operators' official CIDR JSON feeds
//!     (`ip_ranges_url`), refreshed on a timer (`ip_ranges_refresh`). Membership
//!     is an O(ranges) test on a lock-free [`ArcSwap`] snapshot — the hot path
//!     never blocks. Parsing lives in [`pow_gate_core::ranges`] (unit-tested).
//!   * **FCrDNS** — Forward-Confirmed reverse DNS: PTR(ip) ends in an
//!     `fcrdns_suffix` *and* that host resolves back to the same ip. DNS is done
//!     on a background thread; verdicts are cached (`fcrdns_ttl`) so the hot path
//!     only reads the cache.
//!
//! The registry is built at config time (`pow_gate_verifier_block`); the
//! refresher threads start per worker in [`start_refreshers`] (threads don't
//! survive nginx's fork).

use arc_swap::ArcSwap;
use core::ffi::c_void;
use ngx::core::{NGX_CONF_ERROR, NGX_CONF_OK};
use ngx::ffi::{ngx_command_t, ngx_conf_parse, ngx_conf_t, ngx_str_t};
use pow_gate_core::ranges::IpRangeSet;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::raw::c_char;
use std::ptr;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

/// One configured verifier.
pub struct Verifier {
    pub name: String,
    pub ranges: ArcSwap<IpRangeSet>,
    pub urls: Vec<String>,
    pub refresh: Duration,
    pub fcrdns_suffixes: Vec<String>,
    pub fcrdns_ttl: Duration,
    verdicts: Mutex<HashMap<IpAddr, (bool, Instant)>>,
}

fn registry() -> &'static RwLock<HashMap<String, Arc<Verifier>>> {
    static R: OnceLock<RwLock<HashMap<String, Arc<Verifier>>>> = OnceLock::new();
    R.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Does verifier `name` confirm `ip`? Hot path: lock-free range check, then a
/// cached FCrDNS verdict. Never blocks (DNS happens in the background).
pub fn verifier_allows(name: &str, ip: IpAddr) -> bool {
    let v = match registry().read().ok().and_then(|r| r.get(name).cloned()) {
        Some(v) => v,
        None => return false,
    };
    if v.ranges.load().contains(ip) {
        return true;
    }
    if !v.fcrdns_suffixes.is_empty() {
        return fcrdns_cached(&v, ip);
    }
    false
}

/// Start the per-worker background refreshers — call once from `init_process`.
pub fn start_refreshers() {
    if let Ok(reg) = registry().read() {
        for v in reg.values() {
            spawn_refresher(v.clone());
        }
    }
}

fn spawn_refresher(v: Arc<Verifier>) {
    if v.urls.is_empty() {
        return;
    }
    std::thread::spawn(move || loop {
        let mut set = IpRangeSet::new();
        for url in &v.urls {
            if let Ok(resp) = ureq::get(url).call() {
                let mut buf = Vec::new();
                if resp.into_reader().take(8 << 20).read_to_end(&mut buf).is_ok() {
                    set.add_feed_json(&buf);
                }
            }
        }
        if !set.is_empty() {
            v.ranges.store(Arc::new(set));
        }
        std::thread::sleep(v.refresh);
    });
}

// ─────────────────────────────── FCrDNS ──────────────────────────────────────

fn fcrdns_cached(v: &Arc<Verifier>, ip: IpAddr) -> bool {
    let now = Instant::now();
    if let Ok(cache) = v.verdicts.lock() {
        if let Some((verdict, t)) = cache.get(&ip) {
            if now.duration_since(*t) < v.fcrdns_ttl {
                return *verdict;
            }
        }
    }
    // Miss/stale: mark pending and resolve in the background; fail closed for now
    // (the client just gets a normal challenge this once).
    if let Ok(mut cache) = v.verdicts.lock() {
        cache.insert(ip, (false, now));
    }
    let v = v.clone();
    std::thread::spawn(move || {
        let ok = fcrdns_confirm(ip, &v.fcrdns_suffixes);
        if let Ok(mut cache) = v.verdicts.lock() {
            cache.insert(ip, (ok, Instant::now()));
        }
    });
    false
}

/// PTR(ip) ends in a suffix AND forward-resolves back to ip.
fn fcrdns_confirm(ip: IpAddr, suffixes: &[String]) -> bool {
    let host = match reverse_dns(ip) {
        Some(h) => h.to_lowercase(),
        None => return false,
    };
    let suffix_ok = suffixes.iter().any(|s| host.ends_with(&s.to_lowercase()));
    if !suffix_ok {
        return false;
    }
    forward_dns(&host).iter().any(|a| *a == ip)
}

unsafe fn ip_to_sockaddr(ip: IpAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut ss: libc::sockaddr_storage = std::mem::zeroed();
    match ip {
        IpAddr::V4(a) => {
            let sin = &mut *(&mut ss as *mut _ as *mut libc::sockaddr_in);
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_addr.s_addr = u32::from(a).to_be();
            (ss, std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t)
        }
        IpAddr::V6(a) => {
            let sin6 = &mut *(&mut ss as *mut _ as *mut libc::sockaddr_in6);
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_addr.s6_addr = a.octets();
            (ss, std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t)
        }
    }
}

unsafe fn sockaddr_to_ip(sa: *const libc::sockaddr) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    match (*sa).sa_family as i32 {
        libc::AF_INET => {
            let s = sa as *const libc::sockaddr_in;
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be((*s).sin_addr.s_addr))))
        }
        libc::AF_INET6 => {
            let s = sa as *const libc::sockaddr_in6;
            Some(IpAddr::V6(Ipv6Addr::from((*s).sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

fn reverse_dns(ip: IpAddr) -> Option<String> {
    unsafe {
        let (ss, len) = ip_to_sockaddr(ip);
        let mut host = [0 as c_char; 1025];
        let rc = libc::getnameinfo(
            &ss as *const _ as *const libc::sockaddr,
            len,
            host.as_mut_ptr(),
            host.len() as libc::socklen_t,
            ptr::null_mut(),
            0,
            libc::NI_NAMEREQD,
        );
        if rc != 0 {
            return None;
        }
        Some(CStr::from_ptr(host.as_ptr()).to_string_lossy().into_owned())
    }
}

fn forward_dns(host: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    let c_host = match CString::new(host) {
        Ok(h) => h,
        Err(_) => return out,
    };
    unsafe {
        let mut hints: libc::addrinfo = std::mem::zeroed();
        hints.ai_family = libc::AF_UNSPEC;
        hints.ai_socktype = libc::SOCK_STREAM;
        let mut res: *mut libc::addrinfo = ptr::null_mut();
        if libc::getaddrinfo(c_host.as_ptr(), ptr::null(), &hints, &mut res) != 0 {
            return out;
        }
        let mut cur = res;
        while !cur.is_null() {
            if let Some(ip) = sockaddr_to_ip((*cur).ai_addr) {
                out.push(ip);
            }
            cur = (*cur).ai_next;
        }
        libc::freeaddrinfo(res);
    }
    out
}

// ───────────────────────── block-directive parser ────────────────────────────

/// Builder accumulated across the inner directives during block parsing.
struct Builder {
    name: String,
    urls: Vec<String>,
    refresh: Duration,
    suffixes: Vec<String>,
    fcrdns_ttl: Duration,
}

/// `pow_gate_verifier <name> { … }` — parse the block body and register a
/// [`Verifier`]. Refreshers are started later, per worker, in `init_process`.
pub extern "C" fn pow_gate_verifier_block(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    _conf: *mut c_void,
) -> *mut c_char {
    unsafe {
        let name = match arg(cf, 1) {
            Some(n) => n,
            None => return NGX_CONF_ERROR,
        };
        let builder = Box::into_raw(Box::new(Builder {
            name,
            urls: Vec::new(),
            refresh: Duration::from_secs(12 * 3600),
            suffixes: Vec::new(),
            fcrdns_ttl: Duration::from_secs(3600),
        }));

        // Parse the { } body: nginx calls `verifier_inner` for each inner line.
        let save = *cf;
        (*cf).handler = Some(verifier_inner);
        (*cf).handler_conf = builder as *mut c_void;
        let rv = ngx_conf_parse(cf, ptr::null_mut());
        *cf = save;

        let b = Box::from_raw(builder);
        if !rv.is_null() && rv != NGX_CONF_OK {
            return rv;
        }
        register(*b);
        NGX_CONF_OK
    }
}

extern "C" fn verifier_inner(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    _conf: *mut c_void,
) -> *mut c_char {
    unsafe {
        let b = (*cf).handler_conf as *mut Builder;
        if b.is_null() {
            return NGX_CONF_ERROR;
        }
        let directive = match arg(cf, 0) {
            Some(d) => d,
            None => return NGX_CONF_OK,
        };
        match directive.as_str() {
            "ip_ranges_url" => {
                if let Some(u) = arg(cf, 1) {
                    (*b).urls.push(u);
                }
            }
            "ip_ranges_refresh" => {
                if let Some(t) = arg(cf, 1) {
                    (*b).refresh = parse_time(&t);
                }
            }
            "fcrdns_suffix" => {
                let mut i = 1;
                while let Some(s) = arg(cf, i) {
                    (*b).suffixes.push(s);
                    i += 1;
                }
            }
            "fcrdns_ttl" => {
                if let Some(t) = arg(cf, 1) {
                    (*b).fcrdns_ttl = parse_time(&t);
                }
            }
            _ => return NGX_CONF_ERROR, // unknown directive inside the block
        }
        NGX_CONF_OK
    }
}

fn register(b: Builder) {
    let v = Arc::new(Verifier {
        name: b.name.clone(),
        ranges: ArcSwap::from_pointee(IpRangeSet::new()),
        urls: b.urls,
        refresh: b.refresh,
        fcrdns_suffixes: b.suffixes,
        fcrdns_ttl: b.fcrdns_ttl,
        verdicts: Mutex::new(HashMap::new()),
    });
    if let Ok(mut reg) = registry().write() {
        reg.insert(b.name, v);
    }
}

/// Read `cf->args->elts[i]` as an owned `String`.
unsafe fn arg(cf: *mut ngx_conf_t, i: usize) -> Option<String> {
    let args = (*cf).args;
    if args.is_null() || i >= (*args).nelts {
        return None;
    }
    let elts = (*args).elts as *const ngx_str_t;
    let s = &*elts.add(i);
    if s.len == 0 || s.data.is_null() {
        return Some(String::new());
    }
    Some(String::from_utf8_lossy(std::slice::from_raw_parts(s.data, s.len)).into_owned())
}

/// Parse `12h` / `30m` / `90s` / `1d` / plain seconds into a `Duration`.
fn parse_time(s: &str) -> Duration {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1u64),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        Some('d') => (&s[..s.len() - 1], 86400),
        _ => (s, 1),
    };
    let n: u64 = num.trim().parse().unwrap_or(0);
    Duration::from_secs(n * mult)
}
