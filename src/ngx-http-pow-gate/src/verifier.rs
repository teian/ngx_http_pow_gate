//! `pow_gate_verifier <name> { ... }` — verified good-bot allowlist.
//!
//! Confirms that a client claiming to be a known bot (`verify:<name>`) really
//! connects from that bot's network, via two independent checks:
//!
//!   * **IP ranges** — fetch the operators' official CIDR JSON feeds
//!     (`ip_ranges_url`), refreshed on a timer (`ip_ranges_refresh`). Membership
//!     is an O(log ranges) test on a lock-free [`ArcSwap`] snapshot — the hot path
//!     never blocks. Parsing lives in [`pow_gate_core::ranges`] (unit-tested).
//!   * **FCrDNS** — Forward-Confirmed reverse DNS: PTR(ip) ends in an
//!     `fcrdns_suffix` *and* that host resolves back to the same ip. DNS is done
//!     on a background thread; verdicts are cached (`fcrdns_ttl`) so the hot path
//!     only reads the cache.
//!
//! The registry is built at config time (`pow_gate_verifier_block`); the
//! refresher threads start per worker in [`start_refreshers`] (threads don't
//! survive nginx's fork).

use crate::config::MainConf;
use arc_swap::ArcSwap;
use core::ffi::c_void;
use ngx::core::{NGX_CONF_ERROR, NGX_CONF_OK};
use ngx::ffi::{
    ngx_command_t, ngx_conf_parse, ngx_conf_t, ngx_cycle_t, ngx_http_conf_ctx_t, ngx_http_module,
    ngx_pool_cleanup_add, ngx_str_t,
};
use pow_gate_core::feeds::FeedSnapshot;
use pow_gate_core::verdict_cache::{Lookup, VerdictCache};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::raw::c_char;
use std::ptr;
use std::sync::{
    mpsc::{sync_channel, SyncSender},
    Arc, Mutex, OnceLock, RwLock,
};
use std::time::{Duration, Instant};

/// One configured verifier.
pub struct Verifier {
    pub ranges: ArcSwap<Vec<Option<FeedSnapshot>>>,
    pub max_stale: Duration,
    pub urls: Vec<String>,
    pub refresh: Duration,
    pub fcrdns_suffixes: Vec<String>,
    verdicts: Mutex<VerdictCache<IpAddr>>,
}

fn registry() -> &'static RwLock<HashMap<String, Arc<Verifier>>> {
    static R: OnceLock<RwLock<HashMap<String, Arc<Verifier>>>> = OnceLock::new();
    R.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Does verifier `name` confirm `ip`? Hot path: lock-free range check, then a
/// cached FCrDNS verdict. Never waits for DNS (resolution happens in the background).
pub fn verifier_result(name: &str, ip: IpAddr) -> (bool, &'static str) {
    let v = match registry().read().ok().and_then(|r| r.get(name).cloned()) {
        Some(v) => v,
        None => return (false, "unknown_verifier"),
    };
    let now = Instant::now();
    if v.ranges
        .load()
        .iter()
        .flatten()
        .any(|feed| feed.contains(ip, now, v.max_stale))
    {
        return (true, "verified_range");
    }
    if !v.fcrdns_suffixes.is_empty() && fcrdns_cached(&v, ip) {
        return (true, "verified_dns");
    }
    let feeds = v.ranges.load();
    let stale = feeds
        .iter()
        .flatten()
        .any(|feed| !feed.fresh(now, v.max_stale));
    (
        false,
        if stale {
            "feed_stale"
        } else {
            "verifier_unconfirmed"
        },
    )
}

/// Start the per-worker background refreshers — call once from `init_process`.
pub fn start_refreshers(cycle: *mut ngx_cycle_t) {
    // Configuration parsing never mutates the runtime registry in the master.
    // A respawn after a FAILED reload must use its still-active cycle's policy.
    let configured = unsafe {
        let ctx =
            *(*cycle).conf_ctx.add(ngx_http_module.index as usize) as *mut ngx_http_conf_ctx_t;
        if ctx.is_null() {
            return;
        }
        let main = *(*ctx)
            .main_conf
            .add(crate::ngx_http_pow_gate_module.ctx_index as usize)
            as *mut MainConf;
        if main.is_null() || (*main).verifiers.is_null() {
            HashMap::new()
        } else {
            (&*((*main).verifiers as *const HashMap<String, Arc<Verifier>>)).clone()
        }
    };
    if let Ok(mut runtime) = registry().write() {
        *runtime = configured.clone();
    }
    for verifier in configured.values() {
        spawn_refresher(verifier.clone());
    }
}

fn spawn_refresher(v: Arc<Verifier>) {
    if v.urls.is_empty() {
        return;
    }
    std::thread::spawn(move || {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(3))
            .timeout_read(Duration::from_secs(5))
            .timeout_write(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .build();
        let mut feeds = vec![None; v.urls.len()];
        loop {
            for (index, url) in v.urls.iter().enumerate() {
                let fresh = (|| {
                    let response = agent.get(url).call().ok()?;
                    let mut bytes = Vec::new();
                    response
                        .into_reader()
                        .take((8 << 20) + 1)
                        .read_to_end(&mut bytes)
                        .ok()?;
                    if bytes.len() > 8 << 20 {
                        return None;
                    }
                    FeedSnapshot::parse(&bytes, Instant::now())
                })();
                if let Some(fresh) = fresh {
                    feeds[index] = Some(fresh);
                } else {
                    eprintln!("[pow_gate] crawler feed refresh failed (source {}, retaining unexpired snapshot)", index);
                }
                // Publish after each source; one slow/failing provider cannot
                // discard another provider's previously verified snapshot.
                v.ranges.store(Arc::new(feeds.clone()));
            }
            // +/-10% jitter spreads workers/reloads without security-sensitive RNG.
            let sample = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos() as u64
                ^ std::process::id() as u64;
            std::thread::sleep(v.refresh.mul_f64(0.9 + (sample % 201) as f64 / 1000.0));
        }
    });
}

// ─────────────────────────────── FCrDNS ──────────────────────────────────────

const DNS_CACHE_ENTRIES: usize = 2048;
const DNS_QUEUE_CAPACITY: usize = 64;
const DNS_THREADS: usize = 2;
const DNS_STACK_BYTES: usize = 512 * 1024;
struct DnsJob {
    verifier: Arc<Verifier>,
    ip: IpAddr,
    generation: u64,
}

fn dns_pool() -> Option<&'static SyncSender<DnsJob>> {
    // Initialized lazily in a worker AFTER fork. Never create a thread per IP.
    static POOL: OnceLock<Option<SyncSender<DnsJob>>> = OnceLock::new();
    POOL.get_or_init(|| {
        let (sender, receiver) = sync_channel::<DnsJob>(DNS_QUEUE_CAPACITY);
        let receiver = Arc::new(Mutex::new(receiver));
        let mut workers = 0;
        for _ in 0..DNS_THREADS {
            let receiver = receiver.clone();
            if std::thread::Builder::new()
                .name("pow-fcrdns".into())
                .stack_size(DNS_STACK_BYTES)
                .spawn(move || loop {
                    let job = match receiver.lock() {
                        Ok(rx) => match rx.recv() {
                            Ok(job) => job,
                            Err(_) => return,
                        },
                        Err(_) => return,
                    };
                    // The receiver lock is released before blocking resolver IO.
                    let ok = fcrdns_confirm(job.ip, &job.verifier.fcrdns_suffixes);
                    if let Ok(mut cache) = job.verifier.verdicts.lock() {
                        cache.complete(&job.ip, job.generation, ok, Instant::now());
                    };
                })
                .is_ok()
            {
                workers += 1;
            }
        }
        if workers > 0 {
            Some(sender)
        } else {
            None
        }
    })
    .as_ref()
}

fn fcrdns_cached(v: &Arc<Verifier>, ip: IpAddr) -> bool {
    let generation = match v.verdicts.lock() {
        Ok(mut cache) => match cache.begin(ip, Instant::now()) {
            Lookup::Cached(verdict) => return verdict,
            Lookup::Full => return false,
            Lookup::Start(id) => id,
        },
        Err(_) => return false,
    };
    let queued = dns_pool().is_some_and(|pool| {
        pool.try_send(DnsJob {
            verifier: v.clone(),
            ip,
            generation,
        })
        .is_ok()
    });
    if !queued {
        if let Ok(mut cache) = v.verdicts.lock() {
            cache.cancel(&ip, generation);
        }
    }
    false
}

/// PTR(ip) ends in a suffix AND forward-resolves back to ip.
fn fcrdns_confirm(ip: IpAddr, suffixes: &[String]) -> bool {
    let host = match reverse_dns(ip) {
        Some(h) => h,
        None => return false,
    };
    pow_gate_core::ranges::fcrdns_confirms(&host, suffixes, ip, forward_dns)
}

unsafe fn ip_to_sockaddr(ip: IpAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut ss: libc::sockaddr_storage = std::mem::zeroed();
    match ip {
        IpAddr::V4(a) => {
            let sin = &mut *(&mut ss as *mut _ as *mut libc::sockaddr_in);
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_addr.s_addr = u32::from(a).to_be();
            (
                ss,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        IpAddr::V6(a) => {
            let sin6 = &mut *(&mut ss as *mut _ as *mut libc::sockaddr_in6);
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_addr.s6_addr = a.octets();
            (
                ss,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
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
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                (*s).sin_addr.s_addr,
            ))))
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
    max_stale: Duration,
}

/// `pow_gate_verifier <name> { … }` — parse the block body and register a
/// [`Verifier`]. Refreshers are started later, per worker, in `init_process`.
pub extern "C" fn pow_gate_verifier_block(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
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
            max_stale: Duration::from_secs(48 * 3600),
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
        if !register(*b, cf, conf as *mut MainConf) {
            return NGX_CONF_ERROR;
        }
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
            "ip_ranges_max_stale" => {
                if let Some(t) = arg(cf, 1).and_then(|s| parse_time(&s)) {
                    (*b).max_stale = t;
                } else {
                    return NGX_CONF_ERROR;
                }
            }
            "ip_ranges_refresh" => {
                if let Some(t) = arg(cf, 1).and_then(|s| parse_time(&s)) {
                    (*b).refresh = t;
                } else {
                    return NGX_CONF_ERROR;
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
                if let Some(t) = arg(cf, 1).and_then(|s| parse_time(&s)) {
                    (*b).fcrdns_ttl = t;
                } else {
                    return NGX_CONF_ERROR;
                }
            }
            _ => return NGX_CONF_ERROR, // unknown directive inside the block
        }
        NGX_CONF_OK
    }
}

unsafe fn register(b: Builder, cf: *mut ngx_conf_t, main: *mut MainConf) -> bool {
    if b.urls.len() > 32 || b.max_stale < b.refresh {
        eprintln!("[pow_gate] at most 32 feed URLs; ip_ranges_max_stale must be >= refresh");
        return false;
    }
    let v = Arc::new(Verifier {
        ranges: ArcSwap::from_pointee(vec![None; b.urls.len()]),
        max_stale: b.max_stale,
        urls: b.urls,
        refresh: b.refresh,
        fcrdns_suffixes: b.suffixes,
        verdicts: Mutex::new(VerdictCache::new(DNS_CACHE_ENTRIES, b.fcrdns_ttl)),
    });
    if main.is_null() {
        return false;
    }
    if (*main).verifiers.is_null() {
        let cleanup = ngx_pool_cleanup_add((*cf).pool, 0);
        if cleanup.is_null() {
            return false;
        }
        let map = Box::into_raw(Box::new(HashMap::<String, Arc<Verifier>>::new()));
        (*main).verifiers = map.cast();
        (*cleanup).data = map.cast();
        (*cleanup).handler = Some(drop_configured);
    }
    let map = &mut *((*main).verifiers as *mut HashMap<String, Arc<Verifier>>);
    map.insert(b.name, v);
    true
}

unsafe extern "C" fn drop_configured(data: *mut c_void) {
    drop(Box::from_raw(data as *mut HashMap<String, Arc<Verifier>>));
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
fn parse_time(s: &str) -> Option<Duration> {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1u64),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        Some('d') => (&s[..s.len() - 1], 86400),
        _ => (s, 1),
    };
    let n: u64 = num.trim().parse().ok()?;
    let seconds = n.checked_mul(mult)?;
    if seconds == 0 || seconds > 365 * 86400 {
        return None;
    }
    Some(Duration::from_secs(seconds))
}
