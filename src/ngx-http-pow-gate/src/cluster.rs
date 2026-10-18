//! Optional Redis primary backend, driven exclusively by nginx socket events.
//! A fixed connection budget, bounded queue, and one deadline per job include
//! connect/write/read/queue time. No background thread touches a request pointer.
use crate::{config::MainConf, redemption::Grant};
use ngx::{
    core::{Status, NGX_CONF_ERROR, NGX_CONF_OK},
    ffi::*,
    http::Request,
};
use pow_gate_core::{
    redemption::Outcome,
    redis::{self, Reply},
};
use std::{
    collections::VecDeque,
    ffi::{c_char, c_void},
    mem,
    net::SocketAddr,
    ptr,
};

#[derive(Clone)]
struct Config {
    address: SocketAddr,
    namespace: String,
    epoch: String,
    issuer: [u8; 32],
    username: String,
    password: Vec<u8>,
    timeout: u64,
    connections: usize,
    queue: usize,
    skew: i64,
}
struct Runtime {
    config: Config,
    pending: VecDeque<*mut Job>,
    active: Vec<*mut Job>,
    health_busy: bool,
    pumping: bool,
    ready: bool,
    fenced: bool,
    last_ok: ngx_msec_t,
    poll: ngx_event_t,
    log: *mut ngx_log_t,
}
struct Job {
    peer: ngx_peer_connection_t,
    address: libc::sockaddr_storage,
    name: ngx_str_t,
    output: Vec<u8>,
    sent: usize,
    input: Vec<u8>,
    auth: bool,
    deadline: ngx_event_t,
    request: *mut ngx_http_request_t,
    cleanup: *mut ngx_http_cleanup_t,
    grant: Option<Grant>,
    expires: i64,
    health: bool,
}
static mut RUNTIME: *mut Runtime = ptr::null_mut();

pub unsafe extern "C" fn configure(
    cf: *mut ngx_conf_t,
    _: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let main = &mut *conf.cast::<MainConf>();
    if !main.cluster.is_null() {
        return NGX_CONF_ERROR;
    }
    let values = Box::into_raw(Box::new(std::collections::HashMap::<String, String>::new()));
    let saved = *cf;
    (*cf).handler = Some(inner);
    (*cf).handler_conf = values.cast();
    let result = ngx_conf_parse(cf, ptr::null_mut());
    *cf = saved;
    let mut values = Box::from_raw(values);
    if result != NGX_CONF_OK {
        return NGX_CONF_ERROR;
    }
    let parsed = (|| -> Option<Config> {
        let address = values.remove("address")?.parse().ok()?;
        let namespace = values.remove("namespace")?;
        if namespace.is_empty()
            || namespace.len() > 64
            || !namespace
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        {
            return None;
        }
        let epoch = std::fs::read_to_string(values.remove("epoch_file")?)
            .ok()?
            .trim()
            .to_ascii_lowercase();
        if epoch.len() != 64 || !epoch.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        // Namespace is part of issuer identity even if an epoch file is reused.
        let issuer = pow_gate_core::redemption::id(&format!("redis:{namespace}:{epoch}"));
        let password = if let Some(path) = values.remove("password_file") {
            let bytes = std::fs::read(path).ok()?;
            let bytes = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
            if bytes.is_empty() || bytes.len() > 512 {
                return None;
            }
            bytes.to_vec()
        } else {
            Vec::new()
        };
        let username = values.remove("username").unwrap_or_default();
        if username.len() > 128 || (!username.is_empty() && password.is_empty()) {
            return None;
        }
        let timeout = values
            .remove("timeout")
            .map(|s| s.parse::<u64>())
            .transpose()
            .ok()?
            .unwrap_or(500);
        let connections = values
            .remove("connections")
            .map(|s| s.parse::<usize>())
            .transpose()
            .ok()?
            .unwrap_or(4);
        let queue = values
            .remove("queue")
            .map(|s| s.parse::<usize>())
            .transpose()
            .ok()?
            .unwrap_or(64);
        let skew = values
            .remove("clock_skew")
            .map(|s| s.parse::<i64>())
            .transpose()
            .ok()?
            .unwrap_or(5);
        if !(10..=5000).contains(&timeout)
            || !(1..=32).contains(&connections)
            || queue > 1024
            || !(1..=60).contains(&skew)
            || !values.is_empty()
        {
            return None;
        }
        Some(Config {
            address,
            namespace,
            epoch,
            issuer,
            username,
            password,
            timeout,
            connections,
            queue,
            skew,
        })
    })();
    let Some(config) = parsed else {
        ngx::ngx_conf_log_error!(NGX_LOG_EMERG,cf,"invalid pow_gate_redis configuration (numeric address, namespace and 64-hex epoch_file required)");
        return NGX_CONF_ERROR;
    };
    let cleanup = ngx_pool_cleanup_add((*cf).pool, 0);
    if cleanup.is_null() {
        return NGX_CONF_ERROR;
    }
    main.cluster = Box::into_raw(Box::new(config)).cast();
    (*cleanup).data = main.cluster;
    (*cleanup).handler = Some(drop_config);
    NGX_CONF_OK
}
unsafe extern "C" fn drop_config(data: *mut c_void) {
    drop(Box::from_raw(data.cast::<Config>()));
}
unsafe extern "C" fn inner(
    cf: *mut ngx_conf_t,
    _: *mut ngx_command_t,
    _: *mut c_void,
) -> *mut c_char {
    let args = &*(*cf).args;
    if args.nelts != 2 {
        return NGX_CONF_ERROR;
    }
    let entries = std::slice::from_raw_parts(args.elts.cast::<ngx_str_t>(), 2);
    let name = crate::response::as_str(&entries[0]).to_owned();
    if ![
        "address",
        "namespace",
        "epoch_file",
        "username",
        "password_file",
        "timeout",
        "connections",
        "queue",
        "clock_skew",
    ]
    .contains(&name.as_str())
    {
        return NGX_CONF_ERROR;
    }
    let values = &mut *(*cf)
        .handler_conf
        .cast::<std::collections::HashMap<String, String>>();
    if values
        .insert(name, crate::response::as_str(&entries[1]).to_owned())
        .is_some()
    {
        return NGX_CONF_ERROR;
    }
    NGX_CONF_OK
}

pub unsafe fn activate(main: *mut MainConf, log: *mut ngx_log_t) {
    RUNTIME = ptr::null_mut();
    if (*main).cluster.is_null() {
        return;
    }
    let config = (&*(*main).cluster.cast::<Config>()).clone();
    let mut runtime = Box::new(Runtime {
        pending: VecDeque::with_capacity(config.queue),
        active: Vec::with_capacity(config.connections),
        config,
        health_busy: false,
        pumping: false,
        ready: false,
        fenced: false,
        last_ok: 0,
        poll: mem::zeroed(),
        log,
    });
    runtime.poll.handler = Some(poll);
    runtime.poll.log = log;
    runtime.poll.set_cancelable(1);
    RUNTIME = Box::into_raw(runtime);
    (*RUNTIME).poll.data = RUNTIME.cast();
    ngx_add_timer(&raw mut (*RUNTIME).poll, 1);
}

pub fn enabled() -> bool {
    unsafe { !RUNTIME.is_null() }
}
pub fn issuer() -> Option<[u8; 32]> {
    unsafe {
        if RUNTIME.is_null() || (*RUNTIME).fenced {
            None
        } else {
            Some((*RUNTIME).config.issuer)
        }
    }
}
pub fn available() -> bool {
    unsafe {
        !RUNTIME.is_null()
            && (*RUNTIME).ready
            && !(*RUNTIME).fenced
            && ngx_current_msec.wrapping_sub((*RUNTIME).last_ok) < 2500
    }
}

unsafe extern "C" fn poll(_: *mut ngx_event_t) {
    if ngx_exiting != 0 || ngx_quit != 0 || ngx_terminate != 0 {
        return;
    }
    if !(*RUNTIME).health_busy && !(*RUNTIME).fenced {
        (*RUNTIME).health_busy = true;
        let job = make_job(ptr::null_mut(), None, "", 0, true);
        connect(job);
    }
    ngx_add_timer(&raw mut (*RUNTIME).poll, 1000);
}

/// Called only after all cryptographic checks. Takes responsibility for finalizing
/// this request, including on timeout, disconnect, queue exhaustion or OOM.
pub fn redeem(r: &mut Request, token: &str, expires: i64, grant: Grant) -> Status {
    unsafe {
        if !available() {
            return crate::redemption::finish(r, Outcome::Full, grant);
        }
        if (*RUNTIME).active.len() >= (*RUNTIME).config.connections
            && (*RUNTIME).pending.len() >= (*RUNTIME).config.queue
        {
            return crate::redemption::finish(r, Outcome::Full, grant);
        }
        let raw = r as *mut Request as *mut ngx_http_request_t;
        let cleanup = ngx_http_cleanup_add(raw, 0);
        if cleanup.is_null() {
            return crate::redemption::finish(r, Outcome::Full, grant);
        }
        let job = make_job(raw, Some(grant), token, expires, false);
        (*job).cleanup = cleanup;
        (*cleanup).data = job.cast();
        (*cleanup).handler = Some(aborted);
        (*raw).read_event_handler = Some(ngx_http_test_reading);
        (*raw).write_event_handler = Some(ngx_http_request_empty_handler);
        ngx_add_timer(
            &raw mut (*job).deadline,
            (*RUNTIME).config.timeout as ngx_msec_t,
        );
        if (*RUNTIME).active.len() < (*RUNTIME).config.connections {
            (*RUNTIME).active.push(job);
            connect(job);
        } else {
            (*RUNTIME).pending.push_back(job);
        }
        Status::NGX_DONE
    }
}

unsafe fn make_job(
    request: *mut ngx_http_request_t,
    grant: Option<Grant>,
    token: &str,
    expires: i64,
    health: bool,
) -> *mut Job {
    let config = &(*RUNTIME).config;
    let keys = redis::keys(&config.namespace, &config.epoch, token);
    let mut output = Vec::new();
    let auth = !config.password.is_empty();
    if auth {
        let mut parts = vec![b"AUTH".as_slice()];
        if !config.username.is_empty() {
            parts.push(config.username.as_bytes());
        }
        parts.push(&config.password);
        output.extend(redis::command(&parts));
    }
    if health {
        output.extend(redis::command(&[
            b"EVAL",
            redis::HEALTH.as_bytes(),
            b"2",
            keys[0].as_bytes(),
            keys[2].as_bytes(),
            config.epoch.as_bytes(),
        ]));
    } else {
        output.extend(redis::command(&[
            b"EVAL",
            redis::CONSUME.as_bytes(),
            b"3",
            keys[0].as_bytes(),
            keys[1].as_bytes(),
            keys[2].as_bytes(),
            config.epoch.as_bytes(),
            expires.to_string().as_bytes(),
            config.skew.to_string().as_bytes(),
            crate::runtime::now().to_string().as_bytes(),
        ]));
    }
    let mut job = Box::new(Job {
        peer: mem::zeroed(),
        address: mem::zeroed(),
        name: mem::zeroed(),
        output,
        sent: 0,
        input: Vec::with_capacity(1024),
        auth,
        deadline: mem::zeroed(),
        request,
        cleanup: ptr::null_mut(),
        grant,
        expires,
        health,
    });
    job.deadline.handler = Some(timeout);
    job.deadline.log = (*RUNTIME).log;
    job.peer.get = Some(ngx_event_get_peer);
    job.peer.log = (*RUNTIME).log;
    let socket = config.address;
    match socket {
        SocketAddr::V4(a) => {
            let addr = &mut *(&mut job.address as *mut _ as *mut libc::sockaddr_in);
            addr.sin_family = libc::AF_INET as _;
            addr.sin_port = a.port().to_be();
            addr.sin_addr.s_addr = u32::from(*a.ip()).to_be();
            job.peer.socklen = mem::size_of::<libc::sockaddr_in>() as _;
        }
        SocketAddr::V6(a) => {
            let addr = &mut *(&mut job.address as *mut _ as *mut libc::sockaddr_in6);
            addr.sin6_family = libc::AF_INET6 as _;
            addr.sin6_port = a.port().to_be();
            addr.sin6_addr.s6_addr = a.ip().octets();
            addr.sin6_scope_id = a.scope_id();
            job.peer.socklen = mem::size_of::<libc::sockaddr_in6>() as _;
        }
    }
    let job = Box::into_raw(job);
    (*job).deadline.data = job.cast();
    (*job).peer.sockaddr = (&raw mut (*job).address).cast();
    // Stable name used only in nginx's connection error logs; no credentials.
    static NAME: &[u8] = b"pow_gate Redis primary";
    (*job).name = ngx_str_t {
        len: NAME.len(),
        data: NAME.as_ptr() as *mut u8,
    };
    (*job).peer.name = &raw mut (*job).name;
    job
}

unsafe fn connect(job: *mut Job) {
    if (*job).health {
        ngx_add_timer(
            &raw mut (*job).deadline,
            (*RUNTIME).config.timeout as ngx_msec_t,
        );
    }
    let rc = ngx_event_connect_peer(&raw mut (*job).peer);
    let connection = (*job).peer.connection;
    if connection.is_null() {
        complete(job, Outcome::Full, false);
        return;
    }
    (*connection).data = job.cast();
    (*(*connection).write).handler = Some(write);
    (*(*connection).read).handler = Some(read);
    if rc == Status::NGX_ERROR.0 || rc == Status::NGX_DECLINED.0 || rc == Status::NGX_BUSY.0 {
        complete(job, Outcome::Full, false);
        return;
    }
    // Even an immediate connect completes through the event loop, never while
    // a request-body callback or queue mutation still borrows its request.
    if rc == Status::NGX_OK.0 {
        ngx_post_event((*connection).write, &raw mut ngx_posted_next_events);
    }
}
unsafe extern "C" fn write(event: *mut ngx_event_t) {
    let connection = (*event).data.cast::<ngx_connection_t>();
    let job = (*connection).data.cast::<Job>();
    let mut error: libc::c_int = 0;
    let mut len = mem::size_of_val(&error) as libc::socklen_t;
    if libc::getsockopt(
        (*connection).fd,
        libc::SOL_SOCKET,
        libc::SO_ERROR,
        (&mut error as *mut libc::c_int).cast(),
        &mut len,
    ) != 0
        || error != 0
    {
        complete(job, Outcome::Full, false);
        return;
    }
    while (*job).sent < (*job).output.len() {
        let bytes = &(&(*job).output)[(*job).sent..];
        let n = (*connection).send.unwrap()(connection, bytes.as_ptr() as *mut u8, bytes.len());
        if n == Status::NGX_AGAIN.0 {
            if ngx_handle_write_event(event, 0) != Status::NGX_OK.0 {
                complete(job, Outcome::Full, false);
            }
            return;
        }
        if n <= 0 {
            complete(job, Outcome::Full, false);
            return;
        }
        (*job).sent += n as usize;
    }
    if ngx_handle_read_event((*connection).read, 0) != Status::NGX_OK.0 {
        complete(job, Outcome::Full, false);
    }
}
unsafe extern "C" fn read(event: *mut ngx_event_t) {
    let connection = (*event).data.cast::<ngx_connection_t>();
    let job = (*connection).data.cast::<Job>();
    loop {
        let mut bytes = [0u8; 256];
        let n = (*connection).recv.unwrap()(connection, bytes.as_mut_ptr(), bytes.len());
        if n == Status::NGX_AGAIN.0 {
            if ngx_handle_read_event(event, 0) != Status::NGX_OK.0 {
                complete(job, Outcome::Full, false);
            }
            return;
        }
        if n <= 0 || (*job).input.len() + n as usize > 1024 {
            complete(job, Outcome::Full, false);
            return;
        }
        (*job).input.extend_from_slice(&bytes[..n as usize]);
        loop {
            match redis::reply(&(*job).input) {
                Ok(Some((reply, used))) => {
                    (*job).input.drain(..used);
                    if (*job).auth {
                        if reply != Reply::Ok {
                            complete(job, Outcome::Full, false);
                            return;
                        }
                        (*job).auth = false;
                        continue;
                    }
                    let (outcome, fenced) = match reply {
                        Reply::Integer(1) => (Outcome::Accepted, false),
                        Reply::Integer(0) => (Outcome::Reused, false),
                        Reply::Integer(-1) => (Outcome::Expired, false),
                        Reply::Integer(-2) => (Outcome::Full, true),
                        _ => (Outcome::Full, false),
                    };
                    complete(job, outcome, fenced);
                    return;
                }
                Ok(None) => break,
                Err(_) => {
                    complete(job, Outcome::Full, false);
                    return;
                }
            }
        }
    }
}
unsafe extern "C" fn timeout(event: *mut ngx_event_t) {
    complete((*event).data.cast(), Outcome::Full, false);
}
unsafe extern "C" fn aborted(data: *mut c_void) {
    let job = data.cast::<Job>();
    (*job).request = ptr::null_mut();
    (*job).cleanup = ptr::null_mut();
    complete(job, Outcome::Full, false);
}
unsafe fn complete(job: *mut Job, mut outcome: Outcome, fenced: bool) {
    if (*job).deadline.timer_set() != 0 {
        ngx_del_timer(&raw mut (*job).deadline);
    }
    if !(*job).peer.connection.is_null() {
        ngx_close_connection((*job).peer.connection);
        (*job).peer.connection = ptr::null_mut();
    }
    if !(*job).cleanup.is_null() {
        (*(*job).cleanup).handler = None;
    }
    if fenced {
        (*RUNTIME).fenced = true;
        (*RUNTIME).ready = false;
    }
    if (*job).health {
        (*RUNTIME).health_busy = false;
        (*RUNTIME).ready = outcome == Outcome::Accepted && !(*RUNTIME).fenced;
        if (*RUNTIME).ready {
            (*RUNTIME).last_ok = ngx_current_msec;
        }
    } else {
        (*RUNTIME).active.retain(|&p| p != job);
        (*RUNTIME).pending.retain(|&p| p != job);
        // A late successful Redis reply cannot mint an already expired token.
        if outcome == Outcome::Accepted && crate::runtime::now() >= (*job).expires {
            outcome = Outcome::Expired;
        }
    }
    let mut job = Box::from_raw(job);
    let request = job.request;
    let grant = job.grant.take();
    drop(job);
    // Drain before finalization: output filters may reenter nginx phase handlers.
    if !(*RUNTIME).pumping {
        (*RUNTIME).pumping = true;
        while (*RUNTIME).active.len() < (*RUNTIME).config.connections {
            let Some(next) = (*RUNTIME).pending.pop_front() else {
                break;
            };
            (*RUNTIME).active.push(next);
            connect(next);
        }
        (*RUNTIME).pumping = false;
    }
    if !request.is_null() {
        if let Some(grant) = grant {
            crate::redemption::finish(Request::from_ngx_http_request(request), outcome, grant);
        }
    }
}
