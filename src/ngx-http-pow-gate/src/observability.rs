//! Request-local outcomes for nginx log_format. Shared with the body limiter.
use ngx::{core::Status, ffi::*, http::Request};
use std::ptr;

pub struct State {
    pub result: &'static str,
    pub reason: &'static str,
    pub difficulty: u64,
    pub verify_bytes: usize,
    pub verify_enabled: bool,
}

pub unsafe fn state(r: *mut ngx_http_request_t, create: bool) -> *mut State {
    if (*r).ctx.is_null() {
        return ptr::null_mut();
    }
    let slot = (*r)
        .ctx
        .add(crate::ngx_http_pow_gate_module.ctx_index as usize);
    if (*slot).is_null() && create {
        let value = ngx_pcalloc((*r).pool, std::mem::size_of::<State>()).cast::<State>();
        if value.is_null() {
            return value;
        }
        ptr::write(
            value,
            State {
                result: "off",
                reason: "disabled",
                difficulty: 0,
                verify_bytes: 0,
                verify_enabled: false,
            },
        );
        *slot = value.cast();
    }
    (*slot).cast()
}

pub fn record(r: &mut Request, result: &'static str, reason: &'static str, difficulty: u64) {
    let raw = r as *mut Request as *mut ngx_http_request_t;
    unsafe {
        // The default variable values already describe a disabled location.
        // Still clear an existing outcome after an internal redirect.
        let s = state(raw, result != "off");
        if !s.is_null() {
            (*s).result = result;
            (*s).reason = reason;
            (*s).difficulty = difficulty;
        }
        if matches!(result, "accepted" | "issued") {
            ngx::ngx_log_error!(
                NGX_LOG_INFO,
                (*(*raw).connection).log,
                "pow_gate result={} reason={} difficulty={}",
                result,
                reason,
                difficulty
            );
        }
    }
}

pub unsafe extern "C" fn register(cf: *mut ngx_conf_t) -> ngx_int_t {
    for (data, name) in [
        "pow_gate_result",
        "pow_gate_reason",
        "pow_gate_difficulty",
        "pow_gate_cookie_name",
    ]
    .iter()
    .enumerate()
    {
        let mut name = ngx_str_t {
            len: name.len(),
            data: name.as_ptr() as *mut u8,
        };
        let v = ngx_http_add_variable(cf, &mut name, NGX_HTTP_VAR_NOCACHEABLE as ngx_uint_t);
        if v.is_null() {
            return Status::NGX_ERROR.0;
        }
        (*v).get_handler = Some(get);
        (*v).data = data;
    }
    Status::NGX_OK.0
}

unsafe extern "C" fn get(
    r: *mut ngx_http_request_t,
    v: *mut ngx_variable_value_t,
    data: usize,
) -> ngx_int_t {
    let s = state(r, false);
    let (result, reason, difficulty) = if s.is_null() {
        ("off", "disabled", 0)
    } else {
        ((*s).result, (*s).reason, (*s).difficulty)
    };
    let number;
    let value = match data {
        0 => result,
        1 => reason,
        2 => {
            number = difficulty.to_string();
            &number
        }
        _ => crate::runtime::location_conf(r)
            .map(|lc| crate::response::as_str(&lc.cookie_effective_name))
            .unwrap_or(""),
    };
    let buffer = ngx_pnalloc((*r).pool, value.len()).cast::<u8>();
    if buffer.is_null() {
        return Status::NGX_ERROR.0;
    }
    ptr::copy_nonoverlapping(value.as_ptr(), buffer, value.len());
    (*v).data = buffer;
    (*v).set_len(value.len() as u32);
    (*v).set_valid(1);
    (*v).set_no_cacheable(1);
    (*v).set_not_found(0);
    Status::NGX_OK.0
}
