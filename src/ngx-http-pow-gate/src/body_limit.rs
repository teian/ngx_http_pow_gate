//! Bound verification bodies before nginx's save filter buffers/spools them.
//! Per-request state lives in the nginx pool; other requests bypass this filter.

use ngx::{core::Status, ffi::*};

pub const VERIFY_LIMIT: usize = 8192;
static mut NEXT: ngx_http_request_body_filter_pt = None;

unsafe fn counter(r: *mut ngx_http_request_t) -> *mut usize {
    let state = crate::observability::state(r, false);
    if state.is_null() || !(*state).verify_enabled {
        std::ptr::null_mut()
    } else {
        &mut (*state).verify_bytes
    }
}

/// Called only for the module-owned verify endpoint, before reading its body.
pub unsafe fn enable(r: *mut ngx_http_request_t) -> bool {
    let state = crate::observability::state(r, true);
    if state.is_null() {
        return false;
    }
    (*state).verify_bytes = 0;
    (*state).verify_enabled = true;
    true
}

pub unsafe fn install() {
    NEXT = ngx_http_top_request_body_filter;
    ngx_http_top_request_body_filter = Some(filter);
}

unsafe extern "C" fn filter(r: *mut ngx_http_request_t, input: *mut ngx_chain_t) -> ngx_int_t {
    let count = counter(r);
    if !count.is_null() {
        let mut chain = input;
        while !chain.is_null() {
            let buffer = (*chain).buf;
            if !buffer.is_null() {
                let memory =
                    (*buffer).temporary() != 0 || (*buffer).memory() != 0 || (*buffer).mmap() != 0;
                let size = if memory && !(*buffer).pos.is_null() && !(*buffer).last.is_null() {
                    (*buffer).last.offset_from((*buffer).pos).max(0) as usize
                } else if (*buffer).in_file() != 0 {
                    ((*buffer).file_last - (*buffer).file_pos).max(0) as usize
                } else {
                    0
                };
                if size > VERIFY_LIMIT.saturating_sub(*count) {
                    let req = ngx::http::Request::from_ngx_http_request(r);
                    crate::observability::record(req, "rejected", "body_too_large", 0);
                    return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE as ngx_int_t;
                }
                *count += size;
            }
            chain = (*chain).next;
        }
    }
    match NEXT {
        Some(next) => next(r, input),
        None => Status::NGX_ERROR.0 as ngx_int_t,
    }
}
