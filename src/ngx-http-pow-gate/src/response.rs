//! Response helpers — write a full body (page / JSON / Set-Cookie) from a phase
//! handler, plus small `ngx_str_t` conveniences. This is the nginx output side of
//! the FFI seam.

use ngx::core::Status;
use ngx::ffi::{ngx_chain_t, ngx_http_finalize_request, ngx_http_request_t, ngx_str_t};
use ngx::http::{HTTPStatus, Request};
use std::ptr;

use ngx::core::Buffer;

/// Borrow an `ngx_str_t` as `&str` (nginx strings are not NUL-terminated).
///
/// # Safety
/// `s.data` must point to `s.len` valid bytes that outlive `'a` (request pool).
pub unsafe fn as_str<'a>(s: &ngx_str_t) -> &'a str {
    if s.len == 0 || s.data.is_null() {
        return "";
    }
    std::str::from_utf8_unchecked(std::slice::from_raw_parts(s.data, s.len))
}

/// Borrow an `ngx_str_t` as bytes.
pub unsafe fn as_bytes<'a>(s: &ngx_str_t) -> &'a [u8] {
    if s.len == 0 || s.data.is_null() {
        return &[];
    }
    std::slice::from_raw_parts(s.data, s.len)
}

/// Send a complete response: status, `Content-Type`, optional `Set-Cookie`, body.
/// Returns the `output_filter` status (or the header status for an empty body).
pub fn send(
    r: &mut Request,
    status: HTTPStatus,
    content_type: &str,
    body: &[u8],
    set_cookie: Option<&str>,
) -> Status {
    r.set_status(status);
    r.set_content_length_n(body.len());
    let _ = r.add_header_out("Content-Type", content_type);
    if let Some(c) = set_cookie {
        let _ = r.add_header_out("Set-Cookie", c);
    }

    let rc = r.send_header();
    if rc != Status::NGX_OK || r.header_only() || body.is_empty() {
        return rc;
    }

    let pool = r.pool();
    let mut buf = match pool.create_buffer(body.len()) {
        Some(b) => b,
        None => return Status::NGX_ERROR,
    };
    unsafe {
        let nb = buf.as_ngx_buf_mut();
        ptr::copy_nonoverlapping(body.as_ptr(), (*nb).pos, body.len());
        (*nb).last = (*nb).pos.add(body.len());
    }
    buf.set_last_buf(true);
    buf.set_last_in_chain(true);

    let mut chain = ngx_chain_t {
        buf: buf.as_ngx_buf_mut(),
        next: ptr::null_mut(),
    };
    r.output_filter(&mut chain)
}

/// Serve a full response and finalize the request — the terminal action of an
/// ACCESS-phase handler that produced content itself. Returns `NGX_DONE` so the
/// phase engine stops (the request is now complete).
pub fn send_and_finish(
    r: &mut Request,
    status: HTTPStatus,
    content_type: &str,
    body: &[u8],
    set_cookie: Option<&str>,
) -> Status {
    let rc = send(r, status, content_type, body, set_cookie);
    let raw: *mut ngx_http_request_t = r as *mut Request as *mut ngx_http_request_t;
    unsafe { ngx_http_finalize_request(raw, rc.0) };
    Status::NGX_DONE
}
