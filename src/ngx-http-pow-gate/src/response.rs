//! Response helpers — write a full body (page / JSON / Set-Cookie) from a phase
//! handler, plus small `ngx_str_t` conveniences. This is the nginx output side of
//! the FFI seam.

use ngx::core::Status;
use ngx::ffi::{ngx_chain_t, ngx_http_finalize_request, ngx_http_request_t, ngx_str_t};
use ngx::http::{HTTPStatus, Request};
use std::ptr;

use ngx::core::Buffer;

/// Protocol responses, including errors, must not enter a shared cache.
/// The content-fingerprinted public solver supplies its own explicit policy.
pub fn no_store(r: &mut Request) {
    let present = r
        .headers_out_iterator()
        .any(|(key, _)| key.as_bytes().eq_ignore_ascii_case(b"cache-control"));
    if !present {
        let _ = r.add_header_out("Cache-Control", "no-store");
    }
}

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

/// Populate nginx's native metadata so gzip/charset filters see the MIME type.
/// Keep bytes in the request pool; output filters may run after this returns.
fn set_content_type(r: &mut Request, value: &str) -> bool {
    let data = r.pool().alloc_unaligned(value.len() + 1).cast::<u8>();
    if data.is_null() {
        return false;
    }
    unsafe {
        ptr::copy_nonoverlapping(value.as_ptr(), data, value.len());
        *data.add(value.len()) = 0;
        let raw = r as *mut Request as *mut ngx_http_request_t;
        let out = &mut (*raw).headers_out;
        out.content_type = ngx_str_t {
            len: value.len(),
            data,
        };
        out.content_type_len = value.len();
        out.content_type_hash = 0;
        out.content_type_lowcase = ptr::null_mut();
        out.charset = ngx_str_t {
            len: 0,
            data: ptr::null_mut(),
        };
        // All module-supplied parameterized MIME types use this spelling.
        // Match nginx's upstream metadata: full type plus separate charset.
        if let Some(offset) = value.find("; charset=") {
            out.content_type_len = offset;
            let start = offset + "; charset=".len();
            out.charset = ngx_str_t {
                len: value.len() - start,
                data: data.add(start),
            };
        }
    }
    true
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
    match set_cookie {
        Some(c) => send_with_headers(r, status, content_type, body, &[("Set-Cookie", c)]),
        None => send_with_headers(r, status, content_type, body, &[]),
    }
}

/// Like [`send`], but with arbitrary extra response headers (`Location`,
/// `Cache-Control`, `Set-Cookie`, …).
pub fn send_with_headers(
    r: &mut Request,
    status: HTTPStatus,
    content_type: &str,
    body: &[u8],
    headers: &[(&str, &str)],
) -> Status {
    send_body(r, status, content_type, body, headers, true)
}

fn send_body(
    r: &mut Request,
    status: HTTPStatus,
    content_type: &str,
    body: &[u8],
    headers: &[(&str, &str)],
    copy_body: bool,
) -> Status {
    r.set_status(status);
    r.set_content_length_n(body.len());
    if !set_content_type(r, content_type) {
        return Status::NGX_ERROR;
    }
    for (name, value) in headers {
        let duplicate = r.headers_out_iterator().any(|(key, existing)| {
            key.as_bytes().eq_ignore_ascii_case(name.as_bytes())
                && existing.as_bytes() == value.as_bytes()
        });
        if !duplicate {
            let _ = r.add_header_out(name, value);
        }
    }
    no_store(r);

    // CONTRACT: pass an empty body ONLY for statuses nginx itself terminates
    // at the header (204). For anything else an empty body skips
    // output_filter below, no last_buf is ever emitted, and the buffered
    // response is never flushed — the client sees a hang, then EOF. Field
    // note: observed on the /verify 400 path (2026-07); every error/redirect
    // response therefore carries at least a tiny body.
    let rc = r.send_header();
    if rc != Status::NGX_OK || r.header_only() || body.is_empty() {
        return rc;
    }

    let pool = r.pool();
    let buf = if copy_body {
        let Some(mut buf) = pool.create_buffer(body.len()) else {
            return Status::NGX_ERROR;
        };
        let raw = buf.as_ngx_buf_mut();
        unsafe {
            ptr::copy_nonoverlapping(body.as_ptr(), (*raw).pos, body.len());
            (*raw).last = (*raw).pos.add(body.len());
        }
        raw
    } else {
        let raw = pool.calloc_type::<ngx::ffi::ngx_buf_t>();
        if raw.is_null() {
            return Status::NGX_ERROR;
        }
        unsafe {
            let data = body.as_ptr().cast_mut();
            (*raw).start = data;
            (*raw).pos = data;
            (*raw).last = data.add(body.len());
            (*raw).end = (*raw).last;
            // nginx filters must treat the shared bytes as read-only. Only
            // this request's buffer metadata may be advanced or replaced.
            (*raw).set_memory(1);
        }
        raw
    };
    unsafe {
        (*buf).set_last_buf(1);
        (*buf).set_last_in_chain(1);
    }

    let mut chain = ngx_chain_t {
        buf,
        next: ptr::null_mut(),
    };
    r.output_filter(&mut chain)
}

/// Send an immutable body without copying it into the request pool.
///
/// # Safety
/// `body` must remain valid and immutable until nginx finishes the request,
/// including buffered/asynchronous output. Callers use configuration-pool
/// templates (whose cycle outlives the request) or the static embedded solver.
pub unsafe fn send_cached_and_finish(
    r: &mut Request,
    status: HTTPStatus,
    content_type: &str,
    body: &[u8],
    headers: &[(&str, &str)],
) -> Status {
    let rc = send_body(r, status, content_type, body, headers, false);
    let raw = r as *mut Request as *mut ngx_http_request_t;
    ngx_http_finalize_request(raw, rc.0);
    Status::NGX_DONE
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

/// [`send_with_headers`] + finalize — see [`send_and_finish`].
pub fn send_and_finish_with_headers(
    r: &mut Request,
    status: HTTPStatus,
    content_type: &str,
    body: &[u8],
    headers: &[(&str, &str)],
) -> Status {
    let rc = send_with_headers(r, status, content_type, body, headers);
    let raw: *mut ngx_http_request_t = r as *mut Request as *mut ngx_http_request_t;
    unsafe { ngx_http_finalize_request(raw, rc.0) };
    Status::NGX_DONE
}
