//! The captured request a challenge page carries, so a `POST` that runs into an
//! expired clearance is not lost.
//!
//! ## Why the client keeps it
//!
//! When a form submit hits the gate, the module answers the `POST` with the
//! challenge page — and the body is gone. Reloading after the solve re-issues a
//! `GET` (the fields are lost) or makes the browser ask the user to confirm a
//! resubmission. Buffering the request *server*-side instead would mean shared
//! state with a TTL, a size budget and an eviction policy — for data the client
//! itself still has.
//!
//! So the client keeps it: the module embeds the captured request into the
//! challenge page it is already sending back to that same client,
//!
//! ```html
//! <script id="pow-replay" type="application/json">
//! {"method":"POST","url":"/order","type":"application/x-www-form-urlencoded","body":"<base64url>"}
//! </script>
//! ```
//!
//! and `solver.js` re-issues the request once the clearance cookie is set (as a
//! real form submit for form-encoded bodies, so redirects and rendering keep
//! their native semantics; via `fetch` otherwise). The gate stays stateless.
//!
//! ## Why it needs no signature
//!
//! Unlike the clearance and no-JS tokens, this payload is not authenticated and
//! does not need to be. It travels only back to the client that sent it, and a
//! client that tampers with it merely sends a different request of its own — it
//! still had to solve the challenge first, which is the gate's whole job. What
//! *does* matter is that the payload cannot break out of the page: the URL is
//! held to [`uri::same_site_path`] and every `<`/`>`/`&` in the JSON is escaped,
//! so it can never close the `<script>` block it lives in.
//!
//! The one thing the operator must bound is size — see `pow_gate_replay_max_body`
//! in the module: the body is read into memory before the client has proven
//! anything.
//!
//! `POST` is the case that matters in practice, but nothing here is specific to
//! it: every method that can carry data is replayed (see [`NEVER_REPLAYED`]).

use crate::codec::b64url;
use crate::uri;

/// `id` of the injected `<script>` block — the contract with `solver.js`.
pub const SCRIPT_ID: &str = "pow-replay";

/// The only methods never replayed: `GET`/`HEAD` carry nothing to preserve (the
/// reload re-issues them), `TRACE` must not carry a body at all (RFC 9110), and
/// `CONNECT` is a tunnel, not a request-response exchange.
///
/// Everything else is replayable — deliberately a deny-list, because capture
/// already requires a declared body, so the *request* decides whether there is
/// data to keep, not a hard-coded verb table. That covers `POST`, `PUT`,
/// `PATCH`, `DELETE`, `OPTIONS`, `REPORT`, `SEARCH`, WebDAV's
/// `PROPFIND`/`PROPPATCH`/`LOCK`/`MKCOL`, and whatever an API invents next.
const NEVER_REPLAYED: [&str; 4] = ["GET", "HEAD", "TRACE", "CONNECT"];

/// Longest `Content-Type` echoed back into the page. Real ones are far shorter
/// (`multipart/form-data; boundary=…` is the long case); the bound just keeps a
/// hostile header out of the payload.
const MAX_CONTENT_TYPE: usize = 200;

/// Is this a method the challenge page should try to replay? Anything that can
/// carry data, i.e. everything but [`NEVER_REPLAYED`] — held to a plain
/// alphabetic token so nothing exotic reaches the page or `fetch()`.
pub fn method_replayable(method: &str) -> bool {
    !method.is_empty()
        && method.bytes().all(|b| b.is_ascii_alphabetic())
        && !NEVER_REPLAYED.iter().any(|m| m.eq_ignore_ascii_case(method))
}

/// A request captured at the gate, ready to be handed to the challenge page.
pub struct Captured<'a> {
    method: &'a str,
    url: &'a str,
    content_type: String,
    body: &'a [u8],
}

impl<'a> Captured<'a> {
    /// Validate and capture. `None` — serve the plain challenge page — when the
    /// method is not replayable or the URL is not a safe same-site path (an
    /// absolute-form request target, say). The caller owns the size limit.
    pub fn new(method: &'a str, url: &'a str, content_type: &str, body: &'a [u8]) -> Option<Self> {
        if !method_replayable(method) || !uri::same_site_path(url) {
            return None;
        }
        Some(Self {
            method,
            url,
            content_type: sanitize_content_type(content_type),
            body,
        })
    }

    /// The JSON payload: `{"method","url","type","body"}`, body base64url.
    pub fn payload(&self) -> String {
        let json = serde_json::json!({
            // verbatim: HTTP methods are case-sensitive, so do not "normalize"
            "method": self.method,
            "url": self.url,
            "type": self.content_type,
            "body": b64url(self.body),
        });
        escape_markup(&json.to_string())
    }

    /// The full `<script>` block to inject, terminated by a newline.
    pub fn script_tag(&self) -> String {
        format!(
            "<script id=\"{}\" type=\"application/json\">{}</script>\n",
            SCRIPT_ID,
            self.payload()
        )
    }
}

/// Insert `tag` into `page` just before the last `</body>` (case-insensitive),
/// or append it when the page has no body element. Deliberately additive: the
/// challenge page is operator-overridable, so a custom page keeps working
/// without carrying a placeholder for this.
pub fn inject(page: &[u8], tag: &str) -> Vec<u8> {
    let at = rfind_ci(page, b"</body>").unwrap_or(page.len());
    let mut out = Vec::with_capacity(page.len() + tag.len());
    out.extend_from_slice(&page[..at]);
    out.extend_from_slice(tag.as_bytes());
    out.extend_from_slice(&page[at..]);
    out
}

/// Last case-insensitive occurrence of `needle` in `haystack`.
fn rfind_ci(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len())
        .rev()
        .find(|&i| haystack[i..i + needle.len()].eq_ignore_ascii_case(needle))
}

/// Keep the `Content-Type` printable and bounded — it is echoed straight back
/// into the page, and `fetch` would reject a header value with controls anyway.
fn sanitize_content_type(ct: &str) -> String {
    ct.chars()
        .filter(|c| (' '..='~').contains(c))
        .take(MAX_CONTENT_TYPE)
        .collect()
}

/// Escape the three characters that could end the surrounding `<script>` block
/// (or open an HTML comment) as JSON `\uXXXX` escapes. Safe to do on the
/// serialized document: outside string literals JSON contains none of them.
fn escape_markup(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        match c {
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            _ => out.push(c),
        }
    }
    out
}
