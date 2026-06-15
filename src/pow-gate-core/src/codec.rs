//! Small encoding helpers shared across the engine: base64url (no padding) and
//! lowercase hex. Kept in one place so the wire format is defined once.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};

/// base64url, no padding.
pub fn b64url(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

/// Decode base64url (no padding). `None` on malformed input.
pub fn unb64url(s: &str) -> Option<Vec<u8>> {
    B64.decode(s).ok()
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}
