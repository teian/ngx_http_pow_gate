//! Tests for the base64url / hex helpers. Own test crate; public API only.

use pow_gate_core::codec::{b64url, hex, unb64url};

#[test]
fn b64url_roundtrips() {
    let data = b"\x00\x01\xfe\xff hello?";
    assert_eq!(unb64url(&b64url(data)).unwrap(), data);
}

#[test]
fn b64url_is_url_safe_unpadded() {
    let s = b64url(&[0xff, 0xff, 0xff, 0xfb, 0xff]);
    assert!(!s.contains('='));
    assert!(!s.contains('+'));
    assert!(!s.contains('/'));
}

#[test]
fn unb64url_rejects_garbage() {
    assert!(unb64url("not base64 !!!").is_none());
}

#[test]
fn hex_is_lowercase_fixed_width() {
    assert_eq!(hex(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
}
