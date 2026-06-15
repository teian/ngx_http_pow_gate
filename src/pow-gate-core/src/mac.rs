//! HMAC-SHA256 and constant-time comparison — the spine of clearance/challenge
//! integrity. Internal to the crate.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// HMAC-SHA256 of `msg` under `key`. Accepts a key of any length (HMAC handles it).
pub fn hmac(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(msg);
    m.finalize().into_bytes().into()
}

/// Constant-time equality. Returns `false` on length mismatch (lengths are not
/// secret here, so an early return is fine).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.ct_eq(b).into()
}
