//! Stable cookie epochs isolate scopes without accepting legacy credentials.
use sha2::{Digest, Sha256};

/// Length-prefix every field so distinct scopes cannot hash the same encoding.
/// TTL and difficulty are deliberately omitted: assurance is checked on use.
pub fn scoped_name(base: &str, fields: &[&str]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"pow-gate-cookie-scope-v2");
    for field in std::iter::once(base).chain(fields.iter().copied()) {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field.as_bytes());
    }
    let digest = hash.finalize();
    let suffix: String = digest[..12].iter().map(|b| format!("{b:02x}")).collect();
    format!("{base}_{suffix}")
}
