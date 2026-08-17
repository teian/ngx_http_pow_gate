//! URI predicates shared by the parts of the engine that hand a client-supplied
//! path back to the client — the no-JS return path ([`crate::nojs`]) and the
//! captured request a challenge page replays ([`crate::replay`]).

/// A safe same-site target: absolute-path form, not protocol-relative, and free
/// of anything that could smuggle bytes into a `Location` header or an HTML
/// attribute (controls, whitespace, quotes, angle brackets).
///
/// Non-ASCII is rejected as well: browsers percent-encode the request target,
/// so a raw high byte here is never something we need to hand back verbatim.
pub fn same_site_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.starts_with("//")
        && path
            .bytes()
            .all(|b| (0x21..0x7f).contains(&b) && !matches!(b, b'"' | b'<' | b'>' | b'\\'))
}
