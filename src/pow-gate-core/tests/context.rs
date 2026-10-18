use pow_gate_core::context::{binding, AddressPolicy};
fn context(ip: &str, ua: &str, scope: &str, issuer: &[u8], policy: AddressPolicy) -> String {
    binding(
        b"server-key",
        ip.parse().unwrap(),
        ua,
        scope,
        issuer,
        policy,
    )
    .unwrap()
}
#[test]
fn exact_address_default_and_context_fields_are_bound() {
    let policy = AddressPolicy::default();
    let original = context("192.0.2.1", "browser", "site", b"issuer", policy);
    for other in [
        context("192.0.2.2", "browser", "site", b"issuer", policy),
        context("192.0.2.1", "other-UA", "site", b"issuer", policy),
        context(
            "192.0.2.1",
            "browser",
            "other-site-or-policy",
            b"issuer",
            policy,
        ),
        context("192.0.2.1", "browser", "site", b"other-store", policy),
        context(
            "192.0.2.1",
            "browser",
            "site",
            b"issuer",
            AddressPolicy {
                ipv4_prefix: 24,
                ..policy
            },
        ),
    ] {
        assert_ne!(original, other);
    }
    assert_eq!(
        original,
        context("::ffff:192.0.2.1", "browser", "site", b"issuer", policy)
    );
}
#[test]
fn configurable_network_prefixes_and_ipv6_boundaries() {
    let policy = AddressPolicy {
        ipv4_prefix: 24,
        ipv6_prefix: 64,
    };
    assert_eq!(
        context("192.0.2.1", "ua", "s", b"i", policy),
        context("192.0.2.255", "ua", "s", b"i", policy)
    );
    assert_ne!(
        context("192.0.2.1", "ua", "s", b"i", policy),
        context("192.0.3.1", "ua", "s", b"i", policy)
    );
    assert_eq!(
        context("2001:db8:1:2::1", "ua", "s", b"i", policy),
        context("2001:db8:1:2::ffff", "ua", "s", b"i", policy)
    );
    assert_ne!(
        context("2001:db8:1:2::1", "ua", "s", b"i", policy),
        context("2001:db8:1:3::1", "ua", "s", b"i", policy)
    );
    let exact = AddressPolicy::default();
    assert_ne!(
        context("2001:db8::1", "ua", "s", b"i", exact),
        context("2001:db8::2", "ua", "s", b"i", exact)
    );
}
#[test]
fn invalid_prefixes_fail_closed() {
    for (v4, v6) in [(0, 128), (33, 128), (32, 0), (32, 129)] {
        assert!(binding(
            b"key",
            "192.0.2.1".parse().unwrap(),
            "",
            "",
            b"",
            AddressPolicy {
                ipv4_prefix: v4,
                ipv6_prefix: v6
            }
        )
        .is_none());
    }
}

#[test]
fn field_boundaries_are_unambiguous() {
    let policy = AddressPolicy::default();
    assert_ne!(
        context("192.0.2.1", "a|b", "c", b"i", policy),
        context("192.0.2.1", "a", "b|c", b"i", policy)
    );
    assert_ne!(
        context("192.0.2.1", "a", "bc", b"d", policy),
        context("192.0.2.1", "ab", "c", b"d", policy)
    );
}
