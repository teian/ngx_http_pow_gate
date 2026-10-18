use pow_gate_core::{
    cookie::scoped_name,
    feeds::FeedSnapshot,
    ranges::{fcrdns_confirms, IpRangeSet},
};
use std::{
    net::IpAddr,
    time::{Duration, Instant},
};

#[test]
fn scopes_isolate_cookie_epochs() {
    let base = scoped_name("pow_clearance", &["example.com", "/", "default"]);
    assert_eq!(
        base,
        scoped_name("pow_clearance", &["example.com", "/", "default"])
    );
    assert_ne!(
        base,
        scoped_name("pow_clearance", &["example.com", "/admin", "default"])
    );
    assert_ne!(
        base,
        scoped_name("pow_clearance", &["example.com", "/", "other"])
    );
    assert_ne!(
        scoped_name("x", &["ab", "c"]),
        scoped_name("x", &["a", "bc"])
    );
}

#[test]
fn invalid_cidr_or_partial_feed_never_widens_an_allowlist() {
    for cidr in [
        "192.0.2.1/33",
        "192.0.2.1/",
        "192.0.2.1/no",
        "::1/129",
        "::1/-1",
    ] {
        let mut set = IpRangeSet::new();
        assert!(!set.add_cidr(cidr), "{cidr}");
        assert!(set.is_empty());
    }
    let mut set = IpRangeSet::new();
    assert_eq!(
        set.add_feed_json(
            br#"{"prefixes":[{"ipv4Prefix":"0.0.0.0/0"},{"ipv4Prefix":"192.0.2.1/33"}]}"#
        ),
        0
    );
    assert!(set.is_empty());
}

#[test]
fn stale_feeds_fail_closed_even_without_a_refresh() {
    let now = Instant::now();
    let snapshot =
        FeedSnapshot::parse(br#"{"prefixes":[{"ipv4Prefix":"192.0.2.0/24"}]}"#, now).unwrap();
    let ip = "192.0.2.3".parse().unwrap();
    assert!(snapshot.contains(ip, now + Duration::from_secs(9), Duration::from_secs(10)));
    assert!(!snapshot.contains(ip, now + Duration::from_secs(10), Duration::from_secs(10)));
    assert!(FeedSnapshot::parse(br#"{"prefixes":[]}"#, now).is_none());
}

#[test]
fn mixed_ptr_records_cannot_combine_trust_and_forward_confirmation() {
    let ip: IpAddr = "192.0.2.3".parse().unwrap();
    let suffixes = vec!["googlebot.com".to_owned()];
    let ptrs = ["fake.googlebot.com", "attacker.example"];
    assert!(!ptrs
        .iter()
        .any(|host| fcrdns_confirms(host, &suffixes, ip, |name| {
            if name == "attacker.example" {
                vec![ip]
            } else {
                vec![]
            }
        })));
    assert!(fcrdns_confirms(
        "crawl.googlebot.com",
        &suffixes,
        ip,
        |_| vec![ip]
    ));
}
