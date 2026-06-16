//! IP-range set tests. Own test crate; public API only.

use pow_gate_core::ranges::{host_matches_suffix, IpRangeSet};
use std::net::IpAddr;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn cidr_v4_membership() {
    let mut s = IpRangeSet::new();
    assert!(s.add_cidr("10.0.0.0/8"));
    assert!(s.add_cidr("192.168.1.0/24"));
    assert!(s.contains(ip("10.255.1.2")));
    assert!(s.contains(ip("192.168.1.42")));
    assert!(!s.contains(ip("192.168.2.1")));
    assert!(!s.contains(ip("11.0.0.1")));
}

#[test]
fn cidr_v6_membership() {
    let mut s = IpRangeSet::new();
    assert!(s.add_cidr("2001:db8::/32"));
    assert!(s.contains(ip("2001:db8:1234::1")));
    assert!(!s.contains(ip("2001:db9::1")));
}

#[test]
fn bare_address_is_host_route() {
    let mut s = IpRangeSet::new();
    assert!(s.add_cidr("203.0.113.5"));
    assert!(s.contains(ip("203.0.113.5")));
    assert!(!s.contains(ip("203.0.113.6")));
}

#[test]
fn rejects_garbage() {
    let mut s = IpRangeSet::new();
    assert!(!s.add_cidr("not-an-ip"));
    assert!(!s.add_cidr("999.0.0.0/8"));
    assert!(s.is_empty());
}

#[test]
fn parses_crawler_feed_json() {
    // the shape Google/Bing publish
    let feed = br#"{
      "creationTime": "2024-01-01T00:00:00.0000000",
      "prefixes": [
        { "ipv4Prefix": "192.178.5.0/27" },
        { "ipv6Prefix": "2001:4860:4801::/48" },
        { "ipv4Prefix": "66.249.64.0/19" }
      ]
    }"#;
    let mut s = IpRangeSet::new();
    let added = s.add_feed_json(feed);
    assert_eq!(added, 3);
    assert!(s.contains(ip("192.178.5.10")));
    assert!(s.contains(ip("66.249.70.1")));
    assert!(s.contains(ip("2001:4860:4801:1::1")));
    assert!(!s.contains(ip("8.8.8.8")));
}

#[test]
fn empty_or_malformed_feed_is_safe() {
    let mut s = IpRangeSet::new();
    assert_eq!(s.add_feed_json(b"not json"), 0);
    assert_eq!(s.add_feed_json(br#"{"prefixes":[]}"#), 0);
    assert!(s.is_empty());
}

#[test]
fn fcrdns_suffix_respects_label_boundary() {
    // legitimate sub-domains match
    assert!(host_matches_suffix("crawl-66-249-66-1.googlebot.com", "googlebot.com"));
    assert!(host_matches_suffix("bot.search.msn.com", ".search.msn.com"));
    // exact match is allowed
    assert!(host_matches_suffix("googlebot.com", "googlebot.com"));
    // the classic look-alike bypass must be rejected
    assert!(!host_matches_suffix("evilgooglebot.com", "googlebot.com"));
    assert!(!host_matches_suffix("googlebot.com.attacker.net", "googlebot.com"));
    // case-insensitive + FQDN trailing dot
    assert!(host_matches_suffix("Bot.GoogleBot.Com.", "googlebot.com"));
    // empty inputs never match
    assert!(!host_matches_suffix("", "googlebot.com"));
    assert!(!host_matches_suffix("googlebot.com", ""));
}
