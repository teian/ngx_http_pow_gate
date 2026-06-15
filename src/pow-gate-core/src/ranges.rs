//! IP-range membership for the good-bot verifier: parse CIDRs (and the official
//! crawler IP-range JSON feeds), then test an address in O(ranges). nginx-free
//! and unit-tested; the module wraps it with fetching + refresh + FCrDNS.

use std::net::IpAddr;

/// A set of IPv4 + IPv6 CIDR ranges, as (network, mask) pairs.
#[derive(Default, Clone)]
pub struct IpRangeSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl IpRangeSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a CIDR like `192.0.2.0/24` or `2001:db8::/32`. A bare address (no `/`)
    /// is treated as a host route (`/32` or `/128`). Returns `false` if unparseable.
    pub fn add_cidr(&mut self, cidr: &str) -> bool {
        let (ip_str, prefix) = match cidr.split_once('/') {
            Some((i, p)) => (i.trim(), p.trim().parse::<u32>().ok()),
            None => (cidr.trim(), None),
        };
        match ip_str.parse::<IpAddr>() {
            Ok(IpAddr::V4(a)) => {
                let bits = prefix.unwrap_or(32).min(32);
                let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
                self.v4.push((u32::from(a) & mask, mask));
                true
            }
            Ok(IpAddr::V6(a)) => {
                let bits = prefix.unwrap_or(128).min(128);
                let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
                self.v6.push((u128::from(a) & mask, mask));
                true
            }
            Err(_) => false,
        }
    }

    /// Is `ip` within any range?
    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(a) => {
                let x = u32::from(a);
                self.v4.iter().any(|(net, mask)| x & mask == *net)
            }
            IpAddr::V6(a) => {
                let x = u128::from(a);
                self.v6.iter().any(|(net, mask)| x & mask == *net)
            }
        }
    }

    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Merge the official crawler feed JSON — Google/Bing publish
    /// `{ "prefixes": [ { "ipv4Prefix": "…" }, { "ipv6Prefix": "…" } ] }`.
    /// Returns the count of prefixes added. Unknown/extra fields are ignored.
    pub fn add_feed_json(&mut self, bytes: &[u8]) -> usize {
        #[derive(serde::Deserialize)]
        struct Feed {
            #[serde(default)]
            prefixes: Vec<Prefix>,
        }
        #[derive(serde::Deserialize)]
        struct Prefix {
            #[serde(rename = "ipv4Prefix", default)]
            v4: Option<String>,
            #[serde(rename = "ipv6Prefix", default)]
            v6: Option<String>,
        }
        let mut n = 0;
        if let Ok(feed) = serde_json::from_slice::<Feed>(bytes) {
            for p in feed.prefixes {
                if let Some(c) = p.v4 {
                    if self.add_cidr(&c) {
                        n += 1;
                    }
                }
                if let Some(c) = p.v6 {
                    if self.add_cidr(&c) {
                        n += 1;
                    }
                }
            }
        }
        n
    }
}
