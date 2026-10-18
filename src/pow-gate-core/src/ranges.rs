//! IP-range membership for the good-bot verifier: parse CIDRs (and the official
//! crawler IP-range JSON feeds), then test an address in O(log ranges). nginx-free
//! and unit-tested; the module wraps it with fetching + refresh + FCrDNS.

use std::net::IpAddr;

/// Forward-confirmed-rDNS suffix test with **label-boundary** semantics.
///
/// `host` matches `suffix` only when it *is* the suffix or sits strictly below it
/// on a DNS label boundary: `bot.googlebot.com` matches `googlebot.com`, but the
/// look-alike `evilgooglebot.com` does **not**. A plain `ends_with` would wrongly
/// accept the latter, letting an attacker who controls the reverse DNS of their
/// own IP impersonate a verified good bot.
///
/// Comparison is case-insensitive; leading/trailing dots on `suffix` and a
/// trailing dot on `host` (FQDN form) are ignored, so `.googlebot.com.` and
/// `googlebot.com` behave identically.
pub fn host_matches_suffix(host: &str, suffix: &str) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let suffix = suffix.trim().trim_matches('.').to_ascii_lowercase();
    if host.is_empty() || suffix.is_empty() {
        return false;
    }
    host == suffix || host.ends_with(&format!(".{suffix}"))
}

/// Sorted, non-overlapping inclusive address intervals, split by family.
#[derive(Default, Clone)]
pub struct IpRangeSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
    prefixes: usize,
}

impl IpRangeSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a CIDR like `192.0.2.0/24` or `2001:db8::/32`. A bare address (no `/`)
    /// is treated as a host route (`/32` or `/128`). Returns `false` if unparseable.
    pub fn add_cidr(&mut self, cidr: &str) -> bool {
        let v4_len = self.v4.len();
        if !self.push_cidr(cidr) {
            return false;
        }
        if self.v4.len() != v4_len {
            let interval = self.v4.pop().expect("new interval");
            insert_interval(&mut self.v4, interval);
        } else {
            let interval = self.v6.pop().expect("new interval");
            insert_interval(&mut self.v6, interval);
        }
        true
    }

    // Feed parsing batches insertion and normalizes once before publication.
    fn push_cidr(&mut self, cidr: &str) -> bool {
        let (ip_str, prefix) = match cidr.split_once('/') {
            Some((i, p)) => match p.trim().parse::<u32>() {
                Ok(bits) => (i.trim(), Some(bits)),
                Err(_) => return false,
            },
            None => (cidr.trim(), None),
        };
        match ip_str.parse::<IpAddr>() {
            Ok(IpAddr::V4(a)) => {
                let bits = prefix.unwrap_or(32);
                if bits > 32 {
                    return false;
                }
                let mask = if bits == 0 {
                    0
                } else {
                    u32::MAX << (32 - bits)
                };
                self.v4.push((u32::from(a) & mask, u32::from(a) | !mask));
                self.prefixes += 1;
                true
            }
            Ok(IpAddr::V6(a)) => {
                let bits = prefix.unwrap_or(128);
                if bits > 128 {
                    return false;
                }
                let mask = if bits == 0 {
                    0
                } else {
                    u128::MAX << (128 - bits)
                };
                self.v6.push((u128::from(a) & mask, u128::from(a) | !mask));
                self.prefixes += 1;
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
                contains_interval(&self.v4, x)
            }
            IpAddr::V6(a) => {
                let x = u128::from(a);
                contains_interval(&self.v6, x)
            }
        }
    }

    pub fn len(&self) -> usize {
        self.prefixes
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
        let mut parsed = Self::new();
        if let Ok(feed) = serde_json::from_slice::<Feed>(bytes) {
            if feed.prefixes.len() > 100_000 {
                return 0;
            }
            for p in feed.prefixes {
                if p.v4.is_none() && p.v6.is_none() {
                    return 0;
                }
                if let Some(c) = p.v4 {
                    if parsed.push_cidr(&c) {
                        n += 1;
                    } else {
                        return 0;
                    }
                }
                if let Some(c) = p.v6 {
                    if parsed.push_cidr(&c) {
                        n += 1;
                    } else {
                        return 0;
                    }
                }
            }
        }
        self.v4.extend(parsed.v4);
        self.v6.extend(parsed.v6);
        self.prefixes += parsed.prefixes;
        normalize(&mut self.v4);
        normalize(&mut self.v6);
        n
    }
}

fn contains_interval<T: Copy + Ord>(ranges: &[(T, T)], address: T) -> bool {
    let i = ranges.partition_point(|(start, _)| *start <= address);
    i != 0 && address <= ranges[i - 1].1
}

fn insert_interval<T: Copy + Ord>(ranges: &mut Vec<(T, T)>, mut interval: (T, T)) {
    let begin = ranges.partition_point(|(_, end)| *end < interval.0);
    let end = ranges.partition_point(|(start, _)| *start <= interval.1);
    if begin < end {
        interval.0 = interval.0.min(ranges[begin].0);
        interval.1 = interval.1.max(ranges[end - 1].1);
    }
    ranges.splice(begin..end, [interval]);
}

fn normalize<T: Copy + Ord>(ranges: &mut Vec<(T, T)>) {
    ranges.sort_unstable();
    let mut used = 0;
    for i in 0..ranges.len() {
        if used != 0 && ranges[i].0 <= ranges[used - 1].1 {
            ranges[used - 1].1 = ranges[used - 1].1.max(ranges[i].1);
        } else {
            ranges[used] = ranges[i];
            used += 1;
        }
    }
    ranges.truncate(used);
}

/// The SAME PTR hostname must satisfy both the suffix and forward checks.
pub fn fcrdns_confirms(
    host: &str,
    suffixes: &[String],
    ip: IpAddr,
    forward: impl FnOnce(&str) -> Vec<IpAddr>,
) -> bool {
    suffixes.iter().any(|s| host_matches_suffix(host, s)) && forward(host).contains(&ip)
}
