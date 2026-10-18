//! Per-source last-known-good feeds. Freshness is enforced on every lookup,
//! even if the fetch thread is blocked or a provider is unavailable.
use crate::ranges::IpRangeSet;
use std::{
    net::IpAddr,
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct FeedSnapshot {
    ranges: IpRangeSet,
    updated: Instant,
}
impl FeedSnapshot {
    pub fn parse(bytes: &[u8], now: Instant) -> Option<Self> {
        let mut ranges = IpRangeSet::new();
        if ranges.add_feed_json(bytes) == 0 {
            return None;
        }
        Some(Self {
            ranges,
            updated: now,
        })
    }
    pub fn age(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.updated)
    }
    pub fn fresh(&self, now: Instant, max_stale: Duration) -> bool {
        self.age(now) < max_stale
    }
    pub fn contains(&self, ip: IpAddr, now: Instant, max_stale: Duration) -> bool {
        self.fresh(now, max_stale) && self.ranges.contains(ip)
    }
}
