//! Client and policy binding. Addresses and User-Agents never appear in tokens:
//! only a domain-separated HMAC of their canonical context is exposed.

use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{codec::b64url, HmacKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressPolicy {
    pub ipv4_prefix: u8,
    pub ipv6_prefix: u8,
}

impl Default for AddressPolicy {
    fn default() -> Self {
        Self {
            ipv4_prefix: 32,
            ipv6_prefix: 128,
        }
    }
}

impl AddressPolicy {
    pub fn valid(self) -> bool {
        (1..=32).contains(&self.ipv4_prefix) && (1..=128).contains(&self.ipv6_prefix)
    }

    pub fn network(self, ip: IpAddr) -> Option<IpAddr> {
        if !self.valid() {
            return None;
        }
        // IPv4-mapped IPv6 sockets and native IPv4 must identify the same client.
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            _ => ip,
        };
        Some(match ip {
            IpAddr::V4(v4) => IpAddr::V4(Ipv4Addr::from(
                u32::from(v4) & (u32::MAX << (32 - self.ipv4_prefix)),
            )),
            IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(
                u128::from(v6) & (u128::MAX << (128 - self.ipv6_prefix)),
            )),
        })
    }
}

/// Pre-serialized policy fields for the existing JSON scope representation.
/// Host-only cookies still bind to the request host; domain cookies reuse the
/// complete scope. Empty normalized hosts/domains fail closed.
pub struct Scope {
    tail: String,
    domain: Option<String>,
}

impl Scope {
    pub fn new(domain: Option<&str>, name: &str, path: &str, endpoint: &str, policy: &str) -> Self {
        let fields =
            serde_json::to_string(&(name, path, endpoint, policy)).expect("serialize scope");
        let tail = format!(",{}", &fields[1..]);
        let domain = domain.map(|domain| {
            let domain = domain.trim_start_matches('.').to_ascii_lowercase();
            if domain.is_empty() {
                return String::new();
            }
            format!(
                "[{}{tail}",
                serde_json::to_string(&domain).expect("serialize domain")
            )
        });
        Self { tail, domain }
    }

    pub fn for_host<'a>(&'a self, host: &str) -> Option<Cow<'a, str>> {
        if let Some(domain) = &self.domain {
            return (!domain.is_empty()).then_some(Cow::Borrowed(domain));
        }
        let host = host.trim_start_matches('.');
        if host.is_empty() {
            return None;
        }
        let host = if host.bytes().any(|b| b.is_ascii_uppercase()) {
            Cow::Owned(host.to_ascii_lowercase())
        } else {
            Cow::Borrowed(host)
        };
        let mut scope = Vec::with_capacity(host.len() + self.tail.len() + 3);
        scope.push(b'[');
        serde_json::to_writer(&mut scope, &host).ok()?;
        scope.extend_from_slice(self.tail.as_bytes());
        Some(Cow::Owned(String::from_utf8(scope).ok()?))
    }
}

/// Scope includes the configured cookie domain (or request host), cookie name,
/// cookie path, endpoint and operator-selected policy name. `issuer` identifies
/// the worker-shared redemption store; independent stores cannot accept each
/// other's challenges or cookies even when they share a signing key.
pub fn binding(
    key: &[u8],
    ip: IpAddr,
    user_agent: &str,
    scope: &str,
    issuer: &[u8],
    address: AddressPolicy,
) -> Option<String> {
    binding_prepared(&HmacKey::new(key), ip, user_agent, scope, issuer, address)
}

/// Bind a request using a reusable key schedule; framing stays protocol v2.
pub fn binding_prepared(
    key: &HmacKey,
    ip: IpAddr,
    user_agent: &str,
    scope: &str,
    issuer: &[u8],
    address: AddressPolicy,
) -> Option<String> {
    let network = address.network(ip)?;
    let network = network.to_string();
    let prefixes = [address.ipv4_prefix, address.ipv6_prefix];
    Some(b64url(&key.fields(&[
        b"pow-gate-context-v2",
        network.as_bytes(),
        user_agent.as_bytes(),
        scope.as_bytes(),
        issuer,
        &prefixes,
    ])))
}

/// Assurance is authenticated in both challenges and clearances. A cheap/no-JS
/// clearance cannot satisfy a stronger PoW policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Assurance {
    Pow { difficulty: u64 },
    NoJs { delay: i64 },
}

impl Assurance {
    pub fn satisfies(self, required: Self) -> bool {
        match (self, required) {
            (Self::Pow { difficulty: got }, Self::Pow { difficulty: need }) => {
                need > 0 && got >= need
            }
            (Self::NoJs { delay: got }, Self::NoJs { delay: need }) => need > 0 && got >= need,
            _ => false,
        }
    }
}
