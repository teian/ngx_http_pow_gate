//! Client and policy binding. Addresses and User-Agents never appear in tokens:
//! only a domain-separated HMAC of their canonical context is exposed.

use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{codec::b64url_into, HmacKey};

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
    binding_fixed(key, ip, user_agent, scope, issuer, address).map(|binding| binding.to_string())
}

/// A context binding: 43 base64url characters, held inline. Dereferences to
/// `str`, so it is used like the `String` [`binding_prepared`] returns.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Binding([u8; 43]);

impl std::ops::Deref for Binding {
    type Target = str;

    fn deref(&self) -> &str {
        // Only ever filled by the base64url encoder.
        std::str::from_utf8(&self.0).unwrap_or("")
    }
}

impl std::fmt::Display for Binding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self)
    }
}

impl std::fmt::Debug for Binding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&**self, f)
    }
}

/// [`binding_prepared`] without heap allocation on the IPv4 path: the same
/// bytes are authenticated and the same text results.
pub fn binding_fixed(
    key: &HmacKey,
    ip: IpAddr,
    user_agent: &str,
    scope: &str,
    issuer: &[u8],
    address: AddressPolicy,
) -> Option<Binding> {
    let prefixes = [address.ipv4_prefix, address.ipv6_prefix];
    let mac = |network: &[u8]| {
        key.fields(&[
            b"pow-gate-context-v2",
            network,
            user_agent.as_bytes(),
            scope.as_bytes(),
            issuer,
            &prefixes,
        ])
    };
    let mac = match address.network(ip)? {
        IpAddr::V4(v4) => {
            let mut text = [0u8; 15];
            let length = dotted_quad(v4, &mut text);
            mac(&text[..length])
        }
        // The canonical IPv6 text form (zero compression) stays with std.
        network => mac(network.to_string().as_bytes()),
    };
    let mut binding = [0u8; 43];
    (b64url_into(&mac, &mut binding)? == binding.len()).then_some(Binding(binding))
}

/// `Ipv4Addr`'s `Display` output, written without the formatting machinery.
fn dotted_quad(address: Ipv4Addr, output: &mut [u8; 15]) -> usize {
    let mut length = 0;
    for (index, octet) in address.octets().into_iter().enumerate() {
        if index > 0 {
            output[length] = b'.';
            length += 1;
        }
        if octet >= 100 {
            output[length] = b'0' + octet / 100;
            length += 1;
        }
        if octet >= 10 {
            output[length] = b'0' + octet / 10 % 10;
            length += 1;
        }
        output[length] = b'0' + octet % 10;
        length += 1;
    }
    length
}

/// Assurance is authenticated in both challenges and clearances. A cheap/no-JS
/// clearance cannot satisfy a stronger PoW policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Assurance {
    Pow { difficulty: u64 },
    NoJs { delay: i64 },
}

/// Reads the same `{"kind":…,…}` object the derived serializer writes, in any
/// key order and ignoring unknown keys. Written by hand because serde's
/// derived reader for a tagged enum first buffers the whole object on the
/// heap, and this runs on every cleared request.
impl<'de> serde::Deserialize<'de> for Assurance {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::{Error, IgnoredAny, MapAccess, Visitor};

        #[derive(serde::Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Kind,
            Difficulty,
            Delay,
            #[serde(other)]
            Other,
        }

        #[derive(Clone, Copy, PartialEq, serde::Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum Kind {
            Pow,
            NoJs,
        }

        struct AssuranceVisitor;

        impl<'de> Visitor<'de> for AssuranceVisitor {
            type Value = Assurance;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an assurance object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Assurance, A::Error> {
                let (mut kind, mut difficulty, mut delay) = (None, None, None);
                while let Some(field) = map.next_key()? {
                    match field {
                        Field::Kind if kind.is_none() => kind = Some(map.next_value::<Kind>()?),
                        Field::Kind => return Err(A::Error::duplicate_field("kind")),
                        // A key of the other variant is an unknown key.
                        Field::Difficulty if kind != Some(Kind::NoJs) => {
                            if difficulty.is_some() {
                                return Err(A::Error::duplicate_field("difficulty"));
                            }
                            difficulty = Some(map.next_value::<u64>()?);
                        }
                        Field::Delay if kind != Some(Kind::Pow) => {
                            if delay.is_some() {
                                return Err(A::Error::duplicate_field("delay"));
                            }
                            delay = Some(map.next_value::<i64>()?);
                        }
                        _ => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                match kind.ok_or_else(|| A::Error::missing_field("kind"))? {
                    Kind::Pow => Ok(Assurance::Pow {
                        difficulty: difficulty
                            .ok_or_else(|| A::Error::missing_field("difficulty"))?,
                    }),
                    Kind::NoJs => Ok(Assurance::NoJs {
                        delay: delay.ok_or_else(|| A::Error::missing_field("delay"))?,
                    }),
                }
            }
        }

        deserializer.deserialize_map(AssuranceVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assurance_reads_what_it_writes() {
        for assurance in [
            Assurance::Pow { difficulty: 0 },
            Assurance::Pow {
                difficulty: u64::MAX,
            },
            Assurance::NoJs { delay: 5 },
            Assurance::NoJs { delay: -1 },
        ] {
            let json = serde_json::to_string(&assurance).unwrap();
            assert_eq!(serde_json::from_str::<Assurance>(&json).unwrap(), assurance);
        }
        assert_eq!(
            serde_json::to_string(&Assurance::Pow { difficulty: 7 }).unwrap(),
            r#"{"kind":"pow","difficulty":7}"#
        );
        assert_eq!(
            serde_json::to_string(&Assurance::NoJs { delay: 3 }).unwrap(),
            r#"{"kind":"no_js","delay":3}"#
        );
    }

    #[test]
    fn assurance_accepts_any_key_order_and_unknown_keys() {
        let parse = |json: &str| serde_json::from_str::<Assurance>(json);
        assert_eq!(
            parse(r#"{"difficulty":9,"kind":"pow"}"#).unwrap(),
            Assurance::Pow { difficulty: 9 }
        );
        assert_eq!(
            parse(r#"{"delay":4,"extra":[1,{"a":null}],"kind":"no_js"}"#).unwrap(),
            Assurance::NoJs { delay: 4 }
        );
        // The other variant's key is just an unknown key once the kind is known.
        assert_eq!(
            parse(r#"{"kind":"pow","delay":"x","difficulty":2}"#).unwrap(),
            Assurance::Pow { difficulty: 2 }
        );
    }

    #[test]
    fn assurance_rejects_malformed_objects() {
        for json in [
            r#"{}"#,
            r#"{"difficulty":1}"#,
            r#"{"kind":"pow"}"#,
            r#"{"kind":"pow","delay":1}"#,
            r#"{"kind":"no_js","difficulty":1}"#,
            r#"{"kind":"other","difficulty":1}"#,
            r#"{"kind":"pow","difficulty":-1}"#,
            r#"{"kind":"pow","difficulty":"1"}"#,
            r#"{"kind":"pow","difficulty":1,"difficulty":2}"#,
            r#"{"kind":"pow","kind":"pow","difficulty":1}"#,
            r#"["pow",1]"#,
            r#""pow""#,
        ] {
            assert!(serde_json::from_str::<Assurance>(json).is_err(), "{json}");
        }
    }

    #[test]
    fn fixed_binding_matches_the_formatted_one() {
        let key = HmacKey::new(b"0123456789abcdef0123456789abcdef");
        let policy = AddressPolicy::default();
        for ip in [
            "0.0.0.0",
            "1.2.3.4",
            "10.0.200.9",
            "192.168.100.255",
            "255.255.255.255",
            "::1",
            "2001:db8::1",
            "::ffff:203.0.113.7",
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            let network = policy.network(ip).unwrap().to_string();
            let expected = crate::codec::b64url(&key.fields(&[
                b"pow-gate-context-v2",
                network.as_bytes(),
                b"agent",
                b"scope",
                b"issuer",
                &[policy.ipv4_prefix, policy.ipv6_prefix],
            ]));
            let fixed = binding_fixed(&key, ip, "agent", "scope", b"issuer", policy).unwrap();
            assert_eq!(&*fixed, expected);
            assert_eq!(
                binding_prepared(&key, ip, "agent", "scope", b"issuer", policy).unwrap(),
                expected
            );
        }
        for octets in [[0, 9, 10, 99], [100, 101, 199, 200], [249, 250, 255, 7]] {
            let address = Ipv4Addr::from(octets);
            let mut text = [0u8; 15];
            let length = dotted_quad(address, &mut text);
            assert_eq!(&text[..length], address.to_string().as_bytes());
        }
    }
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
