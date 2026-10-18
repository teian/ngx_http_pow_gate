//! Protocol v2 clearance. Domain-separated HMAC authenticates version, public
//! key, opaque client/policy binding, assurance and lifetime. Legacy cookies are
//! deliberately rejected: they contain none of these client/policy guarantees.

use crate::codec::{b64url, unb64url};
use crate::context::Assurance;
use crate::mac::{ct_eq, hmac};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Clearance {
    pub version: u8,
    pub pk: String,
    pub context: String,
    pub assurance: Assurance,
    pub iat: i64,
    pub exp: i64,
}

impl Clearance {
    pub fn pk_bytes(&self) -> Option<Vec<u8>> {
        unb64url(&self.pk)
    }
}

fn mac_input(payload: &str) -> Vec<u8> {
    format!("pow-gate-clearance-v2|{payload}").into_bytes()
}

pub fn issue(
    key: &[u8],
    pk_sec1: &[u8],
    context: &str,
    assurance: Assurance,
    iat: i64,
    ttl: i64,
) -> String {
    let payload = Clearance {
        version: 2,
        pk: b64url(pk_sec1),
        context: context.to_owned(),
        assurance,
        iat,
        exp: iat + ttl,
    };
    let payload_b64 = b64url(&serde_json::to_vec(&payload).expect("serialize"));
    let tag = b64url(&hmac(key, &mac_input(&payload_b64)));
    format!("{payload_b64}.{tag}")
}

pub fn verify(
    key: &[u8],
    token: &str,
    context: &str,
    required: Assurance,
    now: i64,
    max_age: i64,
) -> Option<Clearance> {
    if token.len() > 4096 {
        return None;
    }
    let (payload_b64, tag_b64) = token.split_once('.')?;
    let expected = hmac(key, &mac_input(payload_b64));
    if !ct_eq(&expected, &unb64url(tag_b64)?) {
        return None;
    }
    let payload: Clearance = serde_json::from_slice(&unb64url(payload_b64)?).ok()?;
    if payload.version != 2
        || !ct_eq(payload.context.as_bytes(), context.as_bytes())
        || !payload.assurance.satisfies(required)
        || payload.exp <= now
        || payload.iat > now
        || max_age <= 0
        || now.checked_sub(payload.iat)? >= max_age
    {
        return None;
    }
    // A PoW key was curve-validated at issuance; check its canonical shape
    // without repeating curve parsing on cookie-only requests. No-JS clearances
    // have no key, and cannot satisfy a PoW requirement.
    let pk = payload.pk_bytes()?;
    match payload.assurance {
        Assurance::Pow { .. } if pk.len() != 65 || pk[0] != 4 => return None,
        Assurance::NoJs { .. } if !pk.is_empty() => return None,
        _ => {}
    }
    Some(payload)
}
