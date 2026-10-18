//! Protocol v2 clearance. Domain-separated HMAC authenticates version, public
//! key, opaque client/policy binding, assurance and lifetime. Legacy cookies are
//! deliberately rejected: they contain none of these client/policy guarantees.

use std::borrow::Cow;

use crate::codec::{b64url, unb64url, unb64url_fixed, unb64url_into};
use crate::context::Assurance;
use crate::mac::{ct_eq, HmacKey};

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

const MAC_PREFIX: &[u8] = b"pow-gate-clearance-v2|";

#[derive(serde::Deserialize)]
struct Payload<'a> {
    version: u8,
    #[serde(borrow)]
    pk: Cow<'a, str>,
    #[serde(borrow)]
    context: Cow<'a, str>,
    assurance: Assurance,
    iat: i64,
    exp: i64,
}

/// Authenticated payload and its already-decoded key. Its borrowed JSON fields
/// remain inside the verification callback, where the scratch buffer is live.
pub struct VerifiedClearance<'a> {
    payload: Payload<'a>,
    public_key: [u8; 65],
    public_key_len: usize,
}

impl VerifiedClearance<'_> {
    pub fn public_key(&self) -> &[u8] {
        &self.public_key[..self.public_key_len]
    }

    pub fn into_owned(self) -> Clearance {
        Clearance {
            version: self.payload.version,
            pk: self.payload.pk.into_owned(),
            context: self.payload.context.into_owned(),
            assurance: self.payload.assurance,
            iat: self.payload.iat,
            exp: self.payload.exp,
        }
    }
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
    let tag = b64url(&HmacKey::new(key).parts(&[MAC_PREFIX, payload_b64.as_bytes()]));
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
    verify_prepared(&HmacKey::new(key), token, context, required, now, max_age)
}

/// Verify using a reusable key schedule, with identical wire format and checks.
pub fn verify_prepared(
    key: &HmacKey,
    token: &str,
    context: &str,
    required: Assurance,
    now: i64,
    max_age: i64,
) -> Option<Clearance> {
    with_verified_prepared(key, token, context, required, now, max_age, |verified| {
        verified.into_owned()
    })
}

/// Verify with bounded storage and borrow JSON fields when unescaped.
/// The callback runs only after every v2 check passes. It can verify a request
/// proof using `public_key()` without decoding or allocating the key again.
pub fn with_verified_prepared<T>(
    key: &HmacKey,
    token: &str,
    context: &str,
    required: Assurance,
    now: i64,
    max_age: i64,
    use_clearance: impl FnOnce(VerifiedClearance<'_>) -> T,
) -> Option<T> {
    if token.len() > 4096 {
        return None;
    }
    let (payload_b64, tag_b64) = token.split_once('.')?;
    let expected = key.parts(&[MAC_PREFIX, payload_b64.as_bytes()]);
    if !ct_eq(&expected, &unb64url_fixed::<32>(tag_b64)?) {
        return None;
    }
    // Normal module-issued payloads fit here. Avoid clearing a maximum-size
    // buffer on every request. Larger authenticated custom/legacy JSON remains
    // compatible, with its allocation bounded by the 4096-byte token limit.
    let mut decoded = [0; 512];
    if payload_b64.len() <= decoded.len() / 3 * 4 {
        let length = unb64url_into(payload_b64, &mut decoded)?;
        use_authenticated_payload(
            &decoded[..length],
            context,
            required,
            now,
            max_age,
            use_clearance,
        )
    } else {
        let decoded = unb64url(payload_b64)?;
        use_authenticated_payload(&decoded, context, required, now, max_age, use_clearance)
    }
}

fn use_authenticated_payload<T>(
    decoded: &[u8],
    context: &str,
    required: Assurance,
    now: i64,
    max_age: i64,
    use_clearance: impl FnOnce(VerifiedClearance<'_>) -> T,
) -> Option<T> {
    let payload: Payload<'_> = serde_json::from_slice(decoded).ok()?;
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
    let (public_key, public_key_len) = match payload.assurance {
        Assurance::Pow { .. } => {
            let pk = unb64url_fixed::<65>(&payload.pk)?;
            if pk[0] != 4 {
                return None;
            }
            (pk, 65)
        }
        Assurance::NoJs { .. } => {
            if !payload.pk.is_empty() {
                return None;
            }
            ([0; 65], 0)
        }
    };
    Some(use_clearance(VerifiedClearance {
        payload,
        public_key,
        public_key_len,
    }))
}
