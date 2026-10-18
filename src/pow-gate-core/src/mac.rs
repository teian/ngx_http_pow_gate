//! HMAC-SHA256 and constant-time comparison — the spine of clearance/challenge
//! integrity. Internal to the crate.

#[cfg(not(feature = "native-crypto"))]
use hmac::{Hmac, Mac};
#[cfg(not(feature = "native-crypto"))]
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// Reusable HMAC key schedule. Each operation clones the initialized state;
/// messages never share mutable authentication state.
#[derive(Clone)]
pub struct HmacKey(KeyState);

#[cfg(feature = "native-crypto")]
type KeyState = ring::hmac::Key;
#[cfg(not(feature = "native-crypto"))]
type KeyState = Hmac<Sha256>;

#[cfg(feature = "native-crypto")]
struct State(ring::hmac::Context);
#[cfg(not(feature = "native-crypto"))]
struct State(Hmac<Sha256>);

impl State {
    fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    fn finish(self) -> [u8; 32] {
        #[cfg(feature = "native-crypto")]
        {
            self.0
                .sign()
                .as_ref()
                .try_into()
                .expect("SHA-256 tag length")
        }
        #[cfg(not(feature = "native-crypto"))]
        {
            self.0.finalize().into_bytes().into()
        }
    }
}

impl HmacKey {
    pub fn new(key: &[u8]) -> Self {
        #[cfg(feature = "native-crypto")]
        {
            Self(ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key))
        }
        #[cfg(not(feature = "native-crypto"))]
        {
            Self(Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length"))
        }
    }

    fn start(&self) -> State {
        #[cfg(feature = "native-crypto")]
        {
            State(ring::hmac::Context::with_key(&self.0))
        }
        #[cfg(not(feature = "native-crypto"))]
        {
            State(self.0.clone())
        }
    }

    pub fn parts(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut mac = self.start();
        for part in parts {
            mac.update(part);
        }
        mac.finish()
    }

    pub fn fields(&self, fields: &[&[u8]]) -> [u8; 32] {
        let mut mac = self.start();
        for field in fields {
            mac.update(&(field.len() as u64).to_be_bytes());
            mac.update(field);
        }
        mac.finish()
    }
}

/// HMAC-SHA256 of `msg` under `key`. Accepts a key of any length (HMAC handles it).
pub fn hmac(key: &[u8], msg: &[u8]) -> [u8; 32] {
    HmacKey::new(key).parts(&[msg])
}

/// Constant-time equality. Returns `false` on length mismatch (lengths are not
/// secret here, so an early return is fine).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.ct_eq(b).into()
}
