//! Bounded one-use ledger. The caller MUST hold a process-shared lock throughout
//! `consume`; nginx supplies its shared-memory slab mutex and samples a
//! nondecreasing shared clock inside that lock. Expired slots can be
//! reused, but live entries are never evicted, including when capacity runs out.

use sha2::{Digest, Sha256};

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Entry {
    id: [u8; 32],
    expires: i64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Accepted,
    Reused,
    Full,
    Expired,
}

pub fn id(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// Key on the authenticated challenge token, NOT its solution nonce: two
/// different valid nonces for a challenge still redeem the same ledger entry.
pub fn consume(entries: &mut [Entry], id: [u8; 32], expires: i64, now: i64) -> Outcome {
    if expires <= now {
        return Outcome::Expired;
    }
    if entries.is_empty() {
        return Outcome::Full;
    }
    let start = u64::from_be_bytes(id[..8].try_into().unwrap()) as usize % entries.len();
    let mut free = None;
    // A bounded critical section prevents overload from monopolising workers.
    for probe in 0..entries.len().min(64) {
        let index = (start + probe) % entries.len();
        let entry = &entries[index];
        if entry.expires > now && entry.id == id {
            return Outcome::Reused;
        }
        if entry.expires <= now && free.is_none() {
            free = Some(index);
        }
    }
    match free {
        Some(index) => {
            entries[index] = Entry { id, expires };
            Outcome::Accepted
        }
        None => Outcome::Full,
    }
}

/// Random store identity, generated only when nginx creates a fresh zone.
pub fn issuer() -> Option<[u8; 32]> {
    let mut id = [0u8; 32];
    getrandom::getrandom(&mut id).ok()?;
    Some(id)
}
