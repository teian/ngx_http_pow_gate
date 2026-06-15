//! pow-gate-core — the proof-of-work gate engine, free of any nginx dependency.
//!
//! This is the "engine from the earlier files" made real. It implements the three
//! cryptographic concerns the nginx module orchestrates, each unit-tested here:
//!
//!   * [`pow`]       — issue a challenge and verify a submitted solution
//!     (hashcash-style partial preimage, difficulty → 256-bit target).
//!   * [`clearance`] — mint and verify the HMAC-signed clearance token that proves
//!     a client already solved a challenge, bound to its public key.
//!   * [`proof`]     — verify the per-request ECDSA proof that defeats clearance
//!     theft/replay (DPoP-style).
//!
//! The wire protocol these implement is documented in `../docs/protocol.md`, and
//! the browser side lives in `../assets/solver.js`. Keeping this crate
//! nginx-free is what lets `cargo test` run it on any machine — see
//! `../docs/testing.md`.

pub mod clearance;
pub mod codec;
mod mac;
pub mod pow;
pub mod proof;
pub mod ranges;
pub mod target;

pub use clearance::Clearance;
pub use pow::Challenge;
pub use target::{difficulty_to_target, hash_below};
