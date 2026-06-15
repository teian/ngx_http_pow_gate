//! nginx-facing engine layer.
//!
//! The cryptography and protocol live in the standalone, unit-tested
//! [`pow_gate_core`] crate (`../core`). This module is the thin nginx shell over
//! it:
//!
//!   * [`clearance`] — read the clearance cookie + per-request proof off the
//!     request and validate them via `pow_gate_core::{clearance, proof}`.
//!   * [`pow`]       — the `/.pow/challenge` and `/.pow/verify` handlers, calling
//!     `pow_gate_core::pow`.
//!
//! Keeping the crypto in `core` is what lets it be tested without nginx (see
//! docs/testing.md); this layer is the integration seam.

pub mod clearance;
pub mod pow;

use ngx::ffi::{ngx_cycle_t, ngx_int_t};

/// Per-worker init hook (wired as `init_process` in the module struct).
///
/// Starts the background IP-range refreshers for every configured
/// `pow_gate_verifier` and loads every distinct `pow_gate_hmac_key_file` found in
/// the location tree into process memory (the directive inherits, so most
/// deployments have exactly one). Runs once per nginx worker after fork.
pub extern "C" fn init_process(cycle: *mut ngx_cycle_t) -> ngx_int_t {
    let _ = cycle;
    // Start the per-worker IP-range refreshers for every configured verifier.
    // (Threads must start post-fork, hence here rather than at config time.)
    crate::verifier::start_refreshers();
    ngx::core::Status::NGX_OK.0 as ngx_int_t
}
