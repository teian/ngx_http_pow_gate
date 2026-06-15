//! Build script for the PoW gate module.
//!
//! Almost all of the heavy lifting (locating nginx headers, generating the FFI
//! bindings, emitting the right linker flags for a dynamically-loaded module) is
//! done by the `nginx-sys` crate that `ngx` depends on. This script only adds the
//! glue that is specific to *this* module:
//!
//!   * re-run when the bundled challenge asset changes, and
//!   * forward `nginx-sys`'s link directives so the `.so` resolves nginx symbols
//!     at load time (they are provided by the nginx binary, not by us).
//!
//! See docs/build.md for the environment variables (`NGINX_SOURCE_DIR`,
//! `NGINX_VERSION`, `NGINX_CONFIGURE_ARGS`, …) that select the nginx the module
//! is built against. The module is ABI-bound to that nginx build.

fn main() {
    // Rebuild if the embedded fallback challenge page changes.
    // Assets live at the repo root, two levels up from this crate.
    println!("cargo:rerun-if-changed=../../assets/challenge.html");
    println!("cargo:rerun-if-changed=../../assets/solver.js");

    // `nginx-sys` exports the directory containing the nginx objects via the
    // `DEP_NGINX_*` metadata variables. Forward them so the cdylib is allowed to
    // reference nginx-provided symbols that are only resolved once nginx dlopen()s
    // the module. Without `-undefined dynamic_lookup` (macOS) / unresolved-ok
    // behaviour, linking a module .so against nginx symbols fails.
    if let Ok(flags) = std::env::var("DEP_NGINX_LINK_DIRS") {
        for dir in flags.split(':').filter(|s| !s.is_empty()) {
            println!("cargo:rustc-link-search=native={dir}");
        }
    }

    #[cfg(target_os = "macos")]
    {
        println!("cargo:rustc-link-arg=-undefined");
        println!("cargo:rustc-link-arg=dynamic_lookup");
    }
}
