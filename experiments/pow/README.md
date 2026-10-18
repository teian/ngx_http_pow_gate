# Alternative PoW verifier-cost experiment

Run `cargo run --release --manifest-path experiments/pow/Cargo.toml`.
This standalone project never changes the production protocol or nginx binary.
It compares one server verification using SHA-256, Anubis-style default Argon2id,
and HashX including challenge program construction.

One local run on 2026-10-18 measured:

| Algorithm | Time per verification |
| --- | ---: |
| SHA-256 | 0.324 µs |
| Argon2id (19 MiB, t=2, p=1) | 23,413 µs |
| HashX including program construction | 48.620 µs |

These are native CPU measurements, not browser solve times or production capacity
estimates. Argon2id allocates about 19 MiB per concurrent verification; putting
it in the nginx access handler would block a worker. HashX also increases server
verification cost substantially. Retain SHA-256 as the production default.

A production alternative needs an authenticated algorithm/parameter identifier,
identical client/server vectors, downgrade-resistant assurance comparisons,
bounded asynchronous verification, WASM/JS fallback, and mobile/SIMD-disabled
browser benchmarks. Faster WASM SHA-256 changes browser speed, not the underlying
work function's resistance to specialized solvers. This experiment intentionally
does not claim to establish that resistance or select production difficulty.
