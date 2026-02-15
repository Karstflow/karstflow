# Contributing

## Local setup
1. Install Rust via rustup.
2. Enter repository root.
3. Run:
   - `cargo fmt --all`
   - `cargo clippy --workspace --all-targets -- -D warnings`
   - `cargo test --workspace --all-targets`

## Style
- Prefer clear, descriptive names.
- Preserve behavior/invariants over naming parity with source project.
- Keep module mapping updated in `docs/90_module_mapping_working.md`.
