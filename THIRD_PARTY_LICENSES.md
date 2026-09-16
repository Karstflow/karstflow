# Third-Party Licenses

Karstflow itself is licensed under the Apache License, Version 2.0 (see [`LICENSE`](LICENSE)).

This file records third-party material that Karstflow **redistributes**, as required by
Apache License 2.0 §4. Crates consumed from crates.io are not redistributed in source form and
are covered by the dependency section at the bottom.

## Embedded sBPF program binaries

The following pre-compiled programs live in
[`crates/karstflow-control/src/programs/`](crates/karstflow-control/src/programs/) and are
embedded into the Karstflow binary via `include_bytes!` so that a node started from genesis has
real on-chain program code. They are redistributed **unmodified**.

Every one of them is licensed under the **Apache License, Version 2.0** — the same license that
governs Karstflow. A copy of that license is in [`LICENSE`](LICENSE).

### Solana Program Library

Copyright Solana Labs, Anza Technology, and the Solana Program Library contributors.
Upstream: <https://github.com/solana-program> (current), formerly
<https://github.com/solana-labs/solana-program-library>.

| Program | Version | File | SHA-256 |
|---------|---------|------|---------|
| SPL Token | 3.5.0 | `spl_token-3.5.0.so` | `18264f491c7e0ad056dd36f42f8de6d1fedf9f044d1f521e714b4dc6b61594b6` |
| SPL Token-2022 | 10.0.0 | `spl_token_2022-10.0.0.so` | `a794161408080f690dac00832f45b3c3e2b71f1339586667ad1f979cf91d5b68` |
| SPL Memo | 1.0.0 | `spl_memo-1.0.0.so` | `9b097bd59cc2b02b0d78e8d1cdb2b5f92292b9507a4fd3c1b436c61c1931c63b` |
| SPL Memo | 3.0.0 | `spl_memo-3.0.0.so` | `f520eaf096361abbb9639ea4dc3e5388a87b9330e121f476607b87c46ef67954` |
| SPL Associated Token Account | 1.1.1 | `spl_associated_token_account-1.1.1.so` | `e5e7aed11ad3969eea2aa76c8b4d2e73ea25be7e6b5cce989b7710cf5452496e` |

### Solana core-BPF programs

Copyright Anza Technology and contributors.
Upstream: <https://github.com/solana-program>.

| Program | Version | File | SHA-256 |
|---------|---------|------|---------|
| Address Lookup Table | 3.0.0 | `core_bpf_address_lookup_table-3.0.0.so` | `e264e1537c5ee1252aae1fa476c25000b641357bc6af4efab65f314160a99570` |
| Config | 3.0.0 | `core_bpf_config-3.0.0.so` | `06dd0ed33dda54b37fbbb9df5e08d28a71aa817dbc57d7b0a57e348d2f4e34fa` |
| Feature Gate | 0.0.1 | `core_bpf_feature_gate-0.0.1.so` | `4889655084aa7b8a58cb44f56a8396881a7329a1e3b91cebd9763cdf9ad04e88` |
| Stake | 1.0.1 | `core_bpf_stake-1.0.1.so` | `211fa9794905debf92a72a3366634607f05d87c0f8e85193ea1d6fb3c5e31a80` |

The checksums above are the authoritative identity of what is shipped. Verify with:

```sh
shasum -a 256 crates/karstflow-control/src/programs/*.so
```

## Rust dependencies

Karstflow depends on crates from crates.io but does not redistribute their source. The full
dependency set is pinned in `Cargo.lock`. Every dependency is under a permissive license
(MIT, Apache-2.0, BSD-2/3-Clause, ISC, Zlib, Unlicense, CC0-1.0 or CDLA-Permissive-2.0); there
is no copyleft-licensed dependency in the graph. To regenerate the inventory:

```sh
cargo metadata --format-version 1 --all-features
```

## Protocol compatibility

Karstflow is an independent implementation of the Solana protocol with no runtime dependency on
any existing Solana validator codebase. Protocol and RPC compatibility does not imply
derivation from, or affiliation with, any other implementation.
