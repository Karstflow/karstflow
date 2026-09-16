# Embedded sBPF program binaries

These files are **third-party work**, not Karstflow code. They are pre-compiled sBPF programs
from the Solana ecosystem, embedded at compile time by
[`../program_binaries.rs`](../program_binaries.rs) and deployed into genesis accounts so that a
node started from genesis has real on-chain program code.

All of them are licensed under the **Apache License, Version 2.0** and are redistributed
**unmodified**. Attribution, copyright holders and checksums are recorded in
[`THIRD_PARTY_LICENSES.md`](../../../../THIRD_PARTY_LICENSES.md) and
[`NOTICE`](../../../../NOTICE) at the repository root.

Do not add, replace or remove a binary here without updating both of those files — they are
what keeps this repository compliant with Apache-2.0 §4.

## Verifying what is shipped

```sh
shasum -a 256 *.so
```

The expected checksums are the ones listed in `THIRD_PARTY_LICENSES.md`.

## Provenance

The binaries were taken from the Agave distribution of the official program binaries. The
upstream project, version and license of each one are recorded in `THIRD_PARTY_LICENSES.md`;
the exact upstream build commit was not captured when they were vendored, so the SHA-256 of
each file is the authoritative identity. When a binary is next refreshed, record the upstream
release tag it came from alongside the new checksum.
