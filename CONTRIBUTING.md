# Contributing to Karstflow

Karstflow is licensed under the Apache License, Version 2.0. Contributions are welcome.

## License of contributions

By submitting a contribution you agree that it is licensed under the Apache License,
Version 2.0, per §5 of that license. No separate agreement is required.

Sign off every commit with the [Developer Certificate of Origin](https://developercertificate.org/):

```sh
git commit -s
```

The sign-off is your statement that you wrote the contribution, or otherwise have the right to
submit it under the project's license.

Do not submit code you do not have the right to relicense — in particular, do not copy source
from another validator implementation into this repository. Karstflow is an independent
implementation; studying a specification or a reference implementation is fine, copying its
code is not.

## Before you open a pull request

Run the same gates CI runs:

```sh
just ci        # fmt-check + lint + test
```

which is:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

Behaviour changes need tests. Integration and conformance suites are run separately:

```sh
just integration
just conformance
```

## Commit messages

`type(scope): summary` — imperative, one line, 72 characters or less. A short body explaining
what changed and why is welcome; a file-by-file changelog is not.

## Third-party binaries

`crates/karstflow-control/src/programs/` contains third-party Apache-2.0 program binaries. If
you add, replace or remove one, update `NOTICE` and `THIRD_PARTY_LICENSES.md` in the same pull
request. See the README in that directory.

## Security issues

Do not open a public issue for a vulnerability, especially one affecting consensus, the
transaction pipeline or key handling. Email <boogvar@gmail.com> instead.

## Reporting a bug

Include the commit, the execution mode (tokio / pinned / tile), the config, what you expected,
what happened, and the logs. For a consensus or replay problem, the slot number and the fork
state matter more than anything else.
