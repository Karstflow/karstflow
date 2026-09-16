# Contributing to Karstflow

Karstflow is licensed under the Apache License, Version 2.0. Contributions are welcome.

## License of contributions

By submitting a contribution you agree that it is licensed under the Apache License,
Version 2.0, per §5 of that license. **There is no CLA** — nothing to sign, no account to
create, and no rights are transferred to the maintainer beyond what Apache-2.0 already grants
to everyone.

What is required is a sign-off certifying where the code came from, under the
[Developer Certificate of Origin](DCO) (DCO 1.1 — the full text is in the `DCO` file):

```sh
git commit -s
```

which appends one line to your commit message:

```
Signed-off-by: Jane Developer <jane@example.com>
```

Three things make that line meaningful, so please get them right:

- **Use your real name** and a **reachable email address.** A `users.noreply.github.com`
  address or a handle does not identify anyone; commits signed off that way will be asked to be
  amended.
- The sign-off must match the commit author.
- **If you are contributing in the course of employment**, confirm that your employer permits
  it before you submit. Code written on company time or equipment often belongs to the company,
  not to you, and the sign-off is your statement that you have the right to submit it.

Do not submit code you do not have the right to relicense — in particular, do not copy source
from another validator implementation into this repository. Karstflow is an independent
implementation; studying a specification or a reference implementation is fine, copying its
code is not.

Forgot the sign-off? Amend the last commit with `git commit --amend -s`, or for a branch,
`git rebase --signoff main`.

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
