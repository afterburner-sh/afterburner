# Contributing to Afterburner

Thanks for your interest in contributing.

## Contributor License Agreement (required)

Afterburner is source-available under the [Business Source License 1.1](LICENSE)
and is also offered under separate commercial terms. To keep that dual-licensing
possible, **every contributor must sign the [Contributor License Agreement](CLA.md)**.

This is automated: the first time you open a pull request, the **CLA Assistant**
bot (https://cla-assistant.io/) comments with a one-click sign-off link. Your PR
cannot be merged until the check is green. Signing once covers all future
contributions.

If you are contributing on behalf of an employer, make sure you are authorized
to do so (see CLA.md §4).

## Licensing of contributions

By contributing you agree your work is licensed under BSL 1.1 (converting to
Apache-2.0 on the Change Date) and may also be offered by Psila.AI under
commercial license terms, per the CLA. Do not add code under a license
incompatible with this; disclose any third-party code and its license in the PR.

New code goes in the appropriate crate's license tier:

- Engine crates (`afterburner`, `afterburner-core`, `afterburner-wasi`,
  `afterburner-ignite`, `afterburner-flow`, `afterburner-adaptive`,
  `afterburner-node-compat`, `afterburner-thrust`, `afterburner-plugin`) are
  **BSL 1.1** — new `.rs` files must carry the SPDX header used across those
  crates.
- `afterburner-afb`, `burn/*`, and `examples/*` are **Apache-2.0**. (`burndb` is BSL 1.1, licensed separately in its own repo.)

## Development

- See `docs/REPO_CONVENTIONS.md` for code, testing, and commit conventions.
- MSRV is Rust 1.90, edition 2024.
- Run `cargo fmt --all`, `cargo clippy --all-targets`, and `cargo test
  --workspace` before opening a PR.
- Tests are documentation: cover happy path, error paths, edge cases, and
  security/capability denial (10–20 tests per non-trivial module).

## Reporting security issues

Do not open public issues for vulnerabilities. Email **security@afterburner.sh**.
