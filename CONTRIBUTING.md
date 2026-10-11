# Contributing to PassGuardian

Thank you! The project is designed to be maintained by the community.

## Ground rules
1. **Tests before code.** Every change starts from a failing test (see `docs/testing.md`).
2. **Respect the layer boundaries** (`docs/architecture.md`). `scripts/check-layering.sh` enforces them.
3. **No home-made cryptography.** Use established, reviewable crates (RustCrypto, `opaque-ke`).
4. **No secrets in logs**, ever: no passwords, tokens or payloads.
5. **DCO:** sign off your commits with `git commit -s` (Signed-off-by). No CLA is required.
6. **Commit messages** follow [Conventional Commits](https://www.conventionalcommits.org/) in English, one logical change per commit.

## Workflow
```bash
bash scripts/verify.sh   # fmt, clippy, tests, layering, cargo-deny
```
Open small, focused PRs. For important architectural decisions add an ADR in `docs/adr/`.

## Licenses
- `crates/core`, `crates/proto`: MPL-2.0
- `crates/server-*`, `crates/server`, `crates/cli`: AGPL-3.0-or-later

By contributing you agree that your contribution is released under the license of the crate you modify.
