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
The project is **trunk-based** ([ADR 0006](docs/adr/0006-trunk-based-development.md)): `main` is the only long-lived branch and is always green.

1. Cut a short-lived branch from `main`, named `<type>/<topic>` (for example `feat/totp-base32`).
2. Write the failing test first, then the code. Before pushing, run:
   ```bash
   bash scripts/verify.sh   # fmt, clippy, tests, layering, cargo-deny
   ```
3. Open a **small, focused pull request** against `main`. Its title is a Conventional Commit; end the description with `Refs: PG-nn` when there is a Jira task.
4. Merge when the required checks are green (`fmt, clippy, test, layering`, `cargo-deny`, `DCO (Signed-off-by)`): squash for one logical change, rebase when each commit stands on its own.
5. Unfinished work is merged in small steps but not exposed (not wired to an API, command or UI).

For important architectural decisions add an ADR in `docs/adr/`.

## Licenses
- `crates/core`, `crates/proto`: MPL-2.0
- `crates/server-*`, `crates/server`, `crates/cli`: AGPL-3.0-or-later

By contributing you agree that your contribution is released under the license of the crate you modify.
