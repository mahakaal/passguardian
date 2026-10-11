# Sprint roadmap

Indicative sprints of ~2 weeks (a part-time personal project: dates are estimates, not commitments).
Every task has an ID, mirrored in Jira (project PG). **Rule: the tests listed in `docs/testing.md` are written before the code.**
A sprint ends when its exit criteria are met and CI is green.

## Sprint 0 – Foundations ✅ (done)
- S0-1 Rust workspace with 7 crates and layer boundaries
- S0-2 Quality checks: fmt, clippy `-D warnings`, tests, layering, cargo-deny (`scripts/verify.sh`)
- S0-3 Per-crate licenses, README, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT, ADRs 0001-0004
- S0-4 `GET /api/v1/health` endpoint (vertical slice api → domain → data)
- S0-5 Local git repository with atomic commits
- S0-6 Publish `.github/` (CI) and make the first push to GitHub

**Exit:** build, lint and tests green; the server answers on `/api/v1/health`.

## Sprint 1 – Cryptographic core (`core`)
- S1-1 Tests first, then code: Argon2id key derivation with known vectors
- S1-2 Random vault key and wrap/unwrap with the master key
- S1-3 Item encryption (XChaCha20-Poly1305), tampered ciphertext rejected, unique nonces
- S1-4 Versioned vault format + migration between versions
- S1-5 Password/passphrase generator (no modulo bias)
- S1-6 TOTP with RFC 6238 vectors
- S1-7 ADR on Argon2id parameters and the vault format

**Exit:** all the "Sprint 1" tests in `docs/testing.md` green; secrets zeroized.

## Sprint 2 – Server domain (`server-domain`)
- S2-1 Entities (`User`, `Device`, `Cipher`, `Folder`) and typed identifiers
- S2-2 Ports: `UserRepository`, `DeviceRepository`, `CipherRepository`, `Clock`, `UnitOfWork`
- S2-3 Services: registration, device management, cipher CRUD, sync with revisions and tombstones
- S2-4 In-memory fake repositories + reusable **contract test suite**
- S2-5 Isolation between users (no access to other people's data)

**Exit:** all the "Sprint 2" tests green, no I/O in the crate (checked by `check-layering.sh`).

## Sprint 3 – PostgreSQL and migrations (`server-data`)
- S3-1 Development environment: `docker compose` with Postgres, `TEST_DATABASE_URL`
- S3-2 Initial `sqlx` migrations (users, devices, ciphers, folders, user_revision)
- S3-3 Migration tests (from empty, idempotency, checksums, schema snapshot, upgrade from previous release)
- S3-4 Repository implementations with sqlx → domain error mapping
- S3-5 Contract tests also run on Postgres; concurrency and monotonic revisions
- S3-6 Evaluate and decide on Row-Level Security (ADR)
- S3-7 `cargo sqlx prepare` offline mode and a CI check

**Exit:** all the "Sprint 3" tests green in CI with Postgres; migrations applied at startup.

## Sprint 4 – HTTP API (`server-api`) and CLI
- S4-1 `/api/v1` router: register, login (temporary), devices, ciphers, sync
- S4-2 Uniform errors (problem+json), 404/400/401 without internal details
- S4-3 OpenAPI generated from code + snapshot in the repo
- S4-4 Generated TypeScript client
- S4-5 CLI commands (register, login, add, list, sync)
- S4-6 End-to-end CLI test against server + Postgres

**Exit:** all the "Sprint 4" tests green; end-to-end flow runnable from the CLI.

## Sprint 5 – Authentication and security
- S5-1 OPAQUE (`opaque-ke`) replacing the temporary login
- S5-2 Short-lived access tokens + per-device refresh with rotation and revocation
- S5-3 Rate limiting and lockout, indistinguishable responses for unknown users
- S5-4 Logs without secrets (a test proves it)
- S5-5 Parser fuzzing, `cargo-audit` in CI, documented threat model
- S5-6 Account 2FA (TOTP)

**Exit:** all the "Sprint 5" tests green; threat model and security ADRs published.

## Sprint 6 – Multi-device sync
- S6-1 Conflict resolution and offline handling in the client
- S6-2 Encrypted local cache in the client (a server outage does not lock users out)
- S6-3 Change notifications (long polling or WebSocket)
- S6-4 Import/export (Bitwarden JSON, CSV, KeePass) with tests on real anonymized files

**Exit:** two CLI clients converge under concurrent writes.

## Sprint 7 – Deployment and operations
- S7-1 Multi-stage Dockerfile, non-root user, minimal image
- S7-2 `docker-compose.yml` for self-hosting
- S7-3 Helm chart (Postgres operator, TLS ingress, probes, backups)
- S7-4 Metrics and tracing (OpenTelemetry/Prometheus), backup/restore guide
- S7-5 Signed releases, SBOM, reproducible builds
- S7-6 CD pipeline on tags: binaries, GHCR image, signing, GitHub Release

**Exit:** complete installation documented in under 15 minutes; restore tested.

## Backlog (after Sprint 7, to be planned)
- Desktop client (Tauri) and web/extension UI (Vue 3 or Angular: decision pending)
- Browser extension with autofill
- Mobile (Android first, then iOS) with autofill and passkey provider
- Passkeys (WebAuthn) in the vault
- Sharing between users (X25519)
- External security audit before any 1.0 release
- Possible hosted SaaS (see project notes): only after an audit

## Open decisions
| Topic | When to decide |
|---|---|
| Final license (ADR 0002) | before the first public release |
| UI framework | before the client backlog |
| Final name and trademark | before publishing the repository |
| Security contact and donation links | before publishing the repository |
