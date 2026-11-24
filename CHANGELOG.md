# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versions follow [SemVer](https://semver.org/).

## [Unreleased]
### Added
- Rust workspace skeleton (Sprint 0): `core`, `proto`, `server-domain`, `server-data`, `server-api`, `server`, `cli`.
- `GET /api/v1/health` endpoint.
- Quality checks: fmt, clippy, tests, layer-boundary check, cargo-deny and DCO verification.
- GitHub Actions CI workflow and Dependabot configuration.
- Cryptographic core (`passguardian-core`): Argon2id key derivation, random vault key with wrapping, XChaCha20-Poly1305 item encryption and a versioned vault document with step-by-step migrations.
- Password and passphrase generator without modulo bias.
- HOTP and TOTP (RFC 4226, RFC 6238) with SHA-1, SHA-256 and SHA-512.
- ADR 0005: Argon2id parameters and the vault format.
- Server domain (`passguardian-server-domain`): entities, ports, registration, login with throttling, devices, cipher CRUD and sync with revisions and tombstones, in-memory fakes and a reusable repository contract suite.
- PostgreSQL storage (`passguardian-server-data`) with embedded migrations; the contract suite also runs on Postgres. ADR 0008.
- HTTP API v1 (`passguardian-server-api`): accounts, login, token refresh, devices, ciphers and sync. ADR 0009.
- Command-line client (`passguardian`): register, login, logout, add, list, get, delete, status and generate, with an end-to-end test against the real router.
- The server binary now serves the API on PostgreSQL (`DATABASE_URL`, `PASSGUARDIAN_BIND`, `PASSGUARDIAN_TOKEN_SECRET`).
- Self-hosting: multi-stage `Dockerfile` (non-root, distroless), `compose.yaml` with PostgreSQL and `docs/self-hosting.md` with backup and restore.
