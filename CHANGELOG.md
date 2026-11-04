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
