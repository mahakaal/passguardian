# Test strategy (test-first)

Rule: **no production code without a test that fails first.**
This page lists the tests each sprint must pass *before* the implementation is written.
A test listed here is an acceptance criterion.

## Levels
| Layer | Type | Where | Dependencies |
|---|---|---|---|
| `core` | unit + known test vectors + property tests | `crates/core` | none |
| `server-domain` | unit tests with in-memory fake repositories | `crates/server-domain` | no I/O |
| `server-data` | integration on real PostgreSQL + migration tests | `crates/server-data` | `TEST_DATABASE_URL` |
| `server-api` | HTTP tests with `tower::ServiceExt::oneshot` on top of the domain with fakes | `crates/server-api` | no I/O |
| end-to-end | `cli` against the real server + Postgres (compose) | `tests/e2e` | Docker |

Every data-layer test uses an **isolated schema** (one database or schema per test) so tests can run in parallel.

## Repository contract tests
A single suite, written against the domain traits, run on **every implementation** (in-memory fake and Postgres).
If both pass, the domain is truly independent of storage.

## Sprint 1 – Core cryptography (write first)
- `argon2id_derive_matches_known_vector`: known vector → expected output (RFC 9106 / the crate's official tests).
- `wrap_unwrap_vault_key_roundtrip` and `unwrap_with_wrong_master_key_fails`.
- `encrypt_decrypt_item_roundtrip` (property test: for any payload the roundtrip is the identity).
- `tampered_ciphertext_is_rejected` (every modified bit → authentication error).
- `nonce_is_never_reused` (N encryptions of the same plaintext → all nonces distinct).
- `unknown_format_version_is_rejected` and `old_format_version_is_migrated`.
- `secrets_are_zeroized_on_drop` (where measurable).
- Generator: `password_has_requested_length_and_classes`, `no_modulo_bias` (uniform distribution over the alphabet), `passphrase_uses_wordlist`.
- TOTP: official RFC 6238 vectors (SHA1/SHA256/SHA512).

## Sprint 2 – Server domain (write first, with fakes)
- `register_creates_user_and_first_device`
- `register_with_existing_email_fails_without_leaking_which_field`
- `login_with_wrong_credentials_is_indistinguishable_from_unknown_user` (same error, same shape)
- `login_is_rate_limited_after_n_failures`
- `create_cipher_increments_user_revision`
- `update_cipher_with_stale_revision_conflicts`
- `delete_cipher_creates_tombstone_and_is_returned_by_sync`
- `sync_since_returns_only_newer_changes_in_order`
- `user_cannot_read_or_modify_another_users_ciphers`
- `revoked_device_cannot_refresh_token`

## Sprint 3 – Data: PostgreSQL and migrations (write first)
**Migrations**
- `migrations_apply_on_empty_database`
- `migrations_are_idempotent_when_rerun` (second startup = no changes)
- `schema_after_migrations_matches_snapshot` (compared with a versioned schema snapshot)
- `applied_migration_checksums_match_files` (a migration edited after merge fails CI)
- `upgrade_from_previous_release_schema_preserves_data` (start from the previous release schema, insert, migrate, read)
- `only_forward_migrations_exist` (no `.down` files)

**Repositories (contract tests on Postgres)**
- All the storage-dependent domain tests, rerun against the Postgres repository.
- `unique_email_constraint_maps_to_domain_conflict` (sqlx error → `DomainError`, never propagated).
- `concurrent_updates_with_same_revision_only_one_wins` (transaction + optimistic check).
- `user_revision_is_monotonic_under_concurrency`.
- `row_level_security_blocks_cross_tenant_reads` (if RLS is adopted).
- `ciphertext_is_stored_and_returned_byte_for_byte`.

## Sprint 4 – API (write first)
- `health_returns_200_ok_json` / `health_returns_503_when_storage_down` (already present).
- `unknown_route_returns_404_problem_json`.
- `malformed_json_returns_400_without_echoing_input`.
- `protected_route_without_token_returns_401`.
- `error_bodies_never_contain_internal_details`.
- `openapi_spec_matches_committed_snapshot` (the contract does not change by accident).

## Sprint 5 – Security (write first)
- OPAQUE: registration/login roundtrip, rejection with a wrong password, no password-equivalent value in stored data.
- `refresh_token_rotation_invalidates_the_previous_one`.
- `logs_never_contain_secrets` (test that captures logs during login and checks for the absence of passwords and tokens).
- Fuzzing of parsers (vault format, API requests) with `cargo-fuzz`.
- `cargo-deny` and `cargo-audit` green in CI.

## Definition of done for every PR
- The test was seen failing before the implementation (red → green).
- `fmt`, `clippy -D warnings`, `test`, `check-layering.sh` green.
- No secrets in logs; documentation and ADRs updated.

## How to verify everything (one command)
```bash
bash scripts/verify.sh
```
It runs formatting, clippy, tests, the layering check and `cargo-deny`: the same checks as CI.
Every claim in this documentation has a test or a check that proves it; if one is missing, it is a documentation bug.

| Claim | How it is verified |
|---|---|
| "The domain does not depend on HTTP/DB" | `scripts/check-layering.sh` |
| "No dependency with an incompatible license" | `cargo deny check licenses` |
| "The API answers according to the documented contract" | API tests + OpenAPI snapshot (Sprint 4) |
| "Migrations are safe" | migration tests (Sprint 3) |
| "No secrets in logs" | test that captures logs (Sprint 5) |
