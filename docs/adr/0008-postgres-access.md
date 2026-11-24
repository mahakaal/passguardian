# ADR 0008 – How the data layer talks to PostgreSQL

**Status:** accepted (Sprint 3). Refines [ADR 0004](0004-postgres-and-migrations.md).

**Decision.**
- `server-data` uses `sqlx` with the **runtime** query API (`sqlx::query(...).bind(...)`), not the compile-time `query!` macros. The macros need either a live database at build time or a committed `.sqlx/` cache that must be regenerated and reviewed on every query change. With a small set of queries, each one covered by the contract suite and run against a real PostgreSQL in CI, a wrong query is caught by tests, and the build stays independent of a database. This replaces the "offline mode" line of ADR 0004; revisit if the query count grows.
- Migrations live in `crates/server-data/migrations/` as `NNNN_description.sql`, are embedded in the binary (`sqlx::migrate!`) and applied at startup when `DATABASE_URL` is set. They are forward-only: no `.up`/`.down` pairs. `sqlx` records a checksum of each applied file and refuses to start if one was edited.
- The **same contract suite** as the in-memory fake runs on PostgreSQL (`TEST_DATABASE_URL`). Each test creates a throw-away database, so tests run in parallel. Without the variable they are skipped locally and fail when `CI` is set.
- A schema snapshot (`tests/snapshots/schema.txt`) is compared with the migrated schema; changing the schema means refreshing it on purpose (`UPDATE_SNAPSHOT=1`).
- Errors: unique and foreign-key violations become `DomainError::Conflict`; everything else, including data that fails domain validation, becomes `Unavailable`. No `sqlx` type leaves the crate.
- Concurrency: `bump_revision` is an upsert, which locks the user's revision row until the transaction ends, so concurrent writers of one user get strictly increasing revisions. Cipher updates carry the expected revision in the `WHERE` clause, so two writers on the same revision cannot both win. The isolation level stays at PostgreSQL's default (read committed).

**Row-Level Security: not adopted for now.**
Every port method already names the owner and every query filters on `user_id`, and the contract suite checks that another user's rows are invisible. RLS would add a second wall, but it needs a per-transaction `SET LOCAL` of the current user and an application role that is not the table owner, and it would make the tests depend on that setup. Revisit when the server runs behind a role separate from the migration role (Sprint 7), as a hardening step.

**Known gaps.**
- `ciphers.folder_id` has no foreign key yet: there is no folder repository, and the in-memory fake does not check it either. Adding both together keeps the two implementations equal.
- There is no previous release to upgrade from, so `upgrade_from_previous_release_schema_preserves_data` starts with the first release that changes the schema.
