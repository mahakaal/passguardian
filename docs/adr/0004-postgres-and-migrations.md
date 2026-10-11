# ADR 0004 – PostgreSQL and migrations

**Status:** accepted (supersedes the earlier "SQLite first" idea)

**Decision.**
- Primary database: **PostgreSQL**. We use `sqlx` with **versioned migrations** in `crates/server-data/migrations/`.
- Migrations are **forward-only**, immutable after merge, and applied at server startup (or by a dedicated command).
- Multi-tenancy by `user_id`; evaluate **Row-Level Security** as a second line of defense.
- Queries are checked at compile time with `sqlx` (offline mode: `cargo sqlx prepare`, versioned `.sqlx/` directory).
- SQLite remains a possible future option for minimal self-hosting, not a priority.

**Tests.** See `docs/testing.md`: every migration must apply to an empty database and the result must match the expected schema.
