# Architecture

Modular monolith in Rust. Three layers with one-way dependencies:

```
api  ──►  domain  ◄──  data
```

- `server-domain` defines entities, services and **ports** (traits). It does not import HTTP, database or network I/O crates.
- `server-api` translates HTTP ⇄ use cases. No logic in handlers.
- `server-data` implements the ports with PostgreSQL (`sqlx`) and holds the **migrations**.
- `server` is the *composition root*: the only place where concrete implementations are chosen.

## Rules (enforced in CI)
1. `server-domain`, `core` and `proto` do not depend on `axum`, `hyper`, `sqlx`, `reqwest`, ...
2. `server-data` does not depend on the HTTP layer.
3. Database types never leave `server-data`.
4. Errors on three levels: `DataError` → `DomainError` → HTTP response (mapping only in `server-api/src/error.rs`).

## Data (the server only sees ciphertext)
`users`, `devices`, `ciphers` (encrypted blobs + `revision` + tombstones), `folders`, `user_revision`.
Sync: `GET /api/v1/sync?since=<rev>`; conflict → `409`.

Decisions: see `docs/adr/`. Planning: `docs/roadmap.md`. Tests: `docs/testing.md`.
