# ADR 0007 – Domain ports: repositories, clock and unit of work

**Status:** proposed (Sprint 2, PG-24). To be reviewed before the services are written.

**Context.** The domain needs storage and time without knowing PostgreSQL. The same contract tests (PG-26) must pass on an in-memory fake and on the Postgres implementation (Sprint 3).

**Decision.**
- Ports are traits in `server-domain::ports`, using `impl Future + Send` as `StorageProbe` already does (no `async-trait`, no dynamic dispatch). Services are generic over them.
- **Every query names the owner.** `DeviceRepository::find`, `CipherRepository::find` and `changes_since` take a `UserId`; a row of another user is reported as not found, never as forbidden. Isolation (PG-27) is therefore structural, not a check someone can forget.
- **Optimistic concurrency.** `CipherRepository::update` takes the revision the caller read and fails with `DomainError::Conflict` if the stored one differs. The API maps it to `409`. An update that matches no row of that owner (missing, or another user's) fails the same way, so it reveals nothing about other users' data.
- **Revisions.** Each user has one counter. `UserRepository::bump_revision` increments it atomically and returns the new value; a service bumps it once per change and stamps the cipher with it. `changes_since(user, rev)` returns every cipher with a higher revision, tombstones included, in increasing order.
- **Unique email.** `UserRepository::insert` fails with `Conflict` when the email exists. The service must not tell the caller which field clashed.
- **Transactions belong to the domain.** `UnitOfWork::begin` returns a `Transaction` that implements the three repositories; `commit(self)` makes the changes permanent and dropping it rolls back. A service that must write a cipher and bump the revision together does both inside one transaction.
- **Time is injected.** `Clock::now()` returns a `Timestamp` (seconds since the Unix epoch); the domain never reads the system clock.
- Errors: implementations map their own errors to `DomainError` (`Conflict`, `Unavailable`); storage types never leave `server-data` (architecture rule 3).

**Alternatives considered.**
- *A closure-based API (`run_in_transaction(|repos| ...)`)*: awkward with async and borrowing in Rust; a value that rolls back on drop is simpler to implement and test.
- *Repositories receiving an executor argument on every call*: leaks the storage type into the domain.
- *Checking ownership in services only*: one forgotten check is a data leak; passing the owner to the port makes the safe path the only path.

**Consequences.** The Postgres transaction will hold its connection behind interior mutability, because the traits take `&self`. If that proves awkward, revisit with `&mut self` before Sprint 3 starts.

**Open points for review.** Pagination of `changes_since`; whether `find_by_email` should be restricted to the login flow; the exact shape of refresh-token storage (Sprint 5).
