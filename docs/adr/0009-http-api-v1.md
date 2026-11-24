# ADR 0009 – HTTP API v1: accounts, tokens and sync

**Status:** accepted (Sprint 4). The login in this ADR is **temporary**: Sprint 5 replaces it with OPAQUE.

## Endpoints (`/api/v1`, JSON)

| Method and path | Auth | What it does |
|---|---|---|
| `GET /health` | none | 200, or 503 if storage is down |
| `POST /accounts` | none | registers a user and the first device; 201 with a session |
| `POST /login` | none | checks the login key, registers the calling device; 200 with a session |
| `POST /token` | refresh token in the body | 200 with a new access token while the device is not revoked |
| `DELETE /devices/{id}` | access token | revokes one of the caller's devices; 204 |
| `POST /ciphers` | access token | stores an encrypted item with a client-chosen UUID; 201 |
| `PUT /ciphers/{id}` | access token | replaces it, if `revision` is the stored one; 409 otherwise |
| `DELETE /ciphers/{id}?revision=N` | access token | leaves a tombstone; deleting twice is harmless |
| `GET /sync?since=N` | access token | everything changed after revision `N`, tombstones included, oldest first, plus the current revision |

Binary fields are standard base64. The types live in `passguardian-proto`.

## Decisions

- **Zero knowledge.** The client derives the master key with Argon2id, then a **login key** from it with HMAC-SHA256 and a fixed label (`passguardian/v1/auth-key`, `passguardian-core::auth`). The server receives the login key, never the password or the master key, and stores only `SHA-256(label ‖ user id ‖ login key)`, compared in constant time. Knowing the stored hash gives no way back to the master key or the vault key. The login key is a 256-bit secret, so a fast hash is enough.
- **Key envelope.** At registration the client sends an opaque `key_envelope`: a vault document without items (KDF parameters, salt, wrapped vault key; ADR 0005). The server stores it and returns it at login, so a new device can unlock the vault. The server never parses it.
- **Tokens** are stateless: `base64url(payload).base64url(HMAC-SHA256(secret, payload))`, carrying kind, user, device and expiry. Access tokens last 15 minutes, refresh tokens 30 days. The secret comes from `PASSGUARDIAN_TOKEN_SECRET`; without it a random one is used and sessions end at restart. Every verification failure is the same `401`.
- **Revocation.** Revoking a device stops its refresh; its current access token (at most 15 minutes) stays valid until it expires. Checking the device on every request would cost a query per call; revisit if that window is too long.
- **Errors** are `{ "code", "message" }` with fixed texts: they never echo the request, a storage message or a trace. Malformed JSON, bad UUIDs and bad query strings are all the same `400`. This keeps ADR-level simplicity instead of full RFC 9457 `problem+json`.
- **Rate limiting.** 5 failed logins per 15 minutes per normalised email, known or not, then `429`. The state is in the process (one node).
- Request bodies are limited to 1 MiB.

## Known limitations (follow-ups)

1. **Salt and parameters at login.** A new device must derive the login key before it can read the envelope, so in v1 the salt is derived from the email and the KDF parameters are the defaults. Raising the parameters later needs a `prelogin` endpoint that returns them (and a fake answer for unknown emails). Until then the parameters stored in the envelope must equal the defaults.
2. **No refresh-token rotation.** A stolen refresh token works until it expires or the device is revoked (Sprint 5).
3. **Lockout can be abused.** Anyone can lock a known email out for 15 minutes by failing logins on purpose. Per-IP limits and OPAQUE reduce this; both come in Sprint 5.
4. **Folders** have entities but no endpoints yet.
5. **No OpenAPI document yet.** The contract is this table plus the tests in `crates/server-api/tests/api.rs`.
